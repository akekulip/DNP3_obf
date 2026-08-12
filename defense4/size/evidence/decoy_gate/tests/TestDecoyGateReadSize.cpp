// SPDX-License-Identifier: Apache-2.0
//
// PART B (READ axis) — configured real measurement points + inert decoy measurement
// points, read by the SAME all-points (class-0 integrity) poll from an UNMODIFIED
// opendnp3 master. Software only: crafted class-0 responses are produced by a real
// opendnp3 outstation and driven straight into a real opendnp3 master. No networking,
// no hardware, no relay.
//
// PREMISE (endpoint preconfiguration REQUIRED). The decoys are REAL, CONFIGURED analog
// input points in the outstation database (higher indices). This is a firmware/config
// change; it is NOT a completely unmodified outstation.
//
//   B1  per-object invariance of the REAL points, measured TWO ways as decoys are added:
//         (a) SEMANTIC  — the master parses the padded response and every real point's
//             value + quality flag equal the loaded value (parsed-measurement compare);
//         (b) SERIALIZED — each real object's on-wire bytes (group/variation, index,
//             quality byte, value bytes) are byte-identical between the native (K=0)
//             response and the decoy-padded response. This is the corrected byte-level
//             claim: we do NOT require the WHOLE response to be byte-identical (header
//             range/count/length legitimately change), only each REAL OBJECT.
//       Plus: the unmodified master ACCEPTS the padded response and delivers all points.
//
//   B2  COMMON-TARGET CONVERGENCE (the normalization gate). TWO software outstation
//       profiles with DIFFERENT native real-point counts (=> different native response
//       lengths) are each padded with configured decoys so both expose ONE declared
//       common public schema. PASS only if both profiles reach the SAME measured target
//       at the declared layer (object variation, qualifier, index range, object count,
//       application bytes, fragment count). A response that merely grows is NOT a pass.
//
//   B3  single-profile size/fragment/segment ENLARGEMENT sweep. Explicitly NOT the
//       normalization gate — one device's response simply gets larger with K. Kept as a
//       contrast to B2 so "bigger" is never mistaken for "normalized".

#include "utils/APDUHexBuilders.h"
#include "utils/MasterTestFixture.h"
#include "utils/MeasurementComparisons.h"
#include "utils/OutstationTestObject.h"

#include <dnp3mocks/DatabaseHelpers.h>

#include <opendnp3/app/MeasurementTypes.h>
#include <opendnp3/gen/GroupVariation.h>

#include <catch.hpp>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace opendnp3;

#define SUITE(name) "DecoyGateReadTestSuite - " name

namespace
{

// ----- hex-token helpers (an object-aware slicer over the class-0 response) --------------

std::vector<std::string> tokens(const std::string& hex)
{
    std::istringstream ss(hex);
    std::vector<std::string> out;
    std::string t;
    while (ss >> t)
        out.push_back(t);
    return out;
}

size_t byteLen(const std::string& hex)
{
    return tokens(hex).size();
}

// A parsed class-0 analog response (single Group30Var1 header, 1-byte range qualifier 0x00).
// Group30Var1 object = 1 quality/flag byte + 4 value bytes (LE) = 5 bytes.
struct Class0
{
    std::string ctl;                            // application control octet
    std::string group, var;                     // 1E 01 for Group30Var1
    std::string qual;                           // 00 => 1-byte start/stop range
    int start = 0, stop = 0;                    // inclusive index range
    std::vector<std::vector<std::string>> objs; // per-object 5-byte slices, index = start + n

    int count() const
    {
        return stop - start + 1;
    }
    // the 5 on-wire bytes for absolute index i (quality byte + 4 value bytes)
    const std::vector<std::string>& object(int i) const
    {
        return objs.at(static_cast<size_t>(i - start));
    }
    std::string qualityByte(int i) const
    {
        return object(i).at(0);
    }
    std::string valueBytes(int i) const
    {
        const auto& o = object(i);
        return o[1] + " " + o[2] + " " + o[3] + " " + o[4];
    }
    std::string variation() const
    {
        return group + " " + var; // declared object type on the wire
    }
};

// Parse a single-fragment class-0 analog response. Asserts the structural expectations so a
// format surprise fails loudly rather than mis-slicing.
Class0 parseClass0(const std::string& respHex)
{
    const auto tk = tokens(respHex);
    REQUIRE(tk.size() >= 9u);
    Class0 c;
    c.ctl = tk[0];
    REQUIRE(tk[1] == "81");   // RESPONSE
    c.group = tk[4];
    c.var = tk[5];
    c.qual = tk[6];
    REQUIRE(c.group == "1E"); // group 30 (analog input)
    REQUIRE(c.var == "01");   // variation 1 (32-bit with flag)
    REQUIRE(c.qual == "00");  // 1-byte start/stop range
    c.start = std::stoi(tk[7], nullptr, 16);
    c.stop = std::stoi(tk[8], nullptr, 16);
    const int n = c.stop - c.start + 1;
    REQUIRE(static_cast<size_t>(9 + 5 * n) == tk.size()); // exactly n 5-byte objects, no trailer
    for (int k = 0; k < n; ++k)
    {
        const size_t base = 9 + 5 * k;
        c.objs.push_back({tk[base], tk[base + 1], tk[base + 2], tk[base + 3], tk[base + 4]});
    }
    return c;
}

// ----- machine-readable vector emission (evidence for the observer scorer) ---------------
// Emits one JSON object per line, prefixed with ##VEC##, carrying the EXACT on-wire bytes plus
// the ground-truth role/value of every object. The observer scorer parses these committed lines;
// it does not re-invent responses. Additive only: the human-readable prints above are unchanged.

long i32le(const std::string& hex4) // "E8 03 00 00" -> 1000 (signed 32-bit LE)
{
    const auto t = tokens(hex4);
    long v = 0;
    for (int b = 3; b >= 0; --b)
        v = (v << 8) | std::stoi(t[b], nullptr, 16);
    return (v & 0x80000000L) ? (v - 0x100000000L) : v;
}

// kind: read_native | read_padded | read_b2_native | read_b2_target. realBase/real are the
// GROUND TRUTH (indices [0,real) are real device points valued realBase+i; [real,total) decoys).
void emitReadVec(const std::string& kind, const char* profile, uint16_t real, double realBase,
                 uint16_t total, const std::string& respHex, const Class0& c)
{
    std::ostringstream j;
    j << "##VEC## {\"kind\":\"" << kind << "\",\"profile\":\"" << profile << "\",\"real_count\":" << real
      << ",\"real_base\":" << static_cast<long>(realBase) << ",\"total_points\":" << total
      << ",\"app_bytes\":" << byteLen(respHex) << ",\"variation\":\"" << c.variation() << "\",\"qual\":\""
      << c.qual << "\",\"start\":" << c.start << ",\"stop\":" << c.stop << ",\"count\":" << c.count()
      << ",\"response_hex\":\"" << respHex << "\",\"objects\":[";
    for (int idx = c.start; idx <= c.stop; ++idx)
    {
        const bool isReal = (idx < static_cast<int>(real));
        if (idx != c.start)
            j << ",";
        j << "{\"index\":" << idx << ",\"role\":\"" << (isReal ? "real" : "decoy") << "\",\"quality\":\""
          << c.qualityByte(idx) << "\",\"value_hex\":\"" << c.valueBytes(idx) << "\",\"value_i32\":"
          << i32le(c.valueBytes(idx)) << ",\"obj5\":\"";
        const auto& o = c.object(idx);
        for (size_t z = 0; z < o.size(); ++z)
            j << (z ? " " : "") << o[z];
        j << "\"}";
    }
    j << "]}";
    std::cout << j.str() << "\n";
}

// ----- outstation profile builder --------------------------------------------------------

double decoyValue(uint16_t idx)
{
    return 50000.0 + idx;
}

// Build the class-0 response of an outstation configured with `total` analog input points,
// where indices [0, real) carry device (real) values realBase+i and [real, total) carry inert
// decoy values. All points quality ONLINE (0x01). Returns the single application fragment hex.
std::string buildClass0(uint16_t real, uint16_t total, double realBase)
{
    OutstationConfig config; // default maxTxFragSize (2048) -> single fragment for these sizes
    OutstationTestObject t(config, configure::by_count_of::analog_input(total));
    t.LowerLayerUp();
    t.Transaction([real, total, realBase](IUpdateHandler& db) {
        for (uint16_t i = 0; i < real; ++i)
            db.Update(Analog(realBase + i, Flags(0x01)), i);
        for (uint16_t j = real; j < total; ++j)
            db.Update(Analog(decoyValue(j), Flags(0x01)), j);
    });
    t.SendToOutstation("C0 01 3C 01 06"); // read class 0 (all points)
    const std::string frag = t.lower->PopWriteAsHex();
    REQUIRE(t.lower->PopWriteAsHex().empty()); // single application fragment
    return frag;
}

// Feed a class-0 response to an unmodified master that issued the standard integrity poll and
// return the master's SOE handler (for semantic + declared-layer checks).
std::shared_ptr<MockSOEHandler> deliverToMaster(const std::string& resp)
{
    MasterParams params;
    params.disableUnsolOnStartup = false;
    params.unsolClassMask = ClassField::None();
    params.ignoreRestartIIN = true; // the real outstation sets IIN1.7; don't let it schedule side tasks
    auto fixture = std::make_shared<MasterTestFixture>(params);
    fixture->context->OnLowerLayerUp();
    fixture->exe->run_many();
    REQUIRE(fixture->lower->PopWriteAsHex() == hex::IntegrityPoll(0)); // same all-points READ every time
    fixture->context->OnTxReady();
    REQUIRE(fixture->SendToMaster(resp)); // master parses/accepts the decoy-augmented response
    // keep the fixture alive by leaking into the returned handler's lifetime via a static sink
    static std::vector<std::shared_ptr<MasterTestFixture>> keep;
    keep.push_back(fixture);
    return fixture->meas;
}

} // namespace

TEST_CASE(SUITE("B1: real points semantically AND per-object-serialized unchanged as decoys grow; master accepts"))
{
    constexpr uint16_t R = 4;                       // native real points 0..3
    const std::vector<uint16_t> totals = {4, 5, 6, 8, 12, 20}; // K = total-R decoys
    const std::string native = buildClass0(R, R, 1000.0);
    const Class0 nativeC = parseClass0(native);

    std::cout << "DECOY-READ[B1] native response = " << native << "  (" << byteLen(native) << " B)\n";
    std::cout << "DECOY-READ[B1] per-real-object SERIALIZED bytes (must be byte-identical vs padded):\n";
    for (uint16_t i = 0; i < R; ++i)
        std::cout << "  real idx=" << i << " variation=" << nativeC.variation() << " qual=" << nativeC.qual
                  << " qualityByte=" << nativeC.qualityByte(i) << " valueBytes=" << nativeC.valueBytes(i) << "\n";
    emitReadVec("read_native", "B1", R, 1000.0, R, native, nativeC);

    for (auto total : totals)
    {
        const uint16_t K = total - R;
        const std::string padded = buildClass0(R, total, 1000.0);
        const Class0 paddedC = parseClass0(padded);

        // (b) SERIALIZED per-object invariance: every REAL object's on-wire bytes are identical.
        for (uint16_t i = 0; i < R; ++i)
        {
            REQUIRE(paddedC.variation() == nativeC.variation());       // same object type on the wire
            REQUIRE(paddedC.qual == nativeC.qual);                     // same qualifier
            REQUIRE(paddedC.qualityByte(i) == nativeC.qualityByte(i)); // same quality byte
            REQUIRE(paddedC.valueBytes(i) == nativeC.valueBytes(i));   // same value bytes
            REQUIRE(paddedC.object(i) == nativeC.object(i));           // full 5-byte slice identical
        }

        // (a) SEMANTIC invariance + master acceptance: an unmodified master accepts and delivers.
        auto meas = deliverToMaster(padded);
        REQUIRE(meas->TotalReceived() == total);
        for (uint16_t i = 0; i < R; ++i)
        {
            REQUIRE(meas->analogSOE.count(i) == 1);
            REQUIRE((meas->analogSOE[i].meas == Analog(1000.0 + i, Flags(0x01))));
            REQUIRE(meas->analogSOE[i].info.gv == GroupVariation::Group30Var1); // declared layer as master sees it
        }

        std::cout << "  K=" << std::setw(2) << K << " decoys: response=" << std::setw(4) << byteLen(padded)
                  << " B, TotalReceived=" << total
                  << " | real objs 0.." << (R - 1) << " SERIALIZED-IDENTICAL, SEMANTIC-EQUAL, master ACCEPTED\n";
        emitReadVec("read_padded", "B1", R, 1000.0, total, padded, paddedC);
    }
    std::cout << "DECOY-READ[B1] -> PASS (per-object serialized + semantic invariance; whole response NOT required identical)\n";
}

TEST_CASE(SUITE("B2: COMMON-TARGET convergence — two profiles with different native sizes reach ONE declared schema"))
{
    // Two DIFFERENT software outstation profiles (different native real-point counts => different
    // native response lengths). Both are padded with configured decoys to ONE common public target.
    constexpr uint16_t NTARGET = 16; // declared common schema: analog inputs at indices 0..15

    struct Profile
    {
        const char* name;
        uint16_t real;
        double base;
    };
    const Profile P1{"P1", 4, 1000.0};  // native 4 real points
    const Profile P2{"P2", 10, 2000.0}; // native 10 real points

    // native (undefended) responses: DIFFERENT lengths => a passive observer can tell them apart
    const std::string n1 = buildClass0(P1.real, P1.real, P1.base);
    const std::string n2 = buildClass0(P2.real, P2.real, P2.base);
    const Class0 nc1 = parseClass0(n1), nc2 = parseClass0(n2);
    std::cout << "DECOY-READ[B2] NATIVE (undefended): " << P1.name << "=" << byteLen(n1) << "B range[0.."
              << nc1.stop << "]  " << P2.name << "=" << byteLen(n2) << "B range[0.." << nc2.stop << "]  -> DISTINGUISHABLE\n";
    REQUIRE(byteLen(n1) != byteLen(n2)); // premise: the two devices are natively different sizes

    // padded to the common target
    const std::string t1 = buildClass0(P1.real, NTARGET, P1.base);
    const std::string t2 = buildClass0(P2.real, NTARGET, P2.base);
    const Class0 c1 = parseClass0(t1), c2 = parseClass0(t2);

    auto declaredRow = [](const char* nm, const std::string& resp, const Class0& c) {
        std::printf("  %-2s target: appBytes=%-3zu variation=%s qual=%s indexRange=[%d..%d] objCount=%-2d dnp3Frags=1 transportSegs=1\n",
                    nm, byteLen(resp), c.variation().c_str(), c.qual.c_str(), c.start, c.stop, c.count());
    };
    std::cout << "DECOY-READ[B2] PADDED to common target (NTARGET=" << NTARGET << "):\n";
    declaredRow(P1.name, t1, c1);
    declaredRow(P2.name, t2, c2);
    emitReadVec("read_b2_native", P1.name, P1.real, P1.base, P1.real, n1, nc1);
    emitReadVec("read_b2_native", P2.name, P2.real, P2.base, P2.real, n2, nc2);
    emitReadVec("read_b2_target", P1.name, P1.real, P1.base, NTARGET, t1, c1);
    emitReadVec("read_b2_target", P2.name, P2.real, P2.base, NTARGET, t2, c2);

    // ---- CONVERGENCE at the DECLARED layer: both profiles are byte-identical in schema ----
    const bool converged = (byteLen(t1) == byteLen(t2)) && (c1.variation() == c2.variation()) && (c1.qual == c2.qual)
        && (c1.start == c2.start) && (c1.stop == c2.stop) && (c1.count() == c2.count());
    REQUIRE(converged);
    REQUIRE(c1.start == 0);
    REQUIRE(c1.stop == NTARGET - 1);
    REQUIRE(c1.count() == NTARGET);
    REQUIRE(byteLen(t1) == static_cast<size_t>(9 + 5 * NTARGET)); // 89 B

    // real objects are STILL byte-identical to their native serialization inside each profile
    std::cout << "DECOY-READ[B2] real-object serialized invariance inside each profile:\n";
    for (uint16_t i = 0; i < P1.real; ++i)
        REQUIRE(c1.object(i) == nc1.object(i));
    for (uint16_t i = 0; i < P2.real; ++i)
        REQUIRE(c2.object(i) == nc2.object(i));
    std::cout << "  " << P1.name << " reals 0.." << (P1.real - 1) << " identical; " << P2.name << " reals 0.."
              << (P2.real - 1) << " identical\n";

    // both padded responses are accepted by an unmodified master and deliver the common schema
    auto m1 = deliverToMaster(t1);
    auto m2 = deliverToMaster(t2);
    REQUIRE(m1->TotalReceived() == NTARGET);
    REQUIRE(m2->TotalReceived() == NTARGET);
    for (uint16_t i = 0; i < P1.real; ++i)
        REQUIRE((m1->analogSOE[i].meas == Analog(P1.base + i, Flags(0x01))));
    for (uint16_t i = 0; i < P2.real; ++i)
        REQUIRE((m2->analogSOE[i].meas == Analog(P2.base + i, Flags(0x01))));

    std::cout << "DECOY-READ[B2] VERDICT: two natively-different profiles (" << byteLen(n1) << "B vs " << byteLen(n2)
              << "B) CONVERGE to one declared target (" << byteLen(t1) << "B, g30v1, [0.."
              << (NTARGET - 1) << "], 16 objs) -> COMMON-TARGET CONVERGENCE PASS\n";
}

TEST_CASE(SUITE("B3: single-profile size/fragment/segment ENLARGEMENT sweep (NOT the normalization gate)"))
{
    constexpr uint16_t R = 4;
    std::cout << "DECOY-READ[B3] table1 maxTxFragSize=2048 (R=" << R
              << " real). cols: K | appBytes | dnp3AppFrags | transportSegs(=249B) | tcpSegs(NODELAY)\n";
    const std::vector<uint16_t> ks1 = {0, 1, 2, 4, 8, 16, 32, 64};
    for (auto k : ks1)
    {
        OutstationConfig config;
        OutstationTestObject t(config, configure::by_count_of::analog_input(R + k));
        t.LowerLayerUp();
        t.Transaction([k](IUpdateHandler& db) {
            for (uint16_t i = 0; i < R; ++i)
                db.Update(Analog(1000.0 + i, Flags(0x01)), i);
            for (uint16_t j = 0; j < k; ++j)
                db.Update(Analog(decoyValue(R + j), Flags(0x01)), static_cast<uint16_t>(R + j));
        });
        t.SendToOutstation("C0 01 3C 01 06");
        size_t bytes = 0, frags = 0, segs = 0;
        uint8_t seq = 0;
        while (true)
        {
            const std::string f = t.lower->PopWriteAsHex();
            if (f.empty())
                break;
            const size_t L = byteLen(f);
            ++frags;
            bytes += L;
            segs += static_cast<size_t>(std::ceil(L / 249.0));
            t.OnTxReady();
            char c[8];
            std::snprintf(c, sizeof(c), "C%X 00", seq & 0x0F);
            t.SendToOutstation(c);
            seq = static_cast<uint8_t>((seq + 1) & 0x0F);
        }
        std::printf("  K=%-3u | appBytes=%-5zu | dnp3AppFrags=%-2zu | transportSegs=%-2zu | tcpSegs<=%zu\n",
                    static_cast<unsigned>(k), bytes, frags, segs, segs);
    }

    std::cout << "DECOY-READ[B3] table2 maxTxFragSize=64 (forces DNP3 application fragmentation). cols same as table1\n";
    const std::vector<uint16_t> ks2 = {0, 4, 8, 16, 32};
    for (auto k : ks2)
    {
        OutstationConfig config;
        config.params.maxTxFragSize = 64;
        OutstationTestObject t(config, configure::by_count_of::analog_input(R + k));
        t.LowerLayerUp();
        t.Transaction([k](IUpdateHandler& db) {
            for (uint16_t i = 0; i < R; ++i)
                db.Update(Analog(1000.0 + i, Flags(0x01)), i);
            for (uint16_t j = 0; j < k; ++j)
                db.Update(Analog(decoyValue(R + j), Flags(0x01)), static_cast<uint16_t>(R + j));
        });
        t.SendToOutstation("C0 01 3C 01 06");
        size_t bytes = 0, frags = 0, segs = 0;
        uint8_t seq = 0;
        while (true)
        {
            const std::string f = t.lower->PopWriteAsHex();
            if (f.empty())
                break;
            const size_t L = byteLen(f);
            ++frags;
            bytes += L;
            segs += static_cast<size_t>(std::ceil(L / 249.0));
            t.OnTxReady();
            char c[8];
            std::snprintf(c, sizeof(c), "C%X 00", seq & 0x0F);
            t.SendToOutstation(c);
            seq = static_cast<uint8_t>((seq + 1) & 0x0F);
        }
        std::printf("  K=%-3u | appBytes=%-5zu | dnp3AppFrags=%-2zu | transportSegs=%-2zu | tcpSegs<=%zu\n",
                    static_cast<unsigned>(k), bytes, frags, segs, segs);
    }
    std::cout << "DECOY-READ[B3] NOTE: this is single-profile ENLARGEMENT, not normalization. The gate is B2.\n";
}

// SPDX-License-Identifier: Apache-2.0
//
// NATIVE-PARITY READ size derivation — G30V1 (analog input) and G10V2 (binary output
// status), derived from the REAL bytes a real opendnp3 outstation serializes.
//
// Software only: an outstation is configured with N points (indices [0,N): even = real,
// odd = decoy) and a targeted READ is driven into it; the response fragment is parsed and
// the exact object header / qualifier / range / per-point width are read from the bytes.
// From that we DERIVE the application byte length, the post-link u_READ(N), and the DNP3
// link-frame wire size, and compare to the hypotheses:
//   * G30V1 analog:               u_READ(N) = 10 + 5N   (header 5 + 5 B/point)
//   * G10V2 binary-output-status: u_READ(N) = 10 + N    (header 5 + 1 B/point)
//
// The intersections that make READ and SBO the SAME native wire size (relay model
// u_SBO(K) = 9 + 12K, echo 35/49/61 B) are then CONFIRMED from these derived sizes:
//   * SBO K=2 (u=33, wire=49 B)  ==  G10V2 N=23 (u=33, wire=49 B)
//   * SBO K=3 (u=45, wire=61 B)  ==  G30V1 N=7  (u=45, wire=61 B)
//
// ##VEC## lines carry the committed READ bytes for the derive_sizes.py reducer.

#include "utils/APDUHexBuilders.h"
#include "utils/MasterTestFixture.h"
#include "utils/MeasurementComparisons.h"
#include "utils/NativeParityHelpers.h"
#include "utils/OutstationTestObject.h"

#include <dnp3mocks/DatabaseHelpers.h>

#include <opendnp3/app/MeasurementTypes.h>
#include <opendnp3/gen/GroupVariation.h>

#include <catch.hpp>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using namespace opendnp3;
using namespace np;

#define SUITE(name) "NativeParityReadTestSuite - " name

namespace
{

// A parsed single-fragment static READ response with a 1-byte start/stop range qualifier (0x00).
// pointWidth = on-wire bytes per point (5 for G30V1, 1 for G10V2).
struct ReadResp
{
    std::string group, var, qual;
    int start = 0, stop = 0;
    int pointWidth = 0;
    std::vector<std::vector<std::string>> objs; // per-point byte slices
    int count() const { return stop - start + 1; }
    std::string variation() const { return group + " " + var; }
};

ReadResp parseRead(const std::string& respHex, int pointWidth)
{
    const auto t = toks(respHex);
    REQUIRE(t.size() >= 9u);
    ReadResp r;
    REQUIRE(t[1] == "81"); // RESPONSE
    r.group = t[4];
    r.var = t[5];
    r.qual = t[6];
    REQUIRE(r.qual == "00"); // 1-byte start/stop range
    r.start = hb(t[7]);
    r.stop = hb(t[8]);
    r.pointWidth = pointWidth;
    const int n = r.stop - r.start + 1;
    REQUIRE(static_cast<size_t>(9 + pointWidth * n) == t.size()); // exactly n objects, no trailer
    for (int k = 0; k < n; ++k)
    {
        std::vector<std::string> o;
        for (int b = 0; b < pointWidth; ++b)
            o.push_back(t[9 + pointWidth * k + b]);
        r.objs.push_back(o);
    }
    return r;
}

void emitReadVec(const char* obj, uint16_t real, uint16_t total, const std::string& respHex, const ReadResp& r)
{
    const int app = static_cast<int>(byteLen(respHex));
    const int u = 1 + app;
    std::cout << "##VEC## {\"kind\":\"read\",\"obj\":\"" << obj << "\",\"real_count\":" << real
              << ",\"total_points\":" << total << ",\"app_bytes\":" << app << ",\"u_read\":" << u
              << ",\"wire\":" << linkSize(u) << ",\"variation\":\"" << r.variation() << "\",\"qual\":\"" << r.qual
              << "\",\"start\":" << r.start << ",\"stop\":" << r.stop << ",\"count\":" << r.count()
              << ",\"point_width\":" << r.pointWidth << ",\"response_hex\":\"" << respHex << "\"}\n";
}

// Build an analog-input outstation of `total` points and read Group30Var1 (all points).
std::string readG30V1(uint16_t real, uint16_t total)
{
    OutstationConfig config;
    OutstationTestObject t(config, configure::by_count_of::analog_input(total));
    t.LowerLayerUp();
    t.Transaction([real, total](IUpdateHandler& db) {
        for (uint16_t i = 0; i < total; ++i)
            db.Update(Analog((i < real ? 1000.0 : 50000.0) + i, Flags(0x01)), i);
    });
    t.SendToOutstation("C0 01 1E 01 06"); // READ g30v1, qualifier 0x06 (all points)
    const std::string frag = t.lower->PopWriteAsHex();
    REQUIRE(t.lower->PopWriteAsHex().empty()); // single application fragment
    return frag;
}

// Build a binary-output-status outstation of `total` points and read Group10Var2 (all points).
std::string readG10V2(uint16_t real, uint16_t total)
{
    OutstationConfig config;
    OutstationTestObject t(config, configure::by_count_of::binary_output_status(total));
    t.LowerLayerUp();
    t.Transaction([real, total](IUpdateHandler& db) {
        for (uint16_t i = 0; i < total; ++i)
            db.Update(BinaryOutputStatus((i % 2) == 0, Flags(0x01)), i);
    });
    t.SendToOutstation("C0 01 0A 02 06"); // READ g10v2, qualifier 0x06 (all points)
    const std::string frag = t.lower->PopWriteAsHex();
    REQUIRE(t.lower->PopWriteAsHex().empty());
    return frag;
}

} // namespace

TEST_CASE(SUITE("G30V1 u_READ sweep + master accept"))
{
    std::cout << "\nNP-READ[G30V1] analog input, per-point width derived from bytes:\n";
    const std::vector<uint16_t> ns = {1, 2, 4, 7, 8, 10, 16};
    for (auto n : ns)
    {
        const uint16_t real = (n + 1) / 2; // even indices real; ~half real, half decoy
        const std::string resp = readG30V1(real, n);
        const ReadResp r = parseRead(resp, /*pointWidth*/ 5);
        REQUIRE(r.variation() == "1E 01"); // Group30Var1 on the wire
        const int app = static_cast<int>(byteLen(resp));
        REQUIRE(app == 9 + 5 * n);          // header 5 (grp,var,qual,start,stop) + 5 B/point
        const int u = 1 + app;
        REQUIRE(u == 10 + 5 * n);           // hypothesis confirmed from real bytes
        emitReadVec("G30V1", real, n, resp, r);
        std::printf("  N=%-2u | app=%-3dB u_read=%-3d wire=%-3dB | %s qual=%s [%d..%d]\n",
                    static_cast<unsigned>(n), app, u, linkSize(u), r.variation().c_str(), r.qual.c_str(),
                    r.start, r.stop);
    }

    // master accepts a class-0 analog response and delivers the points (unmodified master).
    {
        const std::string resp = readG30V1(4, 8); // via class-0 integrity poll below
        // deliver the SAME analog data through the standard integrity poll path
        OutstationConfig config;
        OutstationTestObject os(config, configure::by_count_of::analog_input(8));
        os.LowerLayerUp();
        os.Transaction([](IUpdateHandler& db) {
            for (uint16_t i = 0; i < 8; ++i)
                db.Update(Analog((i < 4 ? 1000.0 : 50000.0) + i, Flags(0x01)), i);
        });
        os.SendToOutstation("C0 01 3C 01 06"); // class 0
        const std::string class0 = os.lower->PopWriteAsHex();

        MasterParams p;
        p.disableUnsolOnStartup = false;
        p.unsolClassMask = ClassField::None();
        p.ignoreRestartIIN = true;
        // NOTE: destroying a MasterTestFixture after SendToMaster tears down its scheduler
        // backend and corrupts the shared heap for later test cases (surfaces as a substr abort
        // under Catch -s). The proven pattern is to LEAK the fixture into a static sink so it
        // outlives the case; the binary exits at program end. Software only; no resource held.
        static std::vector<std::shared_ptr<MasterTestFixture>> keep;
        auto ms = std::make_shared<MasterTestFixture>(p);
        keep.push_back(ms);
        ms->context->OnLowerLayerUp();
        ms->exe->run_many();
        REQUIRE(ms->lower->PopWriteAsHex() == hex::IntegrityPoll(0));
        ms->context->OnTxReady();
        REQUIRE(ms->SendToMaster(class0)); // master parses/accepts the padded analog response
        REQUIRE(ms->meas->TotalReceived() == 8);
        for (uint16_t i = 0; i < 4; ++i)
            REQUIRE((ms->meas->analogSOE[i].meas == Analog(1000.0 + i, Flags(0x01))));
        std::cout << "NP-READ[G30V1] unmodified master accepted the analog response, delivered 8 points\n";
    }
}

TEST_CASE(SUITE("G10V2 u_READ sweep"))
{
    std::cout << "\nNP-READ[G10V2] binary output status, per-point width derived from bytes:\n";
    const std::vector<uint16_t> ns = {1, 2, 4, 8, 16, 23, 32};
    for (auto n : ns)
    {
        const uint16_t real = (n + 1) / 2;
        const std::string resp = readG10V2(real, n);
        const ReadResp r = parseRead(resp, /*pointWidth*/ 1);
        REQUIRE(r.variation() == "0A 02"); // Group10Var2 on the wire (1 octet/point)
        const int app = static_cast<int>(byteLen(resp));
        REQUIRE(app == 9 + n);              // header 5 + 1 B/point
        const int u = 1 + app;
        REQUIRE(u == 10 + n);               // hypothesis confirmed from real bytes
        emitReadVec("G10V2", real, n, resp, r);
        std::printf("  N=%-2u | app=%-3dB u_read=%-3d wire=%-3dB | %s qual=%s [%d..%d]\n",
                    static_cast<unsigned>(n), app, u, linkSize(u), r.variation().c_str(), r.qual.c_str(),
                    r.start, r.stop);
    }
}

TEST_CASE(SUITE("native-size intersections 49B and 61B"))
{
    // These are the relay-model (0x17) SBO echo sizes; the SBO suite derives u_SBO(K)=9+12K
    // -> wire 49 B at K=2 and 61 B at K=3. Here we confirm the READ side reaches the same wire
    // sizes from real serialized bytes, so the intersection is grounded in bytes on both axes.

    // 49 B: G10V2 with N=23 points
    {
        const std::string resp = readG10V2(12, 23);
        const ReadResp r = parseRead(resp, 1);
        const int u = 1 + static_cast<int>(byteLen(resp));
        REQUIRE(u == 33);              // 10 + 23
        REQUIRE(linkSize(u) == 49);    // == SBO K=2 relay anchor
        std::cout << "NP-READ[intersection] G10V2 N=23 -> u_read=" << u << " wire=" << linkSize(u)
                  << "B == SBO K=2 (49 B) CONFIRMED from bytes\n";
    }

    // 61 B: G30V1 with N=7 points
    {
        const std::string resp = readG30V1(4, 7);
        const ReadResp r = parseRead(resp, 5);
        const int u = 1 + static_cast<int>(byteLen(resp));
        REQUIRE(u == 45);              // 10 + 5*7
        REQUIRE(linkSize(u) == 61);    // == SBO K=3 relay anchor
        std::cout << "NP-READ[intersection] G30V1 N=7 -> u_read=" << u << " wire=" << linkSize(u)
                  << "B == SBO K=3 (61 B) CONFIRMED from bytes\n";
    }
}

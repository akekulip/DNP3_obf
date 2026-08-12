/*
 * DNP3 address-scoped cover-frame endpoint-discard gate — real-parser experiment.
 *
 * Mechanism under test:
 *   Prepend a CRC-valid DNP3 LINK frame addressed to a NON-ENDPOINT link address
 *   ("cover") in front of the ORIGINAL valid DNP3 frame ("real"), in one DNP3-over-TCP
 *   byte stream. Claim: the endpoint's link layer DISCARDS the cover and processes the
 *   real frame unchanged.
 *
 * This drives the REAL OpenDNP3 receive path end to end:
 *     raw bytes -> LinkLayerParser (real) -> LinkLayer/LinkContext (real address filter)
 *                -> MockTransportLayer (observes what is pushed up to transport)
 * with the LinkLayerTest fixture supplying the executor, listener, upper layer, and the
 * ILinkTx router (observes any frame the endpoint transmits in response).
 *
 * A PASS here is ENDPOINT COMPATIBILITY ONLY: it means the endpoint accepts the real
 * frame and drops the cover at the link layer. It does NOT defeat a parsing observer,
 * which reassembles the TCP stream and reads both frames regardless of link address.
 * The bounded additive-cover impossibility result is preserved: cover framing adds bytes
 * an on-path parser can attribute and strip; it cannot subtract the real frame's
 * fingerprint.
 *
 * Built by copying this file into cpp/tests/unit/ of the opendnp3-community fork and
 * adding it to the `unittests` Catch2 target (see run.sh). Nothing is committed or pushed
 * to that repo; a copy of this source + a focused patch are vendored into the evidence dir.
 */
#include "utils/LinkLayerTest.h"

#include <dnp3mocks/MockFrameSink.h>

#include <link/LinkLayerParser.h>

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;

namespace
{

using Bytes = std::vector<uint8_t>;

// CRC-16/DNP (IEEE 1815): reflected poly 0xA6BC, init 0x0000, final complement.
// Identical to dnp3_split_harness/dnp3_crc.py and opendnp3's link/CRC.cpp.
uint16_t dnp3_crc16(const uint8_t* data, size_t n)
{
    uint16_t crc = 0x0000;
    for (size_t i = 0; i < n; ++i)
    {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b)
        {
            if (crc & 0x0001)
                crc = static_cast<uint16_t>((crc >> 1) ^ 0xA6BC);
            else
                crc = static_cast<uint16_t>(crc >> 1);
        }
    }
    return static_cast<uint16_t>((~crc) & 0xFFFF);
}

std::string toHexNoSpace(const Bytes& b)
{
    static const char* H = "0123456789ABCDEF";
    std::string s;
    s.reserve(b.size() * 2);
    for (auto v : b)
    {
        s.push_back(H[(v >> 4) & 0xF]);
        s.push_back(H[v & 0xF]);
    }
    return s;
}

// Build a DNP3 data-link frame carrying user data (transport+application octets `ud`).
//   fromMaster : DIR bit (true = master->outstation)
//   confirmed  : PRI_CONFIRMED_USER_DATA (func 3, FCV=1) vs PRI_UNCONFIRMED_USER_DATA (func 4)
// Link header (8B) + header CRC (2B) + [<=16B data block + 2B block CRC]...
Bytes buildUserDataFrame(bool fromMaster, uint16_t dest, uint16_t src, bool confirmed, const Bytes& ud)
{
    const uint8_t func = confirmed ? 0x03 : 0x04;
    uint8_t ctrl = static_cast<uint8_t>(0x40 | func); // PRM=1
    if (fromMaster)
        ctrl |= 0x80; // DIR
    if (confirmed)
        ctrl |= 0x10; // FCV required for confirmed user data
    const uint8_t len = static_cast<uint8_t>(5 + ud.size());

    Bytes hdr = {0x05,
                 0x64,
                 len,
                 ctrl,
                 static_cast<uint8_t>(dest & 0xFF),
                 static_cast<uint8_t>((dest >> 8) & 0xFF),
                 static_cast<uint8_t>(src & 0xFF),
                 static_cast<uint8_t>((src >> 8) & 0xFF)};

    Bytes out = hdr;
    const uint16_t hcrc = dnp3_crc16(hdr.data(), hdr.size());
    out.push_back(static_cast<uint8_t>(hcrc & 0xFF));
    out.push_back(static_cast<uint8_t>((hcrc >> 8) & 0xFF));

    for (size_t i = 0; i < ud.size(); i += 16)
    {
        const size_t blen = std::min<size_t>(16, ud.size() - i);
        const uint16_t bcrc = dnp3_crc16(ud.data() + i, blen);
        out.insert(out.end(), ud.begin() + i, ud.begin() + i + blen);
        out.push_back(static_cast<uint8_t>(bcrc & 0xFF));
        out.push_back(static_cast<uint8_t>((bcrc >> 8) & 0xFF));
    }
    return out;
}

// ---- illustrative application PDUs (transport byte 0xC0 = FIR|FIN|seq0, then APDU) ----
// The link layer is APDU-agnostic; these bytes only exercise byte-identity of the pushed-up
// user data. crob() mirrors defense4/size/offline/sbo_oracle.py exactly.

Bytes crob(uint8_t index)
{
    // [index, cc=0x41, count=1, on(4 LE)=100, off(4 LE)=100, status=0]
    return Bytes{index, 0x41, 0x01, 100, 0, 0, 0, 100, 0, 0, 0, 0};
}

Bytes udReadRequest()
{
    return Bytes{0xC0, 0xC0, 0x01, 0x3C, 0x02, 0x06}; // READ g60v2 (class-1) all
}
// Distinct marker payload carried by every COVER frame (READ g60v1 class-0), so a
// pushed-up cover is unambiguously distinguishable from the real frame's user data.
// The link layer is APDU-agnostic; cover CONTENT does not affect the address decision.
Bytes udCover()
{
    return Bytes{0xC0, 0xC0, 0x01, 0x3C, 0x01, 0x06};
}
Bytes udReadResponse()
{
    // transport, app-ctrl(resp), RESPONSE(0x81), IIN(00 00), g1v2 1 point
    return Bytes{0xC0, 0xC1, 0x81, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x81};
}
Bytes udControl(uint8_t appFunc)
{
    // [C0 transport][C0 app-ctrl][func] + g12v1 objhdr(qual 0x17, count=2) + 2 CROBs
    Bytes ud = {0xC0, 0xC0, appFunc, 12, 1, 0x17, 2};
    Bytes a = crob(0), b = crob(1);
    ud.insert(ud.end(), a.begin(), a.end());
    ud.insert(ud.end(), b.begin(), b.end());
    return ud;
}
Bytes udControlResponse()
{
    // transport, app-ctrl(resp), RESPONSE, IIN, echoed g12v1 status objects (illustrative)
    Bytes ud = {0xC0, 0xC1, 0x81, 0x00, 0x00, 12, 1, 0x17, 2};
    Bytes a = crob(0), b = crob(1);
    ud.insert(ud.end(), a.begin(), a.end());
    ud.insert(ud.end(), b.begin(), b.end());
    return ud;
}

// ---- one link frame specification ----
struct FrameSpec
{
    std::string tag;
    bool fromMaster;
    uint16_t dest;
    uint16_t src;
    bool confirmed;
    Bytes ud;
    Bytes bytes() const
    {
        return buildUserDataFrame(fromMaster, dest, src, confirmed, ud);
    }
};

// ---- measured outcome of feeding a byte stream through the real receive path ----
struct Measure
{
    // parser statistics (frame-level)
    size_t rx = 0, hdrCrcErr = 0, bodyCrcErr = 0, badLen = 0, badFunc = 0, badFcv = 0, badFcb = 0;
    // link-layer discard statistics
    uint64_t unexpected = 0, badMaster = 0, unknownDest = 0, unknownSrc = 0;
    // what reached transport (hex of each pushed-up user-data unit), and any endpoint TX
    std::vector<std::string> pushups;
    uint32_t txWrites = 0;
    // log messages that indicate a parse/validation FAILURE (not an address discard)
    int failLogs = 0;
    std::vector<std::string> failLogText;
};

bool isFailureMessage(const std::string& m)
{
    static const char* pats[]
        = {"CRC failure", "out of range", "Unknown", "Bad FCV", "FCB set", "Unexpected LENGTH", "no payload"};
    for (auto p : pats)
        if (m.find(p) != std::string::npos)
            return true;
    return false;
}

// Feed `stream` into a fresh online endpoint via the REAL parser, split into `chunkSizes`
// successive OnRead() calls (empty => single write of the whole stream).
Measure runStream(LinkLayerTest& t, const Bytes& stream, const std::vector<size_t>& chunkSizes)
{
    LinkLayerParser parser(t.log.logger);

    auto feed = [&](size_t from, size_t n) {
        auto wbuf = parser.WriteBuff();
        REQUIRE(n <= wbuf.length());
        memcpy(wbuf, stream.data() + from, n);
        parser.OnRead(n, t.link);
    };

    // `chunkSizes` lists the sizes of the LEADING segments; any remainder is fed as one
    // final segment. Empty => the whole stream in a single OnRead.
    size_t off = 0;
    for (size_t csz : chunkSizes)
    {
        if (off >= stream.size())
            break;
        const size_t n = std::min(csz, stream.size() - off);
        feed(off, n);
        off += n;
    }
    if (off < stream.size())
    {
        feed(off, stream.size() - off);
        off = stream.size();
    }

    Measure m;
    const auto& ps = parser.Statistics();
    m.rx = ps.numLinkFrameRx;
    m.hdrCrcErr = ps.numHeaderCrcError;
    m.bodyCrcErr = ps.numBodyCrcError;
    m.badLen = ps.numBadLength;
    m.badFunc = ps.numBadFunctionCode;
    m.badFcv = ps.numBadFCV;
    m.badFcb = ps.numBadFCB;

    const auto& ls = t.link.GetStatistics();
    m.unexpected = ls.numUnexpectedFrame;
    m.badMaster = ls.numBadMasterBit;
    m.unknownDest = ls.numUnknownDestination;
    m.unknownSrc = ls.numUnknownSource;

    for (const auto& hex : t.upper->receivedQueue)
        m.pushups.push_back(hex);
    m.txWrites = t.NumTotalWrites();

    LogRecord rec;
    while (t.log.GetNextEntry(rec))
    {
        if (isFailureMessage(rec.message))
        {
            ++m.failLogs;
            m.failLogText.push_back(rec.message);
        }
    }
    return m;
}

bool contains(const std::vector<std::string>& v, const std::string& s)
{
    return std::find(v.begin(), v.end(), s) != v.end();
}

// Output sink for the evidence artifacts (results table + frame hex dump).
struct Out
{
    std::ofstream table; // results_table.csv
    std::ofstream frames; // cpp_frames_hex.txt
    std::string dir;
    Out()
    {
        const char* d = std::getenv("COVER_FRAME_OUT");
        dir = d ? d : ".";
        table.open(dir + "/results_table.csv", std::ios::trunc);
        frames.open(dir + "/cpp_frames_hex.txt", std::ios::trunc);
        table << "case,endpoint,local_addr,remote_addr,cover_class,cover_dest_hex,direction,real_apdu,framing,"
                 "n_cover,cover_frame_bytes,real_frame_bytes,real_lpdu_len_field,real_ud_bytes,tcp_payload_bytes,"
                 "parser_frames_rx,unknownDest,unknownSrc,badMaster,unexpected,pushups,tx_writes,fail_logs,"
                 "cover_discarded,real_accepted,gate_verdict\n";
    }
};
Out& out()
{
    static Out o;
    return o;
}

void dumpFrame(const std::string& id, const Bytes& b)
{
    out().frames << id << " " << toHexNoSpace(b) << "\n";
}

// Run one case: N cover frames (all identical class) followed by one real frame.
// classify + record. Returns the gate verdict string ("PASS"/"FAIL").
std::string runCase(const std::string& caseName,
                    bool isMaster,
                    uint16_t local,
                    uint16_t remote,
                    const std::string& coverClass,
                    const std::string& direction,
                    const std::string& realApdu,
                    const std::string& framing,
                    const std::vector<FrameSpec>& covers,
                    const FrameSpec& real,
                    const std::vector<size_t>& chunkSizes)
{
    LinkLayerTest t(LinkConfig(isMaster, local, remote, TimeDuration::Seconds(1), TimeDuration::Max()));
    REQUIRE(t.link.OnLowerLayerUp());
    t.log.ClearLog(); // drop the layer-up bookkeeping; keep only receive-path logs

    Bytes stream;
    for (const auto& c : covers)
    {
        Bytes cb = c.bytes();
        stream.insert(stream.end(), cb.begin(), cb.end());
    }
    Bytes rb = real.bytes();
    stream.insert(stream.end(), rb.begin(), rb.end());

    const Measure m = runStream(t, stream, chunkSizes);

    // expected pushup hex (CRC-stripped user data == what transport should receive)
    const std::string realHex = HexConversions::to_hex(rseq_t(real.ud.data(), real.ud.size()));
    std::string coverHex;
    if (!covers.empty())
        coverHex = HexConversions::to_hex(rseq_t(covers[0].ud.data(), covers[0].ud.size()));

    const bool realAccepted = contains(m.pushups, realHex);
    const bool coverProcessed = !coverHex.empty() && contains(m.pushups, coverHex);
    const bool coverDiscarded = !coverProcessed;

    // Gate verdict: PASS = every cover discarded AND real accepted AND endpoint emitted
    // nothing in response to the cover AND no parse failure.
    const bool gatePass = coverDiscarded && realAccepted && (m.txWrites == 0) && (m.failLogs == 0);
    const std::string verdict = gatePass ? "PASS" : "FAIL";

    // per-layer sizes (bytes)
    const size_t coverFrameBytes = covers.empty() ? 0 : covers[0].bytes().size();
    const size_t realFrameBytes = rb.size();
    const size_t realLpduLen = 5 + real.ud.size();
    const size_t realUdBytes = real.ud.size();
    const size_t tcpPayload = stream.size(); // whole DNP3-over-TCP payload injected

    out().table << caseName << ',' << (isMaster ? "master" : "outstation") << ',' << local << ',' << remote << ','
                << coverClass << ',';
    { char buf[8]; std::snprintf(buf, sizeof buf, "%04X", (unsigned)(covers.empty() ? 0 : covers[0].dest)); out().table << buf; }
    out().table << ',' << direction << ',' << realApdu << ',' << framing << ',' << covers.size() << ','
                << coverFrameBytes << ',' << realFrameBytes << ',' << realLpduLen << ',' << realUdBytes << ','
                << tcpPayload << ',' << m.rx << ',' << m.unknownDest << ',' << m.unknownSrc << ',' << m.badMaster << ','
                << m.unexpected << ',' << m.pushups.size() << ',' << m.txWrites << ',' << m.failLogs << ','
                << (coverDiscarded ? 1 : 0) << ',' << (realAccepted ? 1 : 0) << ',' << verdict << '\n';

    if (!covers.empty())
        dumpFrame(caseName + ".cover", covers[0].bytes());
    dumpFrame(caseName + ".real", real.bytes());

    std::printf("[%-30s] ep=%-10s local=%u cover=%-14s dest=0x%04X dir=%-16s apdu=%-9s framing=%-16s | "
                "rx=%zu pushups=%zu tx=%u unkDest=%llu unkSrc=%llu failLogs=%d | coverDiscarded=%d realAccepted=%d "
                "=> GATE %s\n",
                caseName.c_str(), isMaster ? "master" : "outstation", (unsigned)local, coverClass.c_str(),
                (unsigned)(covers.empty() ? 0 : covers[0].dest), direction.c_str(), realApdu.c_str(), framing.c_str(),
                m.rx, m.pushups.size(), (unsigned)m.txWrites, (unsigned long long)m.unknownDest,
                (unsigned long long)m.unknownSrc, m.failLogs, coverDiscarded ? 1 : 0, realAccepted ? 1 : 0,
                verdict.c_str());

    // Invariants that must always hold for the harness to be trustworthy:
    REQUIRE(realAccepted);            // the real frame is always processed unchanged
    REQUIRE(contains(m.pushups, realHex));
    REQUIRE(m.hdrCrcErr == 0);        // all frames are well-formed (CRC valid)
    REQUIRE(m.bodyCrcErr == 0);
    REQUIRE(m.badLen == 0);
    REQUIRE(m.rx == covers.size() + 1); // parser delivered every frame to the sink

    return verdict;
}

// Address classes to place in the cover's DESTINATION field. Source is held at the endpoint's
// configured RemoteAddr so the DESTINATION class is the only variable (isolates the mechanism).
struct AddrClass
{
    std::string name;
    uint16_t dest;
};

} // namespace

// CLASSIFICATION (corrected): this is a COMPONENT test —
//   "OpenDNP3 3.1.2 link-layer address-filter compatibility".
// It drives the real LinkLayerParser + LinkLayer address filter with a MOCK transport above.
// It does NOT prove application-transaction completion, absence of a TCP/link close, or absence
// of application retries/CONFIRMs. Those are covered by test_full_transaction.cpp.
#define SUITE(name) "LinkLayerAddressFilterCompat - " name

// -----------------------------------------------------------------------------
// Block 1 — Address matrix (core discard result), same-segment, single cover.
//   Outstation endpoint (local=10, remote=1): cover + outstation-bound READ request.
//   Master endpoint     (local=1,  remote=10): cover + master-bound READ response.
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("AddressMatrix"), "[coverframe]")
{
    const std::vector<AddrClass> classes = {
        {"individual", 0x0032},     // 50: a non-endpoint individual address
        {"reserved_lo", 0xFFF0},    // reserved range 0xFFF0..0xFFFB (low end)
        {"reserved_hi", 0xFFFB},    // reserved range (high end)
        {"self_addr", 0xFFFC},      // IEEE 1815 self-address
        {"broadcast_D", 0xFFFD},    // broadcast, no confirm
        {"broadcast_E", 0xFFFE},    // broadcast, shall confirm
        {"broadcast_F", 0xFFFF},    // broadcast, optional confirm
    };

    SECTION("outstation_bound_read_request")
    {
        const uint16_t LOCAL = 10, REMOTE = 1;
        FrameSpec real{"real", /*fromMaster*/ true, LOCAL, REMOTE, false, udReadRequest()};
        for (const auto& c : classes)
        {
            FrameSpec cover{"cover", true, c.dest, REMOTE, false, udCover()};
            const std::string verdict = runCase("B1_out_" + c.name, false, LOCAL, REMOTE, c.name,
                                                "outstation_bound", "READ_req", "same_seg", {cover}, real, {});
            // Mechanism prediction from LinkContext::OnFrame: broadcast destinations are
            // ACCEPTED for user-data functions (processed); all others are dropped as
            // unknown destination. We lock in BOTH outcomes (a negative is valid evidence).
            const bool isBroadcast = (c.dest == 0xFFFD || c.dest == 0xFFFE || c.dest == 0xFFFF);
            if (isBroadcast)
                REQUIRE(verdict == "FAIL"); // cover processed -> gate defeated for broadcast
            else
                REQUIRE(verdict == "PASS"); // cover discarded at the destination gate
        }
    }

    SECTION("master_bound_read_response")
    {
        const uint16_t LOCAL = 1, REMOTE = 10;
        FrameSpec real{"real", /*fromMaster*/ false, LOCAL, REMOTE, false, udReadResponse()};
        for (const auto& c : classes)
        {
            FrameSpec cover{"cover", false, c.dest, REMOTE, false, udCover()};
            const std::string verdict = runCase("B1_mas_" + c.name, true, LOCAL, REMOTE, c.name, "master_bound",
                                                "READ_resp", "same_seg", {cover}, real, {});
            const bool isBroadcast = (c.dest == 0xFFFD || c.dest == 0xFFFE || c.dest == 0xFFFF);
            if (isBroadcast)
                REQUIRE(verdict == "FAIL");
            else
                REQUIRE(verdict == "PASS");
        }
    }
}

// -----------------------------------------------------------------------------
// Block 2 — Application-PDU framings: cover=individual (the discard class), real frame
// cycles through READ / SELECT / OPERATE request and response. Confirms the real APDU is
// pushed up byte-identical and the cover is discarded regardless of the real payload.
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("ApplicationFramings"), "[coverframe]")
{
    const uint16_t OUT_LOCAL = 10, OUT_REMOTE = 1; // outstation endpoint
    const uint16_t MAS_LOCAL = 1, MAS_REMOTE = 10; // master endpoint
    const uint16_t COVER_DEST = 0x0032;            // individual non-endpoint

    // requests -> outstation endpoint (fromMaster=true)
    runCase("B2_read_req", false, OUT_LOCAL, OUT_REMOTE, "individual", "outstation_bound", "READ_req", "same_seg",
            {FrameSpec{"cover", true, COVER_DEST, OUT_REMOTE, false, udCover()}},
            FrameSpec{"real", true, OUT_LOCAL, OUT_REMOTE, false, udReadRequest()}, {});
    runCase("B2_select_req", false, OUT_LOCAL, OUT_REMOTE, "individual", "outstation_bound", "SELECT_req", "same_seg",
            {FrameSpec{"cover", true, COVER_DEST, OUT_REMOTE, false, udCover()}},
            FrameSpec{"real", true, OUT_LOCAL, OUT_REMOTE, false, udControl(0x03)}, {});
    runCase("B2_operate_req", false, OUT_LOCAL, OUT_REMOTE, "individual", "outstation_bound", "OPERATE_req",
            "same_seg", {FrameSpec{"cover", true, COVER_DEST, OUT_REMOTE, false, udCover()}},
            FrameSpec{"real", true, OUT_LOCAL, OUT_REMOTE, false, udControl(0x04)}, {});

    // responses -> master endpoint (fromMaster=false)
    runCase("B2_read_resp", true, MAS_LOCAL, MAS_REMOTE, "individual", "master_bound", "READ_resp", "same_seg",
            {FrameSpec{"cover", false, COVER_DEST, MAS_REMOTE, false, udCover()}},
            FrameSpec{"real", false, MAS_LOCAL, MAS_REMOTE, false, udReadResponse()}, {});
    runCase("B2_select_resp", true, MAS_LOCAL, MAS_REMOTE, "individual", "master_bound", "SELECT_resp", "same_seg",
            {FrameSpec{"cover", false, COVER_DEST, MAS_REMOTE, false, udCover()}},
            FrameSpec{"real", false, MAS_LOCAL, MAS_REMOTE, false, udControlResponse()}, {});
    runCase("B2_operate_resp", true, MAS_LOCAL, MAS_REMOTE, "individual", "master_bound", "OPERATE_resp", "same_seg",
            {FrameSpec{"cover", false, COVER_DEST, MAS_REMOTE, false, udCover()}},
            FrameSpec{"real", false, MAS_LOCAL, MAS_REMOTE, false, udControlResponse()}, {});
}

// -----------------------------------------------------------------------------
// Block 3 — TCP framing / cover multiplicity (orthogonality to the address decision).
//   individual (PASS class) and broadcast_D (FAIL class), real = outstation-bound READ req.
//   Framings: same-seg 1 cover; split inside cover; split inside real; 3 covers same seg;
//   3 covers split across segments.
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("TcpFramingAndMultiplicity"), "[coverframe]")
{
    const uint16_t LOCAL = 10, REMOTE = 1;
    FrameSpec real{"real", true, LOCAL, REMOTE, false, udReadRequest()};

    struct CoverKind
    {
        std::string cls;
        uint16_t dest;
    };
    const std::vector<CoverKind> kinds = {{"individual", 0x0032}, {"broadcast_D", 0xFFFD}};

    for (const auto& k : kinds)
    {
        FrameSpec cover{"cover", true, k.dest, REMOTE, false, udCover()};
        const size_t coverLen = cover.bytes().size();

        // 3a: one cover, split INSIDE the cover header (4 bytes, then the rest)
        runCase("B3_" + k.cls + "_split_in_cover", false, LOCAL, REMOTE, k.cls, "outstation_bound", "READ_req",
                "split_in_cover", {cover}, real, {4});

        // 3b: one cover, split a few bytes INTO the real frame
        runCase("B3_" + k.cls + "_split_in_real", false, LOCAL, REMOTE, k.cls, "outstation_bound", "READ_req",
                "split_in_real", {cover}, real, {coverLen + 5});

        // 3c: three covers, single segment
        runCase("B3_" + k.cls + "_3covers_same_seg", false, LOCAL, REMOTE, k.cls, "outstation_bound", "READ_req",
                "3covers_same_seg", {cover, cover, cover}, real, {});

        // 3d: three covers, split mid-second-cover
        runCase("B3_" + k.cls + "_3covers_split", false, LOCAL, REMOTE, k.cls, "outstation_bound", "READ_req",
                "3covers_split", {cover, cover, cover}, real, {coverLen + 3});
    }
}

// -----------------------------------------------------------------------------
// Block 4 — Sensitivity checks:
//   (a) CONFIRMED-user-data cover (individual): address gate precedes function/state handling.
//   (b) cover with a BOGUS source address: dropped at the SOURCE gate, not the dest gate.
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("Sensitivity"), "[coverframe]")
{
    const uint16_t LOCAL = 10, REMOTE = 1;
    FrameSpec real{"real", true, LOCAL, REMOTE, false, udReadRequest()};

    // (a) confirmed-user-data cover to a non-endpoint destination
    runCase("B4_confirmed_cover_individual", false, LOCAL, REMOTE, "individual_confirmed", "outstation_bound",
            "READ_req", "confirmed_cover", {FrameSpec{"cover", true, 0x0032, REMOTE, /*confirmed*/ true, udCover()}},
            real, {});

    // (b) cover addressed to the LOCAL endpoint destination but from a BOGUS source.
    // This isolates the source gate: dest matches, so only the source check can drop it.
    {
        LinkLayerTest t(LinkConfig(false, LOCAL, REMOTE, TimeDuration::Seconds(1), TimeDuration::Max()));
        REQUIRE(t.link.OnLowerLayerUp());
        t.log.ClearLog();
        FrameSpec cover{"cover", true, LOCAL, /*bogus src*/ 0x0063, false, udCover()};
        Bytes stream = cover.bytes();
        Bytes rb = real.bytes();
        stream.insert(stream.end(), rb.begin(), rb.end());
        const Measure m = runStream(t, stream, {});
        const std::string realHex = HexConversions::to_hex(rseq_t(real.ud.data(), real.ud.size()));
        const std::string coverHex = HexConversions::to_hex(rseq_t(cover.ud.data(), cover.ud.size()));
        std::printf("[%-30s] source-gate probe: unkSrc=%llu unkDest=%llu pushups=%zu (coverProcessed=%d)\n",
                    "B4_bogus_source", (unsigned long long)m.unknownSrc, (unsigned long long)m.unknownDest,
                    m.pushups.size(), contains(m.pushups, coverHex) ? 1 : 0);
        REQUIRE(m.unknownSrc == 1);                  // dropped at the source gate
        REQUIRE_FALSE(contains(m.pushups, coverHex)); // cover not processed
        REQUIRE(contains(m.pushups, realHex));        // real still processed
    }
}

// -----------------------------------------------------------------------------
// Block 5 — Parser-only continuity (address-agnostic): confirms a cover frame of ANY
// address does not disturb stream parsing; both frames are delivered to the sink and the
// real frame's user data is byte-identical. This is the observer's view: the parser reads
// through cover framing regardless of link address (compatibility != observer defeat).
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("ParserContinuity"), "[coverframe]")
{
    FrameSpec cover{"cover", true, 0xFFFD, 1, false, udCover()}; // even a broadcast cover
    FrameSpec real{"real", true, 10, 1, false, udReadRequest()};

    MockLogHandler log;
    MockFrameSink sink;
    LinkLayerParser parser(log.logger);

    Bytes stream = cover.bytes();
    Bytes rb = real.bytes();
    stream.insert(stream.end(), rb.begin(), rb.end());

    auto wbuf = parser.WriteBuff();
    REQUIRE(stream.size() <= wbuf.length());
    memcpy(wbuf, stream.data(), stream.size());
    parser.OnRead(stream.size(), sink);

    // Parser delivers BOTH frames (address-agnostic). MockFrameSink appends every frame's
    // user data, so `received` == cover.ud || real.ud and the last header is the real's.
    // This is the on-path observer's view: the parser reads through cover framing and the
    // real frame's bytes are recovered verbatim, regardless of the cover's link address.
    Bytes both = cover.ud;
    both.insert(both.end(), real.ud.begin(), real.ud.end());
    const bool bothIntact = sink.received.Equals(rseq_t(both.data(), both.size()));
    const bool lastIsReal = (sink.m_last_header.addresses.destination == real.dest)
        && (sink.m_last_header.addresses.source == real.src);
    REQUIRE(sink.m_num_frames == 2);
    REQUIRE(parser.Statistics().numHeaderCrcError == 0);
    REQUIRE(parser.Statistics().numBodyCrcError == 0);
    REQUIRE(bothIntact);   // both payloads delivered byte-identical, in order
    REQUIRE(lastIsReal);   // the real frame is the second one delivered
    std::printf("[%-30s] parser delivered %zu frames; cover||real byte-identical=%d; last-frame-is-real=%d\n",
                "B5_parser_continuity", sink.m_num_frames, bothIntact ? 1 : 0, lastIsReal ? 1 : 0);
}

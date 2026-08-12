/*
 * DNP3 cover-frame BOUNDED APPLICATION-CONTEXT ROUND TRIP through a real link address filter.
 *
 * EVIDENCE CLASS (read this first — corrected 2026-08-12, audit M2):
 *   This test exercises REAL OpenDNP3 master (MContext) and outstation (OContext) APPLICATION
 *   state machines and a REAL LinkLayerParser + LinkLayer ADDRESS FILTER. It does NOT exercise
 *   a TCP channel, a socket, persistent transport reassembly, or TCP sequencing/retransmit/
 *   teardown. Concretely, for every APDU the master emits, the harness:
 *     1. manually prepends ONE 0xC0 transport octet (a single-TPDU stand-in; there is NO real
 *        transport layer and NO reassembly across segments),
 *     2. manually frames it into a DNP3 link frame (and optionally prepends CRC-valid COVER
 *        link frames addressed to a non-endpoint link address),
 *     3. feeds the bytes into a NEWLY CONSTRUCTED LinkLayerParser+LinkLayer fixture created per
 *        APDU (no persistent link session), whose real address filter decides discard vs deliver,
 *     4. strips the surviving user-data back to APDU hex and injects it into the peer context.
 *   Responses flow back the same way.
 *
 *   "Split" in this test splits the bytes across successive LinkLayerParser.OnRead() CALLS
 *   (see `chunkSizes`/`feed`). It is NOT TCP segmentation — there are no TCP segments here.
 *
 *   `masterCloses` counts application-level MockMasterApplication OnClose (CLOSED) callbacks.
 *   It is always 0 here and proves NOTHING about a TCP or link-session close: no TCP/link
 *   session exists in this harness to close.
 *
 *   The real socket / TCP / transport-reassembly / captured-wire evidence lives in
 *   ../real_channel/ (a live single-process OpenDNP3 DNP3Manager TCP loopback, captured with
 *   dumpcap). This file is the APPLICATION-CONTEXT + LINK-FILTER class only.
 *
 * WHAT A PASS MEANS (bounded to the classes above): with the RECOMMENDED cover address (a
 * non-local INDIVIDUAL address unused in the test protection domain), the application-context
 * round trip completes byte-for-byte identically to the no-cover baseline, the cover is dropped
 * at the receiver's link ADDRESS FILTER and never reaches the application, and it provokes no
 * extra application traffic in the reconstructed transcript (no application retry, no spurious
 * CONFIRM). It does NOT defeat a parsing observer (that impossibility result is preserved), and
 * it says nothing about TCP/link close. Broadcast covers are shown to be a HAZARD: they are
 * passed up to the application and change the reconstructed transcript.
 *
 * Built out-of-tree as a standalone Catch target (see run.sh); nothing is committed to the
 * OpenDNP3 fork, which run.sh restores.
 */
#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/LinkLayerTest.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <dnp3mocks/DatabaseHelpers.h>

#include <link/LinkLayerParser.h>

#include <opendnp3/app/ClassField.h>
#include <opendnp3/app/ControlRelayOutputBlock.h>
#include <opendnp3/master/CommandSet.h>

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
uint16_t dnp3_crc16(const uint8_t* data, size_t n)
{
    uint16_t crc = 0x0000;
    for (size_t i = 0; i < n; ++i)
    {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b)
            crc = (crc & 1) ? static_cast<uint16_t>((crc >> 1) ^ 0xA6BC) : static_cast<uint16_t>(crc >> 1);
    }
    return static_cast<uint16_t>((~crc) & 0xFFFF);
}

// Build a DNP3 data-link frame carrying user data `ud` (transport+application octets).
Bytes buildUserDataFrame(bool fromMaster, uint16_t dest, uint16_t src, bool confirmed, const Bytes& ud)
{
    const uint8_t func = confirmed ? 0x03 : 0x04;
    uint8_t ctrl = static_cast<uint8_t>(0x40 | func); // PRM=1
    if (fromMaster)
        ctrl |= 0x80; // DIR
    if (confirmed)
        ctrl |= 0x10; // FCV
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

Bytes hexToBytes(const std::string& hex)
{
    HexSequence hs(hex);
    const uint8_t* p = hs; // CopyableBuffer::operator const uint8_t*()
    return Bytes(p, p + hs.Size());
}

std::string udHexFor(const std::string& apduHex)
{
    Bytes ud = {0xC0};
    Bytes apdu = hexToBytes(apduHex);
    ud.insert(ud.end(), apdu.begin(), apdu.end());
    return HexConversions::to_hex(rseq_t(ud.data(), ud.size()));
}

// Outcome of running [covers...][real] through the receiver's real link layer.
struct FilterOut
{
    std::vector<std::string> deliverApduHex; // surviving user-data, mapped back to APDU hex, in order
    bool realSurvived = false;
    int coverPushups = 0;
    uint32_t linkTx = 0; // frames the receiver's link layer transmitted (e.g. an ACK) — expect 0
};

// Feed [coverFrames...][realFrame] into a fresh receiver LinkLayerParser+LinkLayer configured
// for (local,remote), splitting into successive OnRead() calls per `chunkSizes`.
FilterOut filterThroughLink(bool recvIsMaster,
                            uint16_t local,
                            uint16_t remote,
                            const std::vector<Bytes>& coverFrames,
                            const Bytes& realFrame,
                            const std::string& realUdHex,
                            const std::string& realApduHex,
                            const std::string& coverUdHex,
                            const std::string& coverApduHex,
                            const std::vector<size_t>& chunkSizes)
{
    LinkLayerTest t(LinkConfig(recvIsMaster, local, remote, TimeDuration::Seconds(1), TimeDuration::Max()));
    REQUIRE(t.link.OnLowerLayerUp());
    t.log.ClearLog();
    LinkLayerParser parser(t.log.logger);

    Bytes stream;
    for (const auto& c : coverFrames)
        stream.insert(stream.end(), c.begin(), c.end());
    stream.insert(stream.end(), realFrame.begin(), realFrame.end());

    auto feed = [&](size_t from, size_t n) {
        auto wbuf = parser.WriteBuff();
        REQUIRE(n <= wbuf.length());
        memcpy(wbuf, stream.data() + from, n);
        parser.OnRead(n, t.link);
    };
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
        feed(off, stream.size() - off);

    FilterOut r;
    for (const auto& h : t.upper->receivedQueue)
    {
        if (h == realUdHex)
        {
            r.realSurvived = true;
            r.deliverApduHex.push_back(realApduHex);
        }
        else if (!coverUdHex.empty() && h == coverUdHex)
        {
            ++r.coverPushups;
            r.deliverApduHex.push_back(coverApduHex); // faithfully model the app seeing a passed-up cover
        }
    }
    r.linkTx = t.NumTotalWrites();
    return r;
}

enum class Kind
{
    READ,
    SBO
};
enum class Dir
{
    NONE,
    M2O,
    O2M
};

struct RunResult
{
    std::vector<std::string> transcript; // ordered APDUs exchanged, "M>O <hex>" / "O>M <hex>"
    int masterSoe = 0;
    int outSelect = 0, outOperate = 0;
    int coverPushups = 0;   // covers that reached an application context (expect 0 for discard class)
    uint32_t coverLinkTx = 0; // link frames emitted in response to a cover (expect 0)
    int masterCloses = 0;   // OnClose() callbacks on the master application (expect 0)
    bool taskSuccess = false;
    bool completed = false;
    int iterations = 0;
};

// The cover marker APDU (READ class-1); distinct from any real APDU used here.
const std::string COVER_APDU_HEX = "C0 01 3C 01 06";

// Run one transaction. `covers` are pre-built cover FRAMES injected on every frame in `dir`.
RunResult runTransaction(Kind kind,
                         Dir dir,
                         const std::vector<Bytes>& covers,
                         uint16_t coverDest, // for building the cover frame in the correct direction
                         const std::vector<size_t>& chunks)
{
    const uint16_t M_LOCAL = 1, O_LOCAL = 10;
    MasterTestFixture master(NoStartupTasks(), Addresses(M_LOCAL, O_LOCAL));
    OutstationConfig ocfg;
    OutstationTestObject out(ocfg, configure::by_count_of::binary_input(4));
    out.Transaction([](IUpdateHandler& db) {
        db.Update(Binary(true, Flags(0x01)), 0);
        db.Update(Binary(false, Flags(0x01)), 1);
        db.Update(Binary(true, Flags(0x01)), 2);
        db.Update(Binary(false, Flags(0x01)), 3);
    });

    REQUIRE(master.context->OnLowerLayerUp());
    master.exe->run_many();
    out.LowerLayerUp();

    CommandCallbackQueue cq;
    if (kind == Kind::READ)
        master.context->ScanClasses(ClassField::AllClasses(), master.meas, TaskConfig::Default());
    else
        master.context->SelectAndOperate(CommandSet({WithIndex(ControlRelayOutputBlock(OperationType::PULSE_ON), 1)}),
                                          cq.Callback(), TaskConfig::Default());
    master.exe->run_many();

    const std::string coverUdHex = covers.empty() ? "" : udHexFor(COVER_APDU_HEX);

    RunResult rr;
    const std::vector<size_t> noSplit;
    for (int it = 0; it < 60; ++it)
    {
        rr.iterations = it + 1;
        bool progressed = false;

        // ---- master -> outstation ----
        while (master.lower->NumWrites() > 0)
        {
            const std::string apduHex = master.lower->PopWriteAsHex();
            rr.transcript.push_back("M>O " + apduHex);
            master.context->OnTxReady();

            Bytes ud = {0xC0};
            Bytes apdu = hexToBytes(apduHex);
            ud.insert(ud.end(), apdu.begin(), apdu.end());
            const Bytes real = buildUserDataFrame(/*fromMaster*/ true, O_LOCAL, M_LOCAL, false, ud);

            const bool inject = (dir == Dir::M2O) && !covers.empty();
            FilterOut fo = filterThroughLink(/*recvIsMaster*/ false, O_LOCAL, M_LOCAL, inject ? covers : std::vector<Bytes>{},
                                             real, HexConversions::to_hex(rseq_t(ud.data(), ud.size())), apduHex,
                                             inject ? coverUdHex : "", COVER_APDU_HEX, inject ? chunks : noSplit);
            if (inject)
            {
                rr.coverPushups += fo.coverPushups;
                rr.coverLinkTx += fo.linkTx;
            }
            for (const auto& deliver : fo.deliverApduHex)
                out.SendToOutstation(deliver);
            progressed = true;
        }

        // ---- outstation -> master ----
        while (out.lower->NumWrites() > 0)
        {
            const std::string apduHex = out.lower->PopWriteAsHex();
            rr.transcript.push_back("O>M " + apduHex);
            out.OnTxReady();

            Bytes ud = {0xC0};
            Bytes apdu = hexToBytes(apduHex);
            ud.insert(ud.end(), apdu.begin(), apdu.end());
            const Bytes real = buildUserDataFrame(/*fromMaster*/ false, M_LOCAL, O_LOCAL, false, ud);

            const bool inject = (dir == Dir::O2M) && !covers.empty();
            FilterOut fo = filterThroughLink(/*recvIsMaster*/ true, M_LOCAL, O_LOCAL, inject ? covers : std::vector<Bytes>{},
                                             real, HexConversions::to_hex(rseq_t(ud.data(), ud.size())), apduHex,
                                             inject ? coverUdHex : "", COVER_APDU_HEX, inject ? chunks : noSplit);
            if (inject)
            {
                rr.coverPushups += fo.coverPushups;
                rr.coverLinkTx += fo.linkTx;
            }
            for (const auto& deliver : fo.deliverApduHex)
            {
                master.SendToMaster(deliver);
                master.exe->run_many();
            }
            progressed = true;
        }

        if (!progressed)
            break;
    }

    rr.masterSoe = master.meas->TotalReceived();
    rr.outSelect = out.cmdHandler->NumSelect();
    rr.outOperate = out.cmdHandler->NumOperate();
    for (auto s : master.application->stateChanges)
        if (s == MockMasterApplication::State::CLOSED)
            ++rr.masterCloses;

    if (kind == Kind::READ)
    {
        for (const auto& ti : master.application->taskCompletionEvents)
            if (ti.result == TaskCompletion::SUCCESS)
                rr.taskSuccess = true;
        rr.completed = rr.taskSuccess && rr.masterSoe > 0;
    }
    else
    {
        const bool cbOk = (cq.values.size() == 1) && (cq.values.front().summary == TaskCompletion::SUCCESS);
        rr.completed = cbOk && (rr.outOperate == 1) && (rr.outSelect == 1);
        rr.taskSuccess = cbOk;
    }
    return rr;
}

// The RECOMMENDED cover: a non-local INDIVIDUAL link address unused in the {master=1,
// outstation=10} protection domain. 0x0032 (50) is neither endpoint, not reserved, not self,
// not broadcast.
const uint16_t COVER_INDIVIDUAL = 0x0032;
const uint16_t COVER_BROADCAST = 0xFFFD;

Bytes coverFrame(bool fromMaster, uint16_t dest, uint16_t src)
{
    Bytes ud = {0xC0};
    Bytes apdu = hexToBytes(COVER_APDU_HEX);
    ud.insert(ud.end(), apdu.begin(), apdu.end());
    return buildUserDataFrame(fromMaster, dest, src, false, ud);
}

// Evidence sink.
struct Out
{
    std::ofstream csv;
    Out()
    {
        const char* d = std::getenv("COVER_FRAME_OUT");
        std::string dir = d ? d : ".";
        csv.open(dir + "/full_transaction_results.csv", std::ios::trunc);
        csv << "case,txn,cover_dir,cover_class,n_covers,split,transaction_completed,master_soe,out_select,"
               "out_operate,cover_reached_app,cover_link_tx,master_closes,transcript_equals_baseline,verdict\n";
    }
};
Out& evid()
{
    static Out o;
    return o;
}

void record(const std::string& name,
            const std::string& txn,
            const std::string& dir,
            const std::string& cls,
            size_t nCovers,
            const std::string& split,
            const RunResult& rr,
            int transcriptEqualsBaseline,
            const std::string& verdict)
{
    evid().csv << name << ',' << txn << ',' << dir << ',' << cls << ',' << nCovers << ',' << split << ','
               << (rr.completed ? 1 : 0) << ',' << rr.masterSoe << ',' << rr.outSelect << ',' << rr.outOperate << ','
               << rr.coverPushups << ',' << rr.coverLinkTx << ',' << rr.masterCloses << ',' << transcriptEqualsBaseline
               << ',' << verdict << '\n';
    std::printf("[%-34s] txn=%-4s dir=%-4s cover=%-11s n=%zu split=%-14s | completed=%d soe=%d sel=%d op=%d "
                "coverReachedApp=%d coverLinkTx=%u closes=%d eqBaseline=%d => %s\n",
                name.c_str(), txn.c_str(), dir.c_str(), cls.c_str(), nCovers, split.c_str(), rr.completed ? 1 : 0,
                rr.masterSoe, rr.outSelect, rr.outOperate, rr.coverPushups, (unsigned)rr.coverLinkTx, rr.masterCloses,
                transcriptEqualsBaseline, verdict.c_str());
}

} // namespace

// Suite label reflects the corrected evidence class: application-context round trip through a
// real link address filter (NOT a full TCP/transport transaction — see the header).
#define SUITE(name) "CoverFrameAppContextRoundTrip - " name

// -----------------------------------------------------------------------------
// FT1 — Integrity READ round trip, individual cover on the REQUEST direction.
//   Prove: the real integrity read completes (master receives the outstation's points and the
//   task completes SUCCESS), the transcript is byte-identical to the no-cover baseline, the
//   cover never reaches the application, and it provokes no link ACK and no application close.
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("IntegrityRead_individual_cover_on_request"), "[fulltxn]")
{
    RunResult base = runTransaction(Kind::READ, Dir::NONE, {}, 0, {});
    REQUIRE(base.completed);
    REQUIRE(base.masterSoe == 4);

    std::vector<Bytes> covers = {coverFrame(/*fromMaster*/ true, COVER_INDIVIDUAL, 1)};
    RunResult cov = runTransaction(Kind::READ, Dir::M2O, covers, COVER_INDIVIDUAL, {});

    const int eq = (cov.transcript == base.transcript) ? 1 : 0;
    const bool pass = cov.completed && cov.masterSoe == base.masterSoe && cov.coverPushups == 0 && cov.coverLinkTx == 0
        && cov.masterCloses == 0 && eq == 1;
    record("FT1_read_req_individual", "READ", "M2O", "individual", covers.size(), "same_seg", cov, eq,
           pass ? "PASS" : "FAIL");

    REQUIRE(cov.completed);
    REQUIRE(cov.masterSoe == base.masterSoe);
    REQUIRE(cov.coverPushups == 0);    // cover dropped at outstation link layer
    REQUIRE(cov.coverLinkTx == 0);     // no ACK provoked
    REQUIRE(cov.masterCloses == 0);    // no close
    REQUIRE(cov.transcript == base.transcript); // no extra retry/CONFIRM
}

// -----------------------------------------------------------------------------
// FT2 — Integrity READ, individual cover on the RESPONSE direction (master's link filter).
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("IntegrityRead_individual_cover_on_response"), "[fulltxn]")
{
    RunResult base = runTransaction(Kind::READ, Dir::NONE, {}, 0, {});
    std::vector<Bytes> covers = {coverFrame(/*fromMaster*/ false, COVER_INDIVIDUAL, 10)};
    RunResult cov = runTransaction(Kind::READ, Dir::O2M, covers, COVER_INDIVIDUAL, {});

    const int eq = (cov.transcript == base.transcript) ? 1 : 0;
    const bool pass = cov.completed && cov.masterSoe == base.masterSoe && cov.coverPushups == 0 && cov.coverLinkTx == 0
        && eq == 1;
    record("FT2_read_resp_individual", "READ", "O2M", "individual", covers.size(), "same_seg", cov, eq,
           pass ? "PASS" : "FAIL");

    REQUIRE(cov.completed);
    REQUIRE(cov.coverPushups == 0);
    REQUIRE(cov.transcript == base.transcript);
}

// -----------------------------------------------------------------------------
// FT3 — SELECT + OPERATE (SBO) round trip, individual cover on the REQUEST direction.
//   Prove: the real command completes SUCCESS, the outstation executes exactly one Select and
//   one Operate for the real point, and the cover adds no command and no extra traffic.
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("SelectOperate_individual_cover_on_request"), "[fulltxn]")
{
    RunResult base = runTransaction(Kind::SBO, Dir::NONE, {}, 0, {});
    REQUIRE(base.completed);
    REQUIRE(base.outSelect == 1);
    REQUIRE(base.outOperate == 1);

    std::vector<Bytes> covers = {coverFrame(true, COVER_INDIVIDUAL, 1)};
    RunResult cov = runTransaction(Kind::SBO, Dir::M2O, covers, COVER_INDIVIDUAL, {});

    const int eq = (cov.transcript == base.transcript) ? 1 : 0;
    const bool pass = cov.completed && cov.outSelect == 1 && cov.outOperate == 1 && cov.coverPushups == 0 && eq == 1;
    record("FT3_sbo_req_individual", "SBO", "M2O", "individual", covers.size(), "same_seg", cov, eq,
           pass ? "PASS" : "FAIL");

    REQUIRE(cov.completed);
    REQUIRE(cov.outSelect == 1);
    REQUIRE(cov.outOperate == 1);
    REQUIRE(cov.coverPushups == 0);
    REQUIRE(cov.transcript == base.transcript);
}

// -----------------------------------------------------------------------------
// FT4 — Multiple covers (3) on the request, split across successive LinkLayerParser.OnRead()
//        CALLS (NOT TCP segments) to exercise the link parser's cross-read reassembly.
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("MultipleCovers_and_split_delivery"), "[fulltxn]")
{
    RunResult base = runTransaction(Kind::READ, Dir::NONE, {}, 0, {});

    Bytes c = coverFrame(true, COVER_INDIVIDUAL, 1);
    std::vector<Bytes> covers = {c, c, c};
    // split: 4 bytes (mid first cover header), then remainder — exercises reassembly across reads.
    RunResult cov = runTransaction(Kind::READ, Dir::M2O, covers, COVER_INDIVIDUAL, {4, (size_t)(c.size() + 3)});

    const int eq = (cov.transcript == base.transcript) ? 1 : 0;
    const bool pass = cov.completed && cov.masterSoe == base.masterSoe && cov.coverPushups == 0 && eq == 1;
    record("FT4_3covers_split", "READ", "M2O", "individual", covers.size(), "split_cover+real", cov, eq,
           pass ? "PASS" : "FAIL");

    REQUIRE(cov.completed);
    REQUIRE(cov.coverPushups == 0);
    REQUIRE(cov.transcript == base.transcript);
}

// -----------------------------------------------------------------------------
// FT5 — Broadcast cover HAZARD (negative control). A broadcast cover is NOT discarded; the
//   receiver's link layer passes it up to the application, changing the transcript. This is
//   why broadcast is not a safe cover address and the individual address is recommended.
// -----------------------------------------------------------------------------
TEST_CASE(SUITE("BroadcastCover_is_a_hazard"), "[fulltxn]")
{
    RunResult base = runTransaction(Kind::READ, Dir::NONE, {}, 0, {});

    std::vector<Bytes> covers = {coverFrame(true, COVER_BROADCAST, 1)};
    RunResult cov = runTransaction(Kind::READ, Dir::M2O, covers, COVER_BROADCAST, {});

    const int eq = (cov.transcript == base.transcript) ? 1 : 0;
    // HAZARD verdict = cover reached the application (pushed up) => individual-address recommendation justified.
    const bool hazardShown = cov.coverPushups >= 1;
    record("FT5_broadcast_hazard", "READ", "M2O", "broadcast_D", covers.size(), "same_seg", cov, eq,
           hazardShown ? "HAZARD_CONFIRMED" : "UNEXPECTED");

    REQUIRE(cov.coverPushups >= 1);        // broadcast cover DID reach the application
    REQUIRE(cov.transcript != base.transcript); // and it perturbed the transaction
}

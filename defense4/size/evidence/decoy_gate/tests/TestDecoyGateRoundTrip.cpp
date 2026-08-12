// SPDX-License-Identifier: Apache-2.0
//
// PART A (integrated) — FULL SBO ROUND TRIP for the configured inert-decoy size gate.
//
// One integrated in-memory transaction wiring a REAL opendnp3 master context and a REAL
// opendnp3 outstation context through a size-axis TRANSFORMER. Software only: APDUs move
// between the two contexts as byte strings via their MockLowerLayers; the transformer sits
// on the outstation-bound path and injects the configured inert decoys (Encoding A: a
// SEPARATE trailing G12V1 header). No networking, no hardware, no relay, no switch. This
// is the faithful substitute for a live pydnp3 master<->outstation loopback (which SIGSTKFLTs
// in this environment); it drives the exact production SELECT/OPERATE + SBO state machine.
//
// The ten contracted steps, per round:
//   1. the UNMODIFIED master issues SELECT for the LEGITIMATE CROB only (real index 1);
//   2. the transformer adds the configured inert decoy CROBs (Encoding A);
//   3. the configured outstation receives the EXPANDED SELECT;
//   4. every real and decoy SELECT status is recorded (parsed from the echo);
//   5. the unmodified master accepts the response and emits OPERATE for the legit point only;
//   6. the transformer adds the EXACT corresponding decoy CROBs to OPERATE;
//   7. the outstation processes the expanded OPERATE;
//   8. the legit simulated physical/inert mapping fires EXACTLY ONCE;
//   9. every decoy reaches ONLY its inert simulated mapping;
//  10. the master COMPLETES the command successfully.
//
// Plus: multiple decoy counts; exact retransmission of the transformed SELECT; exact
// retransmission of the transformed OPERATE; SELECT/OPERATE decoy MISMATCH (rejected safely);
// an UNCONFIGURED decoy in the stream; one decoy FORCED to return FAILURE; no unrequested
// index executes; per-object status for every real and decoy object.
//
// NOTE ON EVIDENCE STRENGTH. `physicalActuations` / `inertActuations` are a SIMULATED
// physical/inert mapping in software (the DecoyGateCommandHandler counters). No physical
// relay is touched. The premise is endpoint preconfiguration: the decoys are REAL, CONFIGURED
// points with real handlers, simply not wired to an output.

#include <opendnp3/logging/LogLevels.h>

#include <exe4cpp/MockExecutor.h>

#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockLowerLayer.h"
#include "dnp3mocks/MockOutstationApplication.h"

#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/DecoyGateCommandHandler.h"
#include "utils/MasterTestFixture.h"

#include <link/LinkLayerConstants.h>
#include <outstation/Database.h>
#include <outstation/OutstationContext.h>

#include <opendnp3/gen/CommandPointState.h>
#include <opendnp3/gen/CommandStatus.h>

#include <catch.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace opendnp3;

#define SUITE(name) "DecoyGateRoundTripTestSuite - " name

namespace
{

// ----- hex helpers ----------------------------------------------------------------------

std::vector<std::string> toks(const std::string& hex)
{
    std::istringstream ss(hex);
    std::vector<std::string> out;
    std::string t;
    while (ss >> t)
        out.push_back(t);
    return out;
}
int hb(const std::string& t)
{
    return std::stoi(t, nullptr, 16);
}
std::string u16le(unsigned v)
{
    char b[8];
    std::snprintf(b, sizeof(b), "%02X %02X", v & 0xFF, (v >> 8) & 0xFF);
    return std::string(b);
}
std::string join(const std::vector<std::string>& t, size_t from, size_t toIncl)
{
    std::string s;
    for (size_t i = from; i <= toIncl && i < t.size(); ++i)
        s += (i == from ? "" : " ") + t[i];
    return s;
}

// The master emits a command as: <ctl> <fc> 0C 01 28 <cnt2> <idx2> <11B CROB>. Extract the CROB.
std::string extractCrob(const std::string& cmd)
{
    const auto t = toks(cmd);
    REQUIRE(t.size() == 20u);   // one G12V1 point, qual 0x28
    REQUIRE(t[2] == "0C");      // group 12
    REQUIRE(t[3] == "01");      // var 1 (CROB)
    REQUIRE(t[4] == "28");      // qual: 2-byte count + 2-byte index prefix
    return join(t, 9, 19);      // the 11 CROB bytes
}

// TRANSFORMER (Encoding A): append a SEPARATE trailing G12V1 header carrying the decoys, each
// reusing the real CROB body. Adds decoys to a master SELECT or OPERATE without touching the
// real header the master already wrote.
std::string transform(const std::string& cmd, const std::vector<uint16_t>& decoys)
{
    const std::string crob = extractCrob(cmd);
    std::string h = "0C 01 28 " + u16le(static_cast<unsigned>(decoys.size()));
    for (auto d : decoys)
        h += " " + u16le(d) + " " + crob;
    return cmd + " " + h;
}

// Walk a command echo and pull (index, statusByte) for EVERY object across ALL headers.
struct ObjStatus
{
    int index;
    std::string status;
};
std::vector<ObjStatus> parseEcho(const std::string& echo)
{
    const auto t = toks(echo);
    std::vector<ObjStatus> out;
    size_t i = 4; // skip ctl, fc(81), IIN(2)
    while (i + 3 <= t.size())
    {
        // header: group var qual
        const std::string q = t[i + 2];
        i += 3;
        int cnt = 0, idxBytes = 0;
        if (q == "28")
        {
            cnt = hb(t[i]) | (hb(t[i + 1]) << 8);
            i += 2;
            idxBytes = 2;
        }
        else if (q == "17")
        {
            cnt = hb(t[i]);
            i += 1;
            idxBytes = 1;
        }
        else
            break;
        for (int c = 0; c < cnt; ++c)
        {
            int idx = (idxBytes == 2) ? (hb(t[i]) | (hb(t[i + 1]) << 8)) : hb(t[i]);
            i += idxBytes;
            // CROB body is 11 bytes: code count on(4) off(4) status(1); status is the last
            out.push_back({idx, t[i + 10]});
            i += 11;
        }
    }
    return out;
}
std::string statusName(const std::string& s)
{
    int v = hb(s);
    switch (v)
    {
    case 0:
        return "SUCCESS";
    case 2:
        return "NO_SELECT";
    case 4:
        return "NOT_SUPPORTED";
    case 6:
        return "HARDWARE_ERROR";
    default:
        return "0x" + s;
    }
}

// ----- outstation harness with an injectable DecoyGateCommandHandler --------------------

struct DecoyOutstation
{
    explicit DecoyOutstation(const std::shared_ptr<DecoyGateCommandHandler>& handler,
                             const OutstationConfig& config = OutstationConfig())
        : exe(std::make_shared<exe4cpp::MockExecutor>()),
          lower(std::make_shared<MockLowerLayer>()),
          cmd(handler),
          app(std::make_shared<MockOutstationApplication>()),
          context(Addresses(), config, DatabaseConfig(), log.logger, exe, lower, cmd, app)
    {
        lower->SetUpperLayer(context);
    }
    void LowerLayerUp()
    {
        context.OnLowerLayerUp();
        exe->run_many();
    }
    void OnTxReady()
    {
        context.OnTxReady();
        exe->run_many();
    }
    std::string Send(const std::string& hex)
    {
        HexSequence hs(hex);
        context.OnReceive(Message(Addresses(), hs.ToRSeq()));
        exe->run_many();
        return lower->PopWriteAsHex();
    }
    MockLogHandler log;
    std::shared_ptr<exe4cpp::MockExecutor> exe;
    std::shared_ptr<MockLowerLayer> lower;
    std::shared_ptr<DecoyGateCommandHandler> cmd;
    std::shared_ptr<MockOutstationApplication> app;
    OContext context;
};

MasterParams masterParams()
{
    MasterParams p;
    p.disableUnsolOnStartup = false;
    p.startupIntegrityClassMask = ClassField::None();
    p.unsolClassMask = ClassField::None();
    p.ignoreRestartIIN = true; // real outstation sets IIN1.7; don't let it schedule side tasks
    return p;
}

std::vector<uint16_t> decoyIndices(uint16_t k)
{
    std::vector<uint16_t> v; // decoys at indices 2..k+1
    for (uint16_t j = 0; j < k; ++j)
        v.push_back(static_cast<uint16_t>(2 + j));
    return v;
}

} // namespace

TEST_CASE(SUITE("full SBO round trip: master<->transformer<->outstation, sweep decoy counts; retransmits; ten steps"))
{
    const std::vector<uint16_t> ks = {1, 2, 3, 5, 8};
    std::cout << "DECOY-RT[main] full SBO round trip (real index 1 wired; decoys inert, Encoding A):\n";

    for (auto k : ks)
    {
        const auto decoys = decoyIndices(k);
        auto handler = std::make_shared<DecoyGateCommandHandler>(/*legit*/ 1, decoys);
        DecoyOutstation os(handler);
        os.LowerLayerUp();

        MasterTestFixture ms(masterParams());
        ms.context->OnLowerLayerUp();
        CommandCallbackQueue queue;
        ControlRelayOutputBlock command(OperationType::PULSE_ON);
        ms.context->SelectAndOperate(CommandSet({WithIndex(command, 1)}), queue.Callback(), TaskConfig::Default());
        ms.exe->run_many();

        // STEP 1: master SELECT carries ONLY the real index 1
        const std::string mSel = ms.lower->PopWriteAsHex();
        REQUIRE(mSel == "C0 03 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00");
        ms.context->OnTxReady();

        // STEP 2: transformer adds the configured decoys (Encoding A)
        const std::string xSel = transform(mSel, decoys);

        // STEP 3: outstation receives the EXPANDED SELECT; STEP 4: record every status
        const std::string selEcho = os.Send(xSel);
        os.OnTxReady();
        const auto selStatuses = parseEcho(selEcho);
        REQUIRE(selStatuses.size() == static_cast<size_t>(1 + k)); // real + K decoys
        for (const auto& st : selStatuses)
            REQUIRE(st.status == "00"); // every real+decoy SELECT status SUCCESS (all configured)

        // EXTRA: exact retransmission of the transformed SELECT -> byte-identical cached echo, no re-select
        const std::string selEchoRetx = os.Send(xSel);
        os.OnTxReady();
        REQUIRE(selEchoRetx == selEcho);
        REQUIRE(handler->selects(1) == 1); // duplicate returned the cached response; no second Select
        REQUIRE(handler->physicalActuations == 0); // SELECT never actuates

        // STEP 5: master accepts the padded SELECT echo and emits OPERATE (real index only)
        REQUIRE(ms.SendToMaster(selEcho));
        ms.exe->run_many();
        const std::string mOp = ms.lower->PopWriteAsHex();
        REQUIRE(mOp == "C1 04 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00");
        ms.context->OnTxReady();

        // STEP 6: transformer adds the EXACT corresponding decoys to OPERATE
        const std::string xOp = transform(mOp, decoys);

        // STEP 7: outstation processes the expanded OPERATE
        const std::string opEcho = os.Send(xOp);
        os.OnTxReady();
        const auto opStatuses = parseEcho(opEcho);
        REQUIRE(opStatuses.size() == static_cast<size_t>(1 + k));
        for (const auto& st : opStatuses)
            REQUIRE(st.status == "00");

        // STEP 8: the legit simulated physical/inert mapping fires EXACTLY ONCE
        REQUIRE(handler->operates(1) == 1);
        REQUIRE(handler->physicalActuations == 1);

        // STEP 9: every decoy reaches ONLY its inert simulated mapping
        REQUIRE(handler->inertActuations == static_cast<uint32_t>(k));
        for (auto d : decoys)
            REQUIRE(handler->operates(d) == 1);
        // no unrequested index executes: the operate log is exactly {index 1 PHYSICAL} + K INERT
        REQUIRE(handler->operateLog.size() == static_cast<size_t>(1 + k));
        uint32_t physCount = 0, inertCount = 0;
        for (const auto& e : handler->operateLog)
        {
            const bool requested = (e.first == 1) || (std::find(decoys.begin(), decoys.end(), e.first) != decoys.end());
            REQUIRE(requested); // never an index that was not in the request
            if (e.second == "PHYSICAL")
            {
                REQUIRE(e.first == 1);
                ++physCount;
            }
            else
            {
                REQUIRE(e.second == "INERT");
                ++inertCount;
            }
        }
        REQUIRE(physCount == 1);
        REQUIRE(inertCount == static_cast<uint32_t>(k));

        // EXTRA: exact retransmission of the transformed OPERATE -> cached echo, NO second actuation
        const std::string opEchoRetx = os.Send(xOp);
        os.OnTxReady();
        REQUIRE(opEchoRetx == opEcho);
        REQUIRE(handler->operates(1) == 1);        // still exactly once
        REQUIRE(handler->physicalActuations == 1); // still exactly once
        REQUIRE(handler->inertActuations == static_cast<uint32_t>(k));

        // STEP 10: master COMPLETES the command successfully (real index 1, SUCCESS/SUCCESS)
        REQUIRE(ms.SendToMaster(opEcho));
        ms.exe->run_many();
        REQUIRE(ms.lower->PopWriteAsHex().empty());
        REQUIRE(queue.values.size() == 1);
        REQUIRE(queue.PopOnlyEqualValue(
            TaskCompletion::SUCCESS,
            CommandPointResult(0, 1, CommandPointState::SUCCESS, CommandStatus::SUCCESS)));

        std::printf("  K=%u: SELECT echo=%zuB, OPERATE echo=%zuB | physical=1 inert=%u | retx-SELECT ok, retx-OPERATE no-2nd-actuation | master SUCCESS\n",
                    static_cast<unsigned>(k), toks(selEcho).size(), toks(opEcho).size(),
                    static_cast<unsigned>(k));
        std::cout << "    per-object SELECT status:";
        for (const auto& st : selStatuses)
            std::cout << " (idx=" << st.index << "," << statusName(st.status) << ")";
        std::cout << "\n    per-object OPERATE status:";
        for (const auto& st : opStatuses)
            std::cout << " (idx=" << st.index << "," << statusName(st.status) << ")";
        std::cout << "\n";
    }
    std::cout << "DECOY-RT[main] -> PASS (ten steps hold across the decoy-count sweep)\n";
}

TEST_CASE(SUITE("SELECT/OPERATE decoy MISMATCH is rejected safely (NO_SELECT, nothing actuates)"))
{
    // decoys 2,3,4,5 are all configured; SELECT {2,3,4} succeeds and is cached; OPERATE {2,3,5}
    // differs by one index -> the outstation's CRC/length select match fails -> NO_SELECT for all.
    auto handler = std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{2, 3, 4, 5});
    DecoyOutstation os(handler);
    os.LowerLayerUp();

    const std::string realSel = "C0 03 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00";
    const std::string realOp = "C1 04 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00";
    const std::string xSel = transform(realSel, {2, 3, 4});
    const std::string xOp = transform(realOp, {2, 3, 5}); // MISMATCH: 5 instead of 4

    const std::string selEcho = os.Send(xSel);
    os.OnTxReady();
    for (const auto& st : parseEcho(selEcho))
        REQUIRE(st.status == "00"); // SELECT all-success, so it IS cached

    const std::string opEcho = os.Send(xOp);
    os.OnTxReady();
    const auto opStatuses = parseEcho(opEcho);
    for (const auto& st : opStatuses)
        REQUIRE(st.status == "02"); // NO_SELECT for every object -> nothing operated

    REQUIRE(handler->physicalActuations == 0); // legit did NOT actuate
    REQUIRE(handler->inertActuations == 0);
    REQUIRE(handler->operateLog.empty());

    std::cout << "DECOY-RT[mismatch] OPERATE decoys != SELECT decoys -> per-object";
    for (const auto& st : opStatuses)
        std::cout << " (idx=" << st.index << "," << statusName(st.status) << ")";
    std::cout << "; physicalActuations=0 -> REJECTED SAFELY (fail-safe) PASS\n";
}

TEST_CASE(SUITE("UNCONFIGURED decoy in the stream fails safe: SELECT not cached, OPERATE NO_SELECT, nothing actuates"))
{
    // decoys 2,3 are configured; index 99 is NOT configured. It appears in the transformed stream.
    auto handler = std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{2, 3});
    DecoyOutstation os(handler);
    os.LowerLayerUp();
    REQUIRE(handler->isConfigured(99) == false);

    const std::string realSel = "C0 03 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00";
    const std::string realOp = "C1 04 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00";
    const std::vector<uint16_t> decoys = {2, 3, 99};
    const std::string selEcho = os.Send(transform(realSel, decoys));
    os.OnTxReady();
    const auto selStatuses = parseEcho(selEcho);
    // real 1 and decoys 2,3 -> SUCCESS; unconfigured 99 -> NOT_SUPPORTED
    for (const auto& st : selStatuses)
    {
        if (st.index == 99)
            REQUIRE(st.status == "04");
        else
            REQUIRE(st.status == "00");
    }

    const std::string opEcho = os.Send(transform(realOp, decoys));
    os.OnTxReady();
    for (const auto& st : parseEcho(opEcho))
        REQUIRE(st.status == "02"); // SELECT was not cached (a status != SUCCESS) -> whole OPERATE NO_SELECT

    REQUIRE(handler->physicalActuations == 0); // legit did NOT actuate -> real command lost, but fail-safe
    REQUIRE(handler->inertActuations == 0);
    REQUIRE(handler->unconfiguredSelectRejects == 1);

    std::cout << "DECOY-RT[unconfigured] idx99 -> " << statusName("04")
              << " at SELECT; SELECT not cached; OPERATE all NO_SELECT; physicalActuations=0 -> FAIL-SAFE PASS\n";
    std::cout << "DECOY-RT[unconfigured] NOTE: an unconfigured decoy poisons the SBO (real command safely lost)\n";
}

TEST_CASE(SUITE("one configured decoy FORCED to return FAILURE: SELECT not cached, OPERATE NO_SELECT, nothing actuates"))
{
    // decoys 2,3,4 configured; decoy 3 is a configured point whose device logic reports HARDWARE_ERROR.
    auto handler = std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{2, 3, 4});
    handler->ForceStatus(3, CommandStatus::HARDWARE_ERROR);
    DecoyOutstation os(handler);
    os.LowerLayerUp();

    char hw[8];
    std::snprintf(hw, sizeof(hw), "%02X", static_cast<int>(CommandStatus::HARDWARE_ERROR)); // "06"

    const std::string realSel = "C0 03 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00";
    const std::string realOp = "C1 04 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00";
    const std::vector<uint16_t> decoys = {2, 3, 4};

    const std::string selEcho = os.Send(transform(realSel, decoys));
    os.OnTxReady();
    for (const auto& st : parseEcho(selEcho))
    {
        if (st.index == 3)
            REQUIRE(st.status == std::string(hw)); // the failing decoy reports its error status
        else
            REQUIRE(st.status == "00");
    }

    const std::string opEcho = os.Send(transform(realOp, decoys));
    os.OnTxReady();
    for (const auto& st : parseEcho(opEcho))
        REQUIRE(st.status == "02"); // one non-SUCCESS decoy -> SELECT not cached -> OPERATE NO_SELECT

    REQUIRE(handler->physicalActuations == 0);
    REQUIRE(handler->inertActuations == 0);
    REQUIRE(handler->failedActuations == 0); // OPERATE never reached the handler (NO_SELECT precedes it)

    std::cout << "DECOY-RT[decoy-failure] decoy idx3 -> " << statusName(hw)
              << " at SELECT; SELECT not cached; OPERATE all NO_SELECT; physicalActuations=0 -> FAIL-SAFE PASS\n";
}

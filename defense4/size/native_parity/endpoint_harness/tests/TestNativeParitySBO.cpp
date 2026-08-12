// SPDX-License-Identifier: Apache-2.0
//
// NATIVE-PARITY SBO — full SELECT-before-OPERATE of a NATIVE multi-CROB CommandSet.
//
// This is the endpoint half of the native-parity size defense, and it differs from the
// earlier "transformer" gate in one decisive way: there is NO transformer. The UNMODIFIED
// opendnp3 master itself builds ONE CommandSet containing the even real CROB and the odd
// decoy CROBs, and its own SELECT/OPERATE carry the whole set on the wire. The switch is
// never involved; the master's native serialization is the object of study.
//
// A REAL opendnp3 master context and a REAL opendnp3 outstation context are wired in memory
// through their MockLowerLayers (APDUs move as byte strings). Software only: no networking,
// no hardware, no relay, no switch. This is the faithful substitute for a live pydnp3
// master<->outstation loopback (which SIGSTKFLTs in this sandbox); it drives the exact
// production SELECT/OPERATE + SBO state machine and the real CommandSet serializer.
//
// What this test DERIVES from the real bytes (deliverable 2):
//   * whether opendnp3 emits ONE shared G12V1 object header or repeated headers for a
//     multi-CROB CommandSet  -> countG12Headers(mSel);
//   * the qualifier/prefix widths opendnp3 chooses (0x17 one-byte vs 0x28 two-byte), and
//     that MasterParams::controlQualifierMode selects between them;
//   * the exact serialized request + echo byte lengths for K = 1..maxK CROBs, and the
//     derived post-link u_SBO(K) and DNP3 link-frame wire size, compared to the relay
//     anchors (1-CROB echo 35 B, 2-CROB 49 B) and the hypothesis u_SBO(K) = 9 + 12K.
//
// What this test PROVES about endpoint semantics (deliverable 3, happy path):
//   * SELECT contains the exact even/odd set, in order, one shared header;
//   * OPERATE repeats the SELECT object bytes EXACTLY (byte-identical object portion);
//   * every per-object status is parsed (real + every decoy);
//   * the real (even, wired) callback fires EXACTLY once; odd decoy callbacks are inert;
//   * exact retransmission of SELECT and of OPERATE returns the cached echo with no second
//     Select and no second actuation;
//   * the master COMPLETES with one SUCCESS/SUCCESS per object across the whole set.
//
// Machine-readable ##VEC## lines carry the committed bytes for the derive_sizes.py reducer.

#include <opendnp3/logging/LogLevels.h>

#include <exe4cpp/MockExecutor.h>

#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockLowerLayer.h"
#include "dnp3mocks/MockOutstationApplication.h"

#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/NativeParityCommandHandler.h"
#include "utils/NativeParityHelpers.h"
#include "utils/NativeParityPlan.h"

#include <outstation/OutstationContext.h>

#include <opendnp3/gen/CommandPointState.h>
#include <opendnp3/gen/CommandStatus.h>

#include <catch.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace opendnp3;
using namespace np;

#define SUITE(name) "NativeParitySBOTestSuite - " name

namespace
{

// ----- outstation harness with an injectable NativeParityCommandHandler ------------------

struct ParityOutstation
{
    explicit ParityOutstation(const std::shared_ptr<NativeParityCommandHandler>& handler,
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
    std::shared_ptr<NativeParityCommandHandler> cmd;
    std::shared_ptr<MockOutstationApplication> app;
    OContext context;
};

MasterParams masterParams(IndexQualifierMode qmode)
{
    MasterParams p;
    p.disableUnsolOnStartup = false;
    p.startupIntegrityClassMask = ClassField::None();
    p.unsolClassMask = ClassField::None();
    p.ignoreRestartIIN = true; // the real outstation sets IIN1.7; don't let it schedule side tasks
    p.controlQualifierMode = qmode; // the variable under study: 0x17 (allow_one_byte) vs 0x28
    return p;
}

// Build a CommandSet for the plan: one even real CROB + (K-1) odd decoy CROBs, ALL in ONE
// Add() -> ONE shared G12V1 header. Every CROB is the identical PULSE_ON block, so the size
// depends only on K and the qualifier width.
CommandSet buildParitySet(const NativeParityPlan& plan)
{
    ControlRelayOutputBlock crob(OperationType::PULSE_ON);
    std::vector<Indexed<ControlRelayOutputBlock>> items;
    items.push_back(WithIndex(crob, plan.realIndex));
    for (auto d : plan.decoyIndices)
        items.push_back(WithIndex(crob, d));
    CommandSet set;
    set.Add<ControlRelayOutputBlock>(items);
    return set;
}

const char* qmodeName(IndexQualifierMode m)
{
    return m == IndexQualifierMode::allow_one_byte ? "allow_one_byte" : "always_two_bytes";
}

void emitSboVec(const char* qmode, uint16_t k, const NativeParityPlan& plan, const std::string& mSel,
                const std::string& selEcho, const std::vector<ObjStatus>& selSt, const std::string& mOp,
                const std::string& opEcho, const std::vector<ObjStatus>& opSt)
{
    const int uReq = 1 + static_cast<int>(byteLen(mSel));      // transport octet + request APDU
    const int uEcho = 1 + static_cast<int>(byteLen(selEcho));  // transport octet + echo APDU
    auto arr = [&](const std::vector<ObjStatus>& v) {
        std::string s = "[";
        for (size_t z = 0; z < v.size(); ++z)
            s += (z ? "," : "") + std::string("{\"index\":") + std::to_string(v[z].index) + ",\"status\":\""
                + v[z].status + "\",\"role\":\"" + (v[z].index == plan.realIndex ? "real" : "decoy") + "\"}";
        return s + "]";
    };
    auto ints = [](const std::vector<int>& v) {
        std::string s = "[";
        for (size_t z = 0; z < v.size(); ++z)
            s += (z ? "," : "") + std::to_string(v[z]);
        return s + "]";
    };
    std::string decoyArr = "[";
    for (size_t z = 0; z < plan.decoyIndices.size(); ++z)
        decoyArr += (z ? "," : "") + std::to_string(plan.decoyIndices[z]);
    decoyArr += "]";

    std::cout << "##VEC## {\"kind\":\"sbo\",\"qmode\":\"" << qmode << "\",\"K\":" << k << ",\"real_index\":"
              << plan.realIndex << ",\"decoy_indices\":" << decoyArr
              << ",\"g12_headers\":" << countG12Headers(mSel) << ",\"master_select_hex\":\"" << mSel
              << "\",\"select_echo_hex\":\"" << selEcho << "\",\"select_echo_bytes\":" << byteLen(selEcho)
              << ",\"master_operate_hex\":\"" << mOp << "\",\"operate_echo_hex\":\"" << opEcho
              << "\",\"operate_echo_bytes\":" << byteLen(opEcho) << ",\"u_req\":" << uReq
              << ",\"u_echo\":" << uEcho << ",\"wire_req\":" << linkSize(uReq) << ",\"wire_echo\":"
              << linkSize(uEcho) << ",\"crc_boundaries_echo\":" << ints(crcBoundaries(uEcho))
              << ",\"select_status\":" << arr(selSt) << ",\"operate_status\":" << arr(opSt) << "}\n";
}

} // namespace

TEST_CASE(SUITE("native CommandSet SBO round trip + u_SBO sweep"))
{
    const std::vector<uint16_t> ks = {1, 2, 3, 4, 5, 8, 12};
    for (auto qmode : {IndexQualifierMode::allow_one_byte, IndexQualifierMode::always_two_bytes})
    {
        std::cout << "\nNP-SBO[" << qmodeName(qmode) << "] native CommandSet SBO round trip (even real, odd decoys):\n";
        for (auto k : ks)
        {
            const auto plan = parityPlan(k);
            const auto ordered = plan.ordered();
            auto handler = std::make_shared<NativeParityCommandHandler>(plan.realIndex, plan.decoyIndices);
            ParityOutstation os(handler);
            os.LowerLayerUp();

            MasterTestFixture ms(masterParams(qmode));
            ms.context->OnLowerLayerUp();
            CommandCallbackQueue queue;
            ms.context->SelectAndOperate(buildParitySet(plan), queue.Callback(), TaskConfig::Default());
            ms.exe->run_many();

            // ---- STEP 1 + DERIVATION: the master's SELECT carries the whole even/odd set natively ----
            const std::string mSel = ms.lower->PopWriteAsHex();
            const auto st = toks(mSel);
            REQUIRE(st[0] == "C0"); // FIR/FIN, seq 0
            REQUIRE(st[1] == "03"); // SELECT
            REQUIRE(st[2] == "0C"); // group 12
            REQUIRE(st[3] == "01"); // var 1 (CROB)
            // ONE shared G12V1 header (native CommandSet, single Add):
            REQUIRE(countG12Headers(mSel) == 1);
            // qualifier + count + first index reflect the chosen mode; all indices <= 255 here
            if (qmode == IndexQualifierMode::allow_one_byte)
            {
                REQUIRE(st[4] == "17");                  // UINT8_CNT_UINT8_INDEX
                REQUIRE(hb(st[5]) == static_cast<int>(k)); // 1-byte count == K
                REQUIRE(hb(st[6]) == ordered[0]);          // first index == real (even) index
            }
            else
            {
                REQUIRE(st[4] == "28");                                  // UINT16_CNT_UINT16_INDEX
                REQUIRE((hb(st[5]) | (hb(st[6]) << 8)) == static_cast<int>(k)); // 2-byte count == K
                REQUIRE((hb(st[7]) | (hb(st[8]) << 8)) == ordered[0]);         // first index == real
            }
            ms.context->OnTxReady();

            // ---- STEP 2: outstation receives the native SELECT; STEP 3: record EVERY status ----
            const std::string selEcho = os.Send(mSel);
            os.OnTxReady();
            const auto selStatuses = parseSboEcho(selEcho);
            REQUIRE(selStatuses.size() == static_cast<size_t>(k)); // real + (K-1) decoys
            for (size_t z = 0; z < selStatuses.size(); ++z)
            {
                REQUIRE(selStatuses[z].index == ordered[z]); // exact even/odd set, in order
                REQUIRE(selStatuses[z].status == "00");      // all configured -> SUCCESS
            }

            // ---- exact retransmission of SELECT -> byte-identical cached echo, no re-Select ----
            const std::string selEchoRetx = os.Send(mSel);
            os.OnTxReady();
            REQUIRE(selEchoRetx == selEcho);
            REQUIRE(handler->selects(plan.realIndex) == 1);
            REQUIRE(handler->physicalActuations == 0); // SELECT never actuates

            // ---- STEP 4: master accepts, emits OPERATE that REPEATS the SELECT objects EXACTLY ----
            REQUIRE(ms.SendToMaster(selEcho));
            ms.exe->run_many();
            const std::string mOp = ms.lower->PopWriteAsHex();
            REQUIRE(toks(mOp)[0] == "C1"); // seq 1
            REQUIRE(toks(mOp)[1] == "04"); // OPERATE
            REQUIRE(objectPortion(mOp) == objectPortion(mSel)); // byte-identical object bytes
            ms.context->OnTxReady();

            // ---- STEP 5: outstation processes OPERATE; parse every status ----
            const std::string opEcho = os.Send(mOp);
            os.OnTxReady();
            const auto opStatuses = parseSboEcho(opEcho);
            REQUIRE(opStatuses.size() == static_cast<size_t>(k));
            for (const auto& s : opStatuses)
                REQUIRE(s.status == "00");

            // ---- STEP 6: real (even, wired) fires once; odd decoys inert; no unrequested index ----
            REQUIRE(handler->operates(plan.realIndex) == 1);
            REQUIRE(handler->physicalActuations == 1);
            REQUIRE(handler->inertActuations == static_cast<uint32_t>(k - 1));
            for (auto d : plan.decoyIndices)
                REQUIRE(handler->operates(d) == 1);
            REQUIRE(handler->operateLog.size() == static_cast<size_t>(k));
            uint32_t phys = 0, inert = 0;
            for (const auto& e : handler->operateLog)
            {
                const bool requested = std::find(ordered.begin(), ordered.end(), e.first) != ordered.end();
                REQUIRE(requested);
                if (e.second == "PHYSICAL")
                {
                    REQUIRE(e.first == plan.realIndex);
                    REQUIRE((e.first % 2u) == 0u); // real is even
                    ++phys;
                }
                else
                {
                    REQUIRE(e.second == "INERT");
                    REQUIRE((e.first % 2u) == 1u); // decoys are odd
                    ++inert;
                }
            }
            REQUIRE(phys == 1);
            REQUIRE(inert == static_cast<uint32_t>(k - 1));

            // ---- exact retransmission of OPERATE -> cached echo, NO second actuation ----
            const std::string opEchoRetx = os.Send(mOp);
            os.OnTxReady();
            REQUIRE(opEchoRetx == opEcho);
            REQUIRE(handler->physicalActuations == 1);
            REQUIRE(handler->inertActuations == static_cast<uint32_t>(k - 1));

            // ---- STEP 7: master COMPLETES; one SUCCESS/SUCCESS per object across the whole set ----
            REQUIRE(ms.SendToMaster(opEcho));
            ms.exe->run_many();
            REQUIRE(ms.lower->PopWriteAsHex().empty());
            REQUIRE(queue.values.size() == 1);
            const auto& v = queue.values.front();
            REQUIRE(v.summary == TaskCompletion::SUCCESS);
            REQUIRE(v.results.size() == static_cast<size_t>(k)); // real + every decoy reported
            for (const auto& r : v.results)
            {
                REQUIRE(r.state == CommandPointState::SUCCESS);
                REQUIRE(r.status == CommandStatus::SUCCESS);
            }

            emitSboVec(qmodeName(qmode), k, plan, mSel, selEcho, selStatuses, mOp, opEcho, opStatuses);

            const int uEcho = 1 + static_cast<int>(byteLen(selEcho));
            std::printf("  K=%-2u | headers=%d qual=%s | SELECT req=%zuB echo=%zuB | u_echo=%d wire_echo=%dB | phys=1 inert=%u\n",
                        static_cast<unsigned>(k), countG12Headers(mSel), st[4].c_str(), byteLen(mSel),
                        byteLen(selEcho), uEcho, linkSize(uEcho), static_cast<unsigned>(k - 1));
        }
    }
}

TEST_CASE(SUITE("qualifier width 0x17 vs 0x28"))
{
    // (a) allow_one_byte, all indices <= 255 -> 0x17; the ECHO wire size matches the relay anchors.
    {
        const auto plan = parityPlan(2); // real 0 + one odd decoy 1
        auto handler = std::make_shared<NativeParityCommandHandler>(plan.realIndex, plan.decoyIndices);
        ParityOutstation os(handler);
        os.LowerLayerUp();
        MasterTestFixture ms(masterParams(IndexQualifierMode::allow_one_byte));
        ms.context->OnLowerLayerUp();
        CommandCallbackQueue queue;
        ms.context->SelectAndOperate(buildParitySet(plan), queue.Callback(), TaskConfig::Default());
        ms.exe->run_many();
        const std::string mSel = ms.lower->PopWriteAsHex();
        REQUIRE(toks(mSel)[4] == "17");
        const std::string selEcho = os.Send(mSel);
        const int uEcho = 1 + static_cast<int>(byteLen(selEcho));
        // 2-CROB echo -> relay anchor 49 B; confirms u_SBO(2) = 9 + 12*2 = 33 -> link_size = 49.
        REQUIRE(uEcho == 33);
        REQUIRE(linkSize(uEcho) == 49);
        std::cout << "NP-SBO[qual] allow_one_byte 2-CROB: echo=" << byteLen(selEcho) << "B APDU, u_echo=" << uEcho
                  << ", wire=" << linkSize(uEcho) << "B (relay anchor 49 B) -> u_SBO(K)=9+12K CONFIRMED\n";
    }

    // (b) always_two_bytes, same small indices -> 0x28 (2-byte overhead); does NOT hit 49 B.
    {
        const auto plan = parityPlan(2);
        auto handler = std::make_shared<NativeParityCommandHandler>(plan.realIndex, plan.decoyIndices);
        ParityOutstation os(handler);
        os.LowerLayerUp();
        MasterTestFixture ms(masterParams(IndexQualifierMode::always_two_bytes));
        ms.context->OnLowerLayerUp();
        CommandCallbackQueue queue;
        ms.context->SelectAndOperate(buildParitySet(plan), queue.Callback(), TaskConfig::Default());
        ms.exe->run_many();
        const std::string mSel = ms.lower->PopWriteAsHex();
        REQUIRE(toks(mSel)[4] == "28");
        const std::string selEcho = os.Send(mSel);
        const int uEcho = 1 + static_cast<int>(byteLen(selEcho));
        REQUIRE(uEcho != 33); // 0x28 overhead moves off the 0x17 relay anchor
        std::cout << "NP-SBO[qual] always_two_bytes 2-CROB: echo=" << byteLen(selEcho) << "B APDU, u_echo=" << uEcho
                  << ", wire=" << linkSize(uEcho) << "B (DOES NOT match the 49 B relay anchor) -> residual distinguisher\n";
    }

    // (c) a decoy index > 255 forces 2-byte indices even under allow_one_byte. Index 257 is odd.
    {
        NativeParityPlan plan;
        plan.realIndex = 0;              // even
        plan.decoyIndices = {1, 257};    // 257 > 255 (odd)
        auto handler = std::make_shared<NativeParityCommandHandler>(plan.realIndex, plan.decoyIndices);
        ParityOutstation os(handler);
        os.LowerLayerUp();
        MasterTestFixture ms(masterParams(IndexQualifierMode::allow_one_byte));
        ms.context->OnLowerLayerUp();
        CommandCallbackQueue queue;
        ms.context->SelectAndOperate(buildParitySet(plan), queue.Callback(), TaskConfig::Default());
        ms.exe->run_many();
        const std::string mSel = ms.lower->PopWriteAsHex();
        REQUIRE(toks(mSel)[4] == "28"); // forced to 2-byte despite allow_one_byte
        std::cout << "NP-SBO[qual] allow_one_byte but decoy index 257>255 -> qualifier forced to 0x28 "
                     "(1-byte optimization unavailable) -> size model must track the max index\n";
    }
}

TEST_CASE(SUITE("decoy failure fails parity op"))
{
    // K=3: real 0 (even) + decoys 1,3 (odd). Decoy 3 is a configured point whose device logic
    // reports HARDWARE_ERROR at SELECT. opendnp3 caches the SBO selection ONLY if EVERY selected
    // object is SUCCESS, so one failing decoy un-caches the SELECT and the whole parity operation
    // fails: no OPERATE is emitted and the real (even) control is NOT executed.
    const auto plan = parityPlan(3);
    auto handler = std::make_shared<NativeParityCommandHandler>(plan.realIndex, plan.decoyIndices);
    handler->ForceStatus(3, CommandStatus::HARDWARE_ERROR);
    ParityOutstation os(handler);
    os.LowerLayerUp();

    MasterTestFixture ms(masterParams(IndexQualifierMode::allow_one_byte));
    ms.context->OnLowerLayerUp();
    CommandCallbackQueue queue;
    ms.context->SelectAndOperate(buildParitySet(plan), queue.Callback(), TaskConfig::Default());
    ms.exe->run_many();

    const std::string mSel = ms.lower->PopWriteAsHex();
    ms.context->OnTxReady();
    const std::string selEcho = os.Send(mSel);
    os.OnTxReady();
    for (const auto& s : parseSboEcho(selEcho))
    {
        if (s.index == 3)
            REQUIRE(s.status == "06"); // HARDWARE_ERROR
        else
            REQUIRE(s.status == "00");
    }

    // master sees a non-SUCCESS decoy in the SELECT echo -> does NOT emit OPERATE
    REQUIRE(ms.SendToMaster(selEcho));
    ms.exe->run_many();
    REQUIRE(ms.lower->PopWriteAsHex().empty()); // NO OPERATE on the wire

    REQUIRE(handler->physicalActuations == 0); // real command NOT executed -> parity op FAILED, fail-safe
    REQUIRE(handler->inertActuations == 0);

    // the master reports the operation as not-successful (real point never reaches SUCCESS)
    REQUIRE(queue.values.size() == 1);
    const auto& v = queue.values.front();
    bool realSuccess = false;
    for (const auto& r : v.results)
        if (r.index == plan.realIndex && r.state == CommandPointState::SUCCESS)
            realSuccess = true;
    REQUIRE_FALSE(realSuccess);
    std::cout << "NP-SBO[decoy-failure] decoy idx3 HARDWARE_ERROR at SELECT -> no OPERATE emitted; "
                 "physicalActuations=0 -> parity operation FAILED (fail-safe), real command safely lost\n";
}

TEST_CASE(SUITE("real failure fails parity op"))
{
    // Same fail-safe, but the failing point is the REAL (even) control itself.
    const auto plan = parityPlan(3);
    auto handler = std::make_shared<NativeParityCommandHandler>(plan.realIndex, plan.decoyIndices);
    handler->ForceStatus(plan.realIndex, CommandStatus::HARDWARE_ERROR);
    ParityOutstation os(handler);
    os.LowerLayerUp();

    MasterTestFixture ms(masterParams(IndexQualifierMode::allow_one_byte));
    ms.context->OnLowerLayerUp();
    CommandCallbackQueue queue;
    ms.context->SelectAndOperate(buildParitySet(plan), queue.Callback(), TaskConfig::Default());
    ms.exe->run_many();

    const std::string mSel = ms.lower->PopWriteAsHex();
    ms.context->OnTxReady();
    const std::string selEcho = os.Send(mSel);
    os.OnTxReady();
    for (const auto& s : parseSboEcho(selEcho))
    {
        if (s.index == plan.realIndex)
            REQUIRE(s.status == "06");
        else
            REQUIRE(s.status == "00");
    }

    REQUIRE(ms.SendToMaster(selEcho));
    ms.exe->run_many();
    REQUIRE(ms.lower->PopWriteAsHex().empty()); // no OPERATE
    REQUIRE(handler->physicalActuations == 0);
    REQUIRE(handler->inertActuations == 0);
    std::cout << "NP-SBO[real-failure] real idx0 HARDWARE_ERROR at SELECT -> no OPERATE; nothing actuates -> fail-safe\n";
}

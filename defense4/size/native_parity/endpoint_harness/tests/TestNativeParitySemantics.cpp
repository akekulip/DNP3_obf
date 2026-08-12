// SPDX-License-Identifier: Apache-2.0
//
// NATIVE-PARITY endpoint semantics — the REJECTION and SBO-enforcement cases.
//
// A REAL opendnp3 outstation with a NativeParityCommandHandler (even = real/wired,
// odd = decoy/inert) is driven with crafted SELECT/OPERATE APDUs. Software only: no
// networking, no hardware, no relay. The decisive observable is the outstation's echoed
// per-object status and its actuation counters: any command that is not an EXACT repeat
// of a live SELECT must be rejected (NO_SELECT) and must actuate NOTHING.
//
// This is grounded in ControlState::ValidateSelection: an OPERATE is honoured ONLY if its
// application sequence == SELECT.seq+1 AND its object bytes are byte-identical to the cached
// SELECT (same length AND same CRC-16/DNP digest). So added / reordered / value-mutated /
// timing-mutated / missing objects all fail, as does an OPERATE with no prior SELECT.
//
// Cases (dir.md "Endpoint semantics"):
//   * unconfigured point            -> NOT_SUPPORTED at SELECT, SELECT not cached, OPERATE NO_SELECT
//   * missing decoy                 -> OPERATE shorter than SELECT -> NO_SELECT
//   * added object                  -> OPERATE longer than SELECT  -> NO_SELECT
//   * reordered object              -> same objects, different order -> NO_SELECT
//   * value mismatch                -> a CROB on-time byte differs -> NO_SELECT
//   * timing/control-code mismatch  -> a CROB control code byte differs -> NO_SELECT
//   * duplicate request             -> identical SELECT replay -> cached echo, no re-Select
//   * exact retransmission          -> identical OPERATE replay -> cached echo, no 2nd actuation
//   * direct OPERATE where SBO req. -> OPERATE with no prior SELECT -> NO_SELECT, nothing actuates

#include <opendnp3/logging/LogLevels.h>

#include <exe4cpp/MockExecutor.h>

#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockLowerLayer.h"
#include "dnp3mocks/MockOutstationApplication.h"

#include "utils/BufferHelpers.h"
#include "utils/NativeParityCommandHandler.h"
#include "utils/NativeParityHelpers.h"
#include "utils/NativeParityPlan.h"

#include <outstation/OutstationContext.h>

#include <opendnp3/gen/CommandStatus.h>

#include <catch.hpp>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace opendnp3;
using namespace np;

#define SUITE(name) "NativeParitySemanticsTestSuite - " name

namespace
{

struct ParityOutstation
{
    explicit ParityOutstation(const std::shared_ptr<NativeParityCommandHandler>& handler)
        : exe(std::make_shared<exe4cpp::MockExecutor>()),
          lower(std::make_shared<MockLowerLayer>()),
          cmd(handler),
          app(std::make_shared<MockOutstationApplication>()),
          context(Addresses(), OutstationConfig(), DatabaseConfig(), log.logger, exe, lower, cmd, app)
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

// canonical 11-byte CROB body: PULSE_ON, count 1, on/off time 100 (0x64), status 0
const std::string kBody = "01 01 64 00 00 00 64 00 00 00 00";

// Build a native single-header SBO request (qualifier 0x17: 1-byte count + 1-byte index prefix).
std::string buildSbo(const std::string& ctl, const std::string& fc, const std::vector<uint16_t>& idx,
                     const std::string& body = kBody)
{
    std::string s = ctl + " " + fc + " 0C 01 17 " + u8(static_cast<unsigned>(idx.size()));
    for (auto i : idx)
        s += " " + u8(i) + " " + body;
    return s;
}

void requireAllNoSelect(const std::vector<ObjStatus>& v)
{
    REQUIRE_FALSE(v.empty());
    for (const auto& s : v)
        REQUIRE(s.status == "02"); // NO_SELECT
}

} // namespace

TEST_CASE(SUITE("unconfigured point rejected"))
{
    // real 0 (even) + decoys 1,3 (odd) configured; index 99 is NOT configured.
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3});
    ParityOutstation os(handler);
    os.LowerLayerUp();
    REQUIRE(handler->isConfigured(99) == false);

    const std::vector<uint16_t> withUnknown = {0, 1, 3, 99};
    const std::string selEcho = os.Send(buildSbo("C0", "03", withUnknown));
    os.OnTxReady();
    for (const auto& s : parseSboEcho(selEcho))
        REQUIRE(s.status == (s.index == 99 ? "04" : "00")); // 99 -> NOT_SUPPORTED, others SUCCESS
    REQUIRE(handler->unconfiguredSelectRejects == 1);

    const std::string opEcho = os.Send(buildSbo("C1", "04", withUnknown));
    os.OnTxReady();
    requireAllNoSelect(parseSboEcho(opEcho)); // SELECT not cached (a non-SUCCESS) -> OPERATE NO_SELECT
    REQUIRE(handler->physicalActuations == 0);
    REQUIRE(handler->inertActuations == 0);
    std::cout << "NP-SEM[unconfigured] idx99 NOT_SUPPORTED -> SELECT not cached -> OPERATE NO_SELECT; nothing actuates\n";
}

TEST_CASE(SUITE("missing decoy rejected"))
{
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3});
    ParityOutstation os(handler);
    os.LowerLayerUp();

    const std::string selEcho = os.Send(buildSbo("C0", "03", {0, 1, 3}));
    os.OnTxReady();
    for (const auto& s : parseSboEcho(selEcho))
        REQUIRE(s.status == "00"); // cached

    const std::string opEcho = os.Send(buildSbo("C1", "04", {0, 1})); // decoy 3 missing
    os.OnTxReady();
    requireAllNoSelect(parseSboEcho(opEcho));
    REQUIRE(handler->physicalActuations == 0);
    std::cout << "NP-SEM[missing-decoy] OPERATE {0,1} vs SELECT {0,1,3} -> NO_SELECT; nothing actuates\n";
}

TEST_CASE(SUITE("added object rejected"))
{
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3, 5});
    ParityOutstation os(handler);
    os.LowerLayerUp();

    const std::string selEcho = os.Send(buildSbo("C0", "03", {0, 1, 3}));
    os.OnTxReady();
    for (const auto& s : parseSboEcho(selEcho))
        REQUIRE(s.status == "00");

    const std::string opEcho = os.Send(buildSbo("C1", "04", {0, 1, 3, 5})); // decoy 5 added
    os.OnTxReady();
    requireAllNoSelect(parseSboEcho(opEcho));
    REQUIRE(handler->physicalActuations == 0);
    std::cout << "NP-SEM[added-object] OPERATE {0,1,3,5} vs SELECT {0,1,3} -> NO_SELECT; nothing actuates\n";
}

TEST_CASE(SUITE("reordered object rejected"))
{
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3});
    ParityOutstation os(handler);
    os.LowerLayerUp();

    const std::string selEcho = os.Send(buildSbo("C0", "03", {0, 1, 3}));
    os.OnTxReady();
    for (const auto& s : parseSboEcho(selEcho))
        REQUIRE(s.status == "00");

    const std::string opEcho = os.Send(buildSbo("C1", "04", {0, 3, 1})); // 3 and 1 swapped
    os.OnTxReady();
    requireAllNoSelect(parseSboEcho(opEcho));
    REQUIRE(handler->physicalActuations == 0);
    std::cout << "NP-SEM[reordered] OPERATE {0,3,1} vs SELECT {0,1,3} -> NO_SELECT; nothing actuates\n";
}

TEST_CASE(SUITE("value mismatch rejected"))
{
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3});
    ParityOutstation os(handler);
    os.LowerLayerUp();

    const std::string selEcho = os.Send(buildSbo("C0", "03", {0, 1, 3}));
    os.OnTxReady();
    for (const auto& s : parseSboEcho(selEcho))
        REQUIRE(s.status == "00");

    // OPERATE with a different on-time (0x65 instead of 0x64) on every CROB body
    const std::string mutatedBody = "01 01 65 00 00 00 64 00 00 00 00";
    const std::string opEcho = os.Send(buildSbo("C1", "04", {0, 1, 3}, mutatedBody));
    os.OnTxReady();
    requireAllNoSelect(parseSboEcho(opEcho));
    REQUIRE(handler->physicalActuations == 0);
    std::cout << "NP-SEM[value-mismatch] OPERATE on-time 0x65 vs SELECT 0x64 -> NO_SELECT; nothing actuates\n";
}

TEST_CASE(SUITE("control-code mismatch rejected"))
{
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3});
    ParityOutstation os(handler);
    os.LowerLayerUp();

    const std::string selEcho = os.Send(buildSbo("C0", "03", {0, 1, 3}));
    os.OnTxReady();
    for (const auto& s : parseSboEcho(selEcho))
        REQUIRE(s.status == "00");

    // OPERATE with a different control code (0x03 LATCH-ish instead of 0x01 PULSE_ON)
    const std::string mutatedBody = "03 01 64 00 00 00 64 00 00 00 00";
    const std::string opEcho = os.Send(buildSbo("C1", "04", {0, 1, 3}, mutatedBody));
    os.OnTxReady();
    requireAllNoSelect(parseSboEcho(opEcho));
    REQUIRE(handler->physicalActuations == 0);
    std::cout << "NP-SEM[control-code-mismatch] OPERATE code 0x03 vs SELECT 0x01 -> NO_SELECT; nothing actuates\n";
}

TEST_CASE(SUITE("duplicate SELECT cached"))
{
    // NOTE: this is an application-layer identical-APDU replay, NOT a TCP retransmission.
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3});
    ParityOutstation os(handler);
    os.LowerLayerUp();

    const std::string sel = buildSbo("C0", "03", {0, 1, 3});
    const std::string echo1 = os.Send(sel);
    os.OnTxReady();
    const std::string echo2 = os.Send(sel); // identical replay
    os.OnTxReady();
    REQUIRE(echo2 == echo1);                 // byte-identical cached echo
    REQUIRE(handler->selects(0) == 1);       // Select ran once (duplicate returned the cache)
    REQUIRE(handler->physicalActuations == 0);
    std::cout << "NP-SEM[duplicate-SELECT] identical SELECT replay -> cached echo, selects=1, no actuation\n";
}

TEST_CASE(SUITE("exact retransmission of OPERATE"))
{
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3});
    ParityOutstation os(handler);
    os.LowerLayerUp();

    os.Send(buildSbo("C0", "03", {0, 1, 3})); // SELECT (cached)
    os.OnTxReady();
    const std::string op = buildSbo("C1", "04", {0, 1, 3});
    const std::string opEcho1 = os.Send(op);
    os.OnTxReady();
    for (const auto& s : parseSboEcho(opEcho1))
        REQUIRE(s.status == "00"); // SUCCESS -> the real control fired
    REQUIRE(handler->physicalActuations == 1);
    REQUIRE(handler->inertActuations == 2);

    const std::string opEcho2 = os.Send(op); // identical OPERATE replay
    os.OnTxReady();
    REQUIRE(opEcho2 == opEcho1);               // cached echo
    REQUIRE(handler->physicalActuations == 1); // still exactly once
    REQUIRE(handler->inertActuations == 2);
    std::cout << "NP-SEM[retransmit-OPERATE] identical OPERATE replay -> cached echo; physical actuates exactly once\n";
}

TEST_CASE(SUITE("direct OPERATE rejected"))
{
    // A bare Operate (fc 0x04) with no live SELECT must be rejected. (A DirectOperate, fc 0x05,
    // is a DIFFERENT function that would actuate without a select; the safety requirement is that
    // the wired point is SBO-only so only the select-gated Operate path can reach it. That the
    // point be configured SBO-only is a relay-configuration prerequisite, documented in README.)
    auto handler = std::make_shared<NativeParityCommandHandler>(0, std::vector<uint16_t>{1, 3});
    ParityOutstation os(handler);
    os.LowerLayerUp();

    const std::string opEcho = os.Send(buildSbo("C0", "04", {0, 1, 3})); // OPERATE, NO prior SELECT
    os.OnTxReady();
    requireAllNoSelect(parseSboEcho(opEcho));
    REQUIRE(handler->physicalActuations == 0);
    REQUIRE(handler->inertActuations == 0);
    std::cout << "NP-SEM[direct-operate] Operate(0x04) with no prior SELECT -> NO_SELECT; nothing actuates\n";
}

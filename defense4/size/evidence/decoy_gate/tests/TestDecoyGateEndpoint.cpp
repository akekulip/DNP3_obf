// SPDX-License-Identifier: Apache-2.0
//
// PART A (endpoint side) — configured inert-decoy SBO gate on the OUTSTATION.
//
// Drives crafted SELECT / OPERATE APDU bytes directly into a real opendnp3
// OContext (no networking) whose command handler is a DecoyGateCommandHandler
// modelling endpoint preconfiguration: one wired legit CROB + several configured
// inert decoy CROBs, and everything else unconfigured. We assert, at the endpoint:
//
//   1. the legit CROB actuates EXACTLY once (SELECT then OPERATE);
//   2. a decoy CROB reaches ONLY its own isolated software callback and causes
//      NO physical actuation (inert);
//   3. no unrequested point executes (operating index X never touches Y);
//   4. a repeated / retransmitted SELECT or OPERATE is safe (no double actuation);
//   5. an UNCONFIGURED decoy index fails safe (NOT_SUPPORTED, no callback);
//   6. per-object echo status is recorded (SUCCESS 0x00 vs NOT_SUPPORTED 0x04).
//
// This is the counterpart of the master-acceptance test: here we prove the
// endpoint semantics; there we prove an unmodified master accepts the padded echo.

#include <opendnp3/logging/LogLevels.h>

#include <exe4cpp/MockExecutor.h>

#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockLowerLayer.h"
#include "dnp3mocks/MockOutstationApplication.h"

#include "utils/BufferHelpers.h"
#include "utils/DecoyGateCommandHandler.h"

#include <link/LinkLayerConstants.h>
#include <outstation/Database.h>
#include <outstation/OutstationContext.h>

#include <catch.hpp>

#include <cstdio>
#include <iostream>
#include <memory>
#include <string>

using namespace opendnp3;

#define SUITE(name) "DecoyGateEndpointTestSuite - " name

namespace
{

// Minimal outstation harness that mirrors OutstationTestObject but lets us inject
// a custom ICommandHandler (the stock helper hardcodes MockCommandHandler).
struct DecoyOutstation
{
    DecoyOutstation(const std::shared_ptr<DecoyGateCommandHandler>& handler,
                    const OutstationConfig& config = OutstationConfig(),
                    const DatabaseConfig& db = DatabaseConfig())
        : exe(std::make_shared<exe4cpp::MockExecutor>()),
          lower(std::make_shared<MockLowerLayer>()),
          cmd(handler),
          app(std::make_shared<MockOutstationApplication>()),
          context(Addresses(), config, db, log.logger, exe, lower, cmd, app)
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

    void Send(const std::string& hex)
    {
        HexSequence hs(hex);
        context.OnReceive(Message(Addresses(), hs.ToRSeq()));
        exe->run_many();
    }

    std::string PopTx()
    {
        return lower->PopWriteAsHex();
    }

    MockLogHandler log;
    std::shared_ptr<exe4cpp::MockExecutor> exe;
    std::shared_ptr<MockLowerLayer> lower;
    std::shared_ptr<DecoyGateCommandHandler> cmd;
    std::shared_ptr<MockOutstationApplication> app;
    OContext context;
};

// 11-byte CROB body: code=0x01, count=1, on=1, off=1, status=0x00 (SUCCESS request)
const std::string kCrobBody = "01 01 01 00 00 00 01 00 00 00 00";

std::string idxHex(uint16_t i)
{
    char b[4];
    std::snprintf(b, sizeof(b), "%02X", static_cast<int>(i & 0xFF));
    return std::string(b);
}

// g12v1, qual 0x17 (1-byte count + 1-byte index), single point at index i
std::string selectHex(uint16_t i)
{
    return "C0 03 0C 01 17 01 " + idxHex(i) + " " + kCrobBody;
}
std::string operateHex(uint16_t i)
{
    return "C1 04 0C 01 17 01 " + idxHex(i) + " " + kCrobBody;
}
std::string operateHexSeq(uint16_t i, const std::string& appctl, const std::string& fc)
{
    return appctl + " " + fc + " 0C 01 17 01 " + idxHex(i) + " " + kCrobBody;
}
std::string echoHex(const std::string& appctl, const std::string& iin, uint16_t i, const std::string& status)
{
    return appctl + " 81 " + iin + " 0C 01 17 01 " + idxHex(i) + " 01 01 01 00 00 00 01 00 00 00 " + status;
}

} // namespace

TEST_CASE(SUITE("legit CROB actuates exactly once; decoys and others untouched"))
{
    auto h = std::make_shared<DecoyGateCommandHandler>(/*legit*/ 1, /*decoys*/ std::vector<uint16_t>{2, 3, 4});
    DecoyOutstation t(h);
    t.LowerLayerUp();

    // SELECT the legit index 1 -> SUCCESS echo, no actuation yet
    t.Send(selectHex(1));
    const auto selEcho = t.PopTx();
    REQUIRE(selEcho == echoHex("C0", "80 00", 1, "00"));
    REQUIRE(h->physicalActuations == 0);
    t.OnTxReady();

    // OPERATE the legit index 1 -> SUCCESS echo, actuates exactly once
    t.Send(operateHex(1));
    const auto opEcho = t.PopTx();
    REQUIRE(opEcho == echoHex("C1", "80 00", 1, "00"));
    t.OnTxReady();

    REQUIRE(h->operates(1) == 1);
    REQUIRE(h->physicalActuations == 1);
    REQUIRE(h->inertActuations == 0);
    // no decoy or other point moved
    REQUIRE(h->operates(2) == 0);
    REQUIRE(h->operates(3) == 0);
    REQUIRE(h->operates(4) == 0);
    REQUIRE(h->operateLog.size() == 1);
    REQUIRE(h->operateLog[0].first == 1);
    REQUIRE(h->operateLog[0].second == "PHYSICAL");

    std::cout << "DECOY-EP[legit-once]  SELECT.echo=" << selEcho << "\n";
    std::cout << "DECOY-EP[legit-once]  OPERATE.echo=" << opEcho << "\n";
    std::cout << "DECOY-EP[legit-once]  physicalActuations=" << h->physicalActuations
              << " inertActuations=" << h->inertActuations << " -> PASS\n";
}

TEST_CASE(SUITE("decoy CROB is inert: SUCCESS echo, isolated callback, no physical actuation"))
{
    auto h = std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{2, 3, 4});
    DecoyOutstation t(h);
    t.LowerLayerUp();

    // SELECT + OPERATE decoy index 2
    t.Send(selectHex(2));
    REQUIRE(t.PopTx() == echoHex("C0", "80 00", 2, "00")); // decoy SELECT still SUCCESS (configured)
    t.OnTxReady();
    t.Send(operateHex(2));
    REQUIRE(t.PopTx() == echoHex("C1", "80 00", 2, "00")); // decoy OPERATE SUCCESS but inert
    t.OnTxReady();

    REQUIRE(h->operates(2) == 1);
    REQUIRE(h->inertActuations == 1);
    REQUIRE(h->physicalActuations == 0); // the wired point never moved
    REQUIRE(h->operates(1) == 0);
    REQUIRE(h->operates(3) == 0);
    REQUIRE(h->operateLog.size() == 1);
    REQUIRE(h->operateLog[0].first == 2);
    REQUIRE(h->operateLog[0].second == "INERT");

    std::cout << "DECOY-EP[decoy-inert] operate idx2 -> INERT; physicalActuations="
              << h->physicalActuations << " (0 expected) -> PASS\n";
}

TEST_CASE(SUITE("repeated SELECT and repeated OPERATE are safe (actuate exactly once)"))
{
    auto h = std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{2, 3, 4});
    DecoyOutstation t(h);
    t.LowerLayerUp();

    // duplicate SELECT (same sequence) then OPERATE
    t.Send(selectHex(1));
    REQUIRE(t.PopTx() == echoHex("C0", "80 00", 1, "00"));
    t.OnTxReady();
    t.Send(selectHex(1)); // retransmitted SELECT
    REQUIRE(t.PopTx() == echoHex("C0", "80 00", 1, "00"));
    t.OnTxReady();

    // SELECT alone (even repeated) must never actuate
    REQUIRE(h->operates(1) == 0);
    REQUIRE(h->physicalActuations == 0);

    t.Send(operateHex(1));
    REQUIRE(t.PopTx() == echoHex("C1", "80 00", 1, "00"));
    t.OnTxReady();

    // retransmitted OPERATE (same sequence) -> cached response, no second actuation
    t.Send(operateHex(1));
    REQUIRE(t.PopTx() == echoHex("C1", "80 00", 1, "00"));
    t.OnTxReady();

    REQUIRE(h->operates(1) == 1);        // exactly once
    REQUIRE(h->physicalActuations == 1); // exactly once
    REQUIRE(h->inertActuations == 0);

    std::cout << "DECOY-EP[retx-safe]   selects(1)=" << h->selects(1)
              << " operates(1)=" << h->operates(1) << " physicalActuations="
              << h->physicalActuations << " (exactly 1) -> PASS\n";
}

TEST_CASE(SUITE("unconfigured decoy index fails safe (NOT_SUPPORTED, no callback, no actuation)"))
{
    auto h = std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{2, 3, 4});
    DecoyOutstation t(h);
    t.LowerLayerUp();

    REQUIRE(h->isConfigured(99) == false);

    // SELECT an index that was NEVER configured -> NOT_SUPPORTED (status 0x04, IIN2.2 set)
    t.Send(selectHex(99));
    const auto selEcho = t.PopTx();
    REQUIRE(selEcho == echoHex("C0", "80 04", 99, "04"));
    t.OnTxReady();

    // OPERATE it anyway -> still fails safe, still no actuation
    t.Send(operateHex(99));
    const auto opEcho = t.PopTx();
    t.OnTxReady();

    REQUIRE(h->unconfiguredSelectRejects == 1);
    REQUIRE(h->physicalActuations == 0);
    REQUIRE(h->inertActuations == 0);
    REQUIRE(h->operateLog.empty());

    std::cout << "DECOY-EP[unconfigured] SELECT.echo=" << selEcho << "\n";
    std::cout << "DECOY-EP[unconfigured] OPERATE.echo=" << opEcho << "\n";
    std::cout << "DECOY-EP[unconfigured] selectRejects=" << h->unconfiguredSelectRejects
              << " operateRejects=" << h->unconfiguredOperateRejects
              << " actuations=" << (h->physicalActuations + h->inertActuations) << " -> PASS\n";
}

TEST_CASE(SUITE("no unrequested point executes across an interleaved decoy+legit sequence"))
{
    auto h = std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{2, 3, 4});
    DecoyOutstation t(h);
    t.LowerLayerUp();

    struct Step
    {
        uint16_t index;
        bool operate;
    };
    // operate legit 1, decoy 3, decoy 2, decoy 4 (each SELECT then OPERATE)
    const uint16_t order[] = {1, 3, 2, 4};
    std::string appSeqSel = "C0", appSeqOp = "C1";
    uint8_t seq = 0;
    for (auto idx : order)
    {
        char s[4], o[4];
        std::snprintf(s, sizeof(s), "C%X", seq & 0x0F);
        std::snprintf(o, sizeof(o), "C%X", (seq + 1) & 0x0F);
        t.Send(operateHexSeq(idx, s, "03")); // SELECT
        t.PopTx();
        t.OnTxReady();
        t.Send(operateHexSeq(idx, o, "04")); // OPERATE
        t.PopTx();
        t.OnTxReady();
        seq = static_cast<uint8_t>((seq + 2) & 0x0F);
    }

    // each configured index operated exactly once; total physical == 1 (only legit wired)
    REQUIRE(h->operates(1) == 1);
    REQUIRE(h->operates(2) == 1);
    REQUIRE(h->operates(3) == 1);
    REQUIRE(h->operates(4) == 1);
    REQUIRE(h->physicalActuations == 1); // only the one wired point
    REQUIRE(h->inertActuations == 3);    // the three decoys, all inert
    REQUIRE(h->operateLog.size() == 4);

    // print the per-object actuation table
    std::cout << "DECOY-EP[interleaved] operate log:";
    for (auto& e : h->operateLog)
        std::cout << " (idx=" << e.first << "," << e.second << ")";
    std::cout << " -> physical=1 inert=3 PASS\n";
}

// SPDX-License-Identifier: Apache-2.0
//
// PART A (master side) — an UNMODIFIED opendnp3 master accepts a SELECT/OPERATE
// echo padded with configured inert decoy CROBs it never selected.
//
// MasterTestFixture drives crafted APDU response bytes straight into MasterCore
// (no networking), isolating the one variable: the decoy encoding.
//
//   ENCODING A — decoys in a SEPARATE trailing G12V1 header  -> ACCEPTED
//                (master ignores the extra header, still emits OPERATE for the
//                 real index only, real point -> SUCCESS). Swept over K decoys.
//   ENCODING B — decoys MERGED into the real header (count grown 1 -> 1+K)
//                -> REJECTED (no OPERATE emitted; real point never SUCCESS).
//
// The decisive observable is whether the master emits the OPERATE and the
// per-object CommandPointResult it records. We also record the padded echo byte
// length so response size vs decoy count is on the record.

#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"

#include <ser4cpp/util/HexConversions.h>

#include <opendnp3/gen/CommandPointState.h>
#include <opendnp3/gen/CommandStatus.h>

#include <catch.hpp>

#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace opendnp3;

#define SUITE(name) "DecoyGateMasterTestSuite - " name

namespace
{

// g12v1, qual 0x28 (2-byte count + 2-byte index prefix), single real point index 1.
const std::string kRealCrob = "0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00";

// one echoed decoy point for the trailing header: 2-byte index + 11-byte CROB (SUCCESS)
std::string decoyPoint(uint16_t index)
{
    char b[8];
    std::snprintf(b, sizeof(b), "%02X %02X", index & 0xFF, (index >> 8) & 0xFF);
    return std::string(b) + " 01 01 64 00 00 00 64 00 00 00 00";
}

// ENCODING A: a SEPARATE trailing G12V1 header carrying K decoys at indices 2..K+1
std::string trailingDecoyHeader(uint16_t k)
{
    char cnt[8];
    std::snprintf(cnt, sizeof(cnt), "%02X %02X", k & 0xFF, (k >> 8) & 0xFF);
    std::string h = "0C 01 28 " + std::string(cnt);
    for (uint16_t j = 0; j < k; ++j)
        h += " " + decoyPoint(static_cast<uint16_t>(2 + j));
    return h;
}

// count hex tokens => byte length of a DNP3 fragment written as "AA BB CC ..."
size_t byteLen(const std::string& hex)
{
    std::istringstream ss(hex);
    std::string tok;
    size_t n = 0;
    while (ss >> tok)
        ++n;
    return n;
}

void printPointResults(const char* tag, const MockCommandResultType& v)
{
    for (auto& r : v.results)
    {
        std::cout << tag << " per-object: headerIndex=" << r.headerIndex << " index=" << r.index
                  << " state=" << CommandPointStateSpec::to_human_string(r.state)
                  << " status=" << CommandStatusSpec::to_human_string(r.status) << "\n";
    }
}

} // namespace

TEST_CASE(SUITE("ENCODING A (separate trailing decoy header) is ACCEPTED across a decoy-count sweep"))
{
    const std::vector<uint16_t> ks = {1, 2, 3, 5, 8};
    std::cout << "DECOY-MASTER[A] size-vs-decoys (SELECT echo bytes):\n";

    for (auto k : ks)
    {
        MasterTestFixture t(NoStartupTasks());
        t.context->OnLowerLayerUp();

        ControlRelayOutputBlock command(OperationType::PULSE_ON);
        CommandCallbackQueue queue;
        t.context->SelectAndOperate(CommandSet({WithIndex(command, 1)}), queue.Callback(), TaskConfig::Default());
        t.exe->run_many();

        const std::string decoys = trailingDecoyHeader(k);
        const std::string selectEcho = "C0 81 00 00 " + kRealCrob + " " + decoys;
        const std::string operateEcho = "C1 81 00 00 " + kRealCrob + " " + decoys;

        // master's SELECT on the wire carries ONLY the real index 1
        REQUIRE(t.lower->PopWriteAsHex() == "C0 03 " + kRealCrob);
        t.context->OnTxReady();
        t.SendToMaster(selectEcho); // decoy-padded SELECT echo
        t.exe->run_many();

        // DECISIVE: master accepted the padded SELECT and emitted OPERATE (real only)
        REQUIRE(t.lower->PopWriteAsHex() == "C1 04 " + kRealCrob);
        t.context->OnTxReady();
        t.SendToMaster(operateEcho); // decoy-padded OPERATE echo
        t.exe->run_many();

        REQUIRE(t.lower->PopWriteAsHex().empty());

        // exactly one per-object result: the real index 1, SUCCESS/SUCCESS
        REQUIRE(queue.values.size() == 1);
        printPointResults("DECOY-MASTER[A]", queue.values.front());
        REQUIRE(queue.PopOnlyEqualValue(
            TaskCompletion::SUCCESS, CommandPointResult(0, 1, CommandPointState::SUCCESS, CommandStatus::SUCCESS)));

        std::cout << "  K=" << k << " decoys -> SELECT echo=" << byteLen(selectEcho)
                  << " B, master ACCEPTED, OPERATE carried only real index 1\n";
    }
}

TEST_CASE(SUITE("ENCODING B (decoys merged into the real header, count grown) is REJECTED"))
{
    const std::vector<uint16_t> ks = {2, 3};
    for (auto k : ks)
    {
        MasterTestFixture t(NoStartupTasks());
        t.context->OnLowerLayerUp();

        ControlRelayOutputBlock command(OperationType::PULSE_ON);
        CommandCallbackQueue queue;
        t.context->SelectAndOperate(CommandSet({WithIndex(command, 1)}), queue.Callback(), TaskConfig::Default());
        t.exe->run_many();

        // ONE grown G12V1 header: count = 1+k, real index 1 then decoys 2..k+1, all in the same header
        char cnt[8];
        std::snprintf(cnt, sizeof(cnt), "%02X %02X", (1 + k) & 0xFF, ((1 + k) >> 8) & 0xFF);
        std::string merged = "0C 01 28 " + std::string(cnt) + " " + decoyPoint(1);
        for (uint16_t j = 0; j < k; ++j)
            merged += " " + decoyPoint(static_cast<uint16_t>(2 + j));

        REQUIRE(t.lower->PopWriteAsHex() == "C0 03 " + kRealCrob); // SELECT carries only real index 1
        t.context->OnTxReady();
        t.SendToMaster("C0 81 00 00 " + merged); // padded SELECT echo (count grown)
        t.exe->run_many();

        // DECISIVE: master did NOT emit OPERATE -> the SELECT echo was rejected
        REQUIRE(t.lower->PopWriteAsHex().empty());

        REQUIRE(queue.values.size() == 1);
        const auto& v = queue.values.front();
        printPointResults("DECOY-MASTER[B]", v);
        REQUIRE(v.results.size() == 1);
        REQUIRE(v.results.front().state != CommandPointState::SUCCESS); // real point NOT executed

        std::cout << "DECOY-MASTER[B] K=" << k << " merged -> no OPERATE; real index 1 state="
                  << CommandPointStateSpec::to_human_string(v.results.front().state) << " -> REJECT (as expected)\n";
    }
}

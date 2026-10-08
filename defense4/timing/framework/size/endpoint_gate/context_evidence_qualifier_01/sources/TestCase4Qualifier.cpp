// SPDX-License-Identifier: Apache-2.0
// Software-only production-context gate for the qualifier-rewrite construction.
// All callbacks are counters; no I/O. Sibling of TestCase4.cpp (separate-header
// construction); same Endpoint fixture and DecoyGateCommandHandler, different
// transform: rewrite the native object's own header in place (qualifier
// 0x28->0x17, count 1->2) instead of appending a second header object.
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/BufferHelpers.h"
#include "utils/DecoyGateCommandHandler.h"
#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockLowerLayer.h"
#include "dnp3mocks/MockOutstationApplication.h"
#include <outstation/OutstationContext.h>
#include <link/CRC.h>
#include <opendnp3/logging/LogLevels.h>
#include <exe4cpp/MockExecutor.h>
#include <catch.hpp>
#include <iostream>
#include <sstream>
#include <vector>
using namespace opendnp3;
#include "vectors_qualifier.h"

namespace {
struct Endpoint {
    Endpoint(): exe(std::make_shared<exe4cpp::MockExecutor>()), lower(std::make_shared<MockLowerLayer>()),
       handler(std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{201})),
       app(std::make_shared<MockOutstationApplication>()),
       context(Addresses(), OutstationConfig(), DatabaseConfig(), log.logger, exe, lower, handler, app) {
        lower->SetUpperLayer(context); context.OnLowerLayerUp(); exe->run_many();
    }
    std::string Send(const std::string& s) {
        HexSequence h(s); context.OnReceive(Message(Addresses(), h.ToRSeq())); exe->run_many();
        auto out = lower->PopWriteAsHex(); context.OnTxReady(); exe->run_many(); return out;
    }
    MockLogHandler log;
    std::shared_ptr<exe4cpp::MockExecutor> exe;
    std::shared_ptr<MockLowerLayer> lower;
    std::shared_ptr<DecoyGateCommandHandler> handler;
    std::shared_ptr<MockOutstationApplication> app;
    OContext context;
};
MasterParams params() { auto p = NoStartupTasks(); p.ignoreRestartIIN = true; return p; }
std::string objects(const std::string& s) { return s.substr(6); } // drop "ctrl func " (2 bytes)
size_t byteLen(const std::string& s) { std::istringstream in(s); std::string x; size_t n=0; while(in>>x) ++n; return n; }

// Rewrites a native single-CROB SELECT/OPERATE APDU (ctrl,func,0C 01 28 01 00,
// idx16,CROB11 -- 20 bytes) in place to qualifier 0x17/count 2 with one
// appended decoy object (idx 201), the same construction
// case4_qualifier_rewrite.rewrite_qualifier performs in Python. Only ctrl/func
// (bytes 0-1) are carried through unchanged; this is why it is safe to apply
// to the real master's dynamically-generated OPERATE as well as SELECT.
std::string rewritten(const std::string& s) {
    HexSequence h(s);
    auto b = h.ToRSeq();
    REQUIRE(byteLen(s) == 20);
    REQUIRE(b[8] == 0); // index < 256 precondition; a wider index must not reach this helper
    std::vector<uint8_t> out;
    out.push_back(b[0]); out.push_back(b[1]);
    static const uint8_t header17[4] = {0x0C, 0x01, 0x17, 0x02};
    out.insert(out.end(), header17, header17 + 4);
    out.push_back(b[7]);
    for (uint32_t i = 9; i < 20; ++i) out.push_back(b[i]);
    out.push_back(0xC9); // decoy index 201, matching DecoyGateCommandHandler's configured decoy
    static const uint8_t decoyBody[11] = {0x01, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00};
    out.insert(out.end(), decoyBody, decoyBody + 11);
    return ByteStr(out.data(), out.size()).ToHex();
}
void start(MasterTestFixture& m, CommandCallbackQueue& q) {
    m.context->SelectAndOperate(CommandSet({WithIndex(ControlRelayOutputBlock(OperationType::PULSE_ON),1)}), q.Callback(), TaskConfig::Default());
    m.exe->run_many();
}
std::string deliver(MasterTestFixture& m, const std::string& echo) {
    m.context->OnTxReady(); m.SendToMaster(echo); m.exe->run_many(); auto next = m.lower->PopWriteAsHex();
    std::cout << "DELIVER_Q echo=" << echo << " next=" << next << "\n"; return next;
}
}

TEST_CASE("Case4 qualifier-rewrite C++ helper matches the Python codec's generated vector") {
    REQUIRE(byteLen(nativeSelect) == 20);
    REQUIRE(rewritten(nativeSelect) == transformedSelect);
}

TEST_CASE("Case4 qualifier-rewrite vectors accepted through production master and outstation") {
    Endpoint e; MasterTestFixture m(params()); m.context->OnLowerLayerUp(); CommandCallbackQueue q;
    start(m,q); auto select=m.lower->PopWriteAsHex();
    REQUIRE(byteLen(select)==20); REQUIRE(select==nativeSelect);
    REQUIRE(rewritten(select)==transformedSelect);
    auto echo=e.Send(rewritten(select));
    REQUIRE(byteLen(rewritten(select))==30); REQUIRE(byteLen(echo)==32);
    REQUIRE(echo == "C0 81 80 00 " + objects(rewritten(select)));
    auto operate=deliver(m,echo);
    REQUIRE(operate.substr(3,2)=="04"); REQUIRE(objects(select)==objects(operate));
    auto opEcho=e.Send(rewritten(operate));
    REQUIRE(byteLen(opEcho)==32); REQUIRE(opEcho == "C1 81 80 00 " + objects(rewritten(operate)));
    REQUIRE(deliver(m,opEcho).empty());
    REQUIRE(q.PopOnlyEqualValue(TaskCompletion::SUCCESS,CommandPointResult(0,1,CommandPointState::SUCCESS,CommandStatus::SUCCESS)));
    REQUIRE(e.handler->operates(1)==1); REQUIRE(e.handler->operates(201)==1);
    REQUIRE(e.handler->physicalActuations==1); REQUIRE(e.handler->inertActuations==1);
    REQUIRE(e.handler->operates(200)==0);
    // Replayed application request is deduplicated by the actual outstation context.
    REQUIRE(e.Send(rewritten(operate))==opEcho); REQUIRE(e.handler->operates(1)==1);
    std::cout << "QUALIFIER_SUCCESS native_select="<<select<<"\nrewritten_select="<<rewritten(select)<<"\nselect_echo="<<echo<<"\nnative_operate="<<operate<<"\noperate_echo="<<opEcho<<"\n";
}

TEST_CASE("Case4 qualifier-rewrite real SELECT failure emits no OPERATE and next transaction recovers") {
    Endpoint e; MasterTestFixture m(params()); m.context->OnLowerLayerUp(); CommandCallbackQueue q;
    e.handler->ForceStatus(1,CommandStatus::HARDWARE_ERROR);
    start(m,q); auto select=m.lower->PopWriteAsHex(); auto echo=e.Send(rewritten(select));
    REQUIRE(deliver(m,echo).empty()); REQUIRE(q.values.size()==1);
    REQUIRE(q.values.front().results.size()==1);
    REQUIRE(q.values.front().results.front().status==CommandStatus::HARDWARE_ERROR);
    REQUIRE(e.handler->operates(1)==0); REQUIRE(e.handler->operates(201)==0);
    std::cout << "QUALIFIER_REAL_SELECT_FAIL echo="<<echo<<" no_operate=true\n";
    q.values.clear(); e.handler->forced.clear();
    start(m,q); select=m.lower->PopWriteAsHex(); auto operate=deliver(m,e.Send(rewritten(select)));
    REQUIRE(!operate.empty()); REQUIRE(deliver(m,e.Send(rewritten(operate))).empty());
    REQUIRE(q.PopOnlyEqualValue(TaskCompletion::SUCCESS,CommandPointResult(0,1,CommandPointState::SUCCESS,CommandStatus::SUCCESS)));
    REQUIRE(e.handler->operates(1)==1); REQUIRE(e.handler->operates(201)==1);
}

TEST_CASE("Case4 qualifier-rewrite decoy SELECT failure cannot produce successful SBO at endpoint") {
    Endpoint e; MasterTestFixture m(params()); m.context->OnLowerLayerUp(); CommandCallbackQueue q;
    e.handler->ForceStatus(201,CommandStatus::HARDWARE_ERROR);
    start(m,q); auto select=m.lower->PopWriteAsHex(); auto echo=e.Send(rewritten(select));
    auto operate=deliver(m,echo);
    // Whether the native master accepts or rejects a 2-object SELECT response for
    // its own 1-object request is exactly the open question this gate exists to
    // answer for the qualifier-rewrite construction; it is not assumed here.
    std::cout << "QUALIFIER_DECOY_SELECT_FAIL select_echo="<<echo<<" master_emitted_operate="<<(!operate.empty())
               <<" task_results="<<q.values.size()<<"\n";
    if (!operate.empty()) {
        auto opEcho=e.Send(rewritten(operate));
        REQUIRE(deliver(m,opEcho).empty());
        std::cout << "QUALIFIER_DECOY_SELECT_FAIL operate_echo="<<opEcho<<" endpoint_callbacks_point1="<<e.handler->operates(1)<<"\n";
    }
    q.values.clear(); e.handler->forced.clear();
    start(m,q); select=m.lower->PopWriteAsHex(); operate=deliver(m,e.Send(rewritten(select)));
    REQUIRE(!operate.empty()); REQUIRE(deliver(m,e.Send(rewritten(operate))).empty());
    REQUIRE(q.PopOnlyEqualValue(TaskCompletion::SUCCESS,CommandPointResult(0,1,CommandPointState::SUCCESS,CommandStatus::SUCCESS)));
}

TEST_CASE("Case4 qualifier-rewrite transformed link CRCs independently checked by production implementation") {
    HexSequence wire(transformedFrame); auto bytes=wire.ToRSeq();
    REQUIRE(bytes.length()==45); REQUIRE(CRC::IsCorrectCRC(bytes,8));
    size_t left=bytes[2]-5, i=10;
    while(left) { auto n=std::min(size_t(16),left); REQUIRE(CRC::IsCorrectCRC(bytes+i,n)); i+=n+2; left-=n; }
    REQUIRE(i==bytes.length());
}

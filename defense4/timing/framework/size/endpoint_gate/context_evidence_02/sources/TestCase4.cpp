// SPDX-License-Identifier: Apache-2.0
// Software-only production-context gate. All callbacks are counters; no I/O.
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
using namespace opendnp3;
#include "vectors.h"

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
std::string objects(const std::string& s) { return s.substr(6); }
size_t byteLen(const std::string& s) { std::istringstream in(s); std::string x; size_t n=0; while(in>>x) ++n; return n; }
std::string pad(const std::string& s) { return s + " " + paddingObjects; }
void start(MasterTestFixture& m, CommandCallbackQueue& q) {
    m.context->SelectAndOperate(CommandSet({WithIndex(ControlRelayOutputBlock(OperationType::PULSE_ON),1)}), q.Callback(), TaskConfig::Default());
    m.exe->run_many();
}
std::string deliver(MasterTestFixture& m, const std::string& echo) {
    m.context->OnTxReady(); m.SendToMaster(echo); m.exe->run_many(); auto next = m.lower->PopWriteAsHex();
    std::cout << "DELIVER echo=" << echo << " next=" << next << "\n"; return next;
}
}

TEST_CASE("Case4 exact transformer vectors accepted through production master and outstation") {
    Endpoint e; MasterTestFixture m(params()); m.context->OnLowerLayerUp(); CommandCallbackQueue q;
    start(m,q); auto select=m.lower->PopWriteAsHex();
    REQUIRE(byteLen(select)==20); REQUIRE(select==nativeSelect);
    REQUIRE(pad(select)==transformedSelect);
    auto echo=e.Send(pad(select));
    REQUIRE(byteLen(pad(select))==38); REQUIRE(byteLen(echo)==40);
    REQUIRE(echo == "C0 81 80 00 " + objects(pad(select)));
    auto operate=deliver(m,echo);
    REQUIRE(operate.substr(3,2)=="04"); REQUIRE(objects(select)==objects(operate));
    auto opEcho=e.Send(pad(operate));
    REQUIRE(byteLen(opEcho)==40); REQUIRE(opEcho == "C1 81 80 00 " + objects(pad(operate)));
    REQUIRE(deliver(m,opEcho).empty());
    REQUIRE(q.PopOnlyEqualValue(TaskCompletion::SUCCESS,CommandPointResult(0,1,CommandPointState::SUCCESS,CommandStatus::SUCCESS)));
    REQUIRE(e.handler->operates(1)==1); REQUIRE(e.handler->operates(201)==1);
    REQUIRE(e.handler->physicalActuations==1); REQUIRE(e.handler->inertActuations==1);
    REQUIRE(e.handler->operates(200)==0);
    // Replayed application request is deduplicated by the actual outstation context.
    REQUIRE(e.Send(pad(operate))==opEcho); REQUIRE(e.handler->operates(1)==1);
    std::cout << "SUCCESS native_select="<<select<<"\npadded_select="<<pad(select)<<"\nselect_echo="<<echo<<"\nnative_operate="<<operate<<"\noperate_echo="<<opEcho<<"\n";
}

TEST_CASE("Case4 real SELECT failure emits no OPERATE and next transaction recovers") {
    Endpoint e; MasterTestFixture m(params()); m.context->OnLowerLayerUp(); CommandCallbackQueue q;
    e.handler->ForceStatus(1,CommandStatus::HARDWARE_ERROR);
    start(m,q); auto select=m.lower->PopWriteAsHex(); auto echo=e.Send(pad(select));
    REQUIRE(deliver(m,echo).empty()); REQUIRE(q.values.size()==1);
    REQUIRE(q.values.front().results.size()==1);
    REQUIRE(q.values.front().results.front().status==CommandStatus::HARDWARE_ERROR);
    REQUIRE(e.handler->operates(1)==0); REQUIRE(e.handler->operates(201)==0);
    std::cout << "REAL_SELECT_FAIL echo="<<echo<<" no_operate=true\n";
    q.values.clear(); e.handler->forced.clear();
    start(m,q); select=m.lower->PopWriteAsHex(); auto operate=deliver(m,e.Send(pad(select)));
    REQUIRE(!operate.empty()); REQUIRE(deliver(m,e.Send(pad(operate))).empty());
    REQUIRE(q.PopOnlyEqualValue(TaskCompletion::SUCCESS,CommandPointResult(0,1,CommandPointState::SUCCESS,CommandStatus::SUCCESS)));
    REQUIRE(e.handler->operates(1)==1); REQUIRE(e.handler->operates(201)==1);
}

TEST_CASE("Case4 decoy SELECT failure cannot produce successful SBO at endpoint") {
    Endpoint e; MasterTestFixture m(params()); m.context->OnLowerLayerUp(); CommandCallbackQueue q;
    e.handler->ForceStatus(201,CommandStatus::HARDWARE_ERROR);
    start(m,q); auto select=m.lower->PopWriteAsHex(); auto echo=e.Send(pad(select));
    REQUIRE(echo.substr(echo.size()-2)=="06");
    auto operate=deliver(m,echo);
    // Native master ignores the trailing header, including its failing status.
    REQUIRE(!operate.empty()); auto opEcho=e.Send(pad(operate));
    REQUIRE(deliver(m,opEcho).empty()); REQUIRE(e.handler->operates(1)==0); REQUIRE(e.handler->operates(201)==0);
    REQUIRE(q.values.size()==1); REQUIRE(q.values.front().results.front().status==CommandStatus::NO_SELECT);
    std::cout << "DECOY_SELECT_FAIL select_echo="<<echo<<"\noperate_echo="<<opEcho<<"\nmaster_ignored_trailing_failure=true endpoint_callbacks=0\n";
    q.values.clear(); e.handler->forced.clear();
    start(m,q); select=m.lower->PopWriteAsHex(); operate=deliver(m,e.Send(pad(select)));
    REQUIRE(!operate.empty()); REQUIRE(deliver(m,e.Send(pad(operate))).empty());
    REQUIRE(q.PopOnlyEqualValue(TaskCompletion::SUCCESS,CommandPointResult(0,1,CommandPointState::SUCCESS,CommandStatus::SUCCESS)));
}

TEST_CASE("Case4 transformed link CRCs independently checked by production implementation") {
    HexSequence wire(transformedFrame); auto bytes=wire.ToRSeq();
    REQUIRE(bytes.length()==55); REQUIRE(CRC::IsCorrectCRC(bytes,8));
    size_t left=bytes[2]-5, i=10;
    while(left) { auto n=std::min(size_t(16),left); REQUIRE(CRC::IsCorrectCRC(bytes+i,n)); i+=n+2; left-=n; }
    REQUIRE(i==bytes.length());
}

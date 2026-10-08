// SPDX-License-Identifier: Apache-2.0
// Software-only production-context gate for Option B's uniform 58-byte pad
// (case4_pad58.py), the pattern SELECTED_PATTERN.md's 2026-10-08 update makes
// active after the qualifier-rewrite construction (TestCase4Qualifier.cpp)
// failed this same kind of gate. Sibling of TestCase4.cpp/TestCase4Qualifier.cpp;
// same Endpoint/CommandCallbackQueue infrastructure. Unlike the other two
// constructions, case4_pad58 transforms RESPONSES only -- READ and
// SELECT/OPERATE echoes -- and never the request, so here the REQUEST each
// test captures from the real master is sent to the real outstation
// UNMODIFIED; only the resulting live response is padded before being handed
// back to the master. The filler bytes appended here (readFillerObject /
// controlFillerObject) are precomputed by emit_vectors_pad58.py directly from
// case4_pad58._analog_object, so they are byte-identical to what the real
// codec would append; this file never reimplements that byte layout.
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/BufferHelpers.h"
#include "utils/DecoyGateCommandHandler.h"
#include "dnp3mocks/DatabaseHelpers.h"
#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockLowerLayer.h"
#include "dnp3mocks/MockOutstationApplication.h"
#include "dnp3mocks/MockSOEHandler.h"
#include <outstation/OutstationContext.h>
#include <opendnp3/app/GroupVariationID.h>
#include <link/CRC.h>
#include <opendnp3/logging/LogLevels.h>
#include <exe4cpp/MockExecutor.h>
#include <catch.hpp>
#include <iostream>
#include <sstream>
using namespace opendnp3;
#include "vectors_pad58.h"

namespace {
// One shared production OContext exercises both protected roles, the same way
// a single device would: one wired CROB (index 1) plus one configured-inert
// decoy CROB (index 201) for SELECT/OPERATE, and 23 Binary Output Status
// points (index 0..22) for READ -- exactly the profile case4_pad58's READ
// eligibility test requires (HEADER_READ23: G10V2, qualifier 0x00, range
// 0..22). Neither role's config affects the other's wire behavior.
struct Endpoint {
    Endpoint(): exe(std::make_shared<exe4cpp::MockExecutor>()), lower(std::make_shared<MockLowerLayer>()),
       handler(std::make_shared<DecoyGateCommandHandler>(1, std::vector<uint16_t>{201})),
       app(std::make_shared<MockOutstationApplication>()),
       context(Addresses(), OutstationConfig(), configure::by_count_of::binary_output_status(23),
               log.logger, exe, lower, handler, app) {
        lower->SetUpperLayer(context); context.OnLowerLayerUp(); exe->run_many();
        auto& db = context.GetUpdateHandler();
        for (uint16_t i = 0; i < 23; ++i)
        {
            db.Update(BinaryOutputStatus(((i % 2) == 0), Flags(0x01)), i);
        }
        context.HandleNewEvents();
        exe->run_many();
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
size_t byteLen(const std::string& s) { std::istringstream in(s); std::string x; size_t n=0; while(in>>x) ++n; return n; }
// Pure append, matching case4_pad58.pad_control_response/pad_read_response's
// `image = build_frame(head, user + _analog_object(points))` exactly: the
// filler is tacked onto the end of the real response bytes with no other
// change. No re-framing/CRC step is needed here because MockLowerLayer/OContext
// operate above the link layer, the same level case4_padding's own pad()
// helper in TestCase4.cpp already works at.
std::string pad58control(const std::string& s) { return s + " " + controlFillerObject; }
std::string pad58read(const std::string& s) { return s + " " + readFillerObject; }
void start(MasterTestFixture& m, CommandCallbackQueue& q) {
    m.context->SelectAndOperate(CommandSet({WithIndex(ControlRelayOutputBlock(OperationType::PULSE_ON),1)}), q.Callback(), TaskConfig::Default());
    m.exe->run_many();
}
std::string deliver(MasterTestFixture& m, const std::string& echo) {
    m.context->OnTxReady(); m.SendToMaster(echo); m.exe->run_many(); auto next = m.lower->PopWriteAsHex();
    std::cout << "DELIVER_P58 echo=" << echo << " next=" << next << "\n"; return next;
}
}

TEST_CASE("Case4 pad58 filler objects match the sizes SELECTED_PATTERN.md specifies") {
    REQUIRE(byteLen(readFillerObject) == 9);
    REQUIRE(byteLen(controlFillerObject) == 19);
}

TEST_CASE("Case4 pad58 control: production master handling of a padded SELECT/OPERATE echo") {
    Endpoint e; MasterTestFixture m(params()); m.context->OnLowerLayerUp(); CommandCallbackQueue q;
    start(m,q); auto select=m.lower->PopWriteAsHex();
    REQUIRE(byteLen(select)==20);
    // case4_pad58 never transforms the request; the real outstation receives
    // the master's own native SELECT unmodified.
    auto echo=e.Send(select);
    REQUIRE(byteLen(echo)==22); // ctrl+func+iin(2)+header(5)+index(2)+CROB(11)
    auto padded=pad58control(echo);
    REQUIRE(byteLen(padded)==41); // 22 native + 19 filler
    auto operate=deliver(m,padded);
    std::cout << "PAD58_CONTROL_SELECT native_echo="<<echo<<"\npadded_echo="<<padded
               <<"\nmaster_emitted_operate="<<(!operate.empty())<<" task_results="<<q.values.size()<<"\n";
    if (!q.values.empty() && !q.values.front().results.empty()) {
        std::cout << "PAD58_CONTROL_SELECT_STATUS status="<<static_cast<int>(q.values.front().results.front().status)<<"\n";
    }
    if (!operate.empty()) {
        REQUIRE(operate.substr(3,2)=="04");
        auto opEcho=e.Send(operate);
        auto opPadded=pad58control(opEcho);
        auto next=deliver(m,opPadded);
        std::cout << "PAD58_CONTROL_OPERATE native_echo="<<opEcho<<"\npadded_echo="<<opPadded<<"\nnext="<<next<<"\n";
    }
    std::cout << "PAD58_CONTROL_ENDPOINT operates_point1="<<e.handler->operates(1)
               <<" physicalActuations="<<e.handler->physicalActuations<<"\n";
    q.values.clear(); e.handler->forced.clear();
    // Recovery check: the connection must still support a subsequent,
    // completely native (unpadded) SBO transaction on the same stack.
    start(m,q); select=m.lower->PopWriteAsHex(); auto operate2=deliver(m,e.Send(select));
    REQUIRE(!operate2.empty()); REQUIRE(deliver(m,e.Send(operate2)).empty());
    REQUIRE(q.PopOnlyEqualValue(TaskCompletion::SUCCESS,CommandPointResult(0,1,CommandPointState::SUCCESS,CommandStatus::SUCCESS)));
    REQUIRE(e.handler->operates(1)==1); // only the native recovery transaction actuated point 1
}

TEST_CASE("Case4 pad58 read: production master handling of a padded 23-point READ response") {
    Endpoint e; MasterTestFixture m(params()); m.context->OnLowerLayerUp();
    m.context->ScanRange(GroupVariationID(10,2), 0, 22, m.meas);
    m.exe->run_many();
    auto request = m.lower->PopWriteAsHex();
    REQUIRE(!request.empty());
    auto response = e.Send(request);
    // Sanity: the real production outstation's static-response encoder must
    // actually emit the one profile case4_pad58's eligibility test accepts
    // (G10V2, qualifier 0x00, range 0..22) before the padding question is
    // even reachable.
    REQUIRE(response.find(readHeader23) != std::string::npos);
    REQUIRE(byteLen(response)==32); // ctrl+func+iin(2)+header(5)+23 data bytes
    auto padded = pad58read(response);
    REQUIRE(byteLen(padded)==41); // 32 native + 9 filler
    m.context->OnTxReady(); m.SendToMaster(padded); m.exe->run_many();
    auto received_after_padded = m.meas->TotalReceived();
    std::cout << "PAD58_READ request="<<request<<"\nnative_response="<<response<<"\npadded_response="<<padded
               <<"\npoints_received_after_padded="<<received_after_padded<<"\n";
    // Recovery check: a subsequent, completely native (unpadded) READ on the
    // same stack must still deliver all 23 points.
    m.context->ScanRange(GroupVariationID(10,2), 0, 22, m.meas); m.exe->run_many();
    auto request2 = m.lower->PopWriteAsHex();
    auto response2 = e.Send(request2);
    m.context->OnTxReady(); m.SendToMaster(response2); m.exe->run_many();
    std::cout << "PAD58_READ_RECOVERY total_received="<<m.meas->TotalReceived()<<"\n";
    // If the padded response above contributed its 23 points, this totals 46;
    // if it contributed nothing, this totals 23. Either outcome is reported
    // above regardless of this assertion's pass/fail.
    REQUIRE(m.meas->TotalReceived()==23+received_after_padded);
    REQUIRE(e.handler->operates(1)==0); // READ never touches the CROB command path
}

// SPDX-License-Identifier: Apache-2.0
//
// Real-TCP-socket production endpoint for Option B' (case4_pad58b.py) response
// padding. Sibling of SocketGate.cpp, built for run_sockets_pad58b.py instead
// of run.py --sockets. Unlike SocketGate.cpp (one SELECT/OPERATE pair, no
// configured measurement points), this binary additionally configures 23
// Binary Output Status points (index 0..22, alternating true/false with
// Flags(0x01) -- the same seed TestCase4Pad58B.cpp's mocked-context Endpoint
// uses) so the master side can issue real READ (ScanRange G10V2 0..22)
// exchanges that satisfy case4_pad58b's READ eligibility test (HEADER_READ23
// = G10V2, qualifier 0x00, range 0..22). The SELECT/OPERATE wiring (point 1
// real, point 201 configured decoy) reuses DecoyGateCommandHandler
// unmodified, the same way SocketGate.cpp does.
//
// This binary performs NO response padding itself and does not require a
// private network namespace: padding happens in a separate real TCP proxy
// process (pad58b_proxy.py) sitting between this outstation and the master,
// over two independent loopback TCP sockets that this binary knows nothing
// about -- from its perspective it is simply a production outstation and a
// production master talking DNP3 over TCP.
//
// Private software endpoints only. No device I/O or physical output callbacks.
#include "DecoyGateCommandHandler.h"
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/app/GroupVariationID.h>
#include <opendnp3/app/MeasurementTypes.h>
#include <opendnp3/channel/IChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/ICommandTaskResult.h>
#include <opendnp3/master/ISOEHandler.h>
#include <opendnp3/outstation/DatabaseConfig.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/UpdateBuilder.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>
#include <unistd.h>
using namespace opendnp3;
using Clock = std::chrono::steady_clock;
static long long now_ns() { return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count(); }

class Listener final : public IChannelListener {
public:
    std::atomic<int> opens{0}; std::atomic<bool> open{false};
    void OnStateChange(ChannelState state) override { open = state == ChannelState::OPEN; if (open) ++opens; }
};

class Handler final : public SimpleCommandHandler {
public:
    DecoyGateCommandHandler gate{1, {201}};
    long long selected_ns=0, operated_ns=0;
    Handler() : SimpleCommandHandler(CommandStatus::NOT_SUPPORTED) {}
    CommandStatus Select(const ControlRelayOutputBlock& cmd, uint16_t index) override {
        auto result=gate.Select(cmd,index); if(index==1 && result==CommandStatus::SUCCESS) selected_ns=now_ns(); return result;
    }
    CommandStatus Operate(const ControlRelayOutputBlock& cmd, uint16_t index, IUpdateHandler& update, OperateType type) override {
        auto result=gate.Operate(cmd,index,update,type); if(index==1 && result==CommandStatus::SUCCESS) operated_ns=now_ns(); return result;
    }
};

// One ScanRange's worth of received Binary Output Status points: index -> (value, raw flags byte).
struct ScanResult {
    std::map<uint16_t, std::pair<bool, uint8_t>> points;
    bool completed = false;
};

// Records every scan's delivered Binary Output Status points. Mirrors the
// per-index assertions TestCase4Pad58B.cpp's mocked-context READ test makes
// (23 points, index i has value (i%2==0) and Flags(0x01)) but against a real
// master stack's own SOE callbacks instead of MockSOEHandler/m.meas.
class RecordingSOEHandler final : public ISOEHandler {
public:
    std::vector<ScanResult> scans;
    void BeginFragment(const ResponseInfo&) override { scans.emplace_back(); }
    void EndFragment(const ResponseInfo&) override { if (!scans.empty()) scans.back().completed = true; }
    void Process(const HeaderInfo&, const ICollection<Indexed<Binary>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<DoubleBitBinary>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<Analog>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<Counter>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<FrozenCounter>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryOutputStatus>>& values) override {
        if (scans.empty()) scans.emplace_back();
        values.ForeachItem([&](const Indexed<BinaryOutputStatus>& item) {
            scans.back().points[item.index] = std::make_pair(item.value.value, item.value.flags.value);
        });
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogOutputStatus>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<OctetString>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<TimeAndInterval>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<DNPTime>&) override {}
};

static bool matchesSeed(const ScanResult& scan) {
    if (scan.points.size() != 23) return false;
    for (uint16_t i = 0; i < 23; ++i) {
        auto it = scan.points.find(i);
        if (it == scan.points.end()) return false;
        // Group10Var2's wire byte folds the STATE bit (0x80) and the quality
        // bits into one "flags" byte; the server seeded ONLINE (0x01) only,
        // so after the master's own Group10Var2::ReadTarget/
        // BinaryOutputStatusFactory::From split, .value carries the STATE bit
        // and .flags carries the full wire byte (0x81 for on, 0x01 for off) --
        // not a bare 0x01 for every point.
        const bool expectedValue = (i % 2) == 0;
        if (it->second.first != expectedValue) return false;
        const uint8_t expectedFlags = expectedValue ? 0x81 : 0x01;
        if (it->second.second != expectedFlags) return false;
    }
    return true;
}

int main(int argc, char** argv) {
    // argv: outstation host port stop-file [lifetime-seconds=15]
    //      master     host port stop-file [read-count=3] [local-adapter=""]
    // host is the outstation's bind address (0.0.0.0 = any) or the master's target.
    // local-adapter is the master's own source address; empty lets the kernel pick
    // by route, which is required to reach a non-loopback outstation.
    // Start the outstation (wait for READY) before the master: the master makes
    // one connect attempt within 5 s and its next retry is 60 s away.
    if (argc < 5 || !std::getenv("CASE4_PAD58B_SOCKET_GATE")) return 64;
    const std::string role = argv[1], host = argv[2];
    const uint16_t port = static_cast<uint16_t>(std::atoi(argv[3]));
    const std::string stop = argv[4];
    const int reads = argc > 5 ? std::atoi(argv[5]) : 3;
    const int lifetime_s = argc > 5 ? std::atoi(argv[5]) : 15;
    const std::string adapter = argc > 6 ? argv[6] : "";
    DNP3Manager manager(1); auto listener = std::make_shared<Listener>();
    if (role == "outstation") {
        if (lifetime_s <= 0) return 64;
        auto handler = std::make_shared<Handler>();
        auto channel = manager.AddTCPServer("gate", levels::NOTHING, ServerAcceptMode::CloseExisting, IPEndpoint(host, port), listener);
        DatabaseConfig db;
        for (uint16_t i = 0; i < 23; ++i) db.binary_output_status[i] = BOStatusConfig();
        OutstationStackConfig config{db};
        config.outstation.params.allowUnsolicited = false;
        config.outstation.params.selectTimeout = TimeDuration::Milliseconds(500);
        config.link.LocalAddr = 10; config.link.RemoteAddr = 1; config.link.KeepAliveTimeout = TimeDuration::Max();
        auto station = channel->AddOutstation("outstation", handler, DefaultOutstationApplication::Create(), config);
        UpdateBuilder builder;
        for (uint16_t i = 0; i < 23; ++i) builder.Update(BinaryOutputStatus((i % 2) == 0, Flags(0x01)), i);
        station->Apply(builder.Build());
        station->Enable(); std::cout<<"READY\n"<<std::flush;
        const auto end = Clock::now() + std::chrono::seconds(lifetime_s);
        while (Clock::now() < end && !std::ifstream(stop).good()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        manager.Shutdown();
        std::cout << "{\"select_real\":" << handler->gate.selects(1) << ",\"select_decoy\":" << handler->gate.selects(201)
                   << ",\"operate_real\":" << handler->gate.operates(1) << ",\"operate_decoy\":" << handler->gate.operates(201)
                   << ",\"opens\":" << listener->opens << ",\"select_accept_ns\":" << handler->selected_ns
                   << ",\"operate_accept_ns\":" << handler->operated_ns << "}\n";
        return 0;
    }
    if (role != "master") return 64;
    auto retry = ChannelRetry(TimeDuration::Seconds(60), TimeDuration::Seconds(60), TimeDuration::Seconds(60));
    auto channel = manager.AddTCPClient("gate", levels::NOTHING, retry, {IPEndpoint(host, port)}, adapter, listener);
    MasterStackConfig config;
    config.master.disableUnsolOnStartup = false; config.master.startupIntegrityClassMask = ClassField::None();
    config.master.unsolClassMask = ClassField::None(); config.master.ignoreRestartIIN = true;
    config.master.responseTimeout = TimeDuration::Milliseconds(500);
    config.link.LocalAddr = 1; config.link.RemoteAddr = 10; config.link.KeepAliveTimeout = TimeDuration::Max();
    auto soe = std::make_shared<RecordingSOEHandler>();
    auto master = channel->AddMaster("master", soe, DefaultMasterApplication::Create(), config);
    master->Enable();
    const auto connectDeadline = Clock::now() + std::chrono::seconds(5);
    while (!listener->open && Clock::now() < connectDeadline) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    if (!listener->open) { manager.Shutdown(); return 2; }
    for (int i = 0; i < reads; ++i) {
        const size_t before = soe->scans.size();
        master->ScanRange(GroupVariationID(10, 2), 0, 22, soe);
        const auto deadline = Clock::now() + std::chrono::seconds(3);
        while (soe->scans.size() <= before && Clock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        std::this_thread::sleep_for(std::chrono::milliseconds(25)); // let EndFragment land
    }
    std::atomic<bool> done{false}, success{false}; const auto issued = now_ns(); long long completed = 0;
    master->SelectAndOperate(ControlRelayOutputBlock(OperationType::PULSE_ON, TripCloseCode::NUL, false, 1, 100, 100), 1,
        [&](const ICommandTaskResult& result) {
            bool ok = result.summary == TaskCompletion::SUCCESS; int count = 0;
            result.ForeachItem([&](const CommandPointResult& p) { ++count; ok = ok && p.index==1 && p.status==CommandStatus::SUCCESS && p.state==CommandPointState::SUCCESS; });
            success = ok && count == 1; completed = now_ns(); done = true;
        });
    const auto sboDeadline = Clock::now() + std::chrono::seconds(3);
    while (!done && Clock::now() < sboDeadline) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    manager.Shutdown();
    std::ostringstream reads_json;
    reads_json << "[";
    for (size_t i = 0; i < soe->scans.size(); ++i) {
        if (i) reads_json << ",";
        const auto& scan = soe->scans[i];
        reads_json << "{\"completed\":" << (scan.completed ? "true" : "false")
                   << ",\"points_received\":" << scan.points.size()
                   << ",\"matches_seed\":" << (matchesSeed(scan) ? "true" : "false") << "}";
    }
    reads_json << "]";
    const bool allReadsMatch = soe->scans.size() == static_cast<size_t>(reads) &&
        std::all_of(soe->scans.begin(), soe->scans.end(), [](const ScanResult& s) { return s.completed && matchesSeed(s); });
    std::cout << "{\"success\":" << (success ? "true" : "false") << ",\"application_calls\":1,\"opens\":" << listener->opens
               << ",\"issued_ns\":" << issued << ",\"completed_ns\":" << completed
               << ",\"reads_requested\":" << reads << ",\"reads_completed\":" << soe->scans.size()
               << ",\"all_reads_match_seed\":" << (allReadsMatch ? "true" : "false")
               << ",\"reads\":" << reads_json.str() << "}\n";
    return (success && allReadsMatch) ? 0 : 3;
}

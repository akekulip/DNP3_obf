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
#include <opendnp3/master/HeaderTypes.h>
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
#include <memory>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>
#include <unistd.h>
using namespace opendnp3;
using Clock = std::chrono::steady_clock;
static long long now_ns() { return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count(); }

// Strict bounded experiment controls: no atoi truncation, signs, or overflow.
static bool envUnsigned(const char* name, int defaultValue, int maximum, int& value) {
    const char* text = std::getenv(name);
    value = defaultValue;
    if (!text) return true;
    value = 0;
    if (*text) {
        for (const char* p = text; *p; ++p) {
            if (*p < '0' || *p > '9' || value > (maximum - (*p - '0')) / 10) {
                std::cerr << name << " must be a decimal integer in 0.." << maximum << "\n";
                return false;
            }
            value = value * 10 + (*p - '0');
        }
        if (value <= maximum) return true;
    }
    std::cerr << name << " must be a decimal integer in 0.." << maximum << "\n";
    return false;
}

class Listener final : public IChannelListener {
public:
    std::atomic<int> opens{0}; std::atomic<bool> open{false};
    void OnStateChange(ChannelState state) override { open = state == ChannelState::OPEN; if (open) ++opens; }
};

// One accepted or rejected command callback, appended in arrival order and never overwritten. These are
// software-handler callbacks: no device output is driven.
struct CommandEvent {
    const char* kind; uint16_t index; uint32_t on_time_ms; uint32_t off_time_ms; int code; int status; long long ns;
};

class Handler final : public SimpleCommandHandler {
public:
    DecoyGateCommandHandler gate{1, {201}};
    long long selected_ns=0, operated_ns=0;
    std::vector<CommandEvent> events;
    Handler() : SimpleCommandHandler(CommandStatus::NOT_SUPPORTED) {}
    CommandStatus Select(const ControlRelayOutputBlock& cmd, uint16_t index) override {
        auto result=gate.Select(cmd,index); const auto t=now_ns(); if(index==1 && result==CommandStatus::SUCCESS) selected_ns=t;
        events.push_back({"SELECT", index, cmd.onTimeMS, cmd.offTimeMS, static_cast<int>(cmd.rawCode), static_cast<int>(result), t});
        return result;
    }
    CommandStatus Operate(const ControlRelayOutputBlock& cmd, uint16_t index, IUpdateHandler& update, OperateType type) override {
        auto result=gate.Operate(cmd,index,update,type); const auto t=now_ns(); if(index==1 && result==CommandStatus::SUCCESS) operated_ns=t;
        events.push_back({"OPERATE", index, cmd.onTimeMS, cmd.offTimeMS, static_cast<int>(cmd.rawCode), static_cast<int>(result), t});
        return result;
    }
};

static std::string eventsJson(const std::vector<CommandEvent>& events) {
    std::ostringstream out; out << "[";
    for (size_t i = 0; i < events.size(); ++i) {
        const auto& e = events[i];
        out << (i ? "," : "") << "{\"seq\":" << i << ",\"kind\":\"" << e.kind << "\",\"index\":" << e.index
            << ",\"on_time_ms\":" << e.on_time_ms << ",\"off_time_ms\":" << e.off_time_ms << ",\"code\":" << e.code
            << ",\"status\":" << e.status << ",\"ns\":" << e.ns << "}";
    }
    out << "]"; return out.str();
}

// One master SELECT->OPERATE cycle (one SelectAndOperate task) and the READ that follows it.
struct Cycle {
    int cycle = 0; uint32_t on_time_ms = 0; long long issued_ns = 0;
    std::atomic<long long> completed_ns{0}; std::atomic<int> callbacks{0};
    std::atomic<int> summary{-1}; std::atomic<int> points{0};
    std::atomic<int> index{-1}; std::atomic<int> status{-1}; std::atomic<int> state{-1};
    std::atomic<bool> ok{false};
    bool read_completed = false, read_matches_seed = false; size_t read_scan = 0;
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
    std::atomic<size_t> completedScans{0};
    void BeginFragment(const ResponseInfo&) override { scans.emplace_back(); }
    void EndFragment(const ResponseInfo&) override {
        if (!scans.empty()) {
            scans.back().completed = true;
            completedScans.fetch_add(1, std::memory_order_release);
        }
    }
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
    //      master     host port stop-file [read-count=3] [local-adapter=""] [read-range=16|8] [gap-ms=0]
    // host is the outstation's bind address (0.0.0.0 = any) or the master's target.
    // local-adapter is the master's own source address; empty lets the kernel pick
    // by route, which is required to reach a non-loopback outstation.
    // read-range 8 sends the READ with the one-octet start/stop qualifier (a 20-byte request, the form
    // the SEL-751 harness sends) instead of ScanRange's two-octet one (22 bytes); gap-ms pauses after
    // each READ.
    // Start the outstation (wait for READY) before the master: the master makes
    // one connect attempt within 5 s and its next retry is 60 s away.
    if (argc < 5 || !std::getenv("CASE4_PAD58B_SOCKET_GATE")) return 64;
    const std::string role = argv[1], host = argv[2];
    const uint16_t port = static_cast<uint16_t>(std::atoi(argv[3]));
    const std::string stop = argv[4];
    const int reads = argc > 5 ? std::atoi(argv[5]) : 3;
    const int lifetime_s = argc > 5 ? std::atoi(argv[5]) : 15;
    const std::string adapter = argc > 6 ? argv[6] : "";
    const int range_bits = argc > 7 ? std::atoi(argv[7]) : 16;
    const int gap_ms = argc > 8 ? std::atoi(argv[8]) : 0;
    if ((range_bits != 16 && range_bits != 8) || gap_ms < 0) return 64;
    int read_pause_ms, run_sbo, close_grace_ms, pre_read_grace_ms, sbo_cycles;
    if (!envUnsigned("CASE4_READ_PAUSE_MS", 25, 5000, read_pause_ms) ||
        !envUnsigned("CASE4_RUN_SBO", 1, 1, run_sbo) ||
        !envUnsigned("CASE4_CLOSE_GRACE_MS", 0, 5000, close_grace_ms) ||
        !envUnsigned("CASE4_PRE_READ_GRACE_MS", 0, 5000, pre_read_grace_ms) ||
        !envUnsigned("CASE4_SBO_CYCLES", 0, 64, sbo_cycles)) return 64;
    // CASE4_SBO_CYCLES=0 (default) keeps the single trailing SBO. N>0 runs N cycles of SELECT->OPERATE then one
    // READ on the same connection after the initial READs, i.e. READ->SELECT->OPERATE->READ repeated N times.
    if (sbo_cycles && !run_sbo) { std::cerr << "CASE4_SBO_CYCLES requires CASE4_RUN_SBO=1\n"; return 64; }
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
                   << ",\"operate_accept_ns\":" << handler->operated_ns
                   << ",\"actuation\":\"software_handler\",\"physical_actuations\":0"
                   << ",\"events\":" << eventsJson(handler->events) << "}\n";
        return 0;
    }
    if (role != "master" || reads < 0) return 64;
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
    const auto pre_read_ready_ns = now_ns();
    long long first_read_issued_ns = 0;
    if (const char* marker_path = std::getenv("CASE4_PRE_READ_MARKER")) {
        std::ofstream marker(marker_path);
        marker << "{\"pre_read_grace_ms\":" << pre_read_grace_ms
               << ",\"pre_read_ready_ns\":" << pre_read_ready_ns
               << ",\"first_read_issued_ns\":0,\"tcp_open\":true,\"opens\":" << listener->opens << "}\n";
        marker.flush();
        const bool written = marker.good();
        marker.close();
        if (!written || marker.fail()) {
            std::cerr << "CASE4_PRE_READ_MARKER write failed\n";
            manager.Shutdown(); return 74;
        }
    }
    if (pre_read_grace_ms) std::this_thread::sleep_for(std::chrono::milliseconds(pre_read_grace_ms));
    auto doRead = [&](int i) {
        const size_t before = soe->completedScans.load(std::memory_order_acquire);
        if (i == 0) first_read_issued_ns = now_ns();
        if (range_bits == 8) master->Scan({Header::Range8(10, 2, 0, 22)}, soe);
        else master->ScanRange(GroupVariationID(10, 2), 0, 22, soe);
        const auto deadline = Clock::now() + std::chrono::seconds(3);
        while (soe->completedScans.load(std::memory_order_acquire) <= before && Clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        if (read_pause_ms) std::this_thread::sleep_for(std::chrono::milliseconds(read_pause_ms));
        if (gap_ms) std::this_thread::sleep_for(std::chrono::milliseconds(gap_ms));
        return soe->completedScans.load(std::memory_order_acquire) > before;
    };
    for (int i = 0; i < reads; ++i) doRead(i);
    // Each cycle keeps its own record; a late or duplicate callback lands in its own cycle, never a shared one.
    std::vector<std::shared_ptr<Cycle>> cycles;
    auto runSbo = [&](int c, uint32_t on_time_ms) {
        auto cy = std::make_shared<Cycle>(); cy->cycle = c; cy->on_time_ms = on_time_ms; cy->issued_ns = now_ns();
        cycles.push_back(cy);
        master->SelectAndOperate(ControlRelayOutputBlock(OperationType::PULSE_ON, TripCloseCode::NUL, false, 1, on_time_ms, 100), 1,
            [cy](const ICommandTaskResult& result) {
                bool ok = result.summary == TaskCompletion::SUCCESS; int count = 0;
                result.ForeachItem([&](const CommandPointResult& p) {
                    ++count; cy->index = p.index; cy->status = static_cast<int>(p.status); cy->state = static_cast<int>(p.state);
                    ok = ok && p.index==1 && p.status==CommandStatus::SUCCESS && p.state==CommandPointState::SUCCESS; });
                cy->summary = static_cast<int>(result.summary); cy->points = count;
                cy->ok = ok && count == 1; cy->completed_ns = now_ns(); cy->callbacks.fetch_add(1);
            });
        const auto sboDeadline = Clock::now() + std::chrono::seconds(3);
        while (cy->callbacks.load() == 0 && Clock::now() < sboDeadline) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        return cy;
    };
    if (run_sbo && !sbo_cycles) runSbo(0, 100);
    for (int c = 0; c < sbo_cycles; ++c) {
        auto cy = runSbo(c, 100 + static_cast<uint32_t>(c));     // the on-time identifies the cycle in every echo
        if (!cy->ok) break;                                          // a failed cycle ends the run; it is reported
        cy->read_scan = soe->scans.size();
        cy->read_completed = doRead(reads + c);
        cy->read_matches_seed = cy->read_completed && cy->read_scan < soe->scans.size() &&
                                matchesSeed(soe->scans[cy->read_scan]);
        if (!cy->read_matches_seed) break;
    }
    bool success = run_sbo == 0;
    const auto issued = cycles.empty() ? 0 : cycles.front()->issued_ns;
    const long long completed = cycles.empty() ? 0 : cycles.back()->completed_ns.load();
    if (run_sbo) {
        const size_t want = sbo_cycles ? static_cast<size_t>(sbo_cycles) : 1;
        success = cycles.size() == want && std::all_of(cycles.begin(), cycles.end(), [&](const std::shared_ptr<Cycle>& cy) {
            return cy->ok.load() && cy->callbacks.load() == 1 && (!sbo_cycles || cy->read_matches_seed); });
    }
    if (close_grace_ms) std::this_thread::sleep_for(std::chrono::milliseconds(close_grace_ms));
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
    std::ostringstream cycles_json;
    cycles_json << "[";
    for (size_t i = 0; i < cycles.size(); ++i) {
        const auto& cy = *cycles[i];
        cycles_json << (i ? "," : "") << "{\"cycle\":" << cy.cycle << ",\"on_time_ms\":" << cy.on_time_ms
                    << ",\"issued_ns\":" << cy.issued_ns << ",\"completed_ns\":" << cy.completed_ns.load()
                    << ",\"callbacks\":" << cy.callbacks.load() << ",\"summary\":" << cy.summary.load()
                    << ",\"points\":" << cy.points.load() << ",\"index\":" << cy.index.load()
                    << ",\"status\":" << cy.status.load() << ",\"state\":" << cy.state.load()
                    << ",\"ok\":" << (cy.ok.load() ? "true" : "false")
                    << ",\"read_completed\":" << (cy.read_completed ? "true" : "false")
                    << ",\"read_matches_seed\":" << (cy.read_matches_seed ? "true" : "false") << "}";
    }
    cycles_json << "]";
    const size_t expectedScans = static_cast<size_t>(reads) + static_cast<size_t>(sbo_cycles);
    const bool allReadsMatch = soe->scans.size() == expectedScans &&
        std::all_of(soe->scans.begin(), soe->scans.end(), [](const ScanResult& s) { return s.completed && matchesSeed(s); });
    std::cout << "{\"success\":" << (success && allReadsMatch ? "true" : "false")
               << ",\"application_calls\":" << cycles.size() << ",\"opens\":" << listener->opens
               << ",\"sbo_cycles\":" << sbo_cycles << ",\"actuation\":\"software_handler\""
               << ",\"read_pause_ms\":" << read_pause_ms << ",\"run_sbo\":" << (run_sbo ? "true" : "false")
               << ",\"close_grace_ms\":" << close_grace_ms
               << ",\"pre_read_grace_ms\":" << pre_read_grace_ms
               << ",\"pre_read_ready_ns\":" << pre_read_ready_ns
               << ",\"first_read_issued_ns\":" << first_read_issued_ns
               << ",\"issued_ns\":" << issued << ",\"completed_ns\":" << completed
               << ",\"reads_requested\":" << reads << ",\"reads_completed\":" << soe->scans.size()
               << ",\"all_reads_match_seed\":" << (allReadsMatch ? "true" : "false")
               << ",\"reads\":" << reads_json.str() << ",\"cycles\":" << cycles_json.str() << "}\n";
    return (success && allReadsMatch) ? 0 : 3;
}

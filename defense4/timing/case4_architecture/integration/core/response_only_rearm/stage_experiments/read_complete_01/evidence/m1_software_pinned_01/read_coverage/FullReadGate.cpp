// SPDX-License-Identifier: Apache-2.0
//
// Full-READ endpoint for Dr. Lin's 2026-10-19 measurement-object padding study.
// Minimal change of SocketGatePad58B.cpp: same pinned OpenDNP3 stack, same
// outstation/master roles and SELECT/OPERATE wiring, but the outstation
// database holds several measurement types and the master can issue a
// Class 0 or integrity READ instead of only ScanRange(G10V2, 0..22).
//
// Database (default static variations of OpenDNP3 4648fcb):
//   binary input        G1V2   index 0..15      1 octet per point (flags+state)
//   binary output status G10V2 index 0..22      1 octet per point (the existing 23)
//   analog input        G30V1  index 0..20      5 octets per point (flags + INT32)
//                               (the SEL-751 analog map of the paper, Table tab:pointmap)
//   counter             G20V1  index 0..7       5 octets per point (flags + UINT32)
//   db=large adds analog 21..41 (a second feeder) so that a full READ exceeds one
//   transport segment and the natural DNP3 segmentation is visible.
//
// The master records every delivered point of every type and every IIN it
// receives; the runner compares them to the fixture it reads from --fixture.
//
// Private software endpoints only. No device I/O or physical output callbacks.
#include "DecoyGateCommandHandler.h"
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/app/ClassField.h>
#include <opendnp3/app/GroupVariationID.h>
#include <opendnp3/app/MeasurementTypes.h>
#include <opendnp3/channel/IChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/IMasterApplication.h>
#include <opendnp3/master/HeaderTypes.h>
#include <opendnp3/master/ICommandTaskResult.h>
#include <opendnp3/master/ISOEHandler.h>
#include <opendnp3/outstation/DatabaseConfig.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/UpdateBuilder.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
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
    Handler() : SimpleCommandHandler(CommandStatus::NOT_SUPPORTED) {}
    CommandStatus Select(const ControlRelayOutputBlock& cmd, uint16_t index) override { return gate.Select(cmd, index); }
    CommandStatus Operate(const ControlRelayOutputBlock& cmd, uint16_t index, IUpdateHandler& update, OperateType type) override {
        return gate.Operate(cmd, index, update, type);
    }
};

// Fixture values. Analog 0..20 follow the SEL-751 analog map (IA_MAG .. AI304) with plausible integers.
static const int32_t ANALOG[42] = {
    412, 405, 418, 3, 9, 412, 2, 60, 13210, 13195, 13230, 7625, 4, 9310, 2120, 9550, 97, 0, 0, 0, 0,
    388, 391, 379, 2, 6, 386, 1, 60, 13180, 13170, 13205, 7610, 3, 8790, 1985, 9010, 98, 0, 0, 0, 0};
static bool biValue(uint16_t i) { return (i % 3) == 0; }
static bool bosValue(uint16_t i) { return (i % 2) == 0; }
static uint32_t counterValue(uint16_t i) { return 1000u * (i + 1) + 7u; }

struct Point { double value; uint8_t flags; };
struct ScanResult { std::map<std::string, Point> points; bool completed = false; long long begin_ns = 0, end_ns = 0; };

class RecordingSOEHandler final : public ISOEHandler {
public:
    std::mutex m;
    std::vector<ScanResult> scans;
    std::atomic<size_t> completedScans{0};
    std::map<std::string, int> other;  // types the fixture does not configure (events, etc.)
    void BeginFragment(const ResponseInfo&) override { std::lock_guard<std::mutex> g(m); scans.emplace_back(); scans.back().begin_ns = now_ns(); }
    void EndFragment(const ResponseInfo&) override {
        std::lock_guard<std::mutex> g(m);
        if (!scans.empty()) { scans.back().completed = true; scans.back().end_ns = now_ns(); completedScans.fetch_add(1, std::memory_order_release); }
    }
    template<class T> void put(const char* kind, const HeaderInfo&, const ICollection<Indexed<T>>& values) {
        std::lock_guard<std::mutex> g(m);
        if (scans.empty()) scans.emplace_back();
        values.ForeachItem([&](const Indexed<T>& item) {
            std::ostringstream key; key << kind << ":" << item.index;
            scans.back().points[key.str()] = Point{static_cast<double>(item.value.value), item.value.flags.value};
        });
    }
    void Process(const HeaderInfo& i, const ICollection<Indexed<Binary>>& v) override { put("bi", i, v); }
    void Process(const HeaderInfo&, const ICollection<Indexed<DoubleBitBinary>>&) override { std::lock_guard<std::mutex> g(m); other["dbbi"]++; }
    void Process(const HeaderInfo& i, const ICollection<Indexed<Analog>>& v) override { put("ai", i, v); }
    void Process(const HeaderInfo& i, const ICollection<Indexed<Counter>>& v) override { put("ctr", i, v); }
    void Process(const HeaderInfo&, const ICollection<Indexed<FrozenCounter>>&) override { std::lock_guard<std::mutex> g(m); other["fctr"]++; }
    void Process(const HeaderInfo& i, const ICollection<Indexed<BinaryOutputStatus>>& v) override { put("bos", i, v); }
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogOutputStatus>>&) override { std::lock_guard<std::mutex> g(m); other["aos"]++; }
    void Process(const HeaderInfo&, const ICollection<Indexed<OctetString>>&) override { std::lock_guard<std::mutex> g(m); other["octet"]++; }
    void Process(const HeaderInfo&, const ICollection<Indexed<TimeAndInterval>>&) override { std::lock_guard<std::mutex> g(m); other["tai"]++; }
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryCommandEvent>>&) override { std::lock_guard<std::mutex> g(m); other["bce"]++; }
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogCommandEvent>>&) override { std::lock_guard<std::mutex> g(m); other["ace"]++; }
    void Process(const HeaderInfo&, const ICollection<DNPTime>&) override { std::lock_guard<std::mutex> g(m); other["time"]++; }
};

// Records every IIN and task outcome so that no error is hidden.
class RecordingMasterApplication final : public IMasterApplication {
public:
    std::mutex m;
    std::map<uint16_t, int> iins;              // (LSB<<8|MSB) -> count
    std::map<std::string, int> task_results;   // completion name -> count
    void OnReceiveIIN(const IINField& iin) override { std::lock_guard<std::mutex> g(m); iins[static_cast<uint16_t>(iin.LSB << 8 | iin.MSB)]++; }
    void OnTaskComplete(const TaskInfo& info) override {
        std::lock_guard<std::mutex> g(m); task_results[TaskCompletionSpec::to_human_string(info.result)]++;
    }
    bool AssignClassDuringStartup() override { return false; }
    UTCTimestamp Now() override {
        return UTCTimestamp(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }
};

int main(int argc, char** argv) {
    // argv: outstation host port stop-file lifetime-seconds db(base|large)
    //      master     host port stop-file read-count mode(range|class0|integrity|analog) gap-ms
    if (argc < 7 || !std::getenv("FULL_READ_GATE")) return 64;
    const std::string role = argv[1], host = argv[2];
    const uint16_t port = static_cast<uint16_t>(std::atoi(argv[3]));
    const std::string stop = argv[4];
    DNP3Manager manager(1); auto listener = std::make_shared<Listener>();
    if (role == "outstation") {
        const int lifetime_s = std::atoi(argv[5]);
        const std::string dbname = argv[6];
        if (lifetime_s <= 0 || (dbname != "base" && dbname != "large")) return 64;
        const uint16_t analogs = dbname == "large" ? 42 : 21;
        auto handler = std::make_shared<Handler>();
        auto channel = manager.AddTCPServer("gate", levels::NOTHING, ServerAcceptMode::CloseExisting, IPEndpoint(host, port), listener);
        DatabaseConfig db;
        for (uint16_t i = 0; i < 16; ++i) db.binary_input[i] = BinaryConfig();
        for (uint16_t i = 0; i < 23; ++i) db.binary_output_status[i] = BOStatusConfig();
        for (uint16_t i = 0; i < analogs; ++i) db.analog_input[i] = AnalogConfig();
        for (uint16_t i = 0; i < 8; ++i) db.counter[i] = CounterConfig();
        OutstationStackConfig config{db};
        config.outstation.params.allowUnsolicited = false;
        config.outstation.params.selectTimeout = TimeDuration::Milliseconds(500);
        config.link.LocalAddr = 10; config.link.RemoteAddr = 1; config.link.KeepAliveTimeout = TimeDuration::Max();
        auto station = channel->AddOutstation("outstation", handler, DefaultOutstationApplication::Create(), config);
        UpdateBuilder builder;
        for (uint16_t i = 0; i < 16; ++i) builder.Update(Binary(biValue(i), Flags(0x01)), i);
        for (uint16_t i = 0; i < 23; ++i) builder.Update(BinaryOutputStatus(bosValue(i), Flags(0x01)), i);
        for (uint16_t i = 0; i < analogs; ++i) builder.Update(Analog(ANALOG[i], Flags(0x01)), i);
        for (uint16_t i = 0; i < 8; ++i) builder.Update(Counter(counterValue(i), Flags(0x01)), i);
        station->Apply(builder.Build());
        station->Enable(); std::cout << "READY\n" << std::flush;
        const auto end = Clock::now() + std::chrono::seconds(lifetime_s);
        while (Clock::now() < end && !std::ifstream(stop).good()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        manager.Shutdown();
        std::cout << "{\"db\":\"" << dbname << "\",\"opens\":" << listener->opens << "}\n";
        return 0;
    }
    if (role != "master") return 64;
    const int reads = std::atoi(argv[5]);
    const std::string mode = argv[6];
    const int gap_ms = argc > 7 ? std::atoi(argv[7]) : 25;
    if (reads <= 0 || gap_ms < 0 || (mode != "range" && mode != "class0" && mode != "integrity" && mode != "analog")) return 64;
    auto retry = ChannelRetry(TimeDuration::Seconds(60), TimeDuration::Seconds(60), TimeDuration::Seconds(60));
    auto channel = manager.AddTCPClient("gate", levels::NOTHING, retry, {IPEndpoint(host, port)}, "", listener);
    MasterStackConfig config;
    config.master.disableUnsolOnStartup = false; config.master.startupIntegrityClassMask = ClassField::None();
    config.master.unsolClassMask = ClassField::None(); config.master.ignoreRestartIIN = true;
    config.master.responseTimeout = TimeDuration::Milliseconds(500);
    config.link.LocalAddr = 1; config.link.RemoteAddr = 10; config.link.KeepAliveTimeout = TimeDuration::Max();
    auto soe = std::make_shared<RecordingSOEHandler>();
    auto app = std::make_shared<RecordingMasterApplication>();
    auto master = channel->AddMaster("master", soe, app, config);
    master->Enable();
    const auto connectDeadline = Clock::now() + std::chrono::seconds(5);
    while (!listener->open && Clock::now() < connectDeadline) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    if (!listener->open) { manager.Shutdown(); return 2; }
    for (int i = 0; i < reads; ++i) {
        const size_t before = soe->completedScans.load(std::memory_order_acquire);
        if (mode == "range") master->ScanRange(GroupVariationID(10, 2), 0, 22, soe);
        else if (mode == "class0") master->ScanClasses(ClassField(PointClass::Class0), soe);
        else if (mode == "integrity") master->ScanClasses(ClassField::AllClasses(), soe);
        else master->ScanRange(GroupVariationID(30, 0), 0, 20, soe);
        const auto deadline = Clock::now() + std::chrono::seconds(3);
        while (soe->completedScans.load(std::memory_order_acquire) <= before && Clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (gap_ms) std::this_thread::sleep_for(std::chrono::milliseconds(gap_ms));
    }
    manager.Shutdown();
    std::ostringstream out;
    out << "{\"mode\":\"" << mode << "\",\"reads_requested\":" << reads << ",\"opens\":" << listener->opens << ",\"scans\":[";
    for (size_t i = 0; i < soe->scans.size(); ++i) {
        const auto& s = soe->scans[i];
        out << (i ? "," : "") << "{\"completed\":" << (s.completed ? "true" : "false")
            << ",\"begin_ns\":" << s.begin_ns << ",\"end_ns\":" << s.end_ns << ",\"points\":{";
        bool first = true;
        for (const auto& kv : s.points) {
            out << (first ? "" : ",") << "\"" << kv.first << "\":[" << kv.second.value << "," << static_cast<int>(kv.second.flags) << "]";
            first = false;
        }
        out << "}}";
    }
    out << "],\"other_types\":{";
    bool first = true;
    for (const auto& kv : soe->other) { out << (first ? "" : ",") << "\"" << kv.first << "\":" << kv.second; first = false; }
    out << "},\"iin\":{";
    first = true;
    for (const auto& kv : app->iins) { out << (first ? "" : ",") << "\"" << std::hex << kv.first << std::dec << "\":" << kv.second; first = false; }
    out << "},\"tasks\":{";
    first = true;
    for (const auto& kv : app->task_results) { out << (first ? "" : ",") << "\"" << kv.first << "\":" << kv.second; first = false; }
    out << "}}\n";
    std::cout << out.str();
    return 0;
}

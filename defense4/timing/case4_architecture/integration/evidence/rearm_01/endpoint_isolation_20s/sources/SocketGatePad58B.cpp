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
#include <iterator>
#include <string>
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

// Opt-in pre-READ permission (isolation endpoint only). CASE4_PRE_READ_PERMIT names a JSON file the
// harness writes atomically after its own checks. At the scheduled first-READ time (readiness + grace) the
// master polls it until scheduled + PERMIT_GRACE_MS. It issues the first READ only for a strictly parsed
// {"run":CASE4_PRE_READ_RUN,"ready_ns":this readiness,"opens":opens at readiness,"grant":true,
// "granted_ns":ready_ns < g <= now} (steady clock, same host). Otherwise it exits before any READ:
// 75 = no permit before the deadline (absent or late), 76 = a permit that is present but refused.
static const long long PERMIT_GRACE_MS = 2000;
static const int PERMIT_ABSENT_RC = 75, PERMIT_REFUSED_RC = 76;

static bool validRunLabel(const char* text) {
    if (!text) return false;
    size_t n = 0;
    for (const char* p = text; *p; ++p, ++n) {
        const char c = *p;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == ':' || c == '-') || n >= 128) return false;
    }
    return n > 0;
}

struct Permit { std::string run; long long ready_ns = -1, opens = -1, granted_ns = -1; bool grant = false; };

// Strict flat JSON object: exactly the five keys, no escapes, no duplicates, no trailing data.
static bool parsePermit(const std::string& text, Permit& out, std::string& why) {
    size_t i = 0; int seen = 0;
    auto ws = [&]() { while (i < text.size() && (text[i] == ' ' || text[i] == '\n' || text[i] == '\r' || text[i] == '\t')) ++i; };
    auto str = [&](std::string& value) {
        if (i >= text.size() || text[i] != '"') return false;
        const size_t end = text.find('"', ++i);
        if (end == std::string::npos) return false;
        value = text.substr(i, end - i); i = end + 1;
        for (char c : value) if (c == '\\' || static_cast<unsigned char>(c) < 0x20) return false;
        return true;
    };
    auto integer = [&](long long& value) {
        const size_t start = i; value = 0;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9') {
            if (value > (9223372036854775807LL - (text[i] - '0')) / 10) return false;
            value = value * 10 + (text[i++] - '0');
        }
        return i > start && !(i - start > 1 && text[start] == '0');
    };
    ws();
    if (i >= text.size() || text[i++] != '{') { why = "malformed: not an object"; return false; }
    for (bool first = true;; first = false) {
        ws();
        if (i < text.size() && text[i] == '}' && !first) { ++i; break; }
        if (!first) { if (i >= text.size() || text[i++] != ',') { why = "malformed: separator"; return false; } ws(); }
        std::string key;
        if (!str(key)) { why = "malformed: key"; return false; }
        ws();
        if (i >= text.size() || text[i++] != ':') { why = "malformed: colon"; return false; }
        ws();
        static const char* names[] = {"run", "ready_ns", "opens", "grant", "granted_ns"};
        int slot = -1;
        for (int k = 0; k < 5; ++k) if (key == names[k]) slot = k;
        if (slot < 0) { why = "malformed: unknown key " + key; return false; }
        if (seen & (1 << slot)) { why = "malformed: duplicate key " + key; return false; }
        seen |= 1 << slot;
        bool ok = false;
        if (slot == 0) ok = str(out.run);
        else if (slot == 3) {
            if (text.compare(i, 4, "true") == 0) { out.grant = true; i += 4; ok = true; }
            else if (text.compare(i, 5, "false") == 0) { out.grant = false; i += 5; ok = true; }
        } else ok = integer(slot == 1 ? out.ready_ns : slot == 2 ? out.opens : out.granted_ns);
        if (!ok) { why = "malformed: value of " + key; return false; }
    }
    ws();
    if (i != text.size()) { why = "malformed: trailing data"; return false; }
    if (seen != 31) { why = "malformed: missing key"; return false; }
    return true;
}

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
    int read_pause_ms, run_sbo, close_grace_ms, pre_read_grace_ms;
    if (!envUnsigned("CASE4_READ_PAUSE_MS", 25, 5000, read_pause_ms) ||
        !envUnsigned("CASE4_RUN_SBO", 1, 1, run_sbo) ||
        !envUnsigned("CASE4_CLOSE_GRACE_MS", 0, 5000, close_grace_ms) ||
        !envUnsigned("CASE4_PRE_READ_GRACE_MS", 0, 20000, pre_read_grace_ms)) return 64;
    const char* permit_path = std::getenv("CASE4_PRE_READ_PERMIT");
    const char* permit_run = std::getenv("CASE4_PRE_READ_RUN");
    if (permit_path && (!*permit_path || !validRunLabel(permit_run) || !std::getenv("CASE4_PRE_READ_MARKER"))) {
        std::cerr << "CASE4_PRE_READ_PERMIT requires a non-empty path, CASE4_PRE_READ_RUN matching "
                     "[A-Za-z0-9._:-]{1,128} and CASE4_PRE_READ_MARKER\n";
        return 64;
    }
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
    const int ready_opens = listener->opens;
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
    long long permit_granted_ns = 0, permit_accepted_ns = 0;
    if (permit_path) {
        const long long deadline_ns = pre_read_ready_ns + pre_read_grace_ms * 1000000LL + PERMIT_GRACE_MS * 1000000LL;
        int rc = PERMIT_ABSENT_RC; std::string why = "absent: no permit before the deadline";
        for (;;) {
            std::ifstream file(permit_path, std::ios::binary);
            if (file.is_open()) {
                std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                const long long checked = now_ns();
                Permit permit; rc = PERMIT_REFUSED_RC;
                if (file.bad() || text.size() > 4096) why = "malformed: unreadable or oversized";
                else if (!parsePermit(text, permit, why)) {}
                else if (permit.run != permit_run) why = "wrong run";
                else if (permit.ready_ns != pre_read_ready_ns) why = "wrong ready_ns";
                else if (permit.opens != ready_opens || listener->opens != ready_opens || !listener->open) why = "wrong opens or reconnect";
                else if (!permit.grant) why = "grant false";
                else if (permit.granted_ns <= pre_read_ready_ns || permit.granted_ns > checked) why = "granted_ns not after readiness";
                else if (checked > deadline_ns) { rc = PERMIT_ABSENT_RC; why = "late: permit read after the deadline"; }
                else { rc = 0; permit_granted_ns = permit.granted_ns; permit_accepted_ns = checked; }
                break;
            }
            if (now_ns() >= deadline_ns) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (rc) {
            std::cerr << "CASE4_PRE_READ_PERMIT refused (" << why << "); exiting before any READ\n";
            manager.Shutdown();
            std::cout << "{\"success\":false,\"pre_read_permit_refused\":true,\"permit_rc\":" << rc
                      << ",\"pre_read_grace_ms\":" << pre_read_grace_ms << ",\"pre_read_ready_ns\":" << pre_read_ready_ns
                      << ",\"first_read_issued_ns\":0,\"reads_completed\":0}\n";
            return rc;
        }
    }
    for (int i = 0; i < reads; ++i) {
        const size_t before = soe->completedScans.load(std::memory_order_acquire);
        if (i == 0) first_read_issued_ns = now_ns();
        if (range_bits == 8) master->Scan({Header::Range8(10, 2, 0, 22)}, soe);
        else master->ScanRange(GroupVariationID(10, 2), 0, 22, soe);
        const auto deadline = Clock::now() + std::chrono::seconds(3);
        while (soe->completedScans.load(std::memory_order_acquire) <= before && Clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        if (read_pause_ms) std::this_thread::sleep_for(std::chrono::milliseconds(read_pause_ms));
        if (gap_ms) std::this_thread::sleep_for(std::chrono::milliseconds(gap_ms));
    }
    std::atomic<bool> done{false}, success{run_sbo == 0};
    const auto issued = run_sbo ? now_ns() : 0; long long completed = 0;
    if (run_sbo) {
        master->SelectAndOperate(ControlRelayOutputBlock(OperationType::PULSE_ON, TripCloseCode::NUL, false, 1, 100, 100), 1,
            [&](const ICommandTaskResult& result) {
                bool ok = result.summary == TaskCompletion::SUCCESS; int count = 0;
                result.ForeachItem([&](const CommandPointResult& p) { ++count; ok = ok && p.index==1 && p.status==CommandStatus::SUCCESS && p.state==CommandPointState::SUCCESS; });
                success = ok && count == 1; completed = now_ns(); done = true;
            });
        const auto sboDeadline = Clock::now() + std::chrono::seconds(3);
        while (!done && Clock::now() < sboDeadline) std::this_thread::sleep_for(std::chrono::milliseconds(2));
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
    const bool allReadsMatch = soe->scans.size() == static_cast<size_t>(reads) &&
        std::all_of(soe->scans.begin(), soe->scans.end(), [](const ScanResult& s) { return s.completed && matchesSeed(s); });
    std::cout << "{\"success\":" << (success && allReadsMatch ? "true" : "false")
               << ",\"application_calls\":" << run_sbo << ",\"opens\":" << listener->opens
               << ",\"read_pause_ms\":" << read_pause_ms << ",\"run_sbo\":" << (run_sbo ? "true" : "false")
               << ",\"close_grace_ms\":" << close_grace_ms
               << ",\"pre_read_grace_ms\":" << pre_read_grace_ms
               << ",\"pre_read_ready_ns\":" << pre_read_ready_ns
               << ",\"first_read_issued_ns\":" << first_read_issued_ns;
    if (permit_path)
        std::cout << ",\"pre_read_permit\":{\"run\":\"" << permit_run << "\",\"granted_ns\":" << permit_granted_ns
                  << ",\"accepted_ns\":" << permit_accepted_ns << "}";
    std::cout
               << ",\"issued_ns\":" << issued << ",\"completed_ns\":" << completed
               << ",\"reads_requested\":" << reads << ",\"reads_completed\":" << soe->scans.size()
               << ",\"all_reads_match_seed\":" << (allReadsMatch ? "true" : "false")
               << ",\"reads\":" << reads_json.str() << "}\n";
    return (success && allReadsMatch) ? 0 : 3;
}

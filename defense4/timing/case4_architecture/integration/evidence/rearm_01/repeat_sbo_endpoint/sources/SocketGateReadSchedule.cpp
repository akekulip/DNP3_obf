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
//
// READ-class schedule fork (2026-10-21). A copy of SocketGatePad58B.cpp (sha256 84ff5bc9..., kept unchanged as the
// pinned record) with two additions, both off by default:
//   CASE4_READ_SCHEDULE=rotate4  (master) READ slot k, counted over every READ on the connection (the leading READs,
//                                then the READ after each SELECT/OPERATE cycle), issues class ORDER[k % 4] with
//                                ORDER = range, analog, class0, integrity. Requires CASE4_DB on the master too, so it
//                                can check every response against the fixture of its class.
//   CASE4_DB=base|large          (outstation) the FullReadGate.cpp database (full_read_01): BI G1 0..15, BOS G10 0..22
//                                (the existing seed), AI G30 0..20 (base) or 0..41 (large), counter G20 0..7. Unset
//                                keeps the existing 23-point BOS database.
// READ requests: range = the existing READ (G10V2 0..22, read-range 8 or 16); analog = ScanRange G30V0 0..20;
// class0 = ScanClasses(Class0); integrity = ScanClasses(AllClasses). With both variables unset every wire byte is the
// existing workload's. The master appends one read_commands record per issued READ (class, request objects, response
// headers, response APDU and link octets derived from the decoded headers, fixture match, success).
//
// Two-READ-target extension (2026-10-22). A fifth class, mixed = ONE READ request carrying two object headers,
// Scan({Range8(1,2,0,15), Range8(30,1,0,7)}): G1V2 binary inputs 0..15 and G30V1 analog inputs 0..7 from the base
// database (one native link frame, 91 encoded octets). New schedules: mixed_full (slot k: mixed if k even, integrity
// if odd), and the single-class mixed and full (= integrity) for recovery blocks. rotate4 is unchanged.
//   CASE4_PAD_EXPECT=<class>=<n>[,<class>=<n>]  (master) the padding a switch is declared to add, per class: exactly n
//                                G1V2 points at indices 1024..1024+n-1, each value 0 and flags 0x00 (the encoder's zero
//                                object octets), in ONE header (qualifier 0x01) that precedes every original header.
//                                The check is strict: the original points must be exactly the class fixture (values,
//                                flags), with no repeated index of any type, and -- for mixed, integrity and class0 --
//                                in the class's exact native header structure (group/variation, qualifier, count, in
//                                order); the padding must be exactly the declared set. A class with no declaration (or
//                                the variable unset) must contain NO added point, so a padding-off arm fails on any
//                                padding. Declaring a class the schedule never issues is rejected. The master does
//                                NOT see the response IIN or link/transport octets: the capture readout checks those.
// The derived response_*_octets fields count the ORIGINAL headers only (the native size); padding_points reports the
// added points. The capture, not this derivation, is the authority on wire length.
#include "DecoyGateCommandHandler.h"
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/app/ClassField.h>
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
#include <string>
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
    bool read_completed = false, read_matches_seed = false; size_t read_scan = 0; const char* read_class = "range";
};

// READ classes of the fixed schedules, in schedule order.
enum ReadClass { RANGE = 0, ANALOG = 1, CLASS0 = 2, INTEGRITY = 3, MIXED = 4 };
static const int READ_CLASSES = 5;
static const char* const READ_CLASS_NAME[READ_CLASSES] = {"range", "analog", "class0", "integrity", "mixed"};
static const ReadClass ROTATE4[4] = {RANGE, ANALOG, CLASS0, INTEGRITY};
static const ReadClass MIXED_FULL[2] = {MIXED, INTEGRITY};

// Reserved padding contract (read_complete_01 vectors, fixture range 1024..4095): the first padding index and the
// object a padded response carries there. Original points never use these indices (the base database ends at 41).
static const uint16_t PAD_FIRST = 1024;

// FullReadGate.cpp fixture (full_read_01), copied unchanged. Analog 0..20 follow the SEL-751 analog map; large adds 21..41.
static const int32_t ANALOG_FIXTURE[42] = {
    412, 405, 418, 3, 9, 412, 2, 60, 13210, 13195, 13230, 7625, 4, 9310, 2120, 9550, 97, 0, 0, 0, 0,
    388, 391, 379, 2, 6, 386, 1, 60, 13180, 13170, 13205, 7610, 3, 8790, 1985, 9010, 98, 0, 0, 0, 0};
// CASE4_FIXTURE_VARIANT=v (both endpoints, 0..9, default 0 = the values above exactly): shifts the binary-input
// pattern, the analog and counter values, and (odd v) adds the RESTART quality bit (0x02) to BI/AI/counter flags, so
// focused cases can show that nothing downstream depends on one capture's measurement bytes. BOS is unchanged.
static int g_variant = 0;
static bool biValue(uint16_t i) { return ((i + g_variant) % 3) == 0; }
static int32_t analogValue(uint16_t i) { return ANALOG_FIXTURE[i] + 1000 * g_variant; }
static uint32_t counterValue(uint16_t i) { return 1000u * (i + 1) + 7u + 100u * static_cast<uint32_t>(g_variant); }
static uint8_t fixtureFlags() { return static_cast<uint8_t>(0x01 | ((g_variant & 1) ? 0x02 : 0x00)); }

// One object header of a received response, as the master's parser delivered it.
// reserved: every object of the header has an index in the reserved padding range (>= PAD_FIRST). A header that mixes
// reserved and original indices is not reserved, and fails the strict check below.
struct HeaderRecord { uint16_t gv; uint8_t qualifier; size_t count; bool event; bool reserved; bool mixes_reserved; };

// One scan's worth of received points: index -> (value, raw flags byte). points holds Binary Output Status (as
// before); bi/ai/ctr hold the other configured types; other counts objects of any type the fixture never configures.
struct ScanResult {
    std::map<uint16_t, std::pair<bool, uint8_t>> points;
    std::map<uint16_t, std::pair<bool, uint8_t>> bi;
    std::map<uint16_t, std::pair<double, uint8_t>> ai, ctr;
    std::vector<HeaderRecord> headers;
    size_t other = 0;
    size_t duplicates = 0;                 // objects whose index repeated one already delivered in this scan
    bool completed = false;
};

// Records every scan's delivered points. Mirrors the
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
    ScanResult& note(const HeaderInfo& info, size_t count) {
        if (scans.empty()) scans.emplace_back();
        scans.back().headers.push_back({static_cast<uint16_t>(info.gv), static_cast<uint8_t>(info.qualifier), count,
                                        info.isEventVariation, false, false});
        return scans.back();
    }
    // Classify the header just noted by the indices it actually carried.
    static void markReserved(ScanResult& scan, size_t reserved, size_t total) {
        auto& h = scan.headers.back();
        h.reserved = total > 0 && reserved == total;
        h.mixes_reserved = reserved > 0 && reserved != total;
    }
    template<class T> void otherType(const HeaderInfo& info, const ICollection<T>& values) {
        note(info, values.Count()).other += values.Count();
    }
    void Process(const HeaderInfo& info, const ICollection<Indexed<Binary>>& values) override {
        auto& scan = note(info, values.Count());
        size_t reserved = 0;
        values.ForeachItem([&](const Indexed<Binary>& item) {
            if (item.index >= PAD_FIRST) ++reserved;
            // A repeated index (an original and a padding point colliding) is kept as a duplicate count so the strict
            // check fails instead of one silently overwriting the other.
            if (scan.bi.count(item.index)) ++scan.duplicates;
            scan.bi[item.index] = std::make_pair(item.value.value, item.value.flags.value);
        });
        markReserved(scan, reserved, values.Count());
    }
    void Process(const HeaderInfo& info, const ICollection<Indexed<DoubleBitBinary>>& values) override { otherType(info, values); }
    void Process(const HeaderInfo& info, const ICollection<Indexed<Analog>>& values) override {
        auto& scan = note(info, values.Count());
        values.ForeachItem([&](const Indexed<Analog>& item) {
            if (scan.ai.count(item.index)) ++scan.duplicates;
            scan.ai[item.index] = std::make_pair(item.value.value, item.value.flags.value);
        });
    }
    void Process(const HeaderInfo& info, const ICollection<Indexed<Counter>>& values) override {
        auto& scan = note(info, values.Count());
        values.ForeachItem([&](const Indexed<Counter>& item) {
            if (scan.ctr.count(item.index)) ++scan.duplicates;
            scan.ctr[item.index] = std::make_pair(static_cast<double>(item.value.value), item.value.flags.value);
        });
    }
    void Process(const HeaderInfo& info, const ICollection<Indexed<FrozenCounter>>& values) override { otherType(info, values); }
    void Process(const HeaderInfo& info, const ICollection<Indexed<BinaryOutputStatus>>& values) override {
        auto& scan = note(info, values.Count());
        values.ForeachItem([&](const Indexed<BinaryOutputStatus>& item) {
            if (scan.points.count(item.index)) ++scan.duplicates;
            scan.points[item.index] = std::make_pair(item.value.value, item.value.flags.value);
        });
    }
    void Process(const HeaderInfo& info, const ICollection<Indexed<AnalogOutputStatus>>& values) override { otherType(info, values); }
    void Process(const HeaderInfo& info, const ICollection<Indexed<OctetString>>& values) override { otherType(info, values); }
    void Process(const HeaderInfo& info, const ICollection<Indexed<TimeAndInterval>>& values) override { otherType(info, values); }
    void Process(const HeaderInfo& info, const ICollection<Indexed<BinaryCommandEvent>>& values) override { otherType(info, values); }
    void Process(const HeaderInfo& info, const ICollection<Indexed<AnalogCommandEvent>>& values) override { otherType(info, values); }
    void Process(const HeaderInfo& info, const ICollection<DNPTime>& values) override { otherType(info, values); }
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

// Original (non-reserved) binary inputs delivered in the scan.
static size_t originalBinaryInputs(const ScanResult& scan) {
    size_t n = 0;
    for (const auto& kv : scan.bi) if (kv.first < PAD_FIRST) ++n;
    return n;
}

// Binary inputs fold the state bit into the wire byte the same way Group10Var2 does. Only the original indices count
// here; reserved-range points are judged by matchesPadding.
static bool matchesBinaryInputs(const ScanResult& scan) {
    if (originalBinaryInputs(scan) != 16) return false;
    for (uint16_t i = 0; i < 16; ++i) {
        auto it = scan.bi.find(i);
        if (it == scan.bi.end() || it->second.first != biValue(i) ||
            it->second.second != ((biValue(i) ? 0x80 : 0x00) | fixtureFlags()))
            return false;
    }
    return true;
}

static bool matchesAnalogs(const ScanResult& scan, uint16_t count) {
    if (scan.ai.size() != count) return false;
    for (uint16_t i = 0; i < count; ++i) {
        auto it = scan.ai.find(i);
        if (it == scan.ai.end() || it->second.first != analogValue(i) || it->second.second != fixtureFlags()) return false;
    }
    return true;
}

static bool matchesCounters(const ScanResult& scan) {
    if (scan.ctr.size() != 8) return false;
    for (uint16_t i = 0; i < 8; ++i) {
        auto it = scan.ctr.find(i);
        if (it == scan.ctr.end() || it->second.first != counterValue(i) || it->second.second != fixtureFlags()) return false;
    }
    return true;
}

// Strict padding check. expected = the declared padding point count for this READ's class (0 = none declared).
// Declared: exactly `expected` G1V2 points at PAD_FIRST..PAD_FIRST+expected-1, each value 0 / flags 0x00, carried in
// exactly one reserved header (G1V2, qualifier 0x01, count expected) that is the FIRST header of the response, so every
// original header follows it in its native order. Not declared: no reserved point and no reserved header at all.
// Any header mixing reserved and original indices, or any repeated index, fails.
static bool matchesPadding(const ScanResult& scan, int expected) {
    if (scan.duplicates) return false;
    size_t reservedHeaders = 0;
    for (const auto& h : scan.headers) {
        if (h.mixes_reserved) return false;
        if (h.reserved) ++reservedHeaders;
    }
    size_t reservedPoints = 0;
    for (const auto& kv : scan.bi) {
        if (kv.first < PAD_FIRST) continue;
        ++reservedPoints;
        if (expected <= 0 || kv.first >= PAD_FIRST + expected) return false;
        if (kv.second.first != false || kv.second.second != 0x00) return false;
    }
    if (expected <= 0) return reservedPoints == 0 && reservedHeaders == 0;
    if (reservedPoints != static_cast<size_t>(expected) || reservedHeaders != 1) return false;
    const auto& first = scan.headers.front();
    return first.reserved && first.gv == 0x0102 && first.qualifier == 0x01 && first.count == static_cast<size_t>(expected);
}

// Exact ORIGINAL header structure for the classes of the two-READ-target profile, as the live master decoded the
// native responses (read_complete_01/evidence/m1_two_read_01): group/variation, qualifier and object count of every
// non-reserved header, in order. The originals must arrive in this structure, not merely as the right index->value
// pairs: a reordered, split, re-qualified or extended original header fails. range and analog keep their existing
// value-set check only.
static bool matchesStructure(const ScanResult& scan, ReadClass cls, bool large) {
    struct Shape { uint16_t gv; uint8_t qualifier; size_t count; };
    std::vector<Shape> want;
    if (cls == MIXED) want = {{0x0102, 0x00, 16}, {0x1E01, 0x00, 8}};
    else if (cls == CLASS0 || cls == INTEGRITY)
        want = {{0x0102, 0x00, 16}, {0x1E01, 0x00, static_cast<size_t>(large ? 42 : 21)}, {0x1401, 0x00, 8}, {0x0A02, 0x00, 23}};
    else return true;
    size_t k = 0;
    for (const auto& h : scan.headers) {
        if (h.reserved) continue;
        if (k >= want.size() || h.gv != want[k].gv || h.qualifier != want[k].qualifier || h.count != want[k].count)
            return false;
        ++k;
    }
    return k == want.size();
}

// The exact point set each class must return from the fixture, and nothing else (no event objects, no other types,
// no repeated index of any type), in the class's exact original header structure, plus exactly the declared padding
// (pad_expected points) and no other added point.
static bool matchesFixture(const ScanResult& scan, ReadClass cls, bool large, int pad_expected) {
    if (!scan.completed || scan.other || scan.duplicates) return false;
    for (const auto& h : scan.headers) if (h.event) return false;
    if (!matchesPadding(scan, pad_expected)) return false;
    if (!matchesStructure(scan, cls, large)) return false;
    switch (cls) {
    case RANGE: return matchesSeed(scan) && originalBinaryInputs(scan) == 0 && scan.ai.empty() && scan.ctr.empty();
    case ANALOG: return matchesAnalogs(scan, 21) && scan.points.empty() && originalBinaryInputs(scan) == 0 && scan.ctr.empty();
    case MIXED: return matchesBinaryInputs(scan) && matchesAnalogs(scan, 8) && scan.points.empty() && scan.ctr.empty();
    default: return matchesSeed(scan) && matchesBinaryInputs(scan) && matchesAnalogs(scan, large ? 42 : 21) &&
                    matchesCounters(scan);
    }
}

// Padding points actually delivered in the scan (reserved-range binary inputs), for the record.
static size_t paddingPoints(const ScanResult& scan) { return scan.bi.size() - originalBinaryInputs(scan); }

// Response APDU octets implied by the decoded headers: control, function, IIN (4), then per header group, variation,
// qualifier (3), its range or count field, and count objects (with their index prefix). Only the static variations
// the fixture uses have a size here; any other header makes the result -1. This is derived, not observed: the
// capture is the authority on wire length.
// Reserved (padding) headers are excluded, so the result is the ORIGINAL response's size; padding is reported apart.
static long apduOctets(const ScanResult& scan) {
    long total = 4;
    for (const auto& h : scan.headers) {
        if (h.reserved) continue;
        long size;
        switch (h.gv) {
        case 0x0102: case 0x0A02: size = 1; break;   // G1V2, G10V2: one flags+state octet
        case 0x1401: case 0x1E01: size = 5; break;   // G20V1, G30V1: flags + 32-bit value
        default: return -1;
        }
        long field, prefix = 0;
        switch (h.qualifier) {
        case 0x00: field = 2; break;
        case 0x01: field = 4; break;
        case 0x07: field = 1; break;
        case 0x08: field = 2; break;
        case 0x17: field = 1; prefix = 1; break;
        case 0x28: field = 2; prefix = 2; break;
        default: return -1;
        }
        total += 3 + field + static_cast<long>(h.count) * (size + prefix);
    }
    return total;
}

// Link octets for an APDU sent as transport segments of at most 249 application octets, each in one link frame
// (10-octet header, one transport octet, a CRC per 16 user octets).
static long linkOctets(long apdu) {
    if (apdu <= 0) return -1;
    long total = 0;
    for (long left = apdu; left > 0; left -= 249) {
        const long user = 1 + std::min(left, 249L);
        total += 10 + user + 2 * ((user + 15) / 16);
    }
    return total;
}

// One issued READ, appended in issue order and never overwritten.
struct ReadCommand {
    int slot = 0; ReadClass cls = RANGE; long long issued_ns = 0, completed_ns = 0;
    bool completed = false; size_t scan_before = 0, scan_after = 0;
};

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
        !envUnsigned("CASE4_SBO_CYCLES", 0, 64, sbo_cycles) ||
        !envUnsigned("CASE4_FIXTURE_VARIANT", 0, 9, g_variant)) return 64;
    // CASE4_SBO_CYCLES=0 (default) keeps the single trailing SBO. N>0 runs N cycles of SELECT->OPERATE then one
    // READ on the same connection after the initial READs, i.e. READ->SELECT->OPERATE->READ repeated N times.
    if (sbo_cycles && !run_sbo) { std::cerr << "CASE4_SBO_CYCLES requires CASE4_RUN_SBO=1\n"; return 64; }
    if (sbo_cycles && role == "master" && reads < 1) { std::cerr << "CASE4_SBO_CYCLES requires at least one leading READ\n"; return 64; }
    // READ-class schedule and database (both off by default; see the header comment).
    const char* schedule_text = std::getenv("CASE4_READ_SCHEDULE");
    const char* db_text = std::getenv("CASE4_DB");
    const std::string schedule = schedule_text ? schedule_text : "";
    const std::string dbname = db_text ? db_text : "legacy";
    std::vector<ReadClass> order;
    if (schedule == "rotate4") order.assign(ROTATE4, ROTATE4 + 4);
    else if (schedule == "mixed_full") order.assign(MIXED_FULL, MIXED_FULL + 2);
    else if (schedule == "mixed") order = {MIXED};
    else if (schedule == "full") order = {INTEGRITY};
    if (schedule_text && order.empty()) {
        std::cerr << "CASE4_READ_SCHEDULE must be rotate4, mixed_full, mixed, full or unset\n"; return 64;
    }
    if (db_text && dbname != "base" && dbname != "large") { std::cerr << "CASE4_DB must be base, large or unset\n"; return 64; }
    if (schedule_text && role == "master" && !db_text) { std::cerr << "CASE4_READ_SCHEDULE requires CASE4_DB=base|large\n"; return 64; }
    // The mixed READ's analog header (0..7) and its 91-octet native are defined for the base database only.
    if (schedule_text && schedule != "rotate4" && dbname != "base") {
        std::cerr << "CASE4_READ_SCHEDULE " << schedule << " requires CASE4_DB=base\n"; return 64;
    }
    const bool scheduled = schedule_text != nullptr, large = dbname == "large";
    auto classOf = [&](int slot) { return scheduled ? order[static_cast<size_t>(slot) % order.size()] : RANGE; };
    // Declared padding per class (see the header comment); strict parse, every class at most once.
    int pad_expect[READ_CLASSES] = {0, 0, 0, 0, 0};
    if (const char* pad_text = std::getenv("CASE4_PAD_EXPECT")) {
        if (role != "master") { std::cerr << "CASE4_PAD_EXPECT is a master control\n"; return 64; }
        bool seen[READ_CLASSES] = {false, false, false, false, false};
        std::string spec = pad_text;
        if (spec.empty()) { std::cerr << "CASE4_PAD_EXPECT must not be empty\n"; return 64; }
        size_t pos = 0;
        while (pos <= spec.size()) {
            const size_t comma = spec.find(',', pos);
            const std::string item = spec.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
            const size_t eq = item.find('=');
            int cls = -1;
            if (eq != std::string::npos)
                for (int c = 0; c < READ_CLASSES; ++c) if (item.substr(0, eq) == READ_CLASS_NAME[c]) cls = c;
            const std::string num = eq == std::string::npos ? "" : item.substr(eq + 1);
            bool digits = !num.empty() && num.size() <= 4;
            for (char ch : num) digits = digits && ch >= '0' && ch <= '9';
            const int n = digits ? std::atoi(num.c_str()) : 0;
            if (cls < 0 || seen[cls] || !digits || n < 1 || n > 4095 - PAD_FIRST + 1) {
                std::cerr << "CASE4_PAD_EXPECT item '" << item << "' must be <class>=<1.." << (4095 - PAD_FIRST + 1)
                          << ">, each class at most once\n";
                return 64;
            }
            seen[cls] = true; pad_expect[cls] = n;
            if (comma == std::string::npos) break;
            pos = comma + 1;
        }
        for (int c = 0; c < READ_CLASSES; ++c)
            if (pad_expect[c] && std::find(order.begin(), order.end(), static_cast<ReadClass>(c)) == order.end()) {
                std::cerr << "CASE4_PAD_EXPECT declares " << READ_CLASS_NAME[c] << ", which the schedule never issues\n";
                return 64;
            }
    }
    if (g_variant && !db_text) { std::cerr << "CASE4_FIXTURE_VARIANT requires CASE4_DB=base|large\n"; return 64; }
    DNP3Manager manager(1); auto listener = std::make_shared<Listener>();
    if (role == "outstation") {
        if (lifetime_s <= 0) return 64;
        auto handler = std::make_shared<Handler>();
        auto channel = manager.AddTCPServer("gate", levels::NOTHING, ServerAcceptMode::CloseExisting, IPEndpoint(host, port), listener);
        const bool full = dbname != "legacy";
        const uint16_t analogs = large ? 42 : 21;
        DatabaseConfig db;
        if (full) for (uint16_t i = 0; i < 16; ++i) db.binary_input[i] = BinaryConfig();
        for (uint16_t i = 0; i < 23; ++i) db.binary_output_status[i] = BOStatusConfig();
        if (full) for (uint16_t i = 0; i < analogs; ++i) db.analog_input[i] = AnalogConfig();
        if (full) for (uint16_t i = 0; i < 8; ++i) db.counter[i] = CounterConfig();
        OutstationStackConfig config{db};
        config.outstation.params.allowUnsolicited = false;
        config.outstation.params.selectTimeout = TimeDuration::Milliseconds(500);
        config.link.LocalAddr = 10; config.link.RemoteAddr = 1; config.link.KeepAliveTimeout = TimeDuration::Max();
        auto station = channel->AddOutstation("outstation", handler, DefaultOutstationApplication::Create(), config);
        UpdateBuilder builder;
        if (full) for (uint16_t i = 0; i < 16; ++i) builder.Update(Binary(biValue(i), Flags(fixtureFlags())), i);
        for (uint16_t i = 0; i < 23; ++i) builder.Update(BinaryOutputStatus((i % 2) == 0, Flags(0x01)), i);
        if (full) for (uint16_t i = 0; i < analogs; ++i) builder.Update(Analog(analogValue(i), Flags(fixtureFlags())), i);
        if (full) for (uint16_t i = 0; i < 8; ++i) builder.Update(Counter(counterValue(i), Flags(fixtureFlags())), i);
        station->Apply(builder.Build());
        station->Enable(); std::cout<<"READY\n"<<std::flush;
        const auto end = Clock::now() + std::chrono::seconds(lifetime_s);
        while (Clock::now() < end && !std::ifstream(stop).good()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        manager.Shutdown();
        std::cout << "{\"select_real\":" << handler->gate.selects(1) << ",\"select_decoy\":" << handler->gate.selects(201)
                   << ",\"operate_real\":" << handler->gate.operates(1) << ",\"operate_decoy\":" << handler->gate.operates(201)
                   << ",\"opens\":" << listener->opens << ",\"select_accept_ns\":" << handler->selected_ns
                   << ",\"operate_accept_ns\":" << handler->operated_ns
                   << ",\"actuation\":\"software_handler\",\"output_driver\":\"none\""
                   << ",\"wired_point_operates\":" << handler->gate.physicalActuations
                   << ",\"db\":\"" << dbname << "\""
                   << ",\"events\":"<< eventsJson(handler->events) << "}\n";
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
    std::vector<ReadCommand> read_commands;                            // one per issued READ, append-only
    auto doRead = [&](int i) {
        const size_t before = soe->completedScans.load(std::memory_order_acquire);
        const ReadClass cls = classOf(i);
        ReadCommand rc; rc.slot = i; rc.cls = cls; rc.scan_before = soe->scans.size();
        if (i == 0) first_read_issued_ns = now_ns();
        rc.issued_ns = now_ns();
        if (cls == MIXED) master->Scan({Header::Range8(1, 2, 0, 15), Header::Range8(30, 1, 0, 7)}, soe);
        else if (cls == ANALOG) master->ScanRange(GroupVariationID(30, 0), 0, 20, soe);
        else if (cls == CLASS0) master->ScanClasses(ClassField(PointClass::Class0), soe);
        else if (cls == INTEGRITY) master->ScanClasses(ClassField::AllClasses(), soe);
        else if (range_bits == 8) master->Scan({Header::Range8(10, 2, 0, 22)}, soe);
        else master->ScanRange(GroupVariationID(10, 2), 0, 22, soe);
        const auto deadline = Clock::now() + std::chrono::seconds(3);
        while (soe->completedScans.load(std::memory_order_acquire) <= before && Clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        rc.completed_ns = now_ns();
        if (read_pause_ms) std::this_thread::sleep_for(std::chrono::milliseconds(read_pause_ms));
        if (gap_ms) std::this_thread::sleep_for(std::chrono::milliseconds(gap_ms));
        rc.completed = soe->completedScans.load(std::memory_order_acquire) > before;
        rc.scan_after = soe->scans.size();
        read_commands.push_back(rc);
        return rc.completed;
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
        cy->read_class = READ_CLASS_NAME[classOf(reads + c)];
        cy->read_completed = doRead(reads + c);
        cy->read_matches_seed = cy->read_completed && cy->read_scan < soe->scans.size() &&
                                matchesFixture(soe->scans[cy->read_scan], classOf(reads + c), large,
                                               pad_expect[classOf(reads + c)]);
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
        // matches_seed: the scan equals the fixture of the class issued in the same slot (range: the 23-point seed).
        reads_json << "{\"completed\":" << (scan.completed ? "true" : "false")
                   << ",\"points_received\":" << scan.points.size()
                   << ",\"class\":\"" << READ_CLASS_NAME[classOf(static_cast<int>(i))] << "\""
                   << ",\"matches_seed\":" << (matchesFixture(scan, classOf(static_cast<int>(i)), large,
                                                              pad_expect[classOf(static_cast<int>(i))]) ? "true" : "false") << "}";
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
                    << ",\"read_class\":\"" << cy.read_class << "\""
                    << ",\"read_matches_seed\":" << (cy.read_matches_seed ? "true" : "false") << "}";
    }
    cycles_json << "]";
    const size_t expectedScans = static_cast<size_t>(reads) + static_cast<size_t>(sbo_cycles);
    const bool allReadsMatch = soe->scans.size() == expectedScans &&
        [&]() { for (size_t i = 0; i < soe->scans.size(); ++i)
                    if (!matchesFixture(soe->scans[i], classOf(static_cast<int>(i)), large,
                                        pad_expect[classOf(static_cast<int>(i))])) return false;
                return true; }();
    // Per issued READ: class, request objects, the response(s) delivered during it, and the fixture check.
    static const char* const REQUEST_OBJECTS[READ_CLASSES] = {"", "g30v0 q0x01 0-20", "g60v1 q0x06",
                                                   "g60v2 q0x06,g60v3 q0x06,g60v4 q0x06,g60v1 q0x06",
                                                   "g1v2 q0x00 0-15,g30v1 q0x00 0-7"};
    std::ostringstream commands_json;
    commands_json << "[";
    std::map<std::string, int> issued_per_class, succeeded_per_class;
    for (size_t k = 0; k < read_commands.size(); ++k) {
        const auto& rc = read_commands[k];
        const size_t fragments = rc.scan_after - rc.scan_before;
        const ScanResult* scan = fragments == 1 ? &soe->scans[rc.scan_before] : nullptr;
        const long apdu = scan ? apduOctets(*scan) : -1;
        const bool fixture = scan && matchesFixture(*scan, rc.cls, large, pad_expect[rc.cls]);
        const bool ok = rc.completed && fixture && apdu > 0;
        issued_per_class[READ_CLASS_NAME[rc.cls]]++; if (ok) succeeded_per_class[READ_CLASS_NAME[rc.cls]]++;
        commands_json << (k ? "," : "") << "{\"seq\":" << k << ",\"slot\":" << rc.slot
                      << ",\"class\":\"" << READ_CLASS_NAME[rc.cls] << "\",\"function\":\"READ\",\"function_code\":1"
                      << ",\"request_objects\":\"" << (rc.cls == RANGE ? (range_bits == 8 ? "g10v2 q0x00 0-22" : "g10v2 q0x01 0-22")
                                                                         : REQUEST_OBJECTS[rc.cls]) << "\""
                      << ",\"issued_ns\":" << rc.issued_ns << ",\"completed_ns\":" << rc.completed_ns
                      << ",\"completed\":" << (rc.completed ? "true" : "false")
                      << ",\"response_fragments\":" << fragments << ",\"response_headers\":[";
        if (scan) for (size_t h = 0; h < scan->headers.size(); ++h) {
            const auto& hd = scan->headers[h];
            commands_json << (h ? "," : "") << "{\"g\":" << (hd.gv >> 8) << ",\"v\":" << (hd.gv & 0xFF)
                          << ",\"q\":" << static_cast<int>(hd.qualifier) << ",\"count\":" << hd.count
                          << ",\"event\":" << (hd.event ? "true" : "false")
                          << ",\"reserved\":" << (hd.reserved ? "true" : "false") << "}";
        }
        commands_json << "],\"response_apdu_octets\":" << apdu << ",\"response_link_octets\":" << linkOctets(apdu)
                      << ",\"length_basis\":\"derived_from_decoded_headers\""
                      << ",\"padding_expected\":" << pad_expect[rc.cls]
                      << ",\"padding_points\":" << (scan ? paddingPoints(*scan) : 0)
                      << ",\"points_received\":" << (scan ? scan->points.size() + scan->bi.size() + scan->ai.size() +
                                                               scan->ctr.size() + scan->other : 0)
                      << ",\"matches_fixture\":" << (fixture ? "true" : "false")
                      << ",\"success\":" << (ok ? "true" : "false") << "}";
    }
    commands_json << "]";
    std::ostringstream per_class_json;
    per_class_json << "{";
    // The four original classes are always listed (the existing record); mixed only when the schedule issues it.
    const bool lists_mixed = std::find(order.begin(), order.end(), MIXED) != order.end();
    for (int c = 0; c < (lists_mixed ? READ_CLASSES : 4); ++c)
        per_class_json << (c ? "," : "") << "\"" << READ_CLASS_NAME[c] << "\":{\"issued\":" << issued_per_class[READ_CLASS_NAME[c]]
                       << ",\"succeeded\":" << succeeded_per_class[READ_CLASS_NAME[c]] << "}";
    per_class_json << "}";
    const bool allCommandsOk = std::all_of(read_commands.begin(), read_commands.end(), [&](const ReadCommand& rc) {
        const size_t f = rc.scan_after - rc.scan_before;
        return rc.completed && f == 1 && matchesFixture(soe->scans[rc.scan_before], rc.cls, large, pad_expect[rc.cls]) &&
               apduOctets(soe->scans[rc.scan_before]) > 0; });
    std::cout << "{\"success\":" << (success && allReadsMatch && allCommandsOk ? "true" : "false")
               << ",\"application_calls\":" << cycles.size() << ",\"opens\":" << listener->opens
               << ",\"sbo_cycles\":" << sbo_cycles << ",\"actuation\":\"software_handler\""
               << ",\"read_pause_ms\":" << read_pause_ms << ",\"run_sbo\":" << (run_sbo ? "true" : "false")
               << ",\"close_grace_ms\":" << close_grace_ms
               << ",\"pre_read_grace_ms\":" << pre_read_grace_ms
               << ",\"pre_read_ready_ns\":" << pre_read_ready_ns
               << ",\"first_read_issued_ns\":" << first_read_issued_ns
               << ",\"issued_ns\":" << issued << ",\"completed_ns\":" << completed
               << ",\"reads_requested\":" << expectedScans << ",\"reads_completed\":" << soe->scans.size()
               << ",\"all_reads_match_seed\":" << (allReadsMatch ? "true" : "false")
               << ",\"read_schedule\":\"" << (scheduled ? schedule : "none") << "\",\"db\":\"" << dbname << "\""
               << ",\"pad_expect\":\"" << (std::getenv("CASE4_PAD_EXPECT") ? std::getenv("CASE4_PAD_EXPECT") : "none") << "\""
               << ",\"read_commands_ok\":" << (allCommandsOk ? "true" : "false")
               << ",\"reads_per_class\":" << per_class_json.str()
               << ",\"reads\":" << reads_json.str() << ",\"cycles\":" << cycles_json.str()
               << ",\"read_commands\":" << commands_json.str() << "}\n";
    return (success && allReadsMatch && allCommandsOk) ? 0 : 3;
}

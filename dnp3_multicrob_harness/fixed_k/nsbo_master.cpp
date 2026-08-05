// nsbo_master.cpp -- HARDENED persistent multi-SBO master for the fixed-K Defense 4 EMULATOR
// experiment. Opens ONE TCP connection to an OpenDNP3 emulator outstation and issues N sequential
// Select-Before-Operate transactions, each a CommandSet of K CROBs (G12V1). One TCP setup, no
// FIN/RST between transactions, one teardown at the end.
//
// EMULATOR ONLY. Fail-closed target guard (inet_pton allowlist) refuses everything except
// 127.0.0.1 / localhost(loopback) / 10.10.54.158 (Hulk emulator). The physical SEL-751, the Tofino
// management address, and arbitrary 10.10.54.* are refused.
//
// Hardening (reviewed): owned shared_ptr callback state (no stack-promise-by-ref UAF); channel
// readiness via IChannelListener OPEN latch (no blind sleep); abort the block on any non-SUCCESS
// or timeout; strict inet_pton address allowlist; strict index/mode/K validation; atomic
// temp+rename JSON that is always valid even on a controlled failure; single manager.Shutdown().
// C++14 (no std::optional).
//
// Build:  ./build.sh    (do NOT commit the compiled binary)
// Usage:  nsbo_master --host H --reps N --indexes CSV --mode alt|on|off --out PATH
//                     --expect-k K [--expect-r R] [--block-id ID] [--seed S]
// Exit codes: 0 all SUCCESS | 1 block aborted | 2 usage/parse | 3 target refused |
//             4 input validation | 5 evidence path | 6 no comms (channel never OPEN)
#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/IChannelListener.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/PrintingSOEHandler.h>
#include <opendnp3/master/CommandSet.h>
#include <opendnp3/master/CommandPointResult.h>
#include <opendnp3/app/ControlRelayOutputBlock.h>
#include <opendnp3/app/Indexed.h>
#include <opendnp3/gen/ChannelState.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace opendnp3;

static constexpr uint16_t EMU_MAX_INDEX = 31;

static double now_epoch()
{
    using namespace std::chrono;
    return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}

static int fail(int code, const std::string& why)
{
    std::cerr << "nsbo_master: " << why << " (exit " << code << ")\n";
    return code;
}

static std::string json_escape(const std::string& s)
{
    std::string o;
    for (char c : s) { if (c == '"' || c == '\\') o.push_back('\\'); if (c >= 0x20) o.push_back(c); }
    return o;
}

// ---- Defect 4: fail-closed address allowlist via strict parsing ----
static bool is_allowed_v4(uint32_t hbo)
{
    return hbo == INADDR_LOOPBACK || hbo == ntohl(inet_addr("10.10.54.158"));
}
static bool target_allowed(const std::string& host, std::string& why)
{
    if (host == "localhost")
    {
        struct addrinfo hints; std::memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) { why = "localhost did not resolve"; return false; }
        bool ok = false;
        for (auto* p = res; p; p = p->ai_next) {
            auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            if (is_allowed_v4(ntohl(sa->sin_addr.s_addr))) { ok = true; break; }
        }
        freeaddrinfo(res);
        if (!ok) why = "localhost resolved outside the loopback allowlist";
        return ok;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, host.c_str(), &a) != 1) { why = "host '" + host + "' is not a valid IPv4 literal"; return false; }
    if (!is_allowed_v4(ntohl(a.s_addr))) {
        why = "host '" + host + "' is not an allowed emulator target (127.0.0.1 / localhost / 10.10.54.158 only)";
        return false;
    }
    return true;
}

// strict integer list parse: reject empty/non-numeric tokens (return false)
static bool parse_ints_strict(const std::string& csv, std::vector<long>& out)
{
    std::stringstream ss(csv); std::string tok;
    while (std::getline(ss, tok, ',')) {
        size_t b = tok.find_first_not_of(" \t"), e = tok.find_last_not_of(" \t");
        if (b == std::string::npos) return false;
        tok = tok.substr(b, e - b + 1);
        char* end = nullptr; errno = 0;
        long v = std::strtol(tok.c_str(), &end, 10);
        if (errno != 0 || end == tok.c_str() || *end != '\0') return false;
        out.push_back(v);
    }
    return !out.empty();
}

// ---- Defect 2: channel readiness latch ----
class OpenLatch : public IChannelListener
{
public:
    void OnStateChange(ChannelState s) override
    {
        std::lock_guard<std::mutex> lk(mtx_);
        last_ = s; if (s == ChannelState::OPEN) open_ = true; cv_.notify_all();
    }
    bool wait_open(std::chrono::milliseconds budget)
    {
        std::unique_lock<std::mutex> lk(mtx_);
        return cv_.wait_for(lk, budget, [&] { return open_; });
    }
private:
    std::mutex mtx_; std::condition_variable cv_;
    bool open_ = false; ChannelState last_ = ChannelState::CLOSED;
};

// ---- Defect 1: owned callback state ----
struct PointOutcome { uint16_t index; std::string state; std::string status; };
struct TaskState {
    std::mutex mtx; std::condition_variable cv;
    bool completed = false;
    TaskCompletion summary = TaskCompletion::FAILURE_NO_COMMS;
    std::vector<PointOutcome> points;
};
static TaskCompletion run_one_sbo(IMaster& master, CommandSet&& set,
                                  std::chrono::milliseconds budget,
                                  std::vector<PointOutcome>& points_out)
{
    auto st = std::make_shared<TaskState>();
    auto cb = [st](const ICommandTaskResult& r) {
        std::vector<PointOutcome> pts; pts.reserve(r.Count());
        r.ForeachItem([&pts](const CommandPointResult& p) {
            pts.push_back({p.index, CommandPointStateSpec::to_string(p.state),
                           CommandStatusSpec::to_string(p.status)});
        });
        { std::lock_guard<std::mutex> lk(st->mtx);
          st->summary = r.summary; st->points = std::move(pts); st->completed = true; }
        st->cv.notify_one();
    };
    master.SelectAndOperate(std::move(set), cb);
    std::unique_lock<std::mutex> lk(st->mtx);
    if (!st->cv.wait_for(lk, budget, [&] { return st->completed; }))
        return TaskCompletion::FAILURE_RESPONSE_TIMEOUT;   // owned state stays alive for a late cb
    points_out = st->points;
    return st->summary;
}

struct TxnRecord { int ordinal; std::string code; double t_issue, t_complete;
                   std::string task_result; std::vector<PointOutcome> points; };
struct Meta { std::string host, mode, block_id; int reps, k, r; long seed;
              std::vector<long> indexes; int ok; };

static int write_evidence(const std::string& out, const std::string& tmp, const Meta& m,
                          const std::vector<TxnRecord>& txns, bool aborted, int abort_rep,
                          const std::string& abort_reason)
{
    std::ostringstream js;
    js << "{\n  \"host\": \"" << json_escape(m.host) << "\", \"reps\": " << m.reps
       << ", \"K\": " << m.k << ", \"R\": " << m.r << ", \"code_mode\": \"" << m.mode
       << "\",\n  \"block_id\": \"" << json_escape(m.block_id) << "\", \"seed\": " << m.seed
       << ",\n  \"indexes\": [";
    for (size_t i = 0; i < m.indexes.size(); ++i) js << (i ? "," : "") << m.indexes[i];
    js << "],\n  \"transactions\": [\n";
    for (size_t i = 0; i < txns.size(); ++i) {
        const auto& t = txns[i];
        js << "    {\"ordinal\": " << t.ordinal << ", \"code\": \"" << t.code
           << "\", \"completion\": \"" << t.task_result << "\", \"t_issue\": " << std::fixed << t.t_issue
           << ", \"t_complete\": " << t.t_complete << ", \"points\": [";
        for (size_t p = 0; p < t.points.size(); ++p) {
            const auto& pt = t.points[p];
            js << (p ? "," : "") << "{\"index\": " << pt.index << ", \"state\": \"" << pt.state
               << "\", \"status\": \"" << pt.status << "\"}";
        }
        js << "]}" << (i + 1 < txns.size() ? "," : "") << "\n";
    }
    js << "  ],\n  \"aborted\": " << (aborted ? "true" : "false") << ", \"abort_rep\": " << abort_rep
       << ", \"abort_reason\": \"" << json_escape(abort_reason) << "\",\n  \"success\": " << m.ok
       << ", \"total\": " << m.reps << "\n}\n";
    std::ofstream f(tmp, std::ios::trunc);
    if (!f.good()) return 5;
    f << js.str(); f.flush(); if (!f.good()) return 5; f.close();
    if (std::rename(tmp.c_str(), out.c_str()) != 0) return 5;
    return 0;
}

static bool arg(const std::map<std::string, std::string>& a, const std::string& k, std::string& v)
{ auto it = a.find(k); if (it == a.end()) return false; v = it->second; return true; }

int main(int argc, char* argv[])
{
    std::map<std::string, std::string> a;
    for (int i = 1; i + 1 < argc; i += 2) { std::string k = argv[i]; if (k.rfind("--", 0) == 0) a[k] = argv[i + 1]; }
    std::string host, indexes_csv, mode, out, sk, sr, block_id = "", sseed = "0", sreps;
    if (!arg(a, "--host", host) || !arg(a, "--reps", sreps) || !arg(a, "--indexes", indexes_csv) ||
        !arg(a, "--mode", mode) || !arg(a, "--out", out) || !arg(a, "--expect-k", sk))
        return fail(2, "usage: --host --reps --indexes --mode --out --expect-k [--expect-r --block-id --seed]");
    arg(a, "--expect-r", sr); arg(a, "--block-id", block_id); arg(a, "--seed", sseed);

    // 3: target guard
    std::string why;
    if (!target_allowed(host, why)) return fail(3, "TARGET GUARD: " + why);
    // 2/4: numeric args
    char* e = nullptr; long reps = std::strtol(sreps.c_str(), &e, 10); if (*e || reps < 1) return fail(2, "--reps must be >= 1");
    long k = std::strtol(sk.c_str(), &e, 10); if (*e || k < 1) return fail(2, "--expect-k must be >= 1");
    long r = sr.empty() ? -1 : std::strtol(sr.c_str(), &e, 10);
    long seed = std::strtol(sseed.c_str(), &e, 10);
    if (mode != "on" && mode != "off" && mode != "alt") return fail(4, "invalid --mode (on|off|alt)");
    std::vector<long> raw; if (!parse_ints_strict(indexes_csv, raw)) return fail(2, "malformed --indexes");
    std::vector<long> indexes; std::set<long> seen;
    for (long v : raw) {
        if (v < 0 || v > EMU_MAX_INDEX) return fail(4, "index " + std::to_string(v) + " out of range [0,31]");
        if (!seen.insert(v).second) return fail(4, "duplicate index " + std::to_string(v));
        indexes.push_back(v);
    }
    if ((long)indexes.size() != k) return fail(4, "index count != --expect-k");
    if (r >= 0 && (r < 0 || r > k)) return fail(4, "--expect-r out of [0,K]");
    // 5: preflight evidence path
    const std::string tmp = out + ".tmp";
    { std::ofstream probe(tmp, std::ios::trunc); if (!probe.good()) return fail(5, "cannot create evidence file " + tmp); }

    Meta meta{host, mode, block_id, (int)reps, (int)k, (int)r, seed, indexes, 0};

    DNP3Manager manager(1, ConsoleLogger::Create());
    auto latch = std::make_shared<OpenLatch>();
    auto channel = manager.AddTCPClient("tcpclient", levels::NORMAL, ChannelRetry::Default(),
                                        {IPEndpoint(host, 20000)}, "0.0.0.0", latch);
    MasterStackConfig cfg;
    cfg.master.responseTimeout = TimeDuration::Seconds(5);
    cfg.master.disableUnsolOnStartup = true;
    cfg.link.LocalAddr = 1; cfg.link.RemoteAddr = 10;
    auto master = channel->AddMaster("master", PrintingSOEHandler::Create(),
                                     DefaultMasterApplication::Create(), cfg);
    std::vector<TxnRecord> txns; bool aborted = false; int abort_rep = -1; std::string abort_reason;

    if (!master->Enable() || !latch->wait_open(std::chrono::seconds(10))) {
        aborted = true; abort_reason = "channel never reached OPEN"; abort_rep = 0;
        manager.Shutdown();
        write_evidence(out, tmp, meta, txns, aborted, abort_rep, abort_reason);
        return 6;
    }

    for (int i = 0; i < reps; ++i) {
        OperationType op = (mode == "on") ? OperationType::LATCH_ON
                         : (mode == "off") ? OperationType::LATCH_OFF
                         : (i % 2 == 0) ? OperationType::LATCH_ON : OperationType::LATCH_OFF;
        std::vector<Indexed<ControlRelayOutputBlock>> items; items.reserve(indexes.size());
        for (long idx : indexes) items.push_back(WithIndex(ControlRelayOutputBlock(op), (uint16_t)idx));
        CommandSet set; set.Add<ControlRelayOutputBlock>(items);

        const double t_issue = now_epoch();
        std::vector<PointOutcome> pts;
        TaskCompletion tc = run_one_sbo(*master, std::move(set), std::chrono::milliseconds(8000), pts);
        const double t_complete = now_epoch();
        const char* op_name = (op == OperationType::LATCH_ON) ? "LATCH_ON" : "LATCH_OFF";
        const std::string tcs = TaskCompletionSpec::to_string(tc);
        txns.push_back({i, op_name, t_issue, t_complete, tcs, pts});
        std::cout << "SBO " << (i + 1) << "/" << reps << " K=" << k << " " << op_name << ": " << tcs << std::endl;
        if (tc != TaskCompletion::SUCCESS) { aborted = true; abort_rep = i; abort_reason = "SBO " + std::to_string(i) + " -> " + tcs; break; }
        ++meta.ok;
    }
    manager.Shutdown();                                   // single teardown, before the JSON write
    int werr = write_evidence(out, tmp, meta, txns, aborted, abort_rep, abort_reason);
    if (werr) return werr;
    std::cout << meta.ok << "/" << reps << " SBOs succeeded on ONE persistent connection\n";
    return (meta.ok == reps) ? 0 : 1;
}

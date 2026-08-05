// nsbo_master.cpp -- persistent multi-SBO master for the fixed-K Defense 4 EMULATOR experiment.
//
// Opens ONE TCP connection to an OpenDNP3 emulator outstation and issues N sequential
// Select-Before-Operate transactions, each carrying the SAME ordered set of K CROBs (Group 12
// Var 1). One TCP setup, no FIN/RST between transactions, one teardown at the end -- a true
// persistent session (the pydnp3 binding is structurally single-shot for SBO; this C++ master
// avoids the non-copyable result-marshalling that aborts/hangs the Python path).
//
// EMULATOR ONLY. A fail-closed target guard REFUSES the physical SEL-751 subnet (192.168.10.0/24)
// so this can never be pointed at the real relay. Allowed: 127.0.0.1 / 10.10.54.x (management net).
//
// Build (no CMake; against the prebuilt lib):
//   REPO=/home/philip/Projects/opendnp3-community
//   g++ -std=c++14 -I "$REPO/cpp/lib/include" nsbo_master.cpp \
//       -L "$REPO/build/cpp/lib" -lopendnp3 -lpthread \
//       -Wl,-rpath,"$REPO/build/cpp/lib" -o nsbo_master
//
// Usage:
//   nsbo_master <host> <reps> <indexes_csv> <code_mode> <out_json>
//     host        emulator IP (127.0.0.1 or 10.10.54.x); physical-relay subnet is refused
//     reps        number of SBO transactions on the one connection
//     indexes_csv the ordered K CROB indexes, e.g. "0,1,16,17"  (identical SELECT+OPERATE list)
//     code_mode   "alt" (alternate LATCH_ON/LATCH_OFF per rep) or "on" / "off" (fixed)
//     out_json    path to write the per-rep + summary JSON
#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/PrintingSOEHandler.h>
#include <opendnp3/master/CommandSet.h>
#include <opendnp3/app/ControlRelayOutputBlock.h>
#include <opendnp3/app/Indexed.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace opendnp3;

static double now_epoch()
{
    using namespace std::chrono;
    return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}

// Fail-closed target guard: refuse the physical SEL-751 subnet, permit only loopback + mgmt net.
static bool target_allowed(const std::string& host, std::string& why)
{
    if (host.rfind("192.168.10.", 0) == 0) { why = "physical SEL-751 subnet 192.168.10.0/24 is REFUSED (emulator only)"; return false; }
    if (host == "127.0.0.1" || host == "localhost") return true;
    if (host.rfind("10.10.54.", 0) == 0) return true;   // management network (emulator hosts)
    why = "host '" + host + "' is not an allowed emulator target (127.0.0.1 or 10.10.54.x only)";
    return false;
}

static std::vector<uint16_t> parse_indexes(const std::string& csv)
{
    std::vector<uint16_t> out;
    std::stringstream ss(csv);
    std::string tok;
    while (std::getline(ss, tok, ','))
        if (!tok.empty()) out.push_back(static_cast<uint16_t>(std::stoi(tok)));
    return out;
}

int main(int argc, char* argv[])
{
    if (argc < 6)
    {
        std::cerr << "usage: nsbo_master <host> <reps> <indexes_csv> <code_mode:alt|on|off> <out_json>\n";
        return 2;
    }
    const std::string host = argv[1];
    const int reps = std::atoi(argv[2]);
    const std::vector<uint16_t> indexes = parse_indexes(argv[3]);
    const std::string code_mode = argv[4];
    const std::string out_json = argv[5];

    std::string why;
    if (!target_allowed(host, why)) { std::cerr << "TARGET GUARD: " << why << "\n"; return 3; }
    if (reps < 1 || indexes.empty()) { std::cerr << "reps>=1 and >=1 index required\n"; return 2; }

    const int K = static_cast<int>(indexes.size());
    DNP3Manager manager(1, ConsoleLogger::Create());
    auto channel = manager.AddTCPClient("tcpclient", levels::NORMAL,
                                        ChannelRetry::Default(),
                                        {IPEndpoint(host, 20000)}, "0.0.0.0",
                                        PrintingChannelListener::Create());

    MasterStackConfig cfg;
    cfg.master.responseTimeout = TimeDuration::Seconds(5);
    cfg.master.disableUnsolOnStartup = true;
    cfg.link.LocalAddr = 1;    // master (lab_config)
    cfg.link.RemoteAddr = 10;  // emulator outstation (lab_config); physical relay is out of scope

    auto master = channel->AddMaster("master", PrintingSOEHandler::Create(),
                                     DefaultMasterApplication::Create(), cfg);
    master->Enable();                                   // ONE TCP setup; stays up across all reps
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::ofstream js(out_json);
    js << "{\n  \"host\": \"" << host << "\", \"reps\": " << reps
       << ", \"K\": " << K << ", \"code_mode\": \"" << code_mode << "\",\n";
    js << "  \"indexes\": [";
    for (int i = 0; i < K; ++i) js << (i ? "," : "") << indexes[i];
    js << "],\n  \"transactions\": [\n";

    int ok = 0;
    for (int i = 0; i < reps; ++i)
    {
        OperationType op;
        if (code_mode == "on") op = OperationType::LATCH_ON;
        else if (code_mode == "off") op = OperationType::LATCH_OFF;
        else op = (i % 2 == 0) ? OperationType::LATCH_ON : OperationType::LATCH_OFF;  // alt

        std::vector<Indexed<ControlRelayOutputBlock>> items;
        items.reserve(K);
        for (uint16_t idx : indexes)
            items.push_back(WithIndex(ControlRelayOutputBlock(op), idx));
        CommandSet set;
        set.Add<ControlRelayOutputBlock>(items);       // one SELECT + one OPERATE carrying K CROBs

        std::promise<TaskCompletion> done;
        auto fut = done.get_future();
        auto cb = [&done](const ICommandTaskResult& r) { done.set_value(r.summary); };

        const double t_issue = now_epoch();
        master->SelectAndOperate(std::move(set), cb);
        TaskCompletion tc = (fut.wait_for(std::chrono::seconds(8)) == std::future_status::ready)
                                ? fut.get() : TaskCompletion::FAILURE_RESPONSE_TIMEOUT;
        const double t_complete = now_epoch();

        const char* op_name = (op == OperationType::LATCH_ON) ? "LATCH_ON" : "LATCH_OFF";
        const std::string tcs = TaskCompletionSpec::to_string(tc);
        if (tc == TaskCompletion::SUCCESS) ++ok;
        js << "    {\"rep\": " << i << ", \"code\": \"" << op_name << "\", \"completion\": \""
           << tcs << "\", \"t_issue\": " << std::fixed << t_issue
           << ", \"t_complete\": " << t_complete << "}" << (i + 1 < reps ? "," : "") << "\n";
        std::cout << "SBO " << (i + 1) << "/" << reps << " K=" << K << " " << op_name
                  << ": " << tcs << std::endl;
    }
    js << "  ],\n  \"success\": " << ok << ", \"total\": " << reps << "\n}\n";
    js.close();
    std::cout << ok << "/" << reps << " SBOs succeeded on ONE persistent connection\n";
    return (ok == reps) ? 0 : 1;    // manager dtor => single teardown at process exit
}

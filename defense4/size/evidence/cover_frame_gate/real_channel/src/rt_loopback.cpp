/*
 * REAL persistent-stack DNP3-over-TCP loopback harness (software only, no hardware).
 *
 * One process, one DNP3Manager, real asio TCP server (outstation) + real asio TCP client
 * (master) over 127.0.0.1. Every layer is the production OpenDNP3 stack: socket, TCP, data
 * link, transport (real reassembly), application. Drives a READ (integrity ScanClasses) and an
 * SBO (SelectAndOperate) and reports what the real stack did. Emits one JSON line to stdout so
 * an external capture (dumpcap on lo) can be correlated.
 *
 * Config via env:
 *   RT_SERVER_PORT   outstation TCP server listen port          (default 20500)
 *   RT_CONNECT_PORT  master TCP client connect port             (default = RT_SERVER_PORT)
 *   RT_NPOINTS       binary inputs in the outstation DB          (default 4)
 *   RT_MAXTXFRAG     outstation maxTxFragSize (bytes)            (default 2048)
 *   RT_DO_READ       1 to run the integrity READ                 (default 1)
 *   RT_DO_SBO        1 to run the SBO                            (default 1)
 *   RT_SETTLE_MS     ms to wait for channel OPEN before driving  (default 1500)
 *   RT_TAG           free-form label echoed in the JSON line     (default "")
 */
#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/IChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/ISOEHandler.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>
#include <opendnp3/outstation/UpdateBuilder.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

using namespace opendnp3;

static int envi(const char* k, int def)
{
    const char* v = std::getenv(k);
    return v ? std::atoi(v) : def;
}
static std::string envs(const char* k, const std::string& def)
{
    const char* v = std::getenv(k);
    return v ? std::string(v) : def;
}

// Counts channel OPEN/CLOSED transitions on one side.
class CountingChannelListener : public IChannelListener
{
public:
    std::atomic<int> opens{0};
    std::atomic<int> closes{0};
    std::atomic<int> lastState{-1};
    void OnStateChange(ChannelState state) override
    {
        lastState = static_cast<int>(state);
        if (state == ChannelState::OPEN)
            ++opens;
        else if (state == ChannelState::CLOSED)
            ++closes;
    }
};

// Counts binary-input values and completed response fragments seen by the master.
class CountingSOEHandler : public ISOEHandler
{
public:
    std::atomic<int> binaries{0};
    std::atomic<int> beginFragments{0};
    std::atomic<int> endFragments{0};

    void BeginFragment(const ResponseInfo&) override { ++beginFragments; }
    void EndFragment(const ResponseInfo&) override { ++endFragments; }
    void Process(const HeaderInfo&, const ICollection<Indexed<Binary>>& v) override
    {
        binaries += static_cast<int>(v.Count());
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<DoubleBitBinary>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<Analog>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<Counter>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<FrozenCounter>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryOutputStatus>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogOutputStatus>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<OctetString>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<TimeAndInterval>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<DNPTime>&) override {}
};

template <class Pred>
static bool wait_until(Pred p, int timeout_ms)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (p())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return p();
}

int main()
{
    const int serverPort = envi("RT_SERVER_PORT", 20500);
    const int connectPort = envi("RT_CONNECT_PORT", serverPort);
    const int nPoints = envi("RT_NPOINTS", 4);
    const int maxTxFrag = envi("RT_MAXTXFRAG", 2048);
    const bool doRead = envi("RT_DO_READ", 1) != 0;
    const bool doSbo = envi("RT_DO_SBO", 1) != 0;
    const int settleMs = envi("RT_SETTLE_MS", 1500);
    const std::string tag = envs("RT_TAG", "");

    const auto logLevels = levels::NORMAL; // keep stderr quiet; the wire is captured externally
    DNP3Manager manager(2, ConsoleLogger::Create());

    // ---- outstation: real TCP server on loopback ----
    auto outListener = std::make_shared<CountingChannelListener>();
    const std::string bindAddr = envs("RT_BIND_ADDR", "127.0.0.1");
    auto srvChannel = manager.AddTCPServer("srv", logLevels, ServerAcceptMode::CloseExisting,
                                           IPEndpoint(bindAddr, static_cast<uint16_t>(serverPort)), outListener);

    DatabaseConfig dbcfg(static_cast<uint16_t>(nPoints));
    for (int i = 0; i < nPoints; ++i)
        dbcfg.binary_input[i].clazz = PointClass::Class1;
    OutstationStackConfig ocfg(dbcfg);
    ocfg.outstation.eventBufferConfig = EventBufferConfig::AllTypes(100);
    ocfg.outstation.params.allowUnsolicited = false;
    ocfg.outstation.params.maxTxFragSize = static_cast<uint32_t>(maxTxFrag);
    ocfg.link.LocalAddr = 10;
    ocfg.link.RemoteAddr = 1;
    ocfg.link.KeepAliveTimeout = TimeDuration::Max();

    auto cmdHandler = std::make_shared<SimpleCommandHandler>(CommandStatus::SUCCESS);
    auto outApp = DefaultOutstationApplication::Create();
    auto outstation = srvChannel->AddOutstation("out", cmdHandler, outApp, ocfg);

    {
        UpdateBuilder b;
        for (int i = 0; i < nPoints; ++i)
            b.Update(Binary((i % 2) == 0, Flags(0x01)), static_cast<uint16_t>(i));
        outstation->Apply(b.Build());
    }
    outstation->Enable();

    // ---- master: real TCP client on loopback ----
    auto mstListener = std::make_shared<CountingChannelListener>();
    auto cliChannel = manager.AddTCPClient("cli", logLevels, ChannelRetry::Default(),
                                           {IPEndpoint("127.0.0.1", static_cast<uint16_t>(connectPort))}, "0.0.0.0",
                                           mstListener);

    MasterStackConfig mcfg;
    mcfg.master.responseTimeout = TimeDuration::Seconds(2);
    mcfg.master.disableUnsolOnStartup = false;
    mcfg.master.startupIntegrityClassMask = ClassField::None(); // we drive the READ explicitly
    mcfg.master.unsolClassMask = ClassField::None();
    mcfg.link.LocalAddr = 1;
    mcfg.link.RemoteAddr = 10;
    mcfg.link.KeepAliveTimeout = TimeDuration::Max();

    auto soe = std::make_shared<CountingSOEHandler>();
    auto master = cliChannel->AddMaster("mst", soe, DefaultMasterApplication::Create(), mcfg);
    master->Enable();

    const bool opened = wait_until([&] { return mstListener->opens.load() > 0 && outListener->opens.load() > 0; },
                                   settleMs);

    bool readSuccess = false;
    if (opened && doRead)
    {
        master->ScanClasses(ClassField::AllClasses(), soe, TaskConfig::Default());
        readSuccess = wait_until([&] { return soe->binaries.load() >= nPoints && soe->endFragments.load() > 0; }, 4000);
    }

    std::atomic<bool> sboDone{false};
    std::atomic<bool> sboSuccess{false};
    if (opened && doSbo)
    {
        ControlRelayOutputBlock crob(OperationType::PULSE_ON);
        master->SelectAndOperate(crob, 1, [&](const ICommandTaskResult& r) {
            sboSuccess = (r.summary == TaskCompletion::SUCCESS);
            sboDone = true;
        });
        wait_until([&] { return sboDone.load(); }, 4000);
    }

    // brief settle so the last app-layer exchange fully drains before teardown
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Emit machine-readable summary BEFORE teardown (teardown FIN/close is captured on the wire).
    std::cout << "{"
              << "\"tag\":\"" << tag << "\","
              << "\"server_port\":" << serverPort << ","
              << "\"connect_port\":" << connectPort << ","
              << "\"npoints\":" << nPoints << ","
              << "\"max_tx_frag\":" << maxTxFrag << ","
              << "\"channel_open\":" << (opened ? 1 : 0) << ","
              << "\"master_opens\":" << mstListener->opens.load() << ","
              << "\"master_closes\":" << mstListener->closes.load() << ","
              << "\"out_opens\":" << outListener->opens.load() << ","
              << "\"out_closes\":" << outListener->closes.load() << ","
              << "\"read_requested\":" << (doRead ? 1 : 0) << ","
              << "\"read_success\":" << (readSuccess ? 1 : 0) << ","
              << "\"soe_binaries\":" << soe->binaries.load() << ","
              << "\"begin_fragments\":" << soe->beginFragments.load() << ","
              << "\"end_fragments\":" << soe->endFragments.load() << ","
              << "\"sbo_requested\":" << (doSbo ? 1 : 0) << ","
              << "\"sbo_success\":" << (sboSuccess ? 1 : 0) << ","
              << "\"out_num_select\":" << cmdHandler->numSelect << ","
              << "\"out_num_operate\":" << cmdHandler->numOperate
              << "}" << std::endl;

    // Explicit orderly shutdown -> real TCP FIN on the wire (captured).
    manager.Shutdown();
    return (opened && (!doRead || readSuccess) && (!doSbo || sboSuccess)) ? 0 : 1;
}

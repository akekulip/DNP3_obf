// Private software endpoints only. No device I/O or physical output callbacks.
#include "DecoyGateCommandHandler.h"
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/IChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/PrintingSOEHandler.h>
#include <opendnp3/master/ICommandTaskResult.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <thread>
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
int main(int argc, char** argv) {
    if(argc!=3 || !std::getenv("CASE4_PRIVATE_SOCKET_GATE")) return 64;
    char netns[256]={}; auto length=readlink("/proc/self/ns/net",netns,sizeof(netns)-1);
    if(length<0 || std::string(netns)==std::getenv("CASE4_PARENT_NETNS")) return 65;
    const std::string role=argv[1], stop=argv[2];
    DNP3Manager manager(1); auto listener=std::make_shared<Listener>();
    if(role=="outstation") {
        auto handler=std::make_shared<Handler>();
        auto channel=manager.AddTCPServer("gate",levels::NOTHING,ServerAcceptMode::CloseExisting,IPEndpoint("10.0.0.2",20000),listener);
        OutstationStackConfig config{DatabaseConfig{}};
        config.outstation.params.allowUnsolicited=false;
        config.outstation.params.selectTimeout=TimeDuration::Milliseconds(500);
        config.link.LocalAddr=10; config.link.RemoteAddr=1; config.link.KeepAliveTimeout=TimeDuration::Max();
        auto station=channel->AddOutstation("outstation",handler,DefaultOutstationApplication::Create(),config);
        station->Enable(); std::cout<<"READY\n"<<std::flush;
        const auto end=Clock::now()+std::chrono::seconds(8);
        while(Clock::now()<end && !std::ifstream(stop).good()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        manager.Shutdown();
        std::cout<<"{\"select_real\":"<<handler->gate.selects(1)<<",\"select_decoy\":"<<handler->gate.selects(201)
                 <<",\"operate_real\":"<<handler->gate.operates(1)<<",\"operate_decoy\":"<<handler->gate.operates(201)
                 <<",\"opens\":"<<listener->opens<<",\"select_accept_ns\":"<<handler->selected_ns
                 <<",\"operate_accept_ns\":"<<handler->operated_ns<<",\"retention_ns\":"<<handler->operated_ns-handler->selected_ns<<"}\n";
        return 0;
    }
    if(role!="master") return 64;
    auto retry=ChannelRetry(TimeDuration::Seconds(60),TimeDuration::Seconds(60),TimeDuration::Seconds(60));
    auto channel=manager.AddTCPClient("gate",levels::NOTHING,retry,{IPEndpoint("10.0.0.2",20000)},"10.0.0.1",listener);
    MasterStackConfig config;
    config.master.disableUnsolOnStartup=false; config.master.startupIntegrityClassMask=ClassField::None();
    config.master.unsolClassMask=ClassField::None(); config.master.ignoreRestartIIN=true;
    config.master.responseTimeout=TimeDuration::Milliseconds(500);
    config.link.LocalAddr=1; config.link.RemoteAddr=10; config.link.KeepAliveTimeout=TimeDuration::Max();
    auto master=channel->AddMaster("master",PrintingSOEHandler::Create(),DefaultMasterApplication::Create(),config);
    master->Enable(); const auto end=Clock::now()+std::chrono::seconds(5);
    while(!listener->open && Clock::now()<end) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    if(!listener->open) { manager.Shutdown(); return 2; }
    std::atomic<bool> done{false}, success{false}; const auto issued=now_ns(); long long completed=0;
    master->SelectAndOperate(ControlRelayOutputBlock(OperationType::PULSE_ON,TripCloseCode::NUL,false,1,100,100),1,
        [&](const ICommandTaskResult& result) {
            bool ok=result.summary==TaskCompletion::SUCCESS; int count=0;
            result.ForeachItem([&](const CommandPointResult& p){ ++count; ok=ok && p.index==1 && p.status==CommandStatus::SUCCESS && p.state==CommandPointState::SUCCESS; });
            success=ok && count==1; completed=now_ns(); done=true;
        });
    while(!done && Clock::now()<end) std::this_thread::sleep_for(std::chrono::milliseconds(2));
    manager.Shutdown();
    std::cout<<"{\"success\":"<<(success?"true":"false")<<",\"application_calls\":1,\"opens\":"<<listener->opens
             <<",\"issued_ns\":"<<issued<<",\"completed_ns\":"<<completed<<"}\n";
    return success ? 0 : 3;
}

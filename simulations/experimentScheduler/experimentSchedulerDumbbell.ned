package mptcp.simulations.experimentScheduler;
@namespace(inet);

import inet.common.scenario.ScenarioManager;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;
import tcppaced.networklayer.configurator.ipv4.AutoNetworkConfigurator;

network experimentSchedulerDumbbell
{
    parameters:
        @display("bgb=860,760");
        int maxSubflows = default(8);
    types:
        channel accessLine extends DatarateChannel
        {
            delay = 4.75ms;
            datarate = 10Gbps;
        }

        channel bottleneckLine extends DatarateChannel
        {
            delay = 0.5ms;
            datarate = 50Mbps;
        }
    submodules:
        client[1]: StandardHost {
            @display("p=90,120");
        }

        configurator: AutoNetworkConfigurator {
            @display("p=430,710");
        }

        server[1]: StandardHost {
            @display("p=770,120");
        }

        router1[maxSubflows]: Router {
            @display("p=300,120,m,1,maxSubflows,72");
        }

        router2[maxSubflows]: Router {
            @display("p=560,120,m,1,maxSubflows,72");
        }

        scenarioManager: ScenarioManager {
            @display("p=130,710;is=s");
        }
    connections:
        for path = 0 .. maxSubflows - 1 {
            client[0].pppg++ <--> accessLine <--> router1[path].pppg++;
            server[0].pppg++ <--> accessLine <--> router2[path].pppg++;
            router1[path].pppg++ <--> bottleneckLine <--> router2[path].pppg++;
        }
}

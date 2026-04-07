package mptcp.simulations;
@namespace(inet);

import inet.node.inet.StandardHost;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.Router;
import ned.DatarateChannel;
import ned.IBidirectionalChannel;
import inet.common.scenario.ScenarioManager;
import tcppaced.networklayer.configurator.ipv4.AutoNetworkConfigurator;

network multipathdumbbell
{
    parameters:
        @display("bgb=700,500");
        int numberOfClientServers = default(1);
        int numberOfSubflows = default(2);

    types:
        channel standardLine extends DatarateChannel
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
        client[numberOfClientServers]: StandardHost {
            @display("p=80,80,m,1,numberOfClientServers,120");
        }

        configurator: AutoNetworkConfigurator {
            @display("p=500,420");
        }

        server[numberOfClientServers]: StandardHost {
            @display("p=600,80,m,1,numberOfClientServers,120");
        }

        // Routers stacked vertically (each pair forms a dumbbell)
        router1[numberOfSubflows]: Router {
            @display("p=250,80,m,1,numberOfSubflows,120");
        }

        router2[numberOfSubflows]: Router {
            @display("p=420,80,m,1,numberOfSubflows,120");
        }

        scenarioManager: ScenarioManager {
            @display("p=100,420;is=s");
        }

    connections:
        // Connect every client to every router1
        for idx=0..sizeof(client)*sizeof(router1)-1 {
            client[int(idx / sizeof(router1))].pppg++ <--> standardLine <--> router1[idx % sizeof(router1)].pppg++;
        }

        // Connect every server to every router2
        for idx=0..sizeof(server)*sizeof(router2)-1 {
            server[int(idx / sizeof(router2))].pppg++ <--> standardLine <--> router2[idx % sizeof(router2)].pppg++;
        }

        // Each router pair forms a dumbbell
        for m=0..sizeof(router1)-1 {
            router1[m].pppg++ <--> bottleneckLine <--> router2[m].pppg++;
        }
}
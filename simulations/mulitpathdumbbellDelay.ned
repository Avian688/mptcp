package mptcp.simulations;
@namespace(inet);

import inet.node.inet.StandardHost;
import inet.node.inet.Router;
import inet.common.scenario.ScenarioManager;
import tcppaced.networklayer.configurator.ipv4.AutoNetworkConfigurator;
import ned.DatarateChannel;

network multipathdumbbelldelay
{
    parameters:
        @display("bgb=700,500");
        int numberOfClientServers = default(1);

    types:
        // Fast path: lower RTT
        channel accessLineFast extends DatarateChannel
        {
            delay = 5ms;
            datarate = 10Gbps;
        }

        channel bottleneckLineFast extends DatarateChannel
        {
            delay = 0.5ms;
            datarate = 50Mbps;
        }

        // Slow path: double the RTT of the fast path
        channel accessLineSlow extends DatarateChannel
        {
            delay = 10ms;
            datarate = 10Gbps;
        }

        channel bottleneckLineSlow extends DatarateChannel
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

        // Dumbbell 1 (fast RTT)
        router1a: Router {
            @display("p=250,140");
        }

        router2a: Router {
            @display("p=420,140");
        }

        // Dumbbell 2 (slow RTT, 2x RTT of dumbbell 1)
        router1b: Router {
            @display("p=250,280");
        }

        router2b: Router {
            @display("p=420,280");
        }

        scenarioManager: ScenarioManager {
            @display("p=100,420;is=s");
        }

    connections:
        // Connect every client to both dumbbells
        for i=0..sizeof(client)-1 {
            client[i].pppg++ <--> accessLineFast <--> router1a.pppg++;
            client[i].pppg++ <--> accessLineSlow <--> router1b.pppg++;
        }

        // Connect every server to both dumbbells
        for i=0..sizeof(server)-1 {
            server[i].pppg++ <--> accessLineFast <--> router2a.pppg++;
            server[i].pppg++ <--> accessLineSlow <--> router2b.pppg++;
        }

        // Two disjoint dumbbell bottlenecks
        router1a.pppg++ <--> bottleneckLineFast <--> router2a.pppg++;
        router1b.pppg++ <--> bottleneckLineSlow <--> router2b.pppg++;
}
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
        @display("bgb=512,395");
        int numberOfClientServers = default(1);
        int numberOfSubflows = default(2);
    types:
        channel standardLine extends DatarateChannel //look at
        {
            delay = 4.75ms;
            datarate = 10Gbps;
        }

        channel bottleneckLine extends DatarateChannel //look at
        {
            delay = 0.5ms;
            datarate = 50Mbps;
        }
    submodules:
        client[numberOfClientServers]: StandardHost {
            @display("p=68,71,m,n,numberOfClientServers,200");
        }
        configurator: AutoNetworkConfigurator {
            @display("p=450,350");
        }
        server[numberOfClientServers]: StandardHost {
            @display("p=431,50,m,n,numberOfClientServers,200");
        }
        router1[numberOfSubflows]: Router {
            @display("p=220,140,m,n,numberOfSubflows,200");
        }
        router2[numberOfSubflows]: Router {
            @display("p=327,140,m,n,numberOfSubflows,200");
        }
        scenarioManager: ScenarioManager {
            @display("p=100,300;is=s");
        }
    connections:
        for i=0..sizeof(client)-1 {
            for j=0..sizeof(router1)-1 {
            	client[i].pppg++ <--> standardLine <--> router1[j].pppg++;
            }
        }

        for k=0..sizeof(server)-1 {
            for l=0..sizeof(router2)-1 {
            	server[k].pppg++ <--> standardLine <--> router2[l].pppg++;
            }
        }

        for m=0..sizeof(router1)-1 {
            router1[m].pppg++ <--> bottleneckLine <--> router2[m].pppg++;
        }
}

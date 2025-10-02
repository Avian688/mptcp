//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#include "inet/common/socket/SocketTag_m.h"

#include <inet/networklayer/ipv4/Ipv4Header_m.h>

#include "MpTcp.h"
namespace inet {
namespace tcp {

Define_Module(MpTcp);

MpTcp::MpTcp() {
    // TODO Auto-generated constructor stub

}

MpTcp::~MpTcp() {
    // TODO Auto-generated destructor stub
}

void MpTcp::initialize(int stage)
{
    Tcp::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        baseConnectionStarted = false;
        mainSocketId = -1;
    }
}

void MpTcp::handleUpperCommand(cMessage *msg)
{
    std::cout << "\n Step 1.1 getting socket tag" << endl;
    int socketId = check_and_cast<ITaggedObject *>(msg)->getTags().getTag<SocketReq>()->getSocketId();
    std::cout << "\n Step 1.2 getting socket tag" << endl;
    TcpConnection *conn = findConnForApp(socketId);

    if (!conn) {
        if(!baseConnectionStarted){
            conn = createConnection(socketId);
        }
        else{
            conn = createSubflowConnection(socketId);
        }

        // add into appConnMap here; it'll be added to connMap during processing
        // the OPEN command in TcpConnection's processAppCommand().
        tcpAppConnMap[socketId] = conn;

        EV_INFO << "Tcp connection created for " << msg << "\n";
    }

    if (!conn->processAppCommand(msg)){
        std::cout << "\n REMOVING CONNECTION AT SIMTIME: " << simTime() << endl;
        std::cout << "\n MSG: " << msg->str() << endl;
        removeConnection(conn);
    }
}

TcpConnection* MpTcp::createConnection(int socketId)
{
    baseConnectionStarted = true;
    auto moduleType = cModuleType::get("mptcp.transportlayer.tcp.MpTcpConnection");
    char submoduleName[24];
    sprintf(submoduleName, "conn-%d", socketId);
    auto module = check_and_cast<TcpConnection*>(moduleType->createScheduleInit(submoduleName, this));
    module->initConnection(this, socketId);
    mainSocketId = socketId;
    return module;
}

TcpConnection* MpTcp::createSubflowConnection(int socketId)
{
    auto moduleType = cModuleType::get("mptcp.transportlayer.tcp.SubflowConnection");
    char submoduleName[24];
    sprintf(submoduleName, "conn-%d", socketId);
    auto module = check_and_cast<TcpConnection*>(moduleType->createScheduleInit(submoduleName, this));
    module->initConnection(this, socketId);
    return module;
}

void MpTcp::handleLowerPacket(Packet *packet)
{
    auto protocol = packet->getTag<PacketProtocolTag>()->getProtocol();
    if (protocol == &Protocol::tcp) {
        if (!checkCrc(packet)) {
            EV_WARN << "Tcp segment has wrong CRC, dropped\n";
            PacketDropDetails details;
            details.setReason(INCORRECTLY_RECEIVED);
            emit(packetDroppedSignal, packet, &details);
            delete packet;
            return;
        }

        // must be a TcpHeader
        auto tcpHeader = packet->peekAtFront<TcpHeader>();

        // get src/dest addresses
        L3Address srcAddr, destAddr;
        srcAddr = packet->getTag<L3AddressInd>()->getSrcAddress();
        destAddr = packet->getTag<L3AddressInd>()->getDestAddress();
        int ecn = 0;
        if (auto ecnTag = packet->findTag<EcnInd>())
            ecn = ecnTag->getExplicitCongestionNotification();
        ASSERT(ecn != -1);

        // process segment
        SubflowConnection *conn = dynamic_cast<SubflowConnection*>(findConnForSegment(tcpHeader, srcAddr, destAddr));
        //RECEIVER - If conn is not found, you need to create a new sublo
        if (conn) {
            TcpStateVariables *state = conn->getState();
            if (state && state->ect) {
                // This may be true only in receiver side. According to RFC 3168, page 20:
                // pure acknowledgement packets (e.g., packets that do not contain
                // any accompanying data) MUST be sent with the not-ECT codepoint.
                state->gotCeIndication = (ecn == 3);
            }

            bool ret = conn->processTCPSegment(packet, tcpHeader, srcAddr, destAddr);
            if (!ret)
                removeConnection(conn);
        }
        else {
            //We need to create a socket, and then pass that socket ID here!
            std::cout << "\n Step 2.1 getting socket tag" << endl;
            int socketId = tcpHeader->getTag<SocketReq>()->getSocketId();
            //Now create socket given this socket ID
            if(socketId){
                std::cout << "\n Step 2.2" << endl;
                conn = check_and_cast<SubflowConnection*>(createSubflowConnection(socketId));
                tcpAppConnMap[socketId] = conn;
                std::cout << "\n SOCKET ID: " << socketId << endl;
                //TcpConnection *conn = findConnForSegment(tcpHeader, srcAddr, destAddr);
                TcpStateVariables *state = conn->getState();
                conn->openNewSocket(mainSocketId);
                std::cout << "\n Step 2.3" << endl;
                if (state && state->ect) {
                    // This may be true only in receiver side. According to RFC 3168, page 20:
                    // pure acknowledgement packets (e.g., packets that do not contain
                    // any accompanying data) MUST be sent with the not-ECT codepoint.
                    state->gotCeIndication = (ecn == 3);
                }
                std::cout << "\n Step 2.4" << endl;
                std::cout << "\n srcAddr " << srcAddr << endl;
                std::cout << "\n destAddr " << destAddr <<  endl;

                //bool ret = conn->processTCPSegment(packet, tcpHeader, srcAddr, destAddr);
                std::cout << "\n Step 2.5" << endl;
                //if (!ret)
                //    removeConnection(conn);

            }
            else{
                segmentArrivalWhileClosed(packet, tcpHeader, srcAddr, destAddr);
            }
        }
    }
    else if (protocol == &Protocol::icmpv4 || protocol == &Protocol::icmpv6) {
        EV_DETAIL << "ICMP error received -- discarding\n"; // FIXME can ICMP packets really make it up to Tcp???
        delete packet;
    }
    else
        throw cRuntimeError("Unknown protocol: '%s'", (protocol != nullptr ? protocol->getName() : "<nullptr>"));
}

}
}

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

#include <algorithm>
#include "SubflowConnection.h"

#include <inet/transportlayer/tcp/TcpSendQueue.h>
#include <inet/transportlayer/tcp/TcpAlgorithm.h>
#include <inet/transportlayer/tcp/TcpReceiveQueue.h>
#include <inet/transportlayer/tcp/TcpSackRexmitQueue.h>
#include <inet/common/socket/SocketTag_m.h>
#include "inet/common/packet/Message.h"

namespace inet {
namespace tcp {

Define_Module(SubflowConnection);

SubflowConnection::SubflowConnection() {
    // TODO Auto-generated constructor stub

}

SubflowConnection::~SubflowConnection() {
    // TODO Auto-generated destructor stub
}

void SubflowConnection::sendSyn()
{
    if (remoteAddr.isUnspecified() || remotePort == -1)
        throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: foreign socket unspecified");

    if (localPort == -1)
        throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: local port unspecified");

    // create segment
    const auto& tcpHeader = makeShared<TcpHeader>();
    tcpHeader->setSequenceNo(state->iss);
    tcpHeader->setSynBit(true);
    updateRcvWnd();
    tcpHeader->setWindow(state->rcv_wnd);

    state->snd_max = state->snd_nxt = state->iss + 1;

    // ECN
    if (state->ecnWillingness) {
        tcpHeader->setEceBit(true);
        tcpHeader->setCwrBit(true);
        state->ecnSynSent = true;
        EV << "ECN-setup SYN packet sent\n";
    }
    else {
        // rfc 3168 page 16:
        // A host that is not willing to use ECN on a TCP connection SHOULD
        // clear both the ECE and CWR flags in all non-ECN-setup SYN and/or
        // SYN-ACK packets that it sends to indicate this unwillingness.
        tcpHeader->setEceBit(false);
        tcpHeader->setCwrBit(false);
        state->ecnSynSent = false;
//        EV << "non-ECN-setup SYN packet sent\n";
    }

    // write header options
    writeHeaderOptions(tcpHeader);

    Packet *fp = new Packet("SYN");

    tcpHeader->addTagIfAbsent<SocketReq>()->setSocketId(socketId);

    // send it
    sendToIP(fp, tcpHeader);
}

void SubflowConnection::openNewSocket(int mainSocketId)
{
    EV_INFO << "Notifying app: " << indicationName(TCP_I_AVAILABLE) << "\n";
    auto indication = new Indication(indicationName(TCP_I_AVAILABLE), TCP_I_AVAILABLE);
    TcpAvailableInfo *ind = new TcpAvailableInfo();
    ind->setNewSocketId(socketId);
    ind->setLocalAddr(localAddr);
    ind->setRemoteAddr(remoteAddr);
    ind->setLocalPort(localPort);
    ind->setRemotePort(remotePort);

    indication->addTag<SocketInd>()->setSocketId(mainSocketId);
    indication->setControlInfo(ind);
    sendToApp(indication);
}

}
}

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
#include "MpTcpConnection.h"

#include <inet/transportlayer/tcp/TcpSendQueue.h>
#include <inet/transportlayer/tcp/TcpAlgorithm.h>
#include <inet/transportlayer/tcp/TcpReceiveQueue.h>
#include <inet/transportlayer/tcp/TcpSackRexmitQueue.h>

namespace inet {
namespace tcp {

Define_Module(MpTcpConnection);

MpTcpConnection::MpTcpConnection() {
    // TODO Auto-generated constructor stub

}

MpTcpConnection::~MpTcpConnection() {
    // TODO Auto-generated destructor stub
}

void MpTcpConnection::process_OPEN_ACTIVE(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg)
{
    TcpOpenCommand *openCmd = check_and_cast<TcpOpenCommand *>(tcpCommand);
    L3Address localAddr, remoteAddr;
    int localPort, remotePort;

    switch (fsm.getState()) {
        case TCP_S_INIT:
            initConnection(openCmd);

            // store local/remote socket
            state->active = true;
            localAddr = openCmd->getLocalAddr();
            remoteAddr = openCmd->getRemoteAddr();
            localPort = openCmd->getLocalPort();
            remotePort = openCmd->getRemotePort();

            if (remoteAddr.isUnspecified() || remotePort == -1)
                throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: remote address and port must be specified");

            if (localPort == -1) {
                localPort = tcpMain->getEphemeralPort();
                EV_DETAIL << "Assigned ephemeral port " << localPort << "\n";
            }

            EV_DETAIL << "OPEN: " << localAddr << ":" << localPort << " --> " << remoteAddr << ":" << remotePort << "\n";

            //create new subflow here, and then initiate next methods in said subflow
            // send initial SYN
            addSubflow(true);
            selectInitialSeqNum();
            //sendSyn();
            //startSynRexmitTimer();
            //scheduleAfter(TCP_TIMEOUT_CONN_ESTAB, connEstabTimer);
            break;

        default:
            throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: connection already exists");
    }

    delete openCmd;
    delete msg;
}

void MpTcpConnection::addSubflow(bool isMaster)
{
    SubflowConnection* subflowConn = new SubflowConnection();
    int newDestPort = 34;
    int newSrcPort = 35;

    //somehow call createSocket!!



//    auto appModule =
//    const char *localAddress = par("localAddress");
//    int localPort = par("localPort");
//    socket.bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), localPort);
//
//    socket.setCallback(this);
//    socket.setOutputGate(gate("socketOut"));

    //->addForkedConnection(this, subflowConn, localAddr, remoteAddr, newDestPort, newSrcPort);
    //initClonedConnection(subflowConn);
    if(isMaster){

    }
    m_subflows[mptcp_states_t::Syn].push_back(subflowConn);
}

}
}

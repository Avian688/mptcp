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

#include "MpTcpSessionApp.h"

#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/tcp/TcpSocket.h"

namespace inet {

#define MSGKIND_CONNECT    1
#define MSGKIND_SEND       2
#define MSGKIND_CLOSE      3

Define_Module(MpTcpSessionApp);

void MpTcpSessionApp::initialize(int stage)
{
    TcpSessionApp::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        numOfFlows = 1;
        portNumber = 1000;
    }
}

TcpSocket* MpTcpSessionApp::createSocket()
{
    // new TCP connection -- create new socket object and server process
    std::cout << "\n SOCKET ATTEMPTING TO BE CREATED" << endl;
    TcpSocket* newSocket = new TcpSocket();

    const char *localAddress = par("localAddress");
    int localPort = par("localPort");

    int newPortNumber = portNumber+1;
    portNumber = newPortNumber;

    if (localAddress && *localAddress) {
        auto resolvedAddr = L3AddressResolver().resolve(localAddress);
        std::cout << "Binding socket to resolved address: " << resolvedAddr
                  << ", port: " << newPortNumber << std::endl;
    } else {
        std::cout << "Binding socket to unspecified address, port: "
                  << newPortNumber << std::endl;
    }

    newSocket->bind(*localAddress ? L3AddressResolver().resolve(localAddress) : L3Address(), newPortNumber);

    // connect
    const char *connectAddress = par("connectAddress");
    int connectPort = par("connectPort");

    L3Address destination;
    L3AddressResolver().tryResolve(connectAddress, destination);


    newSocket->setOutputGate(gate("socketOut"));

    if (destination.isUnspecified()) {
        EV_ERROR << "Connecting newSocket to " << connectAddress << " port=" << connectPort << ": cannot resolve destination address\n";
    }
    else {
        EV_INFO << "Connecting newSocket to " << connectAddress << "(" << destination << ") port=" << connectPort << endl;


        newSocket->connect(destination, newPortNumber);

        numSessions++;
        emit(connectSignal, 1L);
    }

    //const char *serverThreadModuleType = par("serverThreadModuleType");
    //cModuleType *moduleType = cModuleType::get(serverThreadModuleType);

    char name[80];
    sprintf(name, "thread_%i", newSocket->getSocketId());
    //MpTcpSessionThreadBase *proc = check_and_cast<MpTcpSessionThreadBase *>(moduleType->create(name, this));

    //proc->finalizeParameters();
   // proc->callInitialize();

    newSocket->setCallback(this);
    //proc->init(this, newSocket);


    socketMap.addSocket(newSocket);
    ///threadSet.insert(proc);

    return newSocket;
    //socket->accept(availableInfo->getNewSocketId());
}

void MpTcpSessionApp::removeThread(MpTcpSessionThreadBase *thread)
{
    // remove socket
    socketMap.removeSocket(thread->getSocket());
    threadSet.erase(thread);

    // remove thread object
    thread->deleteModule();
}

void MpTcpSessionApp::threadClosed(MpTcpSessionThreadBase *thread)
{
    // remove socket
    socketMap.removeSocket(thread->getSocket());
    threadSet.erase(thread);

    socketClosed(thread->getSocket());

    // remove thread object
    thread->deleteModule();
}

void MpTcpSessionApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        handleTimer(msg);
    }
    else{
        TcpSocket *subflowSocket = check_and_cast_nullable<TcpSocket *>(socketMap.findSocketFor(msg));
        if (subflowSocket)
            subflowSocket->processMessage(msg);
        else if (socket.belongsToSocket(msg))
            socket.processMessage(msg);
        else {
            EV_ERROR << "message " << msg->getFullName() << "(" << msg->getClassName() << ") arrived for unknown socket \n";
            delete msg;
        }
    }
}

void MpTcpSessionApp::sendData()
{
    long numBytes = commands[commandIndex].numBytes;
    EV_INFO << "sending data with " << numBytes << " bytes\n";
    sendPacket(createDataPacket(numBytes));

    int ci = -1;

    while (++ci < (int)commands.size()) {
        const Command& cmd = commands[ci];
        std::cout << "Command Index: " << ci
                  << " | tSend: " << cmd.tSend
                  << " | numBytes: " << cmd.numBytes << std::endl;
    }

    std::cout << "\n commandIndex: " << commandIndex << endl;

    if (++commandIndex < (int)commands.size()) {
        simtime_t tSend = commands[commandIndex].tSend;
        scheduleAt(std::max(tSend, simTime()), timeoutMsg);
    }
    //else {
    //    timeoutMsg->setKind(MSGKIND_CLOSE);
    //   scheduleAt(std::max(tClose, simTime()), timeoutMsg);
    //}
}

void MpTcpSessionApp::handleTimer(cMessage *msg)
{
    switch (msg->getKind()) {
        case MSGKIND_CONNECT:
            if (activeOpen){
                connect(); // sending will be scheduled from socketEstablished()

                //create mainsubflow socket??
                for (int i = 0; i < numOfFlows; i++) {
                    createSocket();
                }
            }
            else{
                throw cRuntimeError("TODO");
            }
            break;

        case MSGKIND_SEND:
            sendData();
            break;

        case MSGKIND_CLOSE:
            close();
            break;

        default:
            throw cRuntimeError("Invalid timer msg: kind=%d", msg->getKind());
    }
}

void MpTcpSessionThreadBase::socketDeleted(TcpSocket *socket)
{
    if (socket == sock) {
        sock = nullptr;
        hostmod->socketDeleted(socket);
    }
}


void MpTcpSessionThreadBase::refreshDisplay() const
{
    getDisplayString().setTagArg("t", 0, TcpSocket::stateName(sock->getState()));
}

}

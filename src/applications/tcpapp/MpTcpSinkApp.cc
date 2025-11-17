//
// Copyright (C) 2004 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#include <inet/common/stlutils.h>

#include "MpTcpSinkApp.h"
#include "../../transportlayer/tcp/TcpOpenSubflowCommand_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"

namespace inet {

Define_Module(MpTcpSinkApp);

void MpTcpSinkApp::initialize(int stage)
{
    TcpSinkApp::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        numOfFlows = 1;
        portNumber = 1000;
    }
}

void MpTcpSinkApp::handleStartOperation(LifecycleOperation *operation)
{
    TcpSinkApp::handleStartOperation(operation);

    for (int i = 0; i < numOfFlows; i++) {
        createSubflowSocket();
    }
}

TcpSocket* MpTcpSinkApp::createSubflowSocket()
{
    // new TCP connection -- create new socket object and server process
    std::cout << "\n SERVER SOCKET ATTEMPTING TO BE CREATED" << endl;
    TcpSocket* newSocket = new TcpSocket();

    const char *localAddress = par("localAddress");
    int localPort = par("localPort");

    int newPortNumber = portNumber+1;
    portNumber = newPortNumber;

    newSocket->bind(localAddress[0] ? L3Address(localAddress) : L3Address(), newPortNumber);

    newSocket->setOutputGate(gate("socketOut"));

    //const char *serverThreadModuleType = par("serverThreadModuleType");
    //cModuleType *moduleType = cModuleType::get(serverThreadModuleType);

    //MpTcpSessionThreadBase *proc = check_and_cast<MpTcpSessionThreadBase *>(moduleType->create(name, this));

    //proc->finalizeParameters();
    // proc->callInitialize();

    const char *serverThreadModuleType = par("serverThreadModuleType");
    cModuleType *moduleType = cModuleType::get(serverThreadModuleType);
    char name[80];
    sprintf(name, "thread_%i", newSocket->getSocketId());
    TcpServerThreadBase *proc = check_and_cast<TcpServerThreadBase *>(moduleType->create(name, this));
    proc->finalizeParameters();
    proc->callInitialize();
    newSocket->setCallback(proc);
    proc->init(this, newSocket);


    socketMap.addSocket(newSocket);
    ///threadSet.insert(proc);

    newSocket->listenOnce();

    return newSocket;
    //socket->ept(availableInfo->getNewSocketId());
}

TcpSocket* MpTcpSinkApp::createSocket(int socketId, L3Address srcAddr, L3Address destAddr)
{
    // new TCP connection -- create new socket object and server process
    std::cout << "\n SOCKET ATTEMPTING TO BE CREATED" << endl;
    const char *localAddress = par("localAddress");
    int localPort = par("localPort");

    int newPortNumber = portNumber+1;
    portNumber = newPortNumber;

    TcpAvailableInfo* availableInfo = new TcpAvailableInfo();
    availableInfo->setLocalAddr(srcAddr);
    availableInfo->setLocalPort(portNumber);
    availableInfo->setRemoteAddr(destAddr);
    availableInfo->setRemotePort(portNumber);
    availableInfo->setNewSocketId(socketId);

    TcpSocket* newSocket = new TcpSocket(availableInfo);

    // connect
    //const char *connectAddress = par("connectAddress");
    //int connectPort = par("connectPort");

    newSocket->setOutputGate(gate("socketOut"));

    char name[80];
    sprintf(name, "thread_%i", newSocket->getSocketId());

    newSocket->setCallback(this);

    newSocket->accept(newSocket->getSocketId());
    //proc->init(this, newSocket);

    //newSocket->bind(destddr, portNumber);
    //newSocket->connect(destAddr, portNumber);
    socketMap.addSocket(newSocket);

    std::cout << "\n CREATING SOCKET WITH ID: " << newSocket->getSocketId() << endl;
    ///threadSet.insert(proc);

    return newSocket;
    //socket->accept(availableInfo->getNewSocketId());
}

void MpTcpSinkApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        TcpServerThreadBase *thread = (TcpServerThreadBase *)msg->getContextPointer();
        if (!contains(threadSet, thread)) // @suppress("Function cannot be instantiated")
            throw cRuntimeError("Invalid thread pointer in the timer (msg->contextPointer is invalid)");
        thread->timerExpired(msg);
    }
    else {
        TcpSocket *socket = check_and_cast_nullable<TcpSocket *>(socketMap.findSocketFor(msg));
        if (socket)
            socket->processMessage(msg);
        else if (serverSocket.belongsToSocket(msg)){
            if (msg->getKind() == 13) {
               std::cout << "\n MSG WORKED CREATING SOCKET" << endl;
               TcpOpenSubflowCommand *connectInfo;
               connectInfo = check_and_cast<TcpOpenSubflowCommand *>(msg->getControlInfo());
               createSocket(connectInfo->getNewSocketId(), connectInfo->getLocalAddr(), connectInfo->getRemoteAddr());
            }
            else{
                serverSocket.processMessage(msg);
            }
        }
        else {
//            throw cRuntimeError("Unknown incoming message: '%s'", msg->getName());
            EV_ERROR << "message " << msg->getFullName() << "(" << msg->getClassName() << ") arrived for unknown socket \n";
            delete msg;
        }
    }
}



} // namespace inet


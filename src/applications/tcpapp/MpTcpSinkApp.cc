//
// Copyright (C) 2004 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#include <inet/common/stlutils.h>

#include "MpTcpSinkApp.h"

namespace inet {

Define_Module(MpTcpSinkApp);

void MpTcpSinkApp::initialize(int stage)
{
    TcpSinkApp::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        portNumber = 1000;
    }
}

TcpSocket* MpTcpSinkApp::createSocket(int socketId, L3Address srcAddr, L3Address destAddr)
{
    // new TCP connection -- create new socket object and server process
    std::cout << "\n SOCKET ATTEMPTING TO BE CREATED" << endl;
    TcpSocket* newSocket = new TcpSocket();

    const char *localAddress = par("localAddress");
    int localPort = par("localPort");

    int newPortNumber = portNumber+1;
    portNumber = newPortNumber;

    // connect
    const char *connectAddress = par("connectAddress");
    int connectPort = par("connectPort");

    newSocket->setOutputGate(gate("socketOut"));

    newSocket->accept(newSocket->getSocketId());

    //const char *serverThreadModuleType = par("serverThreadModuleType");
    //cModuleType *moduleType = cModuleType::get(serverThreadModuleType);

    char name[80];
    sprintf(name, "thread_%i", newSocket->getSocketId());
    //MpTcpSessionThreadBase *proc = check_and_cast<MpTcpSessionThreadBase *>(moduleType->create(name, this));

    //proc->finalizeParameters();
   // proc->callInitialize();

    //newSocket->setCallback(proc);
    //proc->init(this, newSocket);

    socketMap.addSocket(newSocket);
    ///threadSet.insert(proc);

    return newSocket;
    //socket->accept(availableInfo->getNewSocketId());
}

void MpTcpSinkApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        TcpServerThreadBase *thread = (TcpServerThreadBase *)msg->getContextPointer();
        if (!contains(threadSet, thread))
            throw cRuntimeError("Invalid thread pointer in the timer (msg->contextPointer is invalid)");
        thread->timerExpired(msg);
    }
    else {
        TcpSocket *socket = check_and_cast_nullable<TcpSocket *>(socketMap.findSocketFor(msg));
        if (socket)
            socket->processMessage(msg);
        else if (serverSocket.belongsToSocket(msg))
            serverSocket.processMessage(msg);
        else {
//            throw cRuntimeError("Unknown incoming message: '%s'", msg->getName());
            EV_ERROR << "message " << msg->getFullName() << "(" << msg->getClassName() << ") arrived for unknown socket \n";
            delete msg;
        }
    }
}

} // namespace inet


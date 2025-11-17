//
// Copyright (C) 2004 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#ifndef APPLICATIONS_TCPAPP_MPTCPSINKAPP_H
#define APPLICATIONS_TCPAPP_MPTCPSINKAPP_H

#include "inet/applications/tcpapp/TcpSinkApp.h"

namespace inet {

/**
 * Accepts any number of incoming connections, and discards whatever arrives
 * on them.
 */
class INET_API MpTcpSinkApp : public TcpSinkApp
{
protected:
    int portNumber;
    int numOfFlows;

    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;

    TcpSocket* createSocket(int socketId, L3Address srcAddr, L3Address destAddr);

    virtual TcpSocket* createSubflowSocket();

    virtual void handleStartOperation(LifecycleOperation *operation) override;
};

class INET_API MpTcpSinkAppThread : public TcpSinkAppThread
{
  protected:
    long bytesRcvd;
    TcpSinkApp *sinkAppModule = nullptr;

    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void refreshDisplay() const override;

    // TcpServerThreadBase:
    /**
     * Called when connection is established.
     */
    virtual void established() override;

    /*
     * Called when a data packet arrives.
     */
    virtual void dataArrived(Packet *msg, bool urgent) override;

    /*
     * Called when a timer (scheduled via scheduleAt()) expires.
     */
    virtual void timerExpired(cMessage *timer) override { throw cRuntimeError("Model error: unknown timer message arrived"); }

    virtual void init(TcpServerHostApp *hostmodule, TcpSocket *socket) override { TcpServerThreadBase::init(hostmodule, socket); sinkAppModule = check_and_cast<TcpSinkApp *>(hostmod); }
};

} // namespace inet

#endif


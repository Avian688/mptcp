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

    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;
    TcpSocket* createSocket(int socketId, L3Address srcAddr, L3Address destAddr);

};

} // namespace inet

#endif


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

#ifndef APPLICATIONS_TCPAPP_MPTCPSESSIONAPP_H_
#define APPLICATIONS_TCPAPP_MPTCPSESSIONAPP_H_

#include "inet/transportlayer/contract/tcp/TcpSocket.h"

#include <inet/common/socket/SocketMap.h>

#include "../../../../tcpGoodputApplications/src/applications/tcpapp/TcpGoodputSessionApp.h"

namespace inet {

// forward declaration:
class MpTcpSessionThreadBase;

/**
 * Multi-connection TCP application.
 */
class MpTcpSessionApp : public TcpGoodputSessionApp
{

protected:
    int numOfFlows;
    int portNumber;

    SocketMap socketMap;
    typedef std::set<MpTcpSessionThreadBase *> ThreadSet;
    ThreadSet threadSet;

    virtual void initialize(int stage) override;
    virtual void handleTimer(cMessage *msg) override;
    virtual TcpSocket* createSocket();

public:
   virtual ~MpTcpSessionApp() { socketMap.deleteSockets(); }

   virtual void removeThread(MpTcpSessionThreadBase *thread);
   virtual void threadClosed(MpTcpSessionThreadBase *thread);

   friend class MpTcpSessionThreadBase;

};

/**
 * Abstract base class for server processes to be used with TcpServerHostApp.
 * Subclasses need to be registered using the Register_Class() macro.
 *
 * @see TcpServerHostApp
 */
class INET_API MpTcpSessionThreadBase : public cSimpleModule, public TcpSocket::ICallback
{
  protected:
    MpTcpSessionApp *hostmod;
    TcpSocket *sock; // ptr into socketMap managed by TcpServerHostApp

    // internal: TcpSocket::ICallback methods
    virtual void socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent) override { dataArrived(msg, urgent); }
    virtual void socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo) override { socket->accept(availableInfo->getNewSocketId()); }
    virtual void socketEstablished(TcpSocket *socket) override { established(); }
    virtual void socketPeerClosed(TcpSocket *socket) override { peerClosed(); }
    virtual void socketClosed(TcpSocket *socket) override { hostmod->threadClosed(this); }
    virtual void socketFailure(TcpSocket *socket, int code) override { failure(code); }
    virtual void socketStatusArrived(TcpSocket *socket, TcpStatusInfo *status) override { statusArrived(status); }
    virtual void socketDeleted(TcpSocket *socket) override;

    virtual void refreshDisplay() const override;

  public:

    MpTcpSessionThreadBase() { sock = nullptr; hostmod = nullptr; }
    virtual ~MpTcpSessionThreadBase() { delete sock; }

    // internal: called by TcpServerHostApp after creating this module
    virtual void init(MpTcpSessionApp *hostmodule, TcpSocket *socket) { hostmod = hostmodule; sock = socket; }

    /*
     * Returns the socket object
     */
    virtual TcpSocket *getSocket() { return sock; }

    /*
     * Returns pointer to the host module
     */
    virtual MpTcpSessionApp *getHostModule() { return hostmod; }

    /**
     * Called when connection is established. To be redefined.
     */
    virtual void established() = 0;

    /*
     * Called when a data packet arrives. To be redefined.
     */
    virtual void dataArrived(Packet *msg, bool urgent) = 0;

    /*
     * Called when a timer (scheduled via scheduleAt()) expires. To be redefined.
     */
    virtual void timerExpired(cMessage *timer) = 0;

    /*
     * Called when the client closes the connection. By default it closes
     * our side too, but it can be redefined to do something different.
     */
    virtual void peerClosed() { getSocket()->close(); }

    /*
     * Called when the connection breaks (TCP error). By default it deletes
     * this thread, but it can be redefined to do something different.
     */
    virtual void failure(int code) { hostmod->removeThread(this); }

    /*
     * Called when a status arrives in response to getSocket()->getStatus().
     * By default it deletes the status object, redefine it to add code
     * to examine the status.
     */
    virtual void statusArrived(TcpStatusInfo *status) {}
};

} // namespace inet

#endif


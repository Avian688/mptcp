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

#ifndef TRANSPORTLAYER_TCP_SUBFLOWCONNECTION_H_
#define TRANSPORTLAYER_TCP_SUBFLOWCONNECTION_H_

#include <queue>

#include <inet/common/INETUtils.h>
#include <inet/transportlayer/common/L4Tools.h>

#include <inet/networklayer/common/EcnTag_m.h>
#include <inet/networklayer/common/DscpTag_m.h>
#include <inet/networklayer/common/HopLimitTag_m.h>
#include <inet/networklayer/common/TosTag_m.h>
#include <inet/networklayer/common/L3AddressTag_m.h>
#include <inet/networklayer/contract/IL3AddressType.h>

#include "TcpOpenSubflowCommand_m.h"
#include "MpTcpConnectionBase.h"

namespace inet {
namespace tcp {

class MpTcpConnection;

/**
 * Represents a single MPTCP subflow connection.
 * Each subflow behaves like an independent TCP connection but
 * is controlled by a parent MpTcpConnection (the meta socket).
 */
class SubflowConnection : public MpTcpConnectionBase
{
  public:
    SubflowConnection();
    virtual ~SubflowConnection();

    /** Whether this is the meta connection (it is not). */
    virtual bool isMeta() const override { return false; }

    virtual bool getIsMaster();

    /** Called by the meta connection to initialise the subflow. */
    virtual void initSubflowConnection(Tcp *mod, int socketId,
                                       MpTcpConnection *metaConn, bool isMaster);

    /** Outgoing data transmission from the subflow. */
    virtual uint32_t sendSegment(uint32_t bytes) override;

    virtual bool sendDataDuringLossRecovery(uint32_t congestionWindow) override;

    /** Create and bind a new socket for this subflow. */
    virtual void openNewSocket(int mainSocketId);

    /** Setup addressing information for a new subflow. */
    virtual void setUpConnection(L3Address src, L3Address dest,
                                 int srcPort, int destPort);

    virtual void invokeSendCommand();

  protected:
    MpTcpConnection *metaConn = nullptr;  // Pointer to meta connection
    bool isMaster = false;                 // True for initial subflow

    /** Send SYN including MP_JOIN / MP_CAPABLE options. */
    virtual void sendSyn() override ;

    /** Handle incoming segment while in LISTEN. */
    virtual TcpEventCode processSegmentInListen(Packet *tcpSegment,
            const Ptr<const TcpHeader>& tcpHeader,
            L3Address src, L3Address dest) override;

    /** Handle subflow state transitions. */
    virtual bool performStateTransition(const TcpEventCode& event) override;

    /** Main segment processing once established. */
    virtual TcpEventCode process_RCV_SEGMENT(Packet *tcpSegment,
            const Ptr<const TcpHeader>& tcpHeader,
            L3Address src, L3Address dest) override;

    /** Notify the application that the subflow is established. */
    virtual void sendEstabIndicationToApp() override;

    /** Push meta-level data into this subflow's send queue. */
    virtual void enqueueDataFromMeta(uint32_t bytes);
};

} // namespace tcp
} // namespace inet

#endif // TRANSPORTLAYER_TCP_SUBFLOWCONNECTION_H_

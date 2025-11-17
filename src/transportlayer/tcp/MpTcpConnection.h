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

#ifndef TRANSPORTLAYER_TCP_MPTCPCONNECTION_H_
#define TRANSPORTLAYER_TCP_MPTCPCONNECTION_H_

#include <queue>
#include <vector>

#include <inet/common/INETUtils.h>
#include <inet/common/socket/SocketMap.h>

#include <inet/networklayer/common/EcnTag_m.h>
#include <inet/networklayer/common/DscpTag_m.h>
#include <inet/networklayer/common/HopLimitTag_m.h>
#include <inet/networklayer/common/TosTag_m.h>
#include <inet/networklayer/common/L3AddressTag_m.h>

#include <inet/networklayer/contract/IL3AddressType.h>
#include <inet/transportlayer/common/L4Tools.h>

#include "MpTcpConnectionBase.h"
#include "SubflowConnection.h"

namespace inet {
namespace tcp {

/**
 * Represents the *meta* MPTCP connection.
 * Handles connection-level logic and aggregates multiple subflows.
 */
class MpTcpConnection : public MpTcpConnectionBase
{
  public:
    using SubflowList = std::vector<SubflowConnection*>;

    MpTcpConnection();
    virtual ~MpTcpConnection();

    /** Add a newly created subflow to the meta connection */
    virtual void addSubflow(SubflowConnection* subflowConn);

    /** Handle state changes coming from subflows */
    virtual void subflowStateChange(const TcpEventCode& event);

    /** Meta-level data transmission */
    virtual uint32_t sendSegment(uint32_t bytes) override;

    /** Get data from the meta-scheduler for sending */
    virtual uint32_t getMetaSegment(uint32_t bytes);

    /** Identifies this class as the meta connection */
    virtual bool isMeta() const override { return true; }

  protected:
    /** Meta connection state machine states */
    enum mptcp_states_t {
        Established,   // ESTABLISHED / CLOSE_WAIT
        Syn,           // SYN_RCVD / SYN_SENT
        Close,         // CLOSE_WAIT / FIN_WAIT
        mptcp_state_count
    };

    /** Subflows grouped by state */
    SubflowList m_subflows[mptcp_state_count];

    /** Active open processing */
    virtual void process_OPEN_ACTIVE(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg) override;

    /** Send SYN with MPTCP options */
    virtual void setUpSyn();

    /** Application send request */
    virtual void process_SEND(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg) override;

    /** Incoming SYN in LISTEN */
    virtual TcpEventCode processSegmentInListen(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader,
                                                L3Address src, L3Address dest) override;

    /** SYN/SYN-ACK handling during handshake */
    virtual TcpEventCode processSegmentInSynSent(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader,
                                                 L3Address src, L3Address dest) override;
};

} // namespace tcp
} // namespace inet

#endif // TRANSPORTLAYER_TCP_MPTCPCONNECTION_H_

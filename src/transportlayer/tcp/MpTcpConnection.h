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
#include "MpTcpFlowScheduler.h"
#include "MpTcpPacketScheduler.h"
#include "SubflowConnection.h"

namespace inet {

class NetworkInterface;

namespace tcp {

/**
 * Represents the *meta* MPTCP connection.
 * Handles connection-level logic and aggregates multiple subflows.
 */
class MpTcpConnection : public MpTcpConnectionBase
{
  public:
    MpTcpConnection();
    virtual ~MpTcpConnection();

    /** Add a newly created subflow to the meta connection */
    virtual void addSubflow(SubflowConnection* subflowConn);

    virtual void removeSubflow(SubflowConnection *subflowConn);

    /** Handle state changes coming from subflows */
    virtual void subflowStateChange(SubflowConnection *subflowConn, const TcpEventCode& event, int oldState, int newState);

    /** Meta-level data transmission */
    virtual uint32_t sendSegment(uint32_t bytes) override;

    /** Get data from the meta-scheduler for sending */
    virtual uint32_t getSegment(uint32_t bytes);

    virtual MpTcpPacketScheduler& getPacketScheduler() { return packetScheduler; }

    virtual MpTcpFlowScheduler& getFlowScheduler() { return flowScheduler; }

    virtual const std::vector<SubflowConnection *>& getSubflows() const { return m_subflows; }

    virtual SubflowConnection *createManagedSubflow(bool isMaster);

    /** Identifies this class as the meta connection */
    virtual bool isMeta() const override { return true; }

    virtual uint32_t getBytesAvailable();

    virtual uint32_t getSendWindowRemaining() const;

    virtual Packet *createDataPacket(uint32_t dsnStart, uint32_t bytes) const;

    virtual bool hasPendingMetaRetransmission() const { return metaRetransmissionPending; }

    virtual SubflowConnection *dispatchPendingMetaRetransmission(SubflowConnection *requester, uint32_t bytes);

    virtual uint32_t getSndNxt() {return state->snd_nxt;};

    virtual uint32_t getRcvNxt() {return state->rcv_nxt;};

    virtual const L3Address& getLocalAddressForSubflows() const { return localAddr; }

    virtual L3Address getLocalAddressForSubflow(int slot) const;

    virtual const L3Address& getRemoteAddressForSubflows() const { return remoteAddr; }

    virtual L3Address getRemoteAddressForSubflow(int slot) const;

    virtual int getLocalPortNumber() const { return localPort; }

    virtual int getRemotePortNumber() const { return remotePort; }

    virtual bool isActiveSide() const { return state != nullptr && state->active; }

    virtual bool nextUnsentSeg(uint32_t& seqNum);

    virtual void receivedChunk(uint32_t fromSeqNo, uint32_t toSeqNo);

    virtual void receivedUpTo(uint32_t toSeqNo);

    virtual void retransmitOutstandingSubflowData(SubflowConnection *subflowConn);

    virtual void receivedSynListen(uint32_t seqNo, uint32_t iss);

    virtual void setUpSynAck();

    virtual void processSynSent(uint32_t seqNo);

    virtual void processSynSentAck(uint32_t seqNo);

    virtual void sendEstablished();

    virtual void assignInterface(SubflowConnection* subflowConn);

    virtual void updateTotalCwnd(uint32_t oldSubflowCwnd, uint32_t newSubflowCwnd);

    virtual bool processTimer(cMessage *msg) override;
  protected:
    static simsignal_t holBlockedBytesSignal;
    static simsignal_t metaExpectedDsnSignal;
    static simsignal_t metaArrivedDsnStartSignal;
    static simsignal_t metaDsnGapBytesSignal;
    static simsignal_t metaReinjectedBytesSignal;
    static simsignal_t metaReinjectionsSignal;

    /** Meta connection state machine states */
    enum mptcp_states_t {
        Established,   // ESTABLISHED / CLOSE_WAIT
        Syn,           // SYN_RCVD / SYN_SENT
        Close,         // CLOSE_WAIT / FIN_WAIT
        mptcp_state_count
    };

    std::vector<SubflowConnection*> m_subflows;
    MpTcpPacketScheduler packetScheduler;
    MpTcpFlowScheduler flowScheduler;
    cMessage *metaRexmitTimer = nullptr;
    bool metaRetransmissionPending = false;
    uint32_t pendingMetaRetransmitDsn = 0;
    uint64_t metaReinjectedBytes = 0;
    uint64_t metaReinjections = 0;

    IInterfaceTable* ift;

    virtual NetworkInterface *getInterfaceForSubflow(int slot) const;

    virtual void armMetaRexmitTimer(bool restart);

    virtual void cancelMetaRexmitTimer();

    virtual simtime_t getMetaRexmitDelay() const;

    virtual void processMetaRexmitTimer();

    virtual SubflowConnection *findSubflowForDsn(uint32_t dsn) const;

    virtual void initConnection(TcpOpenCommand *openCmd) override;
    /** Active open processing */
    virtual void process_OPEN_ACTIVE(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg) override;

    virtual void process_OPEN_PASSIVE(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg) override;

    virtual void setUpSyn();

    /** Application send request */
    virtual void process_SEND(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg) override;

    /** Incoming SYN in LISTEN */
    virtual TcpEventCode processSegmentInListen(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader,
                                                L3Address src, L3Address dest) override;

    virtual TcpEventCode processSynInListen(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address srcAddr, L3Address destAddr) override;

    virtual TcpEventCode processSegment1stThru8th(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader) override;

    /** SYN/SYN-ACK handling during handshake */
    virtual TcpEventCode processSegmentInSynSent(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader,
                                                 L3Address src, L3Address dest) override;

    virtual bool processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader) override;


};

} // namespace tcp
} // namespace inet

#endif // TRANSPORTLAYER_TCP_MPTCPCONNECTION_H_

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

#include <map>
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
#include "../../common/DataSequenceNumberTag_m.h"

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
    struct DsnMapping {
        uint32_t dsnStart = 0;
        uint32_t dsnEnd = 0;
    };

    SubflowConnection();
    virtual ~SubflowConnection();

    /** Whether this is the meta connection (it is not). */
    virtual bool isMeta() const override { return false; }

    virtual bool getIsMaster();

    /** Called by the meta connection to initialise the subflow. */
    virtual void initSubflowConnection(Tcp *mod, int socketId,
                                       MpTcpConnection *metaConn, bool isMaster);

    virtual bool openActive(L3Address localAddr, L3Address remoteAddr, int localPort, int remotePort);

    virtual bool openPassive(L3Address localAddr, int localPort);

    virtual bool closeFlow();

    virtual bool abortFlow();

    virtual bool destroyFlow();

    /** Outgoing data transmission from the subflow. */
    virtual uint32_t sendSegment(uint32_t bytes) override;

    virtual bool sendDataDuringLossRecovery(uint32_t congestionWindow) override;

    /** Create and bind a new socket for this subflow. */
    virtual void openNewSocket(int mainSocketId);

    /** Setup addressing information for a new subflow. */
    virtual void setUpConnection(L3Address src, L3Address dest,
                                 int srcPort, int destPort);

    virtual void invokeSendCommand();

    virtual simtime_t getSchedulingRtt() const;

    virtual bool canAcceptScheduledData(uint32_t bytes) const;

    virtual bool canAcceptRetransmission(uint32_t bytes) const;

    virtual bool canUseDefaultScheduler(uint32_t bytes) const;

    virtual void enqueueScheduledData(uint32_t bytes);

    virtual bool enqueueRetransmissionData(uint32_t dsnStart, uint32_t bytes);

    virtual uint32_t getSchedulerQueuedBytes() const;

    virtual uint32_t getSchedulerQueueLimit() const;

    virtual double getSchedulerPacingRateBytesPerSecond() const;

    virtual const std::map<uint32_t, DsnMapping>& getSentDsnMappings() const { return sentDsnMapping; }

    virtual bool nextSeg(uint32_t& seqNum, bool isRecovery) override;

    virtual uint32_t sendSegmentDuringLossRecoveryPhase(uint32_t seqNum) override;

    virtual void sendAck() override;

    virtual void setInterfaceId(int id);

    virtual void sendToIP(Packet *tcpSegment, const Ptr<TcpHeader>& tcpHeader) override;

    virtual void updateTotalCwnd(uint32_t oldSubflowCwnd, uint32_t newSubflowCwnd);

  protected:
    MpTcpConnection *metaConn = nullptr;  // Pointer to meta connection
    bool isMaster = false;                 // True for initial subflow
    bool isRetransmission = false;
    int interfaceId;

    uint32_t dsn_rcv_nxt = 0;
    uint32_t dsn_deliv_nxt = 0;

    std::map<uint32_t, DsnMapping> sentDsnMapping;
    std::map<uint32_t, DsnMapping> receivedDsnMapping;
    std::map<uint32_t, DsnMapping> pendingDsnMapping;

    virtual void initConnection(TcpOpenCommand *openCmd) override;

    /** Send SYN including MP_JOIN / MP_CAPABLE options. */
    virtual void sendSyn() override ;

    /** Handle incoming segment while in LISTEN. */
    virtual TcpEventCode processSegmentInListen(Packet *tcpSegment,
            const Ptr<const TcpHeader>& tcpHeader,
            L3Address src, L3Address dest) override;

    virtual TcpEventCode processSynInListen(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address srcAddr, L3Address destAddr) override;
    virtual TcpEventCode processSegmentInSynSent(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address src, L3Address dest) override;
    virtual TcpEventCode processSegment1stThru8th(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader) override;

    virtual bool processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader) override;

    /** Handle subflow state transitions. */
    virtual bool performStateTransition(const TcpEventCode& event) override;

    /** Main segment processing once established. */
    virtual TcpEventCode process_RCV_SEGMENT(Packet *tcpSegment,
            const Ptr<const TcpHeader>& tcpHeader,
            L3Address src, L3Address dest) override;

    /** Notify the application that the subflow is established. */
    virtual void sendEstabIndicationToApp() override;

    /** Ask the meta connection scheduler to place data on a subflow queue. */
    virtual bool enqueueDataFromMeta(uint32_t bytes);

    /** Utility: sends data or data notification to application */
    virtual void sendAvailableDataToApp() override;

    virtual void sendToApp(cMessage *msg) override;

    /** Utility: send SYN+ACK */
    virtual void sendSynAck() override;

    virtual bool processInternalCommand(int commandCode, TcpCommand *tcpCommand);

    virtual void rememberSentDsnMapping(uint32_t subflowSeqNo, uint32_t dsnStart, uint32_t bytes);

    virtual void rememberReceivedDsnMapping(uint32_t subflowSeqNo, uint32_t dsnStart, uint32_t bytes);

    virtual void eraseReceivedMappingsUpTo(uint32_t seqNo);

    virtual bool translateAckToMetaLevel(uint32_t discardUpToSeq, uint32_t& metaAckNo);

    virtual bool consumePendingDsnMapping(uint32_t subflowSeqNo, uint32_t bytes, uint32_t& dsnStart);
};

} // namespace tcp
} // namespace inet

#endif // TRANSPORTLAYER_TCP_SUBFLOWCONNECTION_H_

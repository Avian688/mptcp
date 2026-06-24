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

#include <algorithm>
#include "SubflowConnection.h"
#include "MpTcpConnection.h"

#include <inet/common/socket/SocketTag_m.h>
#include <inet/common/packet/Message.h>
#include <inet/linklayer/common/InterfaceTag_m.h>
#include <inet/transportlayer/contract/tcp/TcpCommand_m.h>

namespace inet {
namespace tcp {

Define_Module(SubflowConnection);

SubflowConnection::SubflowConnection()
{
    // TODO Auto-generated constructor stub
    isMaster = false;
    metaConn = nullptr;
    the2MSLTimer = nullptr;
    connEstabTimer = nullptr;
    finWait2Timer = nullptr;
    synRexmitTimer = nullptr;
    paceMsg = nullptr;
    throughputTimer = nullptr;
    retransmissionRateTimer = nullptr;
    rackTimer = nullptr;

}

SubflowConnection::~SubflowConnection()
{
    // TODO Auto-generated destructor stub
}

void SubflowConnection::initSubflowConnection(Tcp *mod, int socketId, MpTcpConnection* metaConn, bool isMaster)
{
    TcpConnection::initConnection(mod, socketId);
    this->metaConn = metaConn;
    this->isMaster = isMaster;
    metaConn->addSubflow(this);
    metaConn->assignInterface(this);
}

void SubflowConnection::initConnection(TcpOpenCommand *openCmd)
{
    MpTcpConnectionBase::initConnection(openCmd);
}

bool SubflowConnection::openActive(L3Address localAddr, L3Address remoteAddr, int localPort, int remotePort)
{
    TcpOpenCommand *openCmd = new TcpOpenCommand();
    openCmd->setLocalAddr(localAddr);
    openCmd->setRemoteAddr(remoteAddr);
    openCmd->setLocalPort(localPort);
    openCmd->setRemotePort(remotePort);
    return processInternalCommand(TCP_C_OPEN_ACTIVE, openCmd);
}

bool SubflowConnection::openPassive(L3Address localAddr, int localPort)
{
    TcpOpenCommand *openCmd = new TcpOpenCommand();
    openCmd->setLocalAddr(localAddr);
    openCmd->setLocalPort(localPort);
    openCmd->setFork(false);
    return processInternalCommand(TCP_C_OPEN_PASSIVE, openCmd);
}

bool SubflowConnection::closeFlow()
{
    return processInternalCommand(TCP_C_CLOSE, new TcpCommand());
}

bool SubflowConnection::abortFlow()
{
    return processInternalCommand(TCP_C_ABORT, new TcpCommand());
}

bool SubflowConnection::destroyFlow()
{
    return processInternalCommand(TCP_C_DESTROY, new TcpCommand());
}

void SubflowConnection::setUpConnection(L3Address src, L3Address dest, int srcPort, int destPort)
{
    TcpOpenCommand *openCmd = new TcpOpenCommand(); //set the remote connection dest and src to the reverse of the sender
    openCmd->setLocalAddr(dest);
    openCmd->setRemoteAddr(src);
    openCmd->setLocalPort(destPort);
    openCmd->setRemotePort(srcPort);

    initConnection(openCmd);
    state->active = false;
    state->fork = true;
    localAddr = openCmd->getRemoteAddr();
    remoteAddr = openCmd->getLocalAddr();
    localPort = openCmd->getRemotePort();
    remotePort = openCmd->getLocalPort();

    FSM_Goto(fsm, TCP_S_LISTEN);
}

void SubflowConnection::sendSyn()
{
    if (remoteAddr.isUnspecified() || remotePort == -1)
        throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: foreign socket unspecified");

    if (localPort == -1)
        throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: local port unspecified");

    // create segment
    const auto& tcpHeader = makeShared<TcpHeader>();
    tcpHeader->setSequenceNo(state->iss);
    tcpHeader->setSynBit(true);
    updateRcvWnd();
    tcpHeader->setWindow(state->rcv_wnd);

    state->snd_max = state->snd_nxt = state->iss + 1;

    // ECN
    if (state->ecnWillingness) {
        tcpHeader->setEceBit(true);
        tcpHeader->setCwrBit(true);
        state->ecnSynSent = true;
        EV << "ECN-setup SYN packet sent\n";
    }
    else {
        // rfc 3168 page 16:
        // A host that is not willing to use ECN on a TCP connection SHOULD
        // clear both the ECE and CWR flags in all non-ECN-setup SYN and/or
        // SYN-ACK packets that it sends to indicate this unwillingness.
        tcpHeader->setEceBit(false);
        tcpHeader->setCwrBit(false);
        state->ecnSynSent = false;
//        EV << "non-ECN-setup SYN packet sent\n";
    }

    // write header options
    writeHeaderOptions(tcpHeader);

    Packet *fp = new Packet("SYN");

    tcpHeader->addTagIfAbsent<SocketReq>()->setSocketId(socketId);

    tcpHeader->addTagIfAbsent<DataSequenceNumberTag>()->setDataSequenceNumber(state->iss);

    // send it
    sendToIP(fp, tcpHeader);
}

void SubflowConnection::openNewSocket(int mainSocketId)
{
    EV_INFO << "Notifying app: " << indicationName(13) << "\n";
    auto indication = new Indication(indicationName(13), 13);
    TcpOpenSubflowCommand *ind = new TcpOpenSubflowCommand();
    ind->setNewSocketId(socketId);
    ind->setLocalAddr(localAddr);
    ind->setRemoteAddr(remoteAddr);
    ind->setLocalPort(localPort);
    ind->setRemotePort(remotePort);

    indication->addTag<SocketInd>()->setSocketId(mainSocketId);
    indication->setControlInfo(ind);
    sendToApp(indication);
}

TcpEventCode SubflowConnection::processSegmentInListen(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address srcAddr, L3Address destAddr)
{
    EV_DETAIL << "Processing segment in LISTEN\n";
    //"
    // first check for an RST
    //   An incoming RST should be ignored.  Return.
    //"
    if (tcpHeader->getRstBit()) {
        EV_INFO << "RST bit set: dropping segment\n";
        return TCP_E_IGNORE;
    }

    //"
    // second check for an ACK
    //    Any acknowledgment is bad if it arrives on a connection still in
    //    the LISTEN state.  An acceptable reset segment should be formed
    //    for any arriving ACK-bearing segment.  The RST should be
    //    formatted as follows:
    //
    //      <SEQ=SEG.ACK><CTL=RST>
    //
    //    Return.
    //"
    if (tcpHeader->getAckBit()) {
        EV_INFO << "ACK bit set: dropping segment and sending RST\n";
        sendRst(tcpHeader->getAckNo(), destAddr, srcAddr, tcpHeader->getDestPort(), tcpHeader->getSrcPort());
        return TCP_E_IGNORE;
    }

    //"
    // third check for a SYN
    //"
    if (tcpHeader->getSynBit()) {
        if (tcpHeader->getFinBit()) {
            // Looks like implementations vary on how to react to SYN+FIN.
            // Some treat it as plain SYN (and reply with SYN+ACK), some send RST+ACK.
            // Let's just do the former here.
            EV_INFO << "SYN+FIN received: ignoring FIN\n";
        }

        EV_DETAIL << "SYN bit set: filling in foreign socket and sending SYN+ACK\n";

        //"
        // If the listen was not fully specified (i.e., the foreign socket was not
        // fully specified), then the unspecified fields should be filled in now.
        //"
        //
        // Also, we may need to fork, in order to leave another connection
        // LISTENing on the port. Note: forking will change our socketId.
        tcpMain->updateSockPair(this, destAddr, srcAddr, tcpHeader->getDestPort(), tcpHeader->getSrcPort());
        return processSynInListen(tcpSegment, tcpHeader, srcAddr, destAddr);
    }

    //"
    //  fourth other text or control
    //   So you are unlikely to get here, but if you do, drop the segment, and return.
    //"
    EV_WARN << "Unexpected segment: dropping it\n";
    return TCP_E_IGNORE;
}

bool SubflowConnection::performStateTransition(const TcpEventCode& event)
{
    ASSERT(fsm.getState() != TCP_S_CLOSED); // closed connections should be deleted immediately

    if (event == TCP_E_IGNORE) { // e.g. discarded segment
        EV_DETAIL << "Staying in state: " << stateName(fsm.getState()) << " (no FSM event)\n";
        return true;
    }

    // state machine
    // TODO add handling of connection timeout event (KEEP-ALIVE), with transition to CLOSED
    // Note: empty "default:" lines are for gcc's benefit which would otherwise spit warnings
    int oldState = fsm.getState();

    switch (fsm.getState()) {
        case TCP_S_INIT:
            switch (event) {
                case TCP_E_OPEN_PASSIVE:
                    FSM_Goto(fsm, TCP_S_LISTEN);
                    break;

                case TCP_E_OPEN_ACTIVE:
                    FSM_Goto(fsm, TCP_S_SYN_SENT);
                    break;

                case TCP_E_DESTROY:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_LISTEN:
            switch (event) {
                case TCP_E_OPEN_ACTIVE:
                    FSM_Goto(fsm, TCP_S_SYN_SENT);
                    break;

                case TCP_E_SEND:
                    FSM_Goto(fsm, TCP_S_SYN_SENT);
                    break;

                case TCP_E_CLOSE:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_ABORT:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_DESTROY:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_RCV_SYN:
                    FSM_Goto(fsm, TCP_S_SYN_RCVD);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_SYN_RCVD:
            switch (event) {
                case TCP_E_CLOSE:
                    FSM_Goto(fsm, TCP_S_FIN_WAIT_1);
                    break;

                case TCP_E_ABORT:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_DESTROY:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_TIMEOUT_CONN_ESTAB:
                    FSM_Goto(fsm, state->active ? TCP_S_CLOSED : TCP_S_LISTEN);
                    break;

                case TCP_E_RCV_RST:
                    FSM_Goto(fsm, state->active ? TCP_S_CLOSED : TCP_S_LISTEN);
                    break;

                case TCP_E_RCV_ACK:
                    FSM_Goto(fsm, TCP_S_ESTABLISHED);
                    break;

                case TCP_E_RCV_FIN:
                    FSM_Goto(fsm, TCP_S_CLOSE_WAIT);
                    break;

                case TCP_E_RCV_UNEXP_SYN:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_SYN_SENT:
            switch (event) {
                case TCP_E_CLOSE:
                case TCP_E_ABORT:
                case TCP_E_DESTROY:
                case TCP_E_TIMEOUT_CONN_ESTAB:
                case TCP_E_RCV_RST:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_RCV_SYN_ACK:
                    FSM_Goto(fsm, TCP_S_ESTABLISHED);
                    break;

                case TCP_E_RCV_SYN:
                    FSM_Goto(fsm, TCP_S_SYN_RCVD);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_ESTABLISHED:
            switch (event) {
                case TCP_E_CLOSE:
                    FSM_Goto(fsm, TCP_S_FIN_WAIT_1);
                    break;

                case TCP_E_ABORT:
                case TCP_E_DESTROY:
                case TCP_E_RCV_RST:
                case TCP_E_RCV_UNEXP_SYN:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_RCV_FIN:
                    FSM_Goto(fsm, TCP_S_CLOSE_WAIT);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_CLOSE_WAIT:
            switch (event) {
                case TCP_E_CLOSE:
                    FSM_Goto(fsm, TCP_S_LAST_ACK);
                    break;

                case TCP_E_ABORT:
                case TCP_E_DESTROY:
                case TCP_E_RCV_RST:
                case TCP_E_RCV_UNEXP_SYN:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_LAST_ACK:
            switch (event) {
                case TCP_E_ABORT:
                case TCP_E_DESTROY:
                case TCP_E_RCV_ACK:
                case TCP_E_RCV_RST:
                case TCP_E_RCV_UNEXP_SYN:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_FIN_WAIT_1:
            switch (event) {
                case TCP_E_ABORT:
                case TCP_E_DESTROY:
                case TCP_E_RCV_RST:
                case TCP_E_RCV_UNEXP_SYN:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_RCV_FIN:
                    FSM_Goto(fsm, TCP_S_CLOSING);
                    break;

                case TCP_E_RCV_ACK:
                    FSM_Goto(fsm, TCP_S_FIN_WAIT_2);
                    break;

                case TCP_E_RCV_FIN_ACK:
                    FSM_Goto(fsm, TCP_S_TIME_WAIT);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_FIN_WAIT_2:
            switch (event) {
                case TCP_E_ABORT:
                case TCP_E_DESTROY:
                case TCP_E_TIMEOUT_FIN_WAIT_2:
                case TCP_E_RCV_RST:
                case TCP_E_RCV_UNEXP_SYN:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_RCV_FIN:
                    FSM_Goto(fsm, TCP_S_TIME_WAIT);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_CLOSING:
            switch (event) {
                case TCP_E_ABORT:
                case TCP_E_DESTROY:
                case TCP_E_RCV_RST:
                case TCP_E_RCV_UNEXP_SYN:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                case TCP_E_RCV_ACK:
                    FSM_Goto(fsm, TCP_S_TIME_WAIT);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_TIME_WAIT:
            switch (event) {
                case TCP_E_ABORT:
                case TCP_E_TIMEOUT_2MSL:
                case TCP_E_RCV_RST:
                case TCP_E_RCV_UNEXP_SYN:
                case TCP_E_DESTROY:
                    FSM_Goto(fsm, TCP_S_CLOSED);
                    break;

                default:
                    break;
            }
            break;

        case TCP_S_CLOSED:
            break;
    }

    if (oldState != fsm.getState()) {
        EV_INFO << "Transition: " << stateName(oldState) << " --> " << stateName(fsm.getState()) << "  (event was: " << eventName(event) << ")\n";
        EV_DEBUG_C("testing") << tcpMain->getName() << ": " << stateName(oldState) << " --> " << stateName(fsm.getState()) << "  (on " << eventName(event) << ")\n";

        // cancel timers, etc.
        stateEntered(fsm.getState(), oldState, event);
    }
    else {
        EV_DETAIL << "Staying in state: " << stateName(fsm.getState()) << " (event was: " << eventName(event) << ")\n";
    }

    if (oldState != fsm.getState() && metaConn != nullptr)
        metaConn->subflowStateChange(this, event, oldState, fsm.getState());

    return fsm.getState() != TCP_S_CLOSED;
}

TcpEventCode SubflowConnection::process_RCV_SEGMENT(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address src, L3Address dest)
{
    EV_INFO << "Seg arrived: ";
    printSegmentBrief(tcpSegment, tcpHeader);
    EV_DETAIL << "TCB: " << state->str() << "\n";

    emit(rcvSeqSignal, tcpHeader->getSequenceNo());
    emit(rcvAckSignal, tcpHeader->getAckNo());

    emit(tcpRcvPayloadBytesSignal, int(tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get()));

    //
    // Note: this code is organized exactly as RFC 793, section "3.9 Event
    // Processing", subsection "SEGMENT ARRIVES".
    //
    TcpEventCode event;

    if (getFsmState() == TCP_S_LISTEN) {
        pace = false;
        event = processSegmentInListen(tcpSegment, tcpHeader, src, dest);
    }
    else if (getFsmState() == TCP_S_SYN_SENT) {
        event = processSegmentInSynSent(tcpSegment, tcpHeader, src, dest);
    }
    else {
        const uint32_t oldRcvNxt = state->rcv_nxt;
        event = processSegment1stThru8th(tcpSegment, tcpHeader);

        // Count unique, in-order payload delivered by this subflow. A jump in
        // RCV.NXT may release previously buffered out-of-order data, while
        // duplicate and pure ACK segments contribute nothing.
        if (seqGreater(state->rcv_nxt, oldRcvNxt))
            bytesRcvd += state->rcv_nxt - oldRcvNxt;
    }
    delete tcpSegment;
    return event;
}

uint32_t SubflowConnection::sendSegment(uint32_t bytes)
{
    // FIXME check it: where is the right place for the next code (sacked/rexmitted)
    if (state->sack_enabled && state->afterRto) {
        // check rexmitQ and try to forward snd_nxt before sending new data
        uint32_t forward = rexmitQueue->checkRexmitQueueForSackedOrRexmittedSegments(state->snd_nxt);

        if (forward > 0) {
            EV_INFO << "sendSegment(" << bytes << ") forwarded " << forward << " bytes of snd_nxt from " << state->snd_nxt;
            state->snd_nxt += forward;
            EV_INFO << " to " << state->snd_nxt << endl;
            EV_DETAIL << rexmitQueue->detailedInfo();
        }
    }

    uint32_t buffered = sendQueue->getBytesAvailable(state->snd_nxt);

    if (bytes > buffered) // last segment?
        bytes = buffered;

    // if header options will be added, this could reduce the number of data bytes allowed for this segment,
    // because following condition must to be respected:
    //     bytes + options_len <= snd_mss
    const auto& tmpTcpHeader = makeShared<TcpHeader>();
    tmpTcpHeader->setAckBit(true); // needed for TS option, otherwise TSecr will be set to 0
    writeHeaderOptions(tmpTcpHeader);

    //uint options_len = B(tmpTcpHeader->getHeaderLength() - TCP_MIN_HEADER_LENGTH).get();

    //ASSERT(options_len < state->snd_mss);

    bytes = std::min(bytes, state->snd_mss);
    uint32_t sentBytes = bytes;

    // send one segment of 'bytes' bytes from snd_nxt, and advance snd_nxt
    Packet *tcpSegment = sendQueue->createSegmentWithBytes(state->snd_nxt, bytes);
    const auto& tcpHeader = makeShared<TcpHeader>();
    tcpHeader->setSequenceNo(state->snd_nxt);
    ASSERT(tcpHeader != nullptr);

    // Remember old_snd_next to store in SACK rexmit queue.
    uint32_t old_snd_nxt = state->snd_nxt;

    tcpHeader->setAckNo(state->rcv_nxt);
    tcpHeader->setAckBit(true);
    tcpHeader->setWindow(updateRcvWnd());

    // ECN
    if (state->ect && state->sndCwr) {
        tcpHeader->setCwrBit(true);
        EV_INFO << "set CWR bit\n";
        state->sndCwr = false;
    }

    // TODO when to set PSH bit?
    // TODO set URG bit if needed
    ASSERT(bytes == tcpSegment->getByteLength());

    state->snd_nxt += bytes;

    uint32_t metaSnd_nxt = 0;
    if (!consumePendingDsnMapping(old_snd_nxt, sentBytes, metaSnd_nxt)) {
        if (!isRetransmission)
            throw cRuntimeError("Missing scheduled MPTCP DSN mapping at subflow sequence %u", old_snd_nxt);
        else {
            auto it = sentDsnMapping.find(old_snd_nxt);
            if (it != sentDsnMapping.end())
                metaSnd_nxt = it->second.dsnStart;
        }
    }

    // check if afterRto bit can be reset
    if (state->afterRto && seqGE(state->snd_nxt, state->snd_max))
        state->afterRto = false;

    if (state->send_fin && state->snd_nxt == state->snd_fin_seq) {
        EV_DETAIL << "Setting FIN on segment\n";
        tcpHeader->setFinBit(true);
        state->snd_nxt = state->snd_fin_seq + 1;
    }

    // if sack_enabled copy region of tcpHeader to rexmitQueue
    if (state->sack_enabled){
        rexmitQueue->enqueueSentData(old_snd_nxt, state->snd_nxt);
        if ((pace || rack_enabled) && rexmitQueue->isUpdatedSackEnabled()) {
            rexmitQueue->skbSent(state->snd_nxt, m_firstSentTime, simTime(), m_deliveredTime,
                    m_bytesInFlight + sentBytes, false, m_delivered, m_appLimited);
        }
    }

    // add header options and update header length (from tcpseg_temp)
    for (uint i = 0; i < tmpTcpHeader->getHeaderOptionArraySize(); i++)
        tcpHeader->appendHeaderOption(tmpTcpHeader->getHeaderOption(i)->dup());
    tcpHeader->setHeaderLength(TCP_MIN_HEADER_LENGTH + tcpHeader->getHeaderOptionArrayLength());
    tcpHeader->setChunkLength(B(tcpHeader->getHeaderLength()));

    ASSERT(tcpHeader->getHeaderLength() == tmpTcpHeader->getHeaderLength());

    calculateAppLimited();

    tcpHeader->addTagIfAbsent<DataSequenceNumberTag>()->setDataSequenceNumber(metaSnd_nxt);
    rememberSentDsnMapping(tcpHeader->getSequenceNo(), metaSnd_nxt, sentBytes);

    // send it
    sendToIP(tcpSegment, tcpHeader);

    // let application fill queue again, if there is space
    const uint32_t alreadyQueued = sendQueue->getBytesAvailable(sendQueue->getBufferStartSeq());
    const uint32_t abated = (state->sendQueueLimit > alreadyQueued) ? state->sendQueueLimit - alreadyQueued : 0;
    if ((state->sendQueueLimit > 0) && !state->queueUpdate && (abated >= state->snd_mss)) { // request more data if space >= 1 MSS
        // Tell upper layer readiness to accept more data
        sendIndicationToApp(TCP_I_SEND_MSG, abated);
        state->queueUpdate = true;
    }

    // remember highest seq sent (snd_nxt may be set back on retransmission,
    // but we'll need snd_max to check validity of ACKs -- they must ack
    // something we really sent)
    if (seqGreater(state->snd_nxt, state->snd_max))
        state->snd_max = state->snd_nxt;

    updateInFlight();
    return sentBytes;
}

void SubflowConnection::sendEstabIndicationToApp()
{
    //For time being DO NOT send anything to app - this is the meta connections job
//    EV_INFO << "Notifying app: " << indicationName(TCP_I_ESTABLISHED) << "\n";
//    auto indication = new Indication(indicationName(TCP_I_ESTABLISHED), TCP_I_ESTABLISHED);
//    TcpConnectInfo *ind = new TcpConnectInfo();
//    ind->setLocalAddr(localAddr);
//    ind->setRemoteAddr(remoteAddr);
//    ind->setLocalPort(localPort);
//    ind->setRemotePort(remotePort);
//    indication->addTag<SocketInd>()->setSocketId(socketId);
//    indication->setControlInfo(ind);
//    sendToApp(indication);
}

bool SubflowConnection::enqueueDataFromMeta(uint32_t bytes)
{
    if (metaConn == nullptr)
        return false;

    if (metaConn->hasPendingMetaRetransmission())
        return metaConn->dispatchPendingMetaRetransmission(this, bytes) == this;

    if (metaConn->getPacketScheduler().usesDirectPullMode()) {
        if (metaConn->getSegment(bytes) < bytes)
            return false;

        enqueueScheduledData(bytes);
        return true;
    }

    return metaConn->getPacketScheduler().schedulePacket(this, bytes) == this;
}

simtime_t SubflowConnection::getSchedulingRtt() const
{
    auto *pacedAlgorithm = dynamic_cast<TcpPacedFamily *>(tcpAlgorithm);
    if (pacedAlgorithm == nullptr)
        return SIMTIME_MAX;

    const simtime_t srtt = pacedAlgorithm->getRtt();
    return srtt > SIMTIME_ZERO ? srtt : SIMTIME_MAX;
}

simtime_t SubflowConnection::getSchedulingRto() const
{
    if (state == nullptr || state->snd_una == state->snd_max)
        return SIMTIME_ZERO;

    auto *pacedAlgorithm = dynamic_cast<TcpPacedFamily *>(tcpAlgorithm);
    if (pacedAlgorithm != nullptr) {
        const simtime_t expiry = pacedAlgorithm->getRexmitTimerExpiry();
        if (expiry != SIMTIME_MAX && expiry > simTime())
            return expiry - simTime();
    }
    return SIMTIME_ZERO;
}

uint32_t SubflowConnection::getOutstandingDsnBytes(uint32_t dsn) const
{
    for (const auto& entry : sentDsnMapping) {
        const DsnMapping& mapping = entry.second;
        if (seqLE(mapping.dsnStart, dsn) && seqLess(dsn, mapping.dsnEnd))
            return mapping.dsnEnd - dsn;
    }
    return 0;
}

bool SubflowConnection::canAcceptScheduledData(uint32_t bytes) const
{
    if (state == nullptr || sendQueue == nullptr)
        return false;

    const int currentState = fsm.getState();
    if (currentState != TCP_S_ESTABLISHED && currentState != TCP_S_CLOSE_WAIT)
        return false;

    const uint32_t alreadyQueued = sendQueue->getBytesAvailable(sendQueue->getBufferStartSeq());
    const uint32_t queueLimit = getSchedulerQueueLimit();
    return alreadyQueued <= queueLimit && bytes <= queueLimit - alreadyQueued;
}

bool SubflowConnection::canAcceptRetransmission(uint32_t bytes) const
{
    if (!canAcceptScheduledData(bytes))
        return false;

    if (state->snd_una != state->snd_max || state->snd_nxt != state->snd_max)
        return false;

    if (getSchedulerQueuedBytes() != 0)
        return false;

    return std::max(m_bytesInFlight, state->pipe) == 0;
}

bool SubflowConnection::canUseDefaultScheduler(uint32_t bytes) const
{
    if (!isActiveForDefaultScheduler())
        return false;

    // Linux's default scheduler tests sk_stream_memory_free(), which is socket
    // write memory rather than cwnd. In this model a zero sendQueueLimit means
    // unlimited write memory; TCP still enforces cwnd when the subflow sends.
    if (state->sendQueueLimit == 0)
        return true;

    const uint32_t alreadyQueued = getSchedulerQueuedBytes();
    return alreadyQueued <= state->sendQueueLimit &&
            bytes <= state->sendQueueLimit - alreadyQueued;
}

bool SubflowConnection::isActiveForDefaultScheduler() const
{
    if (state == nullptr || sendQueue == nullptr ||
            dynamic_cast<TcpPacedFamily *>(tcpAlgorithm) == nullptr)
        return false;

    const int currentState = fsm.getState();
    return currentState == TCP_S_ESTABLISHED || currentState == TCP_S_CLOSE_WAIT;
}

void SubflowConnection::enqueueScheduledData(uint32_t bytes)
{
    Enter_Method_Silent("enqueueScheduledData");

    ASSERT(metaConn != nullptr);
    ASSERT(sendQueue != nullptr);

    const uint32_t subflowSeqStart = sendQueue->getBufferEndSeq();
    const uint32_t dsnStart = metaConn->sendSegment(bytes);

    DsnMapping mapping;
    mapping.dsnStart = dsnStart;
    mapping.dsnEnd = dsnStart + bytes;
    pendingDsnMapping[subflowSeqStart] = mapping;

    Packet *msg = new Packet("Packet");
    Ptr<Chunk> packetBytes = makeShared<ByteCountChunk>(B(bytes));
    msg->insertAtBack(packetBytes);
    sendQueue->enqueueAppData(msg);
}

bool SubflowConnection::enqueueRetransmissionData(uint32_t dsnStart, uint32_t bytes)
{
    Enter_Method_Silent("enqueueRetransmissionData");

    if (metaConn == nullptr || sendQueue == nullptr || bytes == 0 || !canAcceptScheduledData(bytes))
        return false;

    Packet *msg = metaConn->createDataPacket(dsnStart, bytes);
    if (msg == nullptr)
        return false;

    const uint32_t subflowSeqStart = sendQueue->getBufferEndSeq();
    DsnMapping mapping;
    mapping.dsnStart = dsnStart;
    mapping.dsnEnd = dsnStart + bytes;
    pendingDsnMapping[subflowSeqStart] = mapping;
    sendQueue->enqueueAppData(msg);
    return true;
}

uint32_t SubflowConnection::getSchedulerQueuedBytes() const
{
    if (sendQueue == nullptr)
        return 0;

    return sendQueue->getBytesAvailable(sendQueue->getBufferStartSeq());
}

uint32_t SubflowConnection::getSchedulerQueueLimit() const
{
    if (state == nullptr)
        return 0;

    uint32_t windowBudget = state->snd_wnd;

    if (auto *pacedAlgorithm = dynamic_cast<TcpPacedFamily *>(tcpAlgorithm))
        windowBudget = std::min(windowBudget, pacedAlgorithm->getCwnd());

    if (state->sendQueueLimit > 0)
        windowBudget = std::min(windowBudget, state->sendQueueLimit);

    // bytesAvailable(bufferStartSeq) includes sent-but-unacked bytes and
    // locally queued bytes. This helper is used by schedulers that need actual
    // cwnd/rwnd admission; the Linux-like default scheduler uses
    // canUseDefaultScheduler(), where the stream memory check is send-buffer
    // pressure rather than cwnd.
    return windowBudget;
}

double SubflowConnection::getSchedulerPacingRateBytesPerSecond() const
{
    if (state == nullptr || intersendingTime <= SIMTIME_ZERO)
        return 0.0;

    return static_cast<double>(state->snd_mss) / intersendingTime.dbl();
}

bool SubflowConnection::sendPendingData()
{
    // Current Linux MPTCP dispatches pending meta-level data before entering
    // a particular subflow's TCP send path. Keep retransmission handling local,
    // but let the legacy lowest-RTT policy select any available subflow for new data.
    if (state != nullptr && sendQueue != nullptr && metaConn != nullptr &&
            !state->lossRecovery && !state->afterRto &&
            metaConn->getPacketScheduler().usesLowestRttScheduling() &&
            sendQueue->getBytesAvailable(state->snd_max) == 0)
    {
        SubflowConnection *selected = metaConn->getPacketScheduler().schedulePacket(this, state->snd_mss);
        if (selected == nullptr || selected != this)
            return selected != nullptr;
    }

    return TcpPacedConnection::sendPendingData();
}

bool SubflowConnection::sendDataDuringLossRecovery(uint32_t congestionWindow)
{

    isRetransmission = false;
    // RFC 3517 pages 7 and 8: "(5) In order to take advantage of potential additional available
    // cwnd, proceed to step (C) below.
    // (...)
    // (C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
    // segments as follows:
    // (...)
    // (C.5) If cwnd - pipe >= 1 SMSS, return to (C.1)"
    uint32_t availableWindow = (state->pipe > congestionWindow) ? 0 : congestionWindow - state->pipe;

    if (availableWindow >= (int)state->snd_mss) { // Note: Typecast needed to avoid prohibited transmissions
        // RFC 3517 pages 7 and 8: "(C.1) The scoreboard MUST be queried via NextSeg () for the
        // sequence number range of the next segment to transmit (if any),
        // and the given segment sent.  If NextSeg () returns failure (no
        // data to send) return without sending anything (i.e., terminate
        // steps C.1 -- C.5)."

        uint32_t seqNum;

        if (!nextSeg(seqNum, state->lossRecovery)){ // if nextSeg() returns false (=failure): terminate steps C.1 -- C.5
            return false;
        }

        uint32_t sentBytes = sendSegmentDuringLossRecoveryPhase(seqNum);

        if(sentBytes > 0){
            return true;
        }
        else{
            return false;
        }
        //m_bytesInFlight += sentBytes;
        // RFC 3517 page 8: "(C.4) The estimate of the amount of data outstanding in the
        // network must be updated by incrementing pipe by the number of
        // octets transmitted in (C.1)."
    }
    return false;
}

bool SubflowConnection::nextSeg(uint32_t& seqNum, bool isRecovery)
{
    ASSERT(state->sack_enabled);

    // RFC 3517, page 5: "This routine uses the scoreboard data structure maintained by the
    // Update() function to determine what to transmit based on the SACK
    // information that has arrived from the data receiver (and hence
    // been marked in the scoreboard).  NextSeg () MUST return the
    // sequence number range of the next segment that is to be
    // transmitted, per the following rules:"


    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();// not needed?
    uint32_t highestSackedSeqNum = rexmitQueue->getHighestSackedSeqNum();
    uint32_t shift = state->snd_mss;
    bool sacked = false; // required for rexmitQueue->checkSackBlock()
    bool rexmitted = false; // required for rexmitQueue->checkSackBlock()
    bool lost = false; // required for rexmitQueue->checkSackBlock()
    //auto currIter = rexmitQueue->searchSackBlock(state->highRxt);
    seqNum = 0;

//    if (state->ts_enabled){
//        shift -= B(TCP_OPTION_TS_SIZE).get();
//    }
    // RFC 3517, page 5: "(1) If there exists a smallest unSACKed sequence number 'S2' that
    // meets the following three criteria for determining loss, the
    // sequence range of one segment of up to SMSS octets starting
    // with S2 MUST be returned.
    //
    // (1.a) S2 is greater than HighRxt.
    //
    // (1.b) S2 is less than the highest octet covered by any
    //       received SACK.
    //
    // (1.c) IsLost (S2) returns true."

    // Note: state->highRxt == RFC.HighRxt + 1
    uint32_t seqPerRule3 = 0;
    bool isSeqPerRule3Valid = false;

    for (uint32_t s2 = rexmitQueue->getBufferStartSeq();
         seqLess(s2, state->snd_max) && seqLess(s2, highestSackedSeqNum);
         s2 += shift)
    {
        //rexmitQueue->checkSackBlockIter(s2, shift, sacked, rexmitted, currIter);
        rexmitQueue->checkSackBlockLost(s2, shift, sacked, rexmitted, lost);

        //EV_INFO << "checkSackBlockLost: s2: " << s2 << " shift: " << shift << " sacked: " << sacked << " rexmitted: " << rexmitted << " lost: " << lost << "\n";
        if (!sacked) {
            //if (isLost(s2)) { // 1.a and 1.b are true, see above "for" statement
            if(lost && !rexmitted) {
                seqNum = s2;
                isRetransmission = true;
                return true;
            }
            else if(seqPerRule3 == 0 && isRecovery)
            {
                isSeqPerRule3Valid = true;
                seqPerRule3 = s2;
            }

            //break; // !isLost(x) --> !isLost(x + d)
        }
    }

    //rexmitQueue->checkSackBlockIsLost(state->highRxt, state->snd_max, highestSackedSeqNum);
    // RFC 3517, page 5: "(2) If no sequence number 'S2' per rule (1) exists but there
    // exists available unsent data and the receiver's advertised
    // window allows, the sequence range of one segment of up to SMSS
    // octets of previously unsent data starting with sequence number
    // HighData+1 MUST be returned."
    {
        if(metaConn->nextUnsentSeg(seqNum)){
            isRetransmission = false;

            uint32_t buffered = sendQueue->getBytesAvailable(state->snd_max);
            uint32_t maxWindow = state->snd_wnd;
            // effectiveWindow: number of bytes we're allowed to send now
            uint32_t effectiveWin = maxWindow - state->pipe;
            if (effectiveWin >= state->snd_mss) {
                if(buffered <= 0){
                    if (!enqueueDataFromMeta(state->snd_mss))
                        return false;
                    buffered = sendQueue->getBytesAvailable(state->snd_max);
                    if (buffered <= 0)
                        return false;
                }
                seqNum = state->snd_max; // HighData = snd_max
                return true;
            }
        }
        else{
            std::cout << "\n Meta Connection bottlenecking sending data" << endl;
        }
    }

    // RFC 3517, pages 5 and 6: "(3) If the conditions for rules (1) and (2) fail, but there exists
    // an unSACKed sequence number 'S3' that meets the criteria for
    // detecting loss given in steps (1.a) and (1.b) above
    // (specifically excluding step (1.c)) then one segment of up to
    // SMSS octets starting with S3 MAY be returned.
    //
    // Note that rule (3) is a sort of retransmission "last resort".
    // It allows for retransmission of sequence numbers even when the
    // sender has less certainty a segment has been lost than as with
    // rule (1).  Retransmitting segments via rule (3) will help
    // sustain TCP's ACK clock and therefore can potentially help
    // avoid retransmission timeouts.  However, in sending these
    // segments the sender has two copies of the same data considered
    // to be in the network (and also in the Pipe estimate).  When an
    // ACK or SACK arrives covering this retransmitted segment, the
    // sender cannot be sure exactly how much data left the network
    // (one of the two transmissions of the packet or both
    // transmissions of the packet).  Therefore the sender may
    // underestimate Pipe by considering both segments to have left
    // the network when it is possible that only one of the two has.
    //
    // We believe that the triggering of rule (3) will be rare and
    // that the implications are likely limited to corner cases
    // relative to the entire recovery algorithm.  Therefore we leave
    // the decision of whether or not to use rule (3) to
    // implementors."


    {
        //auto currIter = rexmitQueue->searchSackBlock(state->highRxt);
//        for (uint32_t s3 = state->highRxt;
//             seqLess(s3, state->snd_max) && seqLess(s3, highestSackedSeqNum);
//             s3 += shift)
//        {
//            //rexmitQueue->checkSackBlockIter(s3, shift, sacked, rexmitted, currIter);
//            rexmitQueue->checkSackBlock(s3, shift, sacked, rexmitted);
//
//            if (!sacked) {
//                // 1.a and 1.b are true, see above "for" statement
//                seqNum = s3;
//                return true;
//            }
//        }
        if(isSeqPerRule3Valid)
        {
            std::cout << "\n WEIRD EDGE CASE HAPPENING" << endl;
            isRetransmission = true;
            seqNum = seqPerRule3;
            return true;
        }
    }


//    if(isSeqPerRule3Valid)
//    {
//        seqNum = seqPerRule3;
//        return true;
//    }
    // RFC 3517, page 6: "(4) If the conditions for each of (1), (2), and (3) are not met,
    // then NextSeg () MUST indicate failure, and no segment is
    // returned."
    seqNum = 0;

    return false;
}

uint32_t SubflowConnection::sendSegmentDuringLossRecoveryPhase(uint32_t seqNum)
{
    //ASSERT(state->sack_enabled && state->lossRecovery);

    // start sending from seqNum
    state->snd_nxt = seqNum;

    uint32_t old_highRxt = rexmitQueue->getHighestRexmittedSeqNum();

    // no need to check cwnd and rwnd - has already be done before
    // no need to check nagle - sending mss bytes
    uint32_t sentBytes = sendSegment(state->snd_mss);

    uint32_t sentSeqNum = seqNum + sentBytes;

    if (state->send_fin && sentSeqNum == state->snd_fin_seq)
        sentSeqNum = sentSeqNum + 1;

    ASSERT(seqLE(state->snd_nxt, sentSeqNum));


    // RFC 3517 page 8: "(C.2) If any of the data octets sent in (C.1) are below HighData,
    // HighRxt MUST be set to the highest sequence number of the
    // retransmitted segment."
    if (seqLess(seqNum, state->snd_max)) { // HighData = snd_max
        state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
    }

    // RFC 3517 page 8: "(C.3) If any of the data octets sent in (C.1) are above HighData,
    // HighData must be updated to reflect the transmission of
    // previously unsent data."
    if (seqGreater(sentSeqNum, state->snd_max)) // HighData = snd_max
        state->snd_max = sentSeqNum;

    emit(unackedSignal, state->snd_max - state->snd_una);

    // RFC 3517, page 9: "6   Managing the RTO Timer
    //
    // The standard TCP RTO estimator is defined in [RFC2988].  Due to the
    // fact that the SACK algorithm in this document can have an impact on
    // the behavior of the estimator, implementers may wish to consider how
    // the timer is managed.  [RFC2988] calls for the RTO timer to be
    // re-armed each time an ACK arrives that advances the cumulative ACK
    // point.  Because the algorithm presented in this document can keep the
    // ACK clock going through a fairly significant loss event,
    // (comparatively longer than the algorithm described in [RFC2581]), on
    // some networks the loss event could last longer than the RTO.  In this
    // case the RTO timer would expire prematurely and a segment that need
    // not be retransmitted would be resent.
    //
    // Therefore we give implementers the latitude to use the standard
    // [RFC2988] style RTO management or, optionally, a more careful variant
    // that re-arms the RTO timer on each retransmission that is sent during
    // recovery MAY be used.  This provides a more conservative timer than
    // specified in [RFC2988], and so may not always be an attractive
    // alternative.  However, in some cases it may prevent needless
    // retransmissions, go-back-N transmission and further reduction of the
    // congestion window."
    tcpAlgorithm->ackSent();

    if (old_highRxt != state->highRxt) {
        // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
        EV_INFO << "Retransmission sent during recovery, restarting REXMIT timer.\n";
        tcpAlgorithm->restartRexmitTimer();
    }
    else // don't measure RTT for retransmitted packets
        tcpAlgorithm->dataSent(seqNum); // seqNum = old_snd_nxt

    return sentBytes;
}

void SubflowConnection::sendAvailableDataToApp()
{
    auto it = receivedDsnMapping.begin();
    while (it != receivedDsnMapping.end()) {
        const uint32_t subflowSeqEnd = it->first + (it->second.dsnEnd - it->second.dsnStart);
        if (seqGreater(subflowSeqEnd, state->rcv_nxt))
            break;

        metaConn->receivedChunk(it->second.dsnStart, it->second.dsnEnd);
        it = receivedDsnMapping.erase(it);
    }

    // Subflows do not deliver payload directly to the app. Drain any data
    // packets materialized by the receive queue so they do not remain owned by
    // the connection module until teardown.
    while (auto msg = receiveQueue->extractBytesUpTo(state->rcv_nxt))
        delete msg;
}

TcpEventCode SubflowConnection::processSegment1stThru8th(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{

    // Delegates additional processing of ECN to the algorithm
    tcpAlgorithm->processEcnInEstablished();

    //
    // RFC 793: first check sequence number
    //

    bool acceptable = true;

    if (tcpHeader->getHeaderLength() > TCP_MIN_HEADER_LENGTH) { // Header options present? TCP_HEADER_OCTETS = 20
        // PAWS
        if (state->ts_enabled) {
            uint32_t tsval = getTSval(tcpHeader);
            if (tsval != 0 && seqLess(tsval, state->ts_recent) &&
                (simTime() - state->time_last_data_sent) > PAWS_IDLE_TIME_THRESH) // PAWS_IDLE_TIME_THRESH = 24 days
            {
                EV_DETAIL << "PAWS: Segment is not acceptable, TSval=" << tsval << " in "
                          << stateName(fsm.getState()) << " state received: dropping segment\n";
                acceptable = false;
            }
        }

        readHeaderOptions(tcpHeader);
    }

    if (acceptable)
        acceptable = isSegmentAcceptable(tcpSegment, tcpHeader);

    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();

    if (!acceptable) {
        //"
        // If an incoming segment is not acceptable, an acknowledgment
        // should be sent in reply (unless the RST bit is set, if so drop
        // the segment and return):
        //
        //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        //"
        if (tcpHeader->getRstBit()) {
            EV_DETAIL << "RST with unacceptable seqNum: dropping\n";
        }
        else {
            if (tcpHeader->getSynBit()) {
                EV_DETAIL << "SYN with unacceptable seqNum in " << stateName(fsm.getState()) << " state received (SYN duplicat?)\n";
            }
            else if (payloadLength > 0 && state->sack_enabled && seqLess((tcpHeader->getSequenceNo() + payloadLength), state->rcv_nxt)) {
                state->start_seqno = tcpHeader->getSequenceNo();
                state->end_seqno = tcpHeader->getSequenceNo() + payloadLength;
                state->snd_dsack = true;
                EV_DETAIL << "SND_D-SACK SET (dupseg rcvd)\n";
            }

            EV_DETAIL << "Segment seqNum not acceptable, sending ACK with current receive seq\n";
            // RFC 2018, page 4:
            // "The receiver SHOULD send an ACK for every valid segment that arrives
            // containing new data, and each of these "duplicate" ACKs SHOULD bear a
            // SACK option."
            //
            // The received segment is not "valid" therefore the ACK will not bear a SACK option, if snd_dsack (D-SACK) is not set.
            sendAck();
        }

        state->rcv_naseg++;

        emit(rcvNASegSignal, state->rcv_naseg);

        return TCP_E_IGNORE;
    }

    // ECN
    if (tcpHeader->getCwrBit() == true) {
        EV_INFO << "Received CWR... Leaving ecnEcho State\n";
        state->ecnEchoState = false;
    }

    //
    // RFC 793: second check the RST bit,
    //
    if (tcpHeader->getRstBit()) {
        // Note: if we come from LISTEN, processSegmentInListen() has already handled RST.
        switch (fsm.getState()) {
            case TCP_S_SYN_RCVD:
                //"
                // If this connection was initiated with a passive OPEN (i.e.,
                // came from the LISTEN state), then return this connection to
                // LISTEN state and return.  The user need not be informed.  If
                // this connection was initiated with an active OPEN (i.e., came
                // from SYN-SENT state) then the connection was refused, signal
                // the user "connection refused".  In either case, all segments
                // on the retransmission queue should be removed.  And in the
                // active OPEN case, enter the CLOSED state and delete the TCB,
                // and return.
                //"
                return processRstInSynReceived(tcpHeader);

            case TCP_S_ESTABLISHED:
            case TCP_S_FIN_WAIT_1:
            case TCP_S_FIN_WAIT_2:
            case TCP_S_CLOSE_WAIT:
                //"
                // If the RST bit is set then, any outstanding RECEIVEs and SEND
                // should receive "reset" responses.  All segment queues should be
                // flushed.  Users should also receive an unsolicited general
                // "connection reset" signal.
                //
                // Enter the CLOSED state, delete the TCB, and return.
                //"
                EV_DETAIL << "RST: performing connection reset, closing connection\n";
                sendIndicationToApp(TCP_I_CONNECTION_RESET);
                return TCP_E_RCV_RST; // this will trigger state transition

            case TCP_S_CLOSING:
            case TCP_S_LAST_ACK:
            case TCP_S_TIME_WAIT:
                //"
                // enter the CLOSED state, delete the TCB, and return.
                //"
                EV_DETAIL << "RST: closing connection\n";
                return TCP_E_RCV_RST; // this will trigger state transition

            default:
                ASSERT(0);
                break;
        }
    }

    // RFC 793: third check security and precedence
    // This step is ignored.

    //
    // RFC 793: fourth, check the SYN bit,
    //
    if (tcpHeader->getSynBit()
            && !(fsm.getState() == TCP_S_SYN_RCVD && tcpHeader->getAckBit())) {
        //"
        // If the SYN is in the window it is an error, send a reset, any
        // outstanding RECEIVEs and SEND should receive "reset" responses,
        // all segment queues should be flushed, the user should also
        // receive an unsolicited general "connection reset" signal, enter
        // the CLOSED state, delete the TCB, and return.
        //
        // If the SYN is not in the window this step would not be reached
        // and an ack would have been sent in the first step (sequence
        // number check).
        //"
        // Zoltan Bojthe: but accept SYN+ACK in SYN_RCVD state for simultaneous open

        ASSERT(isSegmentAcceptable(tcpSegment, tcpHeader)); // assert SYN is in the window
        EV_DETAIL << "SYN is in the window: performing connection reset, closing connection\n";
        sendIndicationToApp(TCP_I_CONNECTION_RESET);
        return TCP_E_RCV_UNEXP_SYN;
    }

    //
    // RFC 793: fifth check the ACK field,
    //
    if (!tcpHeader->getAckBit()) {
        // if the ACK bit is off drop the segment and return
        EV_INFO << "ACK not set, dropping segment\n";
        return TCP_E_IGNORE;
    }

    uint32_t old_snd_una = state->snd_una;

    TcpEventCode event = TCP_E_IGNORE;

    if (fsm.getState() == TCP_S_SYN_RCVD) {
        //"
        // If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
        // and continue processing.
        //
        // If the segment acknowledgment is not acceptable, form a
        // reset segment,
        //
        //  <SEQ=SEG.ACK><CTL=RST>
        //
        // and send it.
        //"
        if (!seqLE(state->snd_una, tcpHeader->getAckNo()) || !seqLE(tcpHeader->getAckNo(), state->snd_nxt)) {
            sendRst(tcpHeader->getAckNo());
            return TCP_E_IGNORE;
        }

        // notify tcpAlgorithm and app layer
        tcpAlgorithm->established(false);

        if (isToBeAccepted())
            sendAvailableIndicationToApp();
        else{
            sendEstabIndicationToApp();

            if(isMaster) {
                metaConn->sendEstablished();
            }
        }
        // This will trigger transition to ESTABLISHED. Timers and notifying
        // app will be taken care of in stateEntered().
        event = TCP_E_RCV_ACK;
    }

    uint32_t old_snd_nxt = state->snd_nxt; // later we'll need to see if snd_nxt changed
    // Note: If one of the last data segments is lost while already in LAST-ACK state (e.g. if using TCPEchoApps)
    // TCP must be able to process acceptable acknowledgments, however please note RFC 793, page 73:
    // "LAST-ACK STATE
    //    The only thing that can arrive in this state is an
    //    acknowledgment of our FIN.  If our FIN is now acknowledged,
    //    delete the TCB, enter the CLOSED state, and return."
    if (fsm.getState() == TCP_S_SYN_RCVD || fsm.getState() == TCP_S_ESTABLISHED ||
        fsm.getState() == TCP_S_FIN_WAIT_1 || fsm.getState() == TCP_S_FIN_WAIT_2 ||
        fsm.getState() == TCP_S_CLOSE_WAIT || fsm.getState() == TCP_S_CLOSING ||
        fsm.getState() == TCP_S_LAST_ACK)
    {
        //
        // ESTABLISHED processing:
        //"
        //  If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
        //  Any segments on the retransmission queue which are thereby
        //  entirely acknowledged are removed.  Users should receive
        //  positive acknowledgments for buffers which have been SENT and
        //  fully acknowledged (i.e., SEND buffer should be returned with
        //  "ok" response).  If the ACK is a duplicate
        //  (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
        //  something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
        //  drop the segment, and return.
        //
        //  If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
        //  updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
        //  SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
        //  SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
        //
        //  Note that SND.WND is an offset from SND.UNA, that SND.WL1
        //  records the sequence number of the last segment used to update
        //  SND.WND, and that SND.WL2 records the acknowledgment number of
        //  the last segment used to update SND.WND.  The check here
        //  prevents using old segments to update the window.
        //"
        bool ok = processAckInEstabEtc(tcpSegment, tcpHeader);

        if (!ok)
            return TCP_E_IGNORE; // if acks something not yet sent, drop it
    }

    if ((fsm.getState() == TCP_S_FIN_WAIT_1 && state->fin_ack_rcvd)) {
        //"
        // FIN-WAIT-1 STATE
        //   In addition to the processing for the ESTABLISHED state, if
        //   our FIN is now acknowledged then enter FIN-WAIT-2 and continue
        //   processing in that state.
        //"
        event = TCP_E_RCV_ACK; // will trigger transition to FIN-WAIT-2
    }

    if (fsm.getState() == TCP_S_FIN_WAIT_2) {
        //"
        // FIN-WAIT-2 STATE
        //  In addition to the processing for the ESTABLISHED state, if
        //  the retransmission queue is empty, the user's CLOSE can be
        //  acknowledged ("ok") but do not delete the TCB.
        //"
        // nothing to do here (in our model, used commands don't need to be
        // acknowledged)
    }

    if (fsm.getState() == TCP_S_CLOSING) {
        //"
        // In addition to the processing for the ESTABLISHED state, if
        // the ACK acknowledges our FIN then enter the TIME-WAIT state,
        // otherwise ignore the segment.
        //"
        if (state->fin_ack_rcvd) {
            EV_INFO << "Our FIN acked -- can go to TIME_WAIT now\n";
            event = TCP_E_RCV_ACK; // will trigger transition to TIME-WAIT
            scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer); // start timer

            // we're entering TIME_WAIT, so we can signal CLOSED the user
            // (the only thing left to do is wait until the 2MSL timer expires)
        }
    }

    if (fsm.getState() == TCP_S_LAST_ACK) {
        //"
        // The only thing that can arrive in this state is an
        // acknowledgment of our FIN.  If our FIN is now acknowledged,
        // delete the TCB, enter the CLOSED state, and return.
        //"
        if (state->send_fin && tcpHeader->getAckNo() == state->snd_fin_seq + 1) {
            EV_INFO << "Last ACK arrived\n";
            return TCP_E_RCV_ACK; // will trigger transition to CLOSED
        }
    }

    if (fsm.getState() == TCP_S_TIME_WAIT) {
        //"
        // The only thing that can arrive in this state is a
        // retransmission of the remote FIN.  Acknowledge it, and restart
        // the 2 MSL timeout.
        //"
        // And we are staying in the TIME_WAIT state.
        //
        sendAck();
        rescheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);
    }

    //
    // RFC 793: sixth, check the URG bit,
    //
    if (tcpHeader->getUrgBit() && (fsm.getState() == TCP_S_ESTABLISHED ||
                                   fsm.getState() == TCP_S_FIN_WAIT_1 || fsm.getState() == TCP_S_FIN_WAIT_2))
    {
        //"
        // If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal
        // the user that the remote side has urgent data if the urgent
        // pointer (RCV.UP) is in advance of the data consumed.  If the
        // user has already been signaled (or is still in the "urgent
        // mode") for this continuous sequence of urgent data, do not
        // signal the user again.
        //"

        // TODO URG currently not supported
    }

    //
    // RFC 793: seventh, process the segment text,
    //
    uint32_t old_rcv_nxt = state->rcv_nxt; // if rcv_nxt changes, we need to send/schedule an ACK

    if (fsm.getState() == TCP_S_SYN_RCVD || fsm.getState() == TCP_S_ESTABLISHED ||
        fsm.getState() == TCP_S_FIN_WAIT_1 || fsm.getState() == TCP_S_FIN_WAIT_2)
    {
        //"
        // Once in the ESTABLISHED state, it is possible to deliver segment
        // text to user RECEIVE buffers.  Text from segments can be moved
        // into buffers until either the buffer is full or the segment is
        // empty.  If the segment empties and carries an PUSH flag, then
        // the user is informed, when the buffer is returned, that a PUSH
        // has been received.
        //
        // When the TCP takes responsibility for delivering the data to the
        // user it must also acknowledge the receipt of the data.
        //
        // Once the TCP takes responsibility for the data it advances
        // RCV.NXT over the data accepted, and adjusts RCV.WND as
        // appropriate to the current buffer availability.  The total of
        // RCV.NXT and RCV.WND should not be reduced.
        //
        // Please note the window management suggestions in section 3.7.
        //
        // Send an acknowledgment of the form:
        //
        //   <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        //
        // This acknowledgment should be piggybacked on a segment being
        // transmitted if possible without incurring undue delay.
        //"

        if (payloadLength > 0) {
            // check for full sized segment
            if ((uint32_t)payloadLength == state->snd_mss || (uint32_t)payloadLength + B(tcpHeader->getHeaderLength() - TCP_MIN_HEADER_LENGTH).get() == state->snd_mss)
                state->full_sized_segment_counter++;

            // check for persist probe
            if (payloadLength == 1)
                state->ack_now = true; // TODO how to check if it is really a persist probe?

            updateRcvQueueVars();

            if (hasEnoughSpaceForSegmentInReceiveQueue(tcpSegment, tcpHeader)) { // enough freeRcvBuffer in rcvQueue for new segment?
                EV_DETAIL << "Processing segment text in a data transfer state\n";

                // insert into receive buffers. If this segment is contiguous with
                // previously received ones (seqNo == rcv_nxt), rcv_nxt can be increased;
                // otherwise it stays the same but the data must be cached nevertheless
                // (to avoid "Failure to retain above-sequence data" problem, RFC 2525
                // section 2.5).

                uint32_t old_usedRcvBuffer = state->usedRcvBuffer;

                if(tcpHeader->findTag<DataSequenceNumberTag>()){
                    dsn_rcv_nxt = receiveQueue->getRE(tcpHeader->getTag<DataSequenceNumberTag>()->getDataSequenceNumber());
                }

                rememberReceivedDsnMapping(tcpHeader->getSequenceNo(),
                                           tcpHeader->getTag<DataSequenceNumberTag>()->getDataSequenceNumber(),
                                           payloadLength);
                state->rcv_nxt = receiveQueue->insertBytesFromSegment(tcpSegment, tcpHeader);

                if (seqGreater(state->snd_una, old_snd_una)) {

                    // notify
                    tcpAlgorithm->receivedDataAck(old_snd_una);

                    metaConn->receivedUpTo(old_snd_una);
                    // in the receivedDataAck we need the old value
                    state->dupacks = 0;

                    emit(dupAcksSignal, state->dupacks);
                }

                // out-of-order segment?
                if (old_rcv_nxt == state->rcv_nxt) {
                    state->rcv_oooseg++;

                    emit(rcvOooSegSignal, state->rcv_oooseg);

                    // RFC 2018, page 4:
                    // "The receiver SHOULD send an ACK for every valid segment that arrives
                    // containing new data, and each of these "duplicate" ACKs SHOULD bear a
                    // SACK option."
                    if (state->sack_enabled) {
                        // store start and end sequence numbers of current oooseg in state variables
                        state->start_seqno = tcpHeader->getSequenceNo();
                        state->end_seqno = tcpHeader->getSequenceNo() + payloadLength;

                        if (old_usedRcvBuffer == receiveQueue->getAmountOfBufferedBytes()) { // D-SACK
                            state->snd_dsack = true;
                            EV_DETAIL << "SND_D-SACK SET (old_rcv_nxt == rcv_nxt duplicated oooseg rcvd)\n";
                        }
                        else { // SACK
                            state->snd_sack = true;
                            EV_DETAIL << "SND_SACK SET (old_rcv_nxt == rcv_nxt oooseg rcvd)\n";
                        }
                    }

                    tcpAlgorithm->receivedOutOfOrderSegment();
                }
                else {
                    // forward data to app
                    //
                    // FIXME observe PSH bit
                    //
                    // FIXME we should implement socket READ command, and pass up only
                    // as many bytes as requested. rcv_wnd should be decreased
                    // accordingly!
                    //
                    if (!isToBeAccepted()){
                        sendAvailableDataToApp();
                    }
                    // if this segment "filled the gap" until the previously arrived segment
                    // that carried a FIN (i.e.rcv_nxt == rcv_fin_seq), we have to advance
                    // rcv_nxt over the FIN.
                    if (state->fin_rcvd && state->rcv_nxt == state->rcv_fin_seq) {
                        state->ack_now = true; // although not mentioned in [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 861] seems like we have to set ack_now
                        EV_DETAIL << "All segments arrived up to the FIN segment, advancing rcv_nxt over the FIN\n";
                        state->rcv_nxt = state->rcv_fin_seq + 1;
                        // state transitions will be done in the state machine, here we just set
                        // the proper event code (TCP_E_RCV_FIN or TCP_E_RCV_FIN_ACK)
                        event = TCP_E_RCV_FIN;

                        switch (fsm.getState()) {
                            case TCP_S_FIN_WAIT_1:
                                if (state->fin_ack_rcvd) {
                                    event = TCP_E_RCV_FIN_ACK;
                                    // start the time-wait timer, turn off the other timers
                                    cancelEvent(finWait2Timer);
                                    scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);

                                    // we're entering TIME_WAIT, so we can signal CLOSED the user
                                    // (the only thing left to do is wait until the 2MSL timer expires)
                                }
                                break;

                            case TCP_S_FIN_WAIT_2:
                                // Start the time-wait timer, turn off the other timers.
                                cancelEvent(finWait2Timer);
                                scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);

                                // we're entering TIME_WAIT, so we can signal CLOSED the user
                                // (the only thing left to do is wait until the 2MSL timer expires)
                                break;

                            case TCP_S_TIME_WAIT:
                                // Restart the 2 MSL time-wait timeout.
                                rescheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);
                                break;

                            default:
                                break;
                        }
                    }
                }
            }
            else { // not enough freeRcvBuffer in rcvQueue for new segment
                state->tcpRcvQueueDrops++; // update current number of tcp receive queue drops

                emit(tcpRcvQueueDropsSignal, state->tcpRcvQueueDrops);

                // if the ACK bit is off drop the segment and return
                EV_WARN << "RcvQueueBuffer has run out, dropping segment\n";
                return TCP_E_IGNORE;
            }
        }
    }

    //
    // RFC 793: eighth, check the FIN bit,
    //
    if (tcpHeader->getFinBit()) {
        state->ack_now = true;

        //"
        // If the FIN bit is set, signal the user "connection closing" and
        // return any pending RECEIVEs with same message, advance RCV.NXT
        // over the FIN, and send an acknowledgment for the FIN.  Note that
        // FIN implies PUSH for any segment text not yet delivered to the
        // user.
        //"

        // Note: seems like RFC 793 is not entirely correct here: if the
        // segment is "above sequence" (ie. RCV.NXT < SEG.SEQ), we cannot
        // advance RCV.NXT over the FIN. Instead we remember this sequence
        // number and do it later.
        uint32_t fin_seq = (uint32_t)tcpHeader->getSequenceNo() + (uint32_t)payloadLength;

        if (state->rcv_nxt == fin_seq) {
            // advance rcv_nxt over FIN now
            EV_INFO << "FIN arrived, advancing rcv_nxt over the FIN\n";
            state->rcv_nxt++;
            // state transitions will be done in the state machine, here we just set
            // the proper event code (TCP_E_RCV_FIN or TCP_E_RCV_FIN_ACK)
            event = TCP_E_RCV_FIN;

            switch (fsm.getState()) {
                case TCP_S_FIN_WAIT_1:
                    if (state->fin_ack_rcvd) {
                        event = TCP_E_RCV_FIN_ACK;
                        // start the time-wait timer, turn off the other timers
                        cancelEvent(finWait2Timer);
                        scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);

                        // we're entering TIME_WAIT, so we can signal CLOSED the user
                        // (the only thing left to do is wait until the 2MSL timer expires)
                    }
                    break;

                case TCP_S_FIN_WAIT_2:
                    // Start the time-wait timer, turn off the other timers.
                    cancelEvent(finWait2Timer);
                    scheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);

                    // we're entering TIME_WAIT, so we can signal CLOSED the user
                    // (the only thing left to do is wait until the 2MSL timer expires)
                    break;

                case TCP_S_TIME_WAIT:
                    // Restart the 2 MSL time-wait timeout.
                    rescheduleAfter(2 * tcpMain->getMsl(), the2MSLTimer);
                    break;

                default:
                    break;
            }
        }
        else {
            // we'll have to do it later (when an arriving segment "fills the gap")
            EV_DETAIL << "FIN segment above sequence, storing sequence number of FIN\n";
            state->fin_rcvd = true;
            state->rcv_fin_seq = fin_seq;
        }

        // TODO do PUSH stuff
    }

    if (old_rcv_nxt != state->rcv_nxt) {
        // if rcv_nxt changed, either because we received segment text or we
        // received a FIN that needs to be acked (or both), we need to send or
        // schedule an ACK.
        if (state->sack_enabled) {
            if (receiveQueue->getQueueLength() != 0) {
                // RFC 2018, page 4:
                // "If sent at all, SACK options SHOULD be included in all ACKs which do
                // not ACK the highest sequence number in the data receiver's queue."
                state->start_seqno = tcpHeader->getSequenceNo();
                state->end_seqno = tcpHeader->getSequenceNo() + payloadLength;
                state->snd_sack = true;
                EV_DETAIL << "SND_SACK SET (rcv_nxt changed, but receiveQ is not empty)\n";
                state->ack_now = true; // although not mentioned in [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 861] seems like we have to set ack_now
            }
        }

        // tcpAlgorithm decides when and how to do ACKs
        tcpAlgorithm->receiveSeqChanged();
    }

    if ((fsm.getState() == TCP_S_ESTABLISHED || fsm.getState() == TCP_S_SYN_RCVD) &&
        state->send_fin && state->snd_nxt == state->snd_fin_seq + 1)
    {
        // if the user issued the CLOSE command a long time ago and we've just
        // managed to send off FIN, we simulate a CLOSE command now (we had to
        // defer it at that time because we still had data in the send queue.)
        // This CLOSE will take us into the FIN_WAIT_1 state.
        EV_DETAIL << "Now we can do the CLOSE which was deferred a while ago\n";
        event = TCP_E_CLOSE;
    }

    if (fsm.getState() == TCP_S_CLOSE_WAIT && state->send_fin &&
        state->snd_nxt == state->snd_fin_seq + 1 && old_snd_nxt != state->snd_nxt)
    {
        // if we're in CLOSE_WAIT and we just got to sent our long-pending FIN,
        // we simulate a CLOSE command now (we had to defer it at that time because
        // we still had data in the send queue.) This CLOSE will take us into the
        // LAST_ACK state.
        EV_DETAIL << "Now we can do the CLOSE which was deferred a while ago\n";
        event = TCP_E_CLOSE;
    }

    return event;
}

bool SubflowConnection::processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    EV_DETAIL << "Processing ACK in a data transfer state\n";
    uint64_t previousDelivered = m_delivered;  //RATE SAMPLER SPECIFIC STUFF
    uint32_t previousLost = m_bytesLoss; //TODO Create Sack method to get exact amount of lost packets
    uint32_t priorInFlight = m_bytesInFlight;//get current BytesInFlight somehow
    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();
    beginRateSample();

    // ECN
    TcpStateVariables *state = getState();
    if (state && state->ect) {
        if (tcpHeader->getEceBit() == true)
            EV_INFO << "Received packet with ECE\n";

        state->gotEce = tcpHeader->getEceBit();
    }

    if (payloadLength == 0 && metaConn != nullptr && tcpHeader->findTag<DataSequenceNumberTag>()) {
        const uint32_t dataAckNo = tcpHeader->getTag<DataSequenceNumberTag>()->getDataSequenceNumber();
        metaConn->receivedUpTo(dataAckNo);
        eraseSentDsnMappingsUpToDataAck(dataAckNo);
    }

    //
    //"
    //  If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
    //  Any segments on the retransmission queue which are thereby
    //  entirely acknowledged are removed.  Users should receive
    //  positive acknowledgments for buffers which have been SENT and
    //  fully acknowledged (i.e., SEND buffer should be returned with
    //  "ok" response).  If the ACK is a duplicate
    //  (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
    //  something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
    //  drop the segment, and return.
    //
    //  If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
    //  updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
    //  SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
    //  SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
    //
    //  Note that SND.WND is an offset from SND.UNA, that SND.WL1
    //  records the sequence number of the last segment used to update
    //  SND.WND, and that SND.WL2 records the acknowledgment number of
    //  the last segment used to update SND.WND.  The check here
    //  prevents using old segments to update the window.
    //"
    // Note: should use SND.MAX instead of SND.NXT in above checks
    //
    if (seqGE(state->snd_una, tcpHeader->getAckNo())) {
        //
        // duplicate ACK? A received TCP segment is a duplicate ACK if all of
        // the following apply:
        //    (1) snd_una == ackNo
        //    (2) segment contains no data
        //    (3) there's unacked data (snd_una != snd_max)
        //
        // Note: ssfnet uses additional constraint "window is the same as last
        // received (not an update)" -- we don't do that because window updates
        // are ignored anyway if neither seqNo nor ackNo has changed.
        //
        if (state->snd_una == tcpHeader->getAckNo() && payloadLength == 0 && state->snd_una != state->snd_max) {
            state->dupacks++;

            emit(dupAcksSignal, state->dupacks);

            // we need to update send window even if the ACK is a dupACK, because rcv win
            // could have been changed if faulty data receiver is not respecting the "do not shrink window" rule
            if (rack_enabled)
            {
                if (!scoreboardUpdated && rexmitQueue->findRegion(tcpHeader->getAckNo()))
                    rackAdvance(tcpHeader->getAckNo(), tcpHeader);
                else
                    rackAdvance(rexmitQueue->getHighestSackedSeqNum(), tcpHeader);

                const bool inLossState = state->lossRecovery || isInRtoRecovery();
                const bool exiting = inLossState &&
                        seqGE(tcpHeader->getAckNo(), getPacedAlgorithm()->getRecoveryPoint());
                m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, tcpHeader->getAckNo(),
                        rexmitQueue->getTotalAmountOfSackedBytes(), 3, state->snd_mss,
                        exiting, inLossState);
            }
            scoreboardUpdated = false;

            updateWndInfo(tcpHeader);

            if (rexmitQueue->isUpdatedSackEnabled()) {
                std::list<uint32_t> skbDeliveredList = rexmitQueue->getDiscardList(tcpHeader->getAckNo());
                for (uint32_t endSeqNo : skbDeliveredList) {
                    bool wasRetransmitted = rexmitQueue->isRetransmitted(endSeqNo);
                    rackAdvance(endSeqNo, tcpHeader);
                    skbDelivered(endSeqNo);
                    if ((fack_enabled || rack_enabled) && seqLess(endSeqNo, m_sndFack) && !wasRetransmitted)
                        m_reorder = true;
                }
            }
//
            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;
////
            updateInFlight();
////
            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : 0;
////
            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            bool newRackLoss = false;
            bool rackRecovery = checkRackLoss(&newRackLoss);
            if (shouldApplyRackCongestionResponse() && (rackRecovery || newRackLoss))
                getPacedAlgorithm()->rackLossDetected();

            tcpAlgorithm->receivedDuplicateAck();
            isRetransDataAcked = false;
            sendPendingData();
        }
        else {
            // if doesn't qualify as duplicate ACK, just ignore it.
            if (payloadLength == 0) {
                if (state->snd_una != tcpHeader->getAckNo()){
                    EV_DETAIL << "Old ACK: ackNo < snd_una\n";
                }
                else if (state->snd_una == state->snd_max) {
                    EV_DETAIL << "ACK looks duplicate but we have currently no unacked data (snd_una == snd_max)\n";
                }
            }
            // reset counter
            state->dupacks = 0;

            emit(dupAcksSignal, state->dupacks);
        }
    }
    else if (seqLE(tcpHeader->getAckNo(), state->snd_max)) {
        // ack in window.
        uint32_t old_snd_una = state->snd_una;
        state->snd_una = tcpHeader->getAckNo();

        emit(unackedSignal, state->snd_max - state->snd_una);

        // after retransmitting a lost segment, we may get an ack well ahead of snd_nxt
        if (seqLess(state->snd_nxt, state->snd_una))
            state->snd_nxt = state->snd_una;

        // RFC 1323, page 36:
        // "If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
        // Also compute a new estimate of round-trip time.  If Snd.TS.OK
        // bit is on, use my.TSclock - SEG.TSecr; otherwise use the
        // elapsed time since the first segment in the retransmission
        // queue was sent.  Any segments on the retransmission queue
        // which are thereby entirely acknowledged."
        if (state->ts_enabled)
            tcpAlgorithm->rttMeasurementCompleteUsingTS(getTSecr(tcpHeader));
        // Note: If TS is disabled the RTT measurement is completed in TcpBaseAlg::receivedDataAck()

        uint32_t discardUpToSeq = state->snd_una;
        // our FIN acked?
        if (state->send_fin && tcpHeader->getAckNo() == state->snd_fin_seq + 1) {
            // set flag that our FIN has been acked
            EV_DETAIL << "ACK acks our FIN\n";
            state->fin_ack_rcvd = true;
            discardUpToSeq--; // the FIN sequence number is not real data
        }

        if (rack_enabled)
        {
            if (!scoreboardUpdated && rexmitQueue->findRegion(tcpHeader->getAckNo()))
                rackAdvance(tcpHeader->getAckNo(), tcpHeader);
            else
                rackAdvance(rexmitQueue->getHighestSackedSeqNum(), tcpHeader);

            const bool inLossState = state->lossRecovery || isInRtoRecovery();
            const bool exiting = inLossState &&
                    seqGE(state->snd_una, getPacedAlgorithm()->getRecoveryPoint());
            m_rack->updateReoWnd(m_reorder, m_dsackSeen, state->snd_nxt, state->snd_una,
                    rexmitQueue->getTotalAmountOfSackedBytes(), 3, state->snd_mss,
                    exiting, inLossState);
        }
        scoreboardUpdated = false;
        // acked data no longer needed in send queue

        // acked data no longer needed in rexmit queue
        if (rexmitQueue->isUpdatedSackEnabled()) {
            std::list<uint32_t> skbDeliveredList = rexmitQueue->getDiscardList(discardUpToSeq);
            for (uint32_t endSeqNo : skbDeliveredList) {
                bool wasRetransmitted = rexmitQueue->isRetransmitted(endSeqNo);
                rackAdvance(endSeqNo, tcpHeader);
                skbDelivered(endSeqNo);
                if (state->lossRecovery && rexmitQueue->isRetransmittedDataAcked(endSeqNo))
                    isRetransDataAcked = true;
                if ((fack_enabled || rack_enabled) && seqLess(endSeqNo, m_sndFack) && !wasRetransmitted)
                    m_reorder = true;
            }
        }

        // acked data no longer needed in send queue
        sendQueue->discardUpTo(discardUpToSeq);

        // acked data no longer needed in rexmit queue
        if (state->sack_enabled){
            rexmitQueue->discardUpTo(discardUpToSeq);
        }

        updateWndInfo(tcpHeader);

        // if segment contains data, wait until data has been forwarded to app before sending ACK,
        // otherwise we would use an old ACKNo
        if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {

            uint32_t currentDelivered  = m_delivered - previousDelivered;
            m_lastAckedSackedBytes = currentDelivered;

            updateInFlight();

            uint32_t currentLost = m_bytesLoss;
            uint32_t lost = (currentLost > previousLost) ? currentLost - previousLost : 0;
            // notify

            updateSample(currentDelivered, lost, false, priorInFlight, connMinRtt);

            bool newRackLoss = false;
            bool rackRecovery = checkRackLoss(&newRackLoss);
            if (shouldApplyRackCongestionResponse() && (rackRecovery || newRackLoss))
                getPacedAlgorithm()->rackLossDetected();

            tcpAlgorithm->receivedDataAck(old_snd_una);
            isRetransDataAcked = false;
            // in the receivedDataAck we need the old value
            state->dupacks = 0;

            sendPendingData();

            if (fack_enabled || rack_enabled)
            {
              if (tcpHeader->getAckNo() > m_sndFack)
                {
                  m_sndFack = tcpHeader->getAckNo();
                }
            }

            emit(dupAcksSignal, state->dupacks);
            emit(mDeliveredSignal, m_delivered);
        }
    }
    else {
        ASSERT(seqGreater(tcpHeader->getAckNo(), state->snd_max)); // from if-ladder

        // send an ACK, drop the segment, and return.
        tcpAlgorithm->receivedAckForDataNotYetSent(tcpHeader->getAckNo());
        state->dupacks = 0;

        emit(dupAcksSignal, state->dupacks);
        return false; // means "drop"
    }
    return true;
}

void SubflowConnection::sendSynAck()
{
    // create segment
    const auto& tcpHeader = makeShared<TcpHeader>();
    tcpHeader->setSequenceNo(state->iss);

    tcpHeader->setAckNo(state->rcv_nxt);
    tcpHeader->setSynBit(true);
    tcpHeader->setAckBit(true);
    updateRcvWnd();
    tcpHeader->setWindow(state->rcv_wnd);

    state->snd_max = state->snd_nxt = state->iss + 1;

    // ECN
    if (state->ecnWillingness) {
        tcpHeader->setEceBit(true);
        tcpHeader->setCwrBit(false);
        EV << "ECN-setup SYN-ACK packet sent\n";
    }
    else {
        tcpHeader->setEceBit(false);
        tcpHeader->setCwrBit(false);
        if (state->endPointIsWillingECN)
            EV << "non-ECN-setup SYN-ACK packet sent\n";
    }
    if (state->ecnWillingness && state->endPointIsWillingECN) {
        state->ect = true;
        EV << "both end-points are willing to use ECN... ECN is enabled\n";
    }
    else { // TODO not sure if we have to.
           // rfc-3168, page 16:
           // A host that is not willing to use ECN on a TCP connection SHOULD
           // clear both the ECE and CWR flags in all non-ECN-setup SYN and/or
           // SYN-ACK packets that it sends to indicate this unwillingness.
        state->ect = false;
        if (state->endPointIsWillingECN)
            EV << "ECN is disabled\n";
    }

    // write header options
    writeHeaderOptions(tcpHeader);

    Packet *fp = new Packet("SYN+ACK");

    //tcpHeader->addTagIfAbsent<DataSequenceNumberTag>()->setDataSequenceNumber(state->rcv_nxt);

    // send it
    sendToIP(fp, tcpHeader);

    // notify
    tcpAlgorithm->ackSent();
}

void SubflowConnection::sendAck()
{
    const auto& tcpHeader = makeShared<TcpHeader>();

    tcpHeader->setAckBit(true);
    tcpHeader->setSequenceNo(state->snd_nxt);

    tcpHeader->setAckNo(state->rcv_nxt);
    tcpHeader->setWindow(updateRcvWnd());

    // rfc-3168, pages 19-20:
    // When TCP receives a CE data packet at the destination end-system, the
    // TCP data receiver sets the ECN-Echo flag in the TCP header of the
    // subsequent ACK packet.
    // ...
    // After a TCP receiver sends an ACK packet with the ECN-Echo bit set,
    // that TCP receiver continues to set the ECN-Echo flag in all the ACK
    // packets it sends (whether they acknowledge CE data packets or non-CE
    // data packets) until it receives a CWR packet (a packet with the CWR
    // flag set).  After the receipt of the CWR packet, acknowledgments for
    // subsequent non-CE data packets do not have the ECN-Echo flag set.

    TcpStateVariables *state = getState();
    if (state && state->ect) {
        if (tcpAlgorithm->shouldMarkAck()) {
            tcpHeader->setEceBit(true);
            EV_INFO << "In ecnEcho state... send ACK with ECE bit set\n";
        }
    }

    // write header options
    writeHeaderOptions(tcpHeader);

    const uint32_t dataAckNo = metaConn != nullptr ? metaConn->getRcvNxt() : state->rcv_nxt;
    tcpHeader->addTagIfAbsent<DataSequenceNumberTag>()->setDataSequenceNumber(dataAckNo);

    Packet *fp = new Packet("TcpAck");

    // rfc-3168 page 20: pure ack packets must be sent with not-ECT codepoint
    state->sndAck = true;

    // send it
    sendToIP(fp, tcpHeader);

    state->sndAck = false;

    // notify
    tcpAlgorithm->ackSent();
}

TcpEventCode SubflowConnection::processSynInListen(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address srcAddr, L3Address destAddr)
{
    //"
    //  Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
    //  control or text should be queued for processing later.  ISS
    //  should be selected and a SYN segment sent of the form:
    //
    //    <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
    //
    //  SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
    //  state should be changed to SYN-RECEIVED.
    //"
    state->rcv_nxt = tcpHeader->getSequenceNo() + 1;
    state->rcv_adv = state->rcv_nxt + state->rcv_wnd;

    emit(rcvAdvSignal, state->rcv_adv);

    state->irs = tcpHeader->getSequenceNo();
    receiveQueue->init(state->rcv_nxt); // FIXME may init twice...
    selectInitialSeqNum();

    // although not mentioned in RFC 793, seems like we have to pick up
    // initial snd_wnd from the segment here.
    updateWndInfo(tcpHeader, true);

    if(isMaster){
        metaConn->receivedSynListen(tcpHeader->getSequenceNo(),state->iss);
    }

    if (tcpHeader->getHeaderLength() > TCP_MIN_HEADER_LENGTH) // Header options present?
        readHeaderOptions(tcpHeader);

    state->ack_now = true;

    // ECN
    if (tcpHeader->getEceBit() == true && tcpHeader->getCwrBit() == true) {
        state->endPointIsWillingECN = true;
        EV << "ECN-setup SYN packet received\n";
    }
    sendSynAck();

    if(isMaster){
        metaConn->setUpSynAck();
    }

    startSynRexmitTimer();

    if (!connEstabTimer->isScheduled())
        scheduleAfter(TCP_TIMEOUT_CONN_ESTAB, connEstabTimer);

    //"
    // Note that any other incoming control or data (combined with SYN)
    // will be processed in the SYN-RECEIVED state, but processing of SYN
    // and ACK should not be repeated.
    //"
    // We don't send text in SYN or SYN+ACK, but accept it. Otherwise
    // there isn't much left to do: RST, SYN, ACK, FIN got processed already,
    // so there's only URG and PSH left to handle.
    //
    if (B(tcpSegment->getByteLength()) > tcpHeader->getHeaderLength()) {
        updateRcvQueueVars();

        if (hasEnoughSpaceForSegmentInReceiveQueue(tcpSegment, tcpHeader)) { // enough freeRcvBuffer in rcvQueue for new segment?
            const uint32_t payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();
            rememberReceivedDsnMapping(tcpHeader->getSequenceNo(),
                                       tcpHeader->getTag<DataSequenceNumberTag>()->getDataSequenceNumber(),
                                       payloadLength);
            receiveQueue->insertBytesFromSegment(tcpSegment, tcpHeader);

            if(tcpHeader->getTag<DataSequenceNumberTag>()->getDataSequenceNumber() == 0){
               std::cout << "\n ERROR FOUND: " << endl;
            }

        }
        else { // not enough freeRcvBuffer in rcvQueue for new segment
            state->tcpRcvQueueDrops++; // update current number of tcp receive queue drops

            emit(tcpRcvQueueDropsSignal, state->tcpRcvQueueDrops);

            EV_WARN << "RcvQueueBuffer has run out, dropping segment\n";
            return TCP_E_IGNORE;
        }
    }

    if (tcpHeader->getUrgBit() || tcpHeader->getPshBit())
        EV_DETAIL << "Ignoring URG and PSH bits in SYN\n"; // TODO

    return TCP_E_RCV_SYN; // this will take us to SYN_RCVD
}

TcpEventCode SubflowConnection::processSegmentInSynSent(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address srcAddr, L3Address destAddr)
{
    EV_DETAIL << "Processing segment in SYN_SENT\n";

    //"
    // first check the ACK bit
    //
    //   If the ACK bit is set
    //
    //     If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
    //     the RST bit is set, if so drop the segment and return)
    //
    //       <SEQ=SEG.ACK><CTL=RST>
    //
    //     and discard the segment.  Return.
    //
    //     If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
    //"
    if (tcpHeader->getAckBit()) {
        if (seqLE(tcpHeader->getAckNo(), state->iss) || seqGreater(tcpHeader->getAckNo(), state->snd_nxt)) {
            if (tcpHeader->getRstBit())
                EV_DETAIL << "ACK+RST bit set but wrong AckNo, ignored\n";
            else {
                EV_DETAIL << "ACK bit set but wrong AckNo, sending RST\n";
                sendRst(tcpHeader->getAckNo(), destAddr, srcAddr, tcpHeader->getDestPort(), tcpHeader->getSrcPort());
            }
            return TCP_E_IGNORE;
        }

        EV_DETAIL << "ACK bit set, AckNo acceptable\n";
    }

    //"
    // second check the RST bit
    //
    //   If the RST bit is set
    //
    //     If the ACK was acceptable then signal the user "error:
    //     connection reset", drop the segment, enter CLOSED state,
    //     delete TCB, and return.  Otherwise (no ACK) drop the segment
    //     and return.
    //"
    if (tcpHeader->getRstBit()) {
        if (tcpHeader->getAckBit()) {
            EV_DETAIL << "RST+ACK: performing connection reset\n";
            sendIndicationToApp(TCP_I_CONNECTION_RESET);

            return TCP_E_RCV_RST;
        }
        else {
            EV_DETAIL << "RST without ACK: dropping segment\n";

            return TCP_E_IGNORE;
        }
    }

    //"
    // third check the security and precedence -- not done
    //
    // fourth check the SYN bit
    //
    //   This step should be reached only if the ACK is ok, or there is
    //   no ACK, and it the segment did not contain a RST.
    //
    //   If the SYN bit is on and the security/compartment and precedence
    //   are acceptable then,
    //"
    if (tcpHeader->getSynBit()) {
        //
        //   RCV.NXT is set to SEG.SEQ+1, IRS is set to
        //   SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
        //   is an ACK), and any segments on the retransmission queue which
        //   are thereby acknowledged should be removed.
        //
        state->rcv_nxt = tcpHeader->getSequenceNo() + 1;
        state->rcv_adv = state->rcv_nxt + state->rcv_wnd;

        emit(rcvAdvSignal, state->rcv_adv);

        state->irs = tcpHeader->getSequenceNo();
        receiveQueue->init(state->rcv_nxt);

        eraseReceivedMappingsUpTo(state->rcv_nxt);

        if(isMaster){
            metaConn->processSynSent(tcpHeader->getSequenceNo());
        }

        if (tcpHeader->getAckBit()) {
            state->snd_una = tcpHeader->getAckNo();
            sendQueue->discardUpTo(state->snd_una);

            uint32_t ignoredMetaAck = 0;
            translateAckToMetaLevel(state->snd_una, ignoredMetaAck);

            if (state->sack_enabled)
                rexmitQueue->discardUpTo(state->snd_una);

            if(isMaster){
                metaConn->processSynSentAck(tcpHeader->getAckNo());
            }

            // although not mentioned in RFC 793, seems like we have to pick up
            // initial snd_wnd from the segment here.
            updateWndInfo(tcpHeader, true);

            if(isMaster){
                metaConn->updateWndInfo(tcpHeader, true);
            }
        }

        // this also seems to be a good time to learn our local IP address
        // (was probably unspecified at connection open)
        tcpMain->updateSockPair(this, destAddr, srcAddr, tcpHeader->getDestPort(), tcpHeader->getSrcPort());

        //"
        //   If SND.UNA > ISS (our SYN has been ACKed), change the connection
        //   state to ESTABLISHED, form an ACK segment
        //
        //     <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        //
        //   and send it.  Data or controls which were queued for
        //   transmission may be included.  If there are other controls or
        //   text in the segment then continue processing at the sixth step
        //   below where the URG bit is checked, otherwise return.
        //"
        if (seqGreater(state->snd_una, state->iss)) {
            EV_INFO << "SYN+ACK bits set, connection established.\n";

            // RFC says "continue processing at the sixth step below where
            // the URG bit is checked". Those steps deal with: URG, segment text
            // (and PSH), and FIN.
            // Now: URG and PSH we don't support yet; in SYN+FIN we ignore FIN;
            // with segment text we just take it easy and put it in the receiveQueue
            // -- we'll forward it to the user when more data arrives.
            if (tcpHeader->getFinBit())
                EV_DETAIL << "SYN+ACK+FIN received: ignoring FIN\n";

            if (B(tcpSegment->getByteLength()) > tcpHeader->getHeaderLength()) {
                updateRcvQueueVars();

                if (hasEnoughSpaceForSegmentInReceiveQueue(tcpSegment, tcpHeader)) { // enough freeRcvBuffer in rcvQueue for new segment?
                    const uint32_t payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();
                    rememberReceivedDsnMapping(tcpHeader->getSequenceNo(),
                                               tcpHeader->getTag<DataSequenceNumberTag>()->getDataSequenceNumber(),
                                               payloadLength);
                    receiveQueue->insertBytesFromSegment(tcpSegment, tcpHeader); // TODO forward to app, etc.
                }
                else { // not enough freeRcvBuffer in rcvQueue for new segment
                    state->tcpRcvQueueDrops++; // update current number of tcp receive queue drops

                    emit(tcpRcvQueueDropsSignal, state->tcpRcvQueueDrops);

                    EV_WARN << "RcvQueueBuffer has run out, dropping segment\n";
                    return TCP_E_IGNORE;
                }
            }

            if (tcpHeader->getUrgBit() || tcpHeader->getPshBit())
                EV_DETAIL << "Ignoring URG and PSH bits in SYN+ACK\n"; // TODO

            if (tcpHeader->getHeaderLength() > TCP_MIN_HEADER_LENGTH) // Header options present?
                readHeaderOptions(tcpHeader);

            // notify tcpAlgorithm (it has to send ACK of SYN) and app layer
            state->ack_now = true;
            tcpAlgorithm->established(true);
            tcpMain->emit(Tcp::tcpConnectionAddedSignal, this);
            sendEstabIndicationToApp();

            if(isMaster){
                metaConn->sendEstablished();
            }
            // ECN
            if (state->ecnSynSent) {
                if (tcpHeader->getEceBit() && !tcpHeader->getCwrBit()) {
                    state->ect = true;
                    EV << "ECN-setup SYN-ACK packet was received... ECN is enabled.\n";
                }
                else {
                    state->ect = false;
                    EV << "non-ECN-setup SYN-ACK packet was received... ECN is disabled.\n";
                }
                state->ecnSynSent = false;
            }
            else {
                state->ect = false;
                if (tcpHeader->getEceBit() && !tcpHeader->getCwrBit())
                    EV << "ECN-setup SYN-ACK packet was received... ECN is disabled.\n";
            }

            // This will trigger transition to ESTABLISHED. Timers and notifying
            // app will be taken care of in stateEntered().
            return TCP_E_RCV_SYN_ACK;
        }

        //"
        //   Otherwise enter SYN-RECEIVED, form a SYN,ACK segment
        //
        //     <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
        //
        //   and send it.  If there are other controls or text in the
        //   segment, queue them for processing after the ESTABLISHED state
        //   has been reached, return.
        //"
        EV_INFO << "SYN bit set: sending SYN+ACK\n";
        state->snd_max = state->snd_nxt = state->iss;
        sendSynAck();
        if(isMaster){
            metaConn->setUpSynAck();
        }
        startSynRexmitTimer();

        // Note: code below is similar to processing SYN in LISTEN.

        // For consistency with that code, we ignore SYN+FIN here
        if (tcpHeader->getFinBit())
            EV_DETAIL << "SYN+FIN received: ignoring FIN\n";

        // We don't send text in SYN or SYN+ACK, but accept it. Otherwise
        // there isn't much left to do: RST, SYN, ACK, FIN got processed already,
        // so there's only URG and PSH left to handle.
        if (B(tcpSegment->getByteLength()) > tcpHeader->getHeaderLength()) {
            updateRcvQueueVars();

            if (hasEnoughSpaceForSegmentInReceiveQueue(tcpSegment, tcpHeader)) { // enough freeRcvBuffer in rcvQueue for new segment?
                const uint32_t payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();
                rememberReceivedDsnMapping(tcpHeader->getSequenceNo(),
                                           tcpHeader->getTag<DataSequenceNumberTag>()->getDataSequenceNumber(),
                                           payloadLength);
                receiveQueue->insertBytesFromSegment(tcpSegment, tcpHeader); // TODO forward to app, etc.
            }
            else { // not enough freeRcvBuffer in rcvQueue for new segment
                state->tcpRcvQueueDrops++; // update current number of tcp receive queue drops

                emit(tcpRcvQueueDropsSignal, state->tcpRcvQueueDrops);

                EV_WARN << "RcvQueueBuffer has run out, dropping segment\n";
                return TCP_E_IGNORE;
            }
        }

        if (tcpHeader->getUrgBit() || tcpHeader->getPshBit())
            EV_DETAIL << "Ignoring URG and PSH bits in SYN\n"; // TODO

        return TCP_E_RCV_SYN;
    }

    //"
    // fifth, if neither of the SYN or RST bits is set then drop the
    // segment and return.
    //"
    return TCP_E_IGNORE;
}

void SubflowConnection::invokeSendCommand()
{
    Enter_Method_Silent("invokeSendCommand");

    tcpAlgorithm->sendCommandInvoked();
}

bool SubflowConnection::getIsMaster()
{
    return isMaster;
}

void SubflowConnection::setInterfaceId(int id)
{
    ASSERT(id > 0);
    interfaceId = id;
}

void SubflowConnection::sendToApp(cMessage *msg)
{
    delete msg;
}

void SubflowConnection::sendToIP(Packet *tcpSegment, const Ptr<TcpHeader>& tcpHeader)
{
    // record seq (only if we do send data) and ackno
    if (tcpSegment->getByteLength() > B(tcpHeader->getChunkLength()).get())
        emit(sndNxtSignal, tcpHeader->getSequenceNo());

    emit(sndAckSignal, tcpHeader->getAckNo());

    // final touches on the segment before sending
    tcpHeader->setSrcPort(localPort);
    tcpHeader->setDestPort(remotePort);
    ASSERT(tcpHeader->getHeaderLength() >= TCP_MIN_HEADER_LENGTH);
    ASSERT(tcpHeader->getHeaderLength() <= TCP_MAX_HEADER_LENGTH);
    ASSERT(tcpHeader->getChunkLength() == tcpHeader->getHeaderLength());

    EV_INFO << "Sending: ";
    printSegmentBrief(tcpSegment, tcpHeader);

    // TODO reuse next function for sending

    const IL3AddressType *addressType =  remoteAddr.getAddressType();
    tcpSegment->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(addressType->getNetworkProtocol());

    if (ttl != -1 && tcpSegment->findTag<HopLimitReq>() == nullptr)
        tcpSegment->addTag<HopLimitReq>()->setHopLimit(ttl);

    if (dscp != -1 && tcpSegment->findTag<DscpReq>() == nullptr)
        tcpSegment->addTag<DscpReq>()->setDifferentiatedServicesCodePoint(dscp);

    if (tos != -1 && tcpSegment->findTag<TosReq>() == nullptr)
        tcpSegment->addTag<TosReq>()->setTos(tos);

    auto addresses = tcpSegment->addTagIfAbsent<L3AddressReq>();
    addresses->setSrcAddress(localAddr);
    addresses->setDestAddress(remoteAddr);

    // ECN:
    // We decided to use ECT(1) to indicate ECN capable transport.
    //
    // rfc-3168, page 6:
    // Routers treat the ECT(0) and ECT(1) codepoints
    // as equivalent.  Senders are free to use either the ECT(0) or the
    // ECT(1) codepoint to indicate ECT.
    //
    // rfc-3168, page 20:
    // For the current generation of TCP congestion control algorithms, pure
    // acknowledgement packets (e.g., packets that do not contain any
    // accompanying data) MUST be sent with the not-ECT codepoint.
    //
    // rfc-3168, page 20:
    // ECN-capable TCP implementations MUST NOT set either ECT codepoint
    // (ECT(0) or ECT(1)) in the IP header for retransmitted data packets
    tcpSegment->addTagIfAbsent<EcnReq>()->setExplicitCongestionNotification((state->ect && !state->sndAck && !state->rexmit) ? IP_ECN_ECT_1 : IP_ECN_NOT_ECT);

    tcpSegment->addTagIfAbsent<InterfaceReq>()->setInterfaceId(interfaceId); //Add MP interface

    tcpHeader->setCrc(0);
    tcpHeader->setCrcMode(tcpMain->crcMode);

    insertTransportProtocolHeader(tcpSegment, Protocol::tcp, tcpHeader);

    tcpMain->sendFromConn(tcpSegment, "ipOut");
}

void SubflowConnection::updateTotalCwnd(uint32_t oldSubflowCwnd, uint32_t newSubflowCwnd)
{
    metaConn->updateTotalCwnd(oldSubflowCwnd, newSubflowCwnd);
}

bool SubflowConnection::processInternalCommand(int commandCode, TcpCommand *tcpCommand)
{
    cMessage *msg = new cMessage("InternalSubflowCommand", commandCode);
    msg->setControlInfo(tcpCommand);

    if (!processAppCommand(msg)) {
        tcpMain->removeConnection(this);
        return false;
    }

    return true;
}

void SubflowConnection::rememberSentDsnMapping(uint32_t subflowSeqNo, uint32_t dsnStart, uint32_t bytes)
{
    DsnMapping mapping;
    mapping.dsnStart = dsnStart;
    mapping.dsnEnd = dsnStart + bytes;
    sentDsnMapping[subflowSeqNo] = mapping;
}

void SubflowConnection::rememberReceivedDsnMapping(uint32_t subflowSeqNo, uint32_t dsnStart, uint32_t bytes)
{
    DsnMapping mapping;
    mapping.dsnStart = dsnStart;
    mapping.dsnEnd = dsnStart + bytes;
    receivedDsnMapping[subflowSeqNo] = mapping;
}

void SubflowConnection::eraseReceivedMappingsUpTo(uint32_t seqNo)
{
    auto it = receivedDsnMapping.begin();
    while (it != receivedDsnMapping.end()) {
        const uint32_t subflowSeqEnd = it->first + (it->second.dsnEnd - it->second.dsnStart);
        if (seqGreater(subflowSeqEnd, seqNo))
            break;

        it = receivedDsnMapping.erase(it);
    }
}

void SubflowConnection::eraseSentDsnMappingsUpToDataAck(uint32_t dataAckNo)
{
    auto it = sentDsnMapping.begin();
    while (it != sentDsnMapping.end()) {
        if (seqLE(it->second.dsnEnd, dataAckNo)) {
            it = sentDsnMapping.erase(it);
        }
        else {
            if (seqLess(it->second.dsnStart, dataAckNo))
                it->second.dsnStart = dataAckNo;
            ++it;
        }
    }
}

bool SubflowConnection::translateAckToMetaLevel(uint32_t discardUpToSeq, uint32_t& metaAckNo)
{
    bool translated = false;
    auto it = sentDsnMapping.begin();
    while (it != sentDsnMapping.end()) {
        const uint32_t subflowSeqEnd = it->first + (it->second.dsnEnd - it->second.dsnStart);
        if (seqGreater(subflowSeqEnd, discardUpToSeq))
            break;

        metaAckNo = it->second.dsnEnd;
        translated = true;
        it = sentDsnMapping.erase(it);
    }

    return translated;
}

bool SubflowConnection::consumePendingDsnMapping(uint32_t subflowSeqNo, uint32_t bytes, uint32_t& dsnStart)
{
    auto it = pendingDsnMapping.find(subflowSeqNo);
    if (it == pendingDsnMapping.end())
        return false;

    const uint32_t mappingBytes = it->second.dsnEnd - it->second.dsnStart;
    if (bytes > mappingBytes)
        return false;

    dsnStart = it->second.dsnStart;
    if (bytes == mappingBytes) {
        pendingDsnMapping.erase(it);
    }
    else {
        DsnMapping remaining;
        remaining.dsnStart = it->second.dsnStart + bytes;
        remaining.dsnEnd = it->second.dsnEnd;
        pendingDsnMapping.erase(it);
        pendingDsnMapping[subflowSeqNo + bytes] = remaining;
    }

    return true;
}

}
}

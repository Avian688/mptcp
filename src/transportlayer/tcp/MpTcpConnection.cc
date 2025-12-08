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
#include "MpTcpConnection.h"

namespace inet {
namespace tcp {

Define_Module(MpTcpConnection);

MpTcpConnection::MpTcpConnection() {
    // TODO Auto-generated constructor stub

}

MpTcpConnection::~MpTcpConnection() {
    // TODO Auto-generated destructor stub
}

void MpTcpConnection::process_OPEN_ACTIVE(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg)
{
    TcpOpenCommand *openCmd = check_and_cast<TcpOpenCommand *>(tcpCommand);
    L3Address localAddr, remoteAddr;
    int localPort, remotePort;

    switch (fsm.getState()) {
        case TCP_S_INIT:
            initConnection(openCmd);

            // store local/remote socket
            state->active = true;
            localAddr = openCmd->getLocalAddr();
            remoteAddr = openCmd->getRemoteAddr();
            localPort = openCmd->getLocalPort();
            remotePort = openCmd->getRemotePort();
            state->sack_support = false;

            if (remoteAddr.isUnspecified() || remotePort == -1)
                throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: remote address and port must be specified");

            if (localPort == -1) {
                localPort = tcpMain->getEphemeralPort();
                EV_DETAIL << "Assigned ephemeral port " << localPort << "\n";
            }

            EV_DETAIL << "OPEN: " << localAddr << ":" << localPort << " --> " << remoteAddr << ":" << remotePort << "\n";

            //create new subflow here, and then initiate next methods in said subflow
            // send initial SYN
            //addSubflow(true);
            selectInitialSeqNum();
            setUpSyn();
            //sendSyn();
            //startSynRexmitTimer();
            //scheduleAfter(TCP_TIMEOUT_CONN_ESTAB, connEstabTimer);
            break;

        default:
            throw cRuntimeError(tcpMain, "Error processing command OPEN_ACTIVE: connection already exists");
    }

    delete openCmd;
    delete msg;
}

void MpTcpConnection::setUpSyn()
{
    // create segment
    const auto& tcpHeader = makeShared<TcpHeader>();
    tcpHeader->setSequenceNo(state->iss);
    tcpHeader->setSynBit(true);
    updateRcvWnd();
    tcpHeader->setWindow(state->rcv_wnd);

    state->snd_max = state->snd_nxt = state->iss + 1;

    std::cout << "state->snd_max: " << state->snd_max << std::endl;
    std::cout << "state->snd_nxt: " << state->snd_nxt << std::endl;
    std::cout << "state->iss + 1: " << state->iss + 1 << std::endl;

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

    //Scrap header, only update values as needed
}

void MpTcpConnection::setUpSynAck()
{
    updateRcvWnd();
    state->snd_max = state->snd_nxt = state->iss + 1;
}

void MpTcpConnection::addSubflow(SubflowConnection* subflowConn)
{
    m_subflows[mptcp_states_t::Syn].push_back(subflowConn);
}

void MpTcpConnection::subflowStateChange(const TcpEventCode& event)
{
    performStateTransition(event);
}

TcpEventCode MpTcpConnection::processSegmentInSynSent(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address srcAddr, L3Address destAddr)
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

        if (tcpHeader->getAckBit()) {
            std::cout << "BEFORE:" << std::endl;
            std::cout << "state->snd_una: " << state->snd_una << std::endl;
            std::cout << "tcpHeader->getAckNo(): " << tcpHeader->getAckNo() << std::endl;

            state->snd_una = tcpHeader->getAckNo();
            sendQueue->discardUpTo(state->snd_una);

            std::cout << "AFTER:" << std::endl;
            std::cout << "state->snd_una: " << state->snd_una << std::endl;
            std::cout << "tcpHeader->getAckNo(): " << tcpHeader->getAckNo() << std::endl;

            if (state->sack_enabled)
                rexmitQueue->discardUpTo(state->snd_una);

            // although not mentioned in RFC 793, seems like we have to pick up
            // initial snd_wnd from the segment here.
            updateWndInfo(tcpHeader, true);
        }

        // Not needed as local IP address should have been learnt already
        //tcpMain->updateSockPair(this, destAddr, srcAddr, tcpHeader->getDestPort(), tcpHeader->getSrcPort());

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
        setUpSynAck();
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

TcpEventCode MpTcpConnection::processSegmentInListen(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address srcAddr, L3Address destAddr)
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
        //Dont need to do since we do not clone connections - tcpMain->updateSockPair(this, destAddr, srcAddr, tcpHeader->getDestPort(), tcpHeader->getSrcPort());
        return processSynInListen(tcpSegment, tcpHeader, srcAddr, destAddr);
    }
    //!!Removed Forking from initial implementation, as we create a subflowConnection socket for each subflow!!


    //"
    //  fourth other text or control
    //   So you are unlikely to get here, but if you do, drop the segment, and return.
    //"
    EV_WARN << "Unexpected segment: dropping it\n";
    return TCP_E_IGNORE;
}

void MpTcpConnection::process_SEND(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg)
{
    // FIXME how to support PUSH? One option is to treat each SEND as a unit of data,
    // and set PSH at SEND boundaries
    Packet *packet = check_and_cast<Packet *>(msg);
    std::cout << "\n PROCESSING SEND AT SIMTIME: " << simTime() << endl;
    std::cout << "\n FSM STATE: " << fsm.getState() << endl;
    switch (fsm.getState()) {
        case TCP_S_INIT:
            throw cRuntimeError(tcpMain, "Error processing command SEND: connection not open");

        case TCP_S_LISTEN:
            EV_DETAIL << "SEND command turns passive open into active open, sending initial SYN\n";
            state->active = true;
            selectInitialSeqNum();
            sendSyn();
            startSynRexmitTimer();
            scheduleAfter(TCP_TIMEOUT_CONN_ESTAB, connEstabTimer);
            sendQueue->enqueueAppData(packet); // queue up for later
            EV_DETAIL << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue\n";
            break;

        case TCP_S_SYN_RCVD:
        case TCP_S_SYN_SENT:
            EV_DETAIL << "Queueing up data for sending later.\n";
            std::cout << "\n PACKET INFORMATION: " << packet->getDataLength() << endl;
            sendQueue->enqueueAppData(packet); // queue up for later
            EV_DETAIL << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue\n";

//            std::cout << "\n !! Current Subflow List: " << endl;
//            for (int state = 0; state < mptcp_state_count; ++state) {
//                for (SubflowConnection* conn : m_subflows[state]) {
//                    if (conn) {
//                        std::cout << "\n STATE: "  << state << " " << conn->getClassAndFullName() << endl;
//                        conn->sendPendingData();
//                    }
//                }
//            }
            break;

        case TCP_S_ESTABLISHED:
        case TCP_S_CLOSE_WAIT:
            std::cout << "\n PACKET INFORMATION 2: " << packet->getDataLength() << endl;
            sendQueue->enqueueAppData(packet);
            EV_DETAIL << sendQueue->getBytesAvailable(state->snd_una) << " bytes in queue, plus "
                      << (state->snd_max - state->snd_una) << " bytes unacknowledged\n";
            for (int state = 0; state < mptcp_state_count; ++state) {
                for (SubflowConnection* conn : m_subflows[state]) {
                    if (conn) {
                        if(conn->getIsMaster()){
                            conn->invokeSendCommand();
                        }
                    }
                }
            }
            break;

        case TCP_S_LAST_ACK:
        case TCP_S_FIN_WAIT_1:
        case TCP_S_FIN_WAIT_2:
        case TCP_S_CLOSING:
        case TCP_S_TIME_WAIT:
            throw cRuntimeError(tcpMain, "Error processing command SEND: connection closing");
    }

    if ((state->sendQueueLimit > 0) && (sendQueue->getBytesAvailable(state->snd_una) > state->sendQueueLimit))
        state->queueUpdate = false;
}

uint32_t MpTcpConnection::sendSegment(uint32_t bytes)
{ //MpTcpConnection shouldnt send packets! Subflows control this.
    state->snd_nxt += bytes;

    if (state->afterRto && seqGE(state->snd_nxt, state->snd_max))
            state->afterRto = false;

    if (seqGreater(state->snd_nxt, state->snd_max))
            state->snd_max = state->snd_nxt;

    emit(sndNxtSignal, state->snd_nxt);
    return state->snd_nxt;
}

uint32_t MpTcpConnection::getSegment(uint32_t bytes)
{
    uint32_t bytesAvailable = sendQueue->getBytesAvailable(state->snd_max);
    if(bytesAvailable <= bytes){
        return bytesAvailable;
    }
    else{
        return bytes;
    }
}

bool MpTcpConnection::nextUnsentSeg(uint32_t& seqNum)
{
    uint32_t buffered = getBytesAvailable();
    if(buffered > 0){
        seqNum = state->snd_max;
        return true;
    }
    uint32_t maxWindow = state->snd_wnd;
    // effectiveWindow: number of bytes we're allowed to send now
    uint32_t effectiveWin = maxWindow - state->pipe;

    if (buffered > 0 && effectiveWin >= state->snd_mss) {
        seqNum = state->snd_max; // HighData = snd_max
        return true;
    }
    return false;
}

uint32_t MpTcpConnection::getBytesAvailable()
{
    return sendQueue->getBytesAvailable(state->snd_max);
}

TcpEventCode MpTcpConnection::processSynInListen(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader, L3Address srcAddr, L3Address destAddr)
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

    if (tcpHeader->getHeaderLength() > TCP_MIN_HEADER_LENGTH) // Header options present?
        readHeaderOptions(tcpHeader);

    state->ack_now = true;

    // ECN
    if (tcpHeader->getEceBit() == true && tcpHeader->getCwrBit() == true) {
        state->endPointIsWillingECN = true;
        EV << "ECN-setup SYN packet received\n";
    }
    std::cout << "\nSending Syn Ack = "
              << "localPort: " << localPort
              << ", localAddr: " << localAddr
              << ", remotePort: " << remotePort
              << ", remoteAddr: " << remoteAddr
              << std::endl;
    setUpSynAck();

    //startSynRexmitTimer();

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
            receiveQueue->insertBytesFromSegment(tcpSegment, tcpHeader);
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

TcpEventCode MpTcpConnection::processSegment1stThru8th(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
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

//        std::cout << "\n MPCONNECTION DSN: " << tcpHeader->getTag<DataSequenceNumberTag>()->getDataSequenceNumber() << endl;
//        if (!seqLE(state->snd_una, tcpHeader->getAckNo()) || !seqLE(tcpHeader->getAckNo(), state->snd_nxt)) {
//            sendRst(tcpHeader->getAckNo());
//            return TCP_E_IGNORE;
//        }

        // notify tcpAlgorithm and app layer
        tcpAlgorithm->established(false);

        if (isToBeAccepted())
            sendAvailableIndicationToApp();
        else
            sendEstabIndicationToApp();

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
                state->rcv_nxt = receiveQueue->insertBytesFromSegment(tcpSegment, tcpHeader);

                if (seqGreater(state->snd_una, old_snd_una)) {
                    // notify
                    tcpAlgorithm->receivedDataAck(old_snd_una);

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
        //tcpAlgorithm->receiveSeqChanged();
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

//EDIT SO else if (seqLE(tcpHeader->getAckNo(), state->snd_max)) { is TRUE and sendQUeue stuff is discarded
bool MpTcpConnection::processAckInEstabEtc(Packet *tcpSegment, const Ptr<const TcpHeader>& tcpHeader)
{
    EV_DETAIL << "Processing ACK in a data transfer state\n";

    int payloadLength = tcpSegment->getByteLength() - B(tcpHeader->getHeaderLength()).get();

    // ECN
    TcpStateVariables *state = getState();
    if (state && state->ect) {
        if (tcpHeader->getEceBit() == true)
            EV_INFO << "Received packet with ECE\n";

        state->gotEce = tcpHeader->getEceBit();
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
    std::cout << "tcpHeader->getAckNo(): " << tcpHeader->getAckNo() << std::endl;
    std::cout << "state->snd_max: " << state->snd_max << std::endl;
    std::cout << "seqLE result: "
              << seqLE(tcpHeader->getAckNo(), state->snd_max)
              << std::endl;

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
            updateWndInfo(tcpHeader);

            tcpAlgorithm->receivedDuplicateAck();
        }
        else {
            // if doesn't qualify as duplicate ACK, just ignore it.
            if (payloadLength == 0) {
                if (state->snd_una != tcpHeader->getAckNo())
                    EV_DETAIL << "Old ACK: ackNo < snd_una\n";
                else if (state->snd_una == state->snd_max)
                    EV_DETAIL << "ACK looks duplicate but we have currently no unacked data (snd_una == snd_max)\n";
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

        // acked data no longer needed in send queue
        sendQueue->discardUpTo(discardUpToSeq);

        // acked data no longer needed in rexmit queue
        if (state->sack_enabled)
            rexmitQueue->discardUpTo(discardUpToSeq);

        updateWndInfo(tcpHeader);

        // if segment contains data, wait until data has been forwarded to app before sending ACK,
        // otherwise we would use an old ACKNo
        if (payloadLength == 0 && fsm.getState() != TCP_S_SYN_RCVD) {
            // notify
            tcpAlgorithm->receivedDataAck(old_snd_una);

            // in the receivedDataAck we need the old value
            state->dupacks = 0;

            emit(dupAcksSignal, state->dupacks);
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

}
}

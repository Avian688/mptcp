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

#include "MpTcpConnectionBase.h"
#include "MpTcp.h"
namespace inet {
namespace tcp {

Define_Module(MpTcpConnectionBase);

MpTcpConnectionBase::MpTcpConnectionBase() {
    // TODO Auto-generated constructor stub

}

MpTcpConnectionBase::~MpTcpConnectionBase() {
    // TODO Auto-generated destructor stub
}

void MpTcpConnectionBase::initConnection(TcpOpenCommand *openCmd)
{
    // create send queue
    sendQueue = tcpMain->createSendQueue();
    sendQueue->setConnection(this);

    // create receive queue
    receiveQueue = tcpMain->createReceiveQueue();
    receiveQueue->setConnection(this);

    // create SACK retransmit queue
    rexmitQueue = new TcpSackRexmitQueue();
    rexmitQueue->setConnection(this);

    // create algorithm
    const char *tcpAlgorithmClass = openCmd->getTcpAlgorithmClass();

    if (opp_isempty(tcpAlgorithmClass))
        tcpAlgorithmClass = tcpMain->par("tcpAlgorithmClass");

    if (strcmp(tcpAlgorithmClass, "MpTcpMetaCubic") == 0 && !this->isMeta()) {
        tcpAlgorithmClass = "MpTcpSubflowCubic";
    }
    else if (strcmp(tcpAlgorithmClass, "MpTcpOlia") == 0 && this->isMeta()) {
        tcpAlgorithmClass = "MpTcpMetaCubic";
    }
    else if (strcmp(tcpAlgorithmClass, "MpTcpBalia") == 0 && this->isMeta()) {
        tcpAlgorithmClass = "MpTcpMetaCubic";
    }
    else if (strcmp(tcpAlgorithmClass, "MpTcpReno") == 0 && this->isMeta()) {
        tcpAlgorithmClass = "MpTcpMetaCubic";
    }

    tcpAlgorithm = check_and_cast<TcpAlgorithm *>(inet::utils::createOne(tcpAlgorithmClass));
    tcpAlgorithm->setConnection(this);

    // create state block
    state = tcpAlgorithm->getStateVariables();
    configureStateVariables();

    tcpAlgorithm->initialize();

    m_delivered = 0;
    paceMsg = new cMessage("pacing message");
    throughputTimer = new cMessage("throughputTimer");
    rackTimer = new cMessage("rackTimer");
    retransmissionRateTimer = new cMessage("retransmissionRateTimer"); // NEW
    intersendingTime = 0.0000001;
    paceValueVec.setName("paceValue");
    retransmitOnePacket = false;
    retransmitAfterTimeout = false;
    throughputInterval = check_and_cast<MpTcp*>(tcpMain)->par("throughputInterval");
    lastBytesReceived = 0;
    prevLastBytesReceived = 0;
    currThroughput = 0;
    m_appLimited = false;
    m_rateAppLimited = false;
    m_txItemDelivered = 0;

    scoreboardUpdated = false;

    m_bytesInFlight = 0;
    m_bytesLoss = 0;

    lastThroughputTime = simTime();
    prevLastThroughputTime = simTime();

    m_firstSentTime = simTime();
    m_deliveredTime = simTime();

    m_rack = new TcpRack();
    m_sndFack = state->snd_una;
    m_reorder = false;
    m_dsackSeen = false;
    isRetransDataAcked = false;

    m_rateInterval = 0;
    m_rateDelivered = 0;

    m_lastAckedSackedBytes = 0;
    bytesRcvd = 0;

    m_rateSample.m_ackElapsed = 0;
    m_rateSample.m_ackedSacked = 0;
    m_rateSample.m_bytesLoss = 0;
    m_rateSample.m_delivered = 0;
    m_rateSample.m_deliveryRate = 0;
    m_rateSample.m_interval = 0;
    m_rateSample.m_isAppLimited = false;
    m_rateSample.m_priorDelivered = 0;
    m_rateSample.m_txInFlight = 0;
    m_rateSample.m_priorInFlight = 0;
    m_rateSample.m_priorTime = 0;
    m_rateSample.m_sendElapsed = 0;
    m_rateSample.m_lastSentTime = 0;
    m_rateSample.m_lastEndSeq = 0;
    m_lossNotificationSample = {};

    // sender-side retransmission accounting
    prevLastTotalRetransmittedBytes = 0;
    lastTotalRetransmittedBytes = 0;
    totalRetransmittedBytesCounter = 0;
    currRetransmissionRate = 0;
    nextSegSelectedRetransmission = false;
    lastRetransmissionRateTime = simTime();
    if (!isMeta())
        scheduleAt(simTime() + throughputInterval, throughputTimer);
    scheduleAt(simTime() + throughputInterval, retransmissionRateTimer);
}

bool MpTcpConnectionBase::isMeta() const
{
    return false;
}

}
}

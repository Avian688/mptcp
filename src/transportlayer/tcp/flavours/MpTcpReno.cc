//
// Reno congestion control adapted to the paced MPTCP subflow connection.
//

#include "MpTcpReno.h"

#include <algorithm>
#include <limits>

#include "../MpTcpConnection.h"

namespace inet {
namespace tcp {

Register_Class(MpTcpReno);

simsignal_t MpTcpReno::cwndSegSignal = cComponent::registerSignal("cwndSeg");
simsignal_t MpTcpReno::recoveryPointSignal = cComponent::registerSignal("recoveryPoint");
simsignal_t MpTcpReno::sndUnaSignal = cComponent::registerSignal("sndUna");

void MpTcpReno::initialize()
{
    isMaster = false;
    TcpPacedFamily::initialize();
    congestionAvoidanceAckCounter = 0.0L;
    wasCwndLimited = false;
    maxBytesInFlightForCwnd = 0;
    cwndUsageSeq = 0;
}

void MpTcpReno::established(bool active)
{
    TcpPacedFamily::established(active);
    wasCwndLimited = false;
    maxBytesInFlightForCwnd = 0;
    cwndUsageSeq = state != nullptr ? state->snd_max : 0;
    check_and_cast<TcpPacedConnection *>(conn)->changeIntersendingTime(0.000001);
}

void MpTcpReno::dataSent(uint32_t fromseq)
{
    TcpPacedFamily::dataSent(fromseq);

    if (state == nullptr || state->snd_mss == 0)
        return;

    auto *pacedConnection = check_and_cast<TcpPacedConnection *>(conn);
    const uint32_t cwndPackets = std::max(state->snd_cwnd / state->snd_mss, 1U);
    const uint32_t sendableCwnd = cwndPackets * state->snd_mss;
    recordCwndUsage(pacedConnection->getBytesInFlight() >= sendableCwnd);
}

void MpTcpReno::increaseCongestionWindow()
{
    if (state->snd_mss == 0)
        return;

    const long double cwndPackets = std::max(
            static_cast<long double>(state->snd_cwnd) / state->snd_mss, 1.0L);
    congestionAvoidanceAckCounter += 1.0L;
    if (congestionAvoidanceAckCounter >= cwndPackets) {
        if (state->snd_cwnd <= std::numeric_limits<uint32_t>::max() - state->snd_mss)
            state->snd_cwnd += state->snd_mss;
        congestionAvoidanceAckCounter = 0.0L;
    }
}

void MpTcpReno::recalculateSlowStartThreshold()
{
    if (state->snd_mss == 0)
        return;

    const uint32_t cwndPackets = std::max(state->snd_cwnd / state->snd_mss, 1U);
    state->ssthresh = std::max(cwndPackets / 2, 2U) * state->snd_mss;
    congestionAvoidanceAckCounter = 0.0L;
    conn->emit(ssthreshSignal, state->ssthresh);
    conn->emit(cwndSegSignal, cwndPackets);
}

void MpTcpReno::updatePacing()
{
    if (state->snd_cwnd == 0 || state->snd_mss == 0 || state->srtt <= SIMTIME_ZERO)
        return;

    auto *pacedConnection = check_and_cast<TcpPacedConnection *>(conn);
    const double paceFactor = state->snd_cwnd < state->ssthresh / 2 ? 2.0 : 1.2;
    const uint32_t maxWindow = std::max(state->snd_cwnd, pacedConnection->getBytesInFlight());
    const double packetsInWindow = static_cast<double>(maxWindow) / state->snd_mss;
    if (packetsInWindow > 0.0)
        pacedConnection->changeIntersendingTime(state->srtt.dbl() / (packetsInWindow * paceFactor));
}

void MpTcpReno::recordCwndUsage(bool cwndLimitedSample)
{
    auto *pacedConnection = check_and_cast<TcpPacedConnection *>(conn);
    const uint32_t bytesInFlight = pacedConnection->getBytesInFlight();

    if (cwndUsageSeq == 0 || seqGE(state->snd_una, cwndUsageSeq) ||
            cwndLimitedSample || (!wasCwndLimited && bytesInFlight > maxBytesInFlightForCwnd))
    {
        wasCwndLimited = cwndLimitedSample;
        maxBytesInFlightForCwnd = bytesInFlight;
        cwndUsageSeq = state->snd_max;
    }
}

bool MpTcpReno::isConnectionCwndLimited()
{
    if (state->snd_mss == 0)
        return false;

    auto *pacedConnection = check_and_cast<TcpPacedConnection *>(conn);
    // INET stores cwnd in bytes, and RFC 3390 may initialize it to 4380
    // bytes. With a 1448-byte MSS that permits three full packets (4344
    // bytes), leaving an unusable 36-byte remainder. Linux performs this
    // test in packets, so compare against the full-packet portion of cwnd.
    const uint32_t cwndPackets = std::max(state->snd_cwnd / state->snd_mss, 1U);
    const uint32_t sendableCwnd = cwndPackets * state->snd_mss;

    const bool subflowCwndLimited = pacedConnection->isCwndLimited(sendableCwnd);
    if (subflowCwndLimited)
        return true;

    auto *subflow = dynamic_cast<SubflowConnection *>(conn);
    MpTcpConnection *metaConnection = subflow != nullptr ? subflow->getMetaConnection() : nullptr;
    if (metaConnection != nullptr && metaConnection->getBytesAvailable() > 0 &&
            pacedConnection->getBytesInFlight() + state->snd_mss >= sendableCwnd)
        return true;

    if (wasCwndLimited)
        return true;

    // Linux lets slow start keep probing if the connection used at least half
    // of the current cwnd during the remembered cwnd window.
    if (state->snd_cwnd < state->ssthresh)
        return static_cast<uint64_t>(sendableCwnd) <
                2ULL * static_cast<uint64_t>(maxBytesInFlightForCwnd);

    return false;
}

void MpTcpReno::setRecoveryCongestionWindow()
{
    auto *pacedConnection = check_and_cast<TcpPacedConnection *>(conn);
    const uint64_t recoveryCwnd = static_cast<uint64_t>(pacedConnection->getBytesInFlight()) +
            state->snd_mss;
    state->snd_cwnd = static_cast<uint32_t>(
            std::min(recoveryCwnd, static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())));
}

void MpTcpReno::processRexmitTimer(TcpEventCode& event)
{
    const uint32_t oldCwnd = state->snd_cwnd;
    TcpPacedFamily::processRexmitTimer(event);
    if (event == TCP_E_ABORT)
        return;

    if (shouldApplyRtoCongestionResponse())
        recalculateSlowStartThreshold();
    state->snd_cwnd = state->snd_mss;
    check_and_cast<SubflowConnection *>(conn)->updateTotalCwnd(oldCwnd, state->snd_cwnd);

    state->afterRto = true;
    auto *pacedConnection = check_and_cast<TcpPacedConnection *>(conn);
    pacedConnection->cancelPaceTimer();
    sendData(false);

    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(ssthreshSignal, state->ssthresh);
    conn->emit(cwndSegSignal, state->snd_cwnd / state->snd_mss);
}

void MpTcpReno::rackLossDetected()
{
    auto *pacedConnection = check_and_cast<TcpPacedConnection *>(conn);
    if (!state->sack_enabled)
        return;

    const uint32_t oldCwnd = state->snd_cwnd;
    if (!state->lossRecovery) {
        state->recoveryPoint = state->snd_max;
        pacedConnection->updateInFlight();
        state->lossRecovery = true;

        recalculateSlowStartThreshold();
        setRecoveryCongestionWindow();
        check_and_cast<SubflowConnection *>(conn)->updateTotalCwnd(oldCwnd, state->snd_cwnd);
        conn->emit(recoveryPointSignal, state->recoveryPoint);
        conn->emit(cwndSignal, state->snd_cwnd);
        conn->emit(ssthreshSignal, state->ssthresh);
        conn->emit(cwndSegSignal, state->snd_cwnd / state->snd_mss);
    }
    else {
        pacedConnection->updateInFlight();
    }

    if (pacedConnection->doRetransmit())
        restartRexmitTimer();
}

void MpTcpReno::receivedDataAck(uint32_t firstSeqAcked)
{
    const uint32_t oldCwnd = state->snd_cwnd;
    TcpTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    const bool wasInLossRecovery = state->sack_enabled && state->lossRecovery;
    if (wasInLossRecovery) {
        if (seqGE(state->snd_una, state->recoveryPoint)) {
            state->snd_cwnd = state->ssthresh;
            state->lossRecovery = false;
        }
        conn->emit(sndUnaSignal, state->snd_una);
        conn->emit(recoveryPointSignal, state->recoveryPoint);
        conn->emit(cwndSignal, state->snd_cwnd);
        conn->emit(ssthreshSignal, state->ssthresh);
        conn->emit(cwndSegSignal, state->snd_cwnd / state->snd_mss);
        check_and_cast<SubflowConnection *>(conn)->updateTotalCwnd(oldCwnd, state->snd_cwnd);
        return;
    }

    if (isConnectionCwndLimited()) {
        if (state->snd_cwnd < state->ssthresh)
            state->snd_cwnd += state->snd_mss;
        else
            increaseCongestionWindow();
    }

    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(ssthreshSignal, state->ssthresh);
    conn->emit(cwndSegSignal, state->snd_cwnd / state->snd_mss);
    updatePacing();
    check_and_cast<SubflowConnection *>(conn)->updateTotalCwnd(oldCwnd, state->snd_cwnd);
    sendData(false);
}

void MpTcpReno::receivedDuplicateAck()
{
    const uint32_t oldCwnd = state->snd_cwnd;
    TcpTahoeRenoFamily::receivedDuplicateAck();

    auto *pacedConnection = check_and_cast<TcpPacedConnection *>(conn);
    if (shouldEnterLossRecoveryOnDuplicateAck()) {
        if (state->sack_enabled &&
                (state->recoveryPoint == 0 || seqGE(state->snd_una, state->recoveryPoint)) &&
                !state->lossRecovery)
        {
            state->recoveryPoint = state->snd_max;
            pacedConnection->setSackedHeadLostIfRackDisabled();
            pacedConnection->updateInFlight();
            state->lossRecovery = true;

            recalculateSlowStartThreshold();
            setRecoveryCongestionWindow();
            pacedConnection->doRetransmit();
        }

        conn->emit(recoveryPointSignal, state->recoveryPoint);
        conn->emit(cwndSignal, state->snd_cwnd);
        conn->emit(ssthreshSignal, state->ssthresh);
        conn->emit(cwndSegSignal, state->snd_cwnd / state->snd_mss);

        if (state->lossRecovery)
            restartRexmitTimer();
    }

    updatePacing();
    check_and_cast<SubflowConnection *>(conn)->updateTotalCwnd(oldCwnd, state->snd_cwnd);
    if (!state->lossRecovery)
        sendData(false);
}

} // namespace tcp
} // namespace inet

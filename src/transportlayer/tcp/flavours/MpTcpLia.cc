//
// Linked Increases Algorithm for MPTCP (RFC 6356).
//

#include "MpTcpLia.h"

#include <algorithm>
#include <limits>

#include "../MpTcpConnection.h"

namespace inet {
namespace tcp {

Register_Class(MpTcpLia);

simsignal_t MpTcpLia::alphaSignal = cComponent::registerSignal("liaAlpha");

void MpTcpLia::established(bool active)
{
    MpTcpReno::established(active);
    cwndAccumulator = 0.0L;
    ackedPackets = 1.0L;
}

void MpTcpLia::receivedDataAck(uint32_t firstSeqAcked)
{
    ackedPackets = 1.0L;
    if (state->snd_mss > 0) {
        const uint32_t bytesAcked = state->snd_una - firstSeqAcked;
        ackedPackets = std::max(
                static_cast<long double>(bytesAcked) / state->snd_mss, 1.0L);
    }
    MpTcpReno::receivedDataAck(firstSeqAcked);
    ackedPackets = 1.0L;
}

void MpTcpLia::recalculateSlowStartThreshold()
{
    MpTcpReno::recalculateSlowStartThreshold();
    cwndAccumulator = 0.0L;
}

void MpTcpLia::increaseCongestionWindow()
{
    MpTcpConnection *metaConnection = getMetaConnection();
    if (metaConnection == nullptr || state->snd_mss == 0)
        return;

    long double totalCwnd = 0.0L;
    long double sumRates = 0.0L;
    long double maxRateTerm = 0.0L;
    long double currentCwnd = 0.0L;

    for (SubflowConnection *subflow : metaConnection->getSubflows()) {
        if (!isEligibleSubflow(subflow))
            continue;

        auto *algorithm = dynamic_cast<MpTcpLia *>(subflow->getTcpAlgorithm());
        if (algorithm == nullptr)
            continue;

        const auto *subflowState = static_cast<const TcpTahoeRenoFamilyStateVariables *>(
                subflow->getState());
        const long double rtt = getRttInSeconds(subflowState);
        const long double cwnd = subflowState->lossRecovery ?
                static_cast<long double>(subflowState->ssthresh) / subflowState->snd_mss :
                getCwndInPackets(subflowState);
        if (cwnd <= 0.0L || rtt <= 0.0L)
            continue;

        totalCwnd += cwnd;
        sumRates += cwnd / rtt;
        maxRateTerm = std::max(maxRateTerm, cwnd / (rtt * rtt));
        if (algorithm == this)
            currentCwnd = cwnd;
    }

    if (totalCwnd <= 0.0L || sumRates <= 0.0L || currentCwnd <= 0.0L)
        return;

    // RFC 6356 equations (1) and (2), expressed in packets with appropriate
    // byte counting for ACKs that cover more than one full-sized segment.
    const long double alpha = totalCwnd * maxRateTerm / (sumRates * sumRates);
    const long double linkedIncrease = alpha / totalCwnd;
    const long double renoIncrease = 1.0L / currentCwnd;
    cwndAccumulator += ackedPackets * std::min(linkedIncrease, renoIncrease);
    conn->emit(alphaSignal, static_cast<double>(alpha));

    if (cwndAccumulator >= 1.0L) {
        if (state->snd_cwnd <= std::numeric_limits<uint32_t>::max() - state->snd_mss)
            state->snd_cwnd += state->snd_mss;
        cwndAccumulator = 0.0L;
    }
}

} // namespace tcp
} // namespace inet

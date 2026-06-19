//
// Balanced Linked Adaptation congestion control for MPTCP.
//

#include "MpTcpBalia.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include "../MpTcpConnection.h"

namespace inet {
namespace tcp {

Register_Class(MpTcpBalia);

simsignal_t MpTcpBalia::additiveIncreaseSignal = cComponent::registerSignal("baliaAi");
simsignal_t MpTcpBalia::multiplicativeDecreaseSignal = cComponent::registerSignal("baliaMd");

long double MpTcpBalia::calculateAdditiveIncreaseThreshold() const
{
    MpTcpConnection *metaConnection = getMetaConnection();
    if (metaConnection == nullptr)
        return std::max(getCwndInPackets(state), 1.0L);

    long double currentRate = 0.0L;
    long double maximumRate = 0.0L;
    long double sumRates = 0.0L;
    for (SubflowConnection *subflow : metaConnection->getSubflows()) {
        if (!isEligibleSubflow(subflow) || dynamic_cast<MpTcpBalia *>(subflow->getTcpAlgorithm()) == nullptr)
            continue;

        const auto *subflowState = static_cast<const TcpTahoeRenoFamilyStateVariables *>(
                subflow->getState());
        const long double rate = getCwndInPackets(subflowState) / getRttInSeconds(subflowState);
        sumRates += rate;
        maximumRate = std::max(maximumRate, rate);
        if (subflow->getTcpAlgorithm() == this)
            currentRate = rate;
    }

    const long double currentCwnd = getCwndInPackets(state);
    if (currentRate <= 0.0L || maximumRate <= 0.0L || sumRates <= 0.0L)
        return std::max(currentCwnd, 1.0L);

    const long double numerator = sumRates * sumRates * 10.0L * currentCwnd;
    const long double denominator =
            (currentRate + maximumRate) * (4.0L * currentRate + maximumRate);
    const long double threshold = denominator > 0.0L ? numerator / denominator : currentCwnd;

    // The kernel falls back to one Reno-style cwnd when fixed-point rounding
    // would produce zero.
    return threshold >= 1.0L ? threshold : std::max(currentCwnd, 1.0L);
}

long double MpTcpBalia::calculateMultiplicativeDecrease() const
{
    MpTcpConnection *metaConnection = getMetaConnection();
    const long double currentCwnd = getCwndInPackets(state);
    const long double currentRtt = getRttInSeconds(state);
    if (metaConnection == nullptr || currentCwnd <= 0.0L || currentRtt <= 0.0L)
        return std::floor(currentCwnd / 2.0L);

    const long double currentRate = currentCwnd / currentRtt;
    long double maximumRate = currentRate;
    for (SubflowConnection *subflow : metaConnection->getSubflows()) {
        if (!isEligibleSubflow(subflow) || dynamic_cast<MpTcpBalia *>(subflow->getTcpAlgorithm()) == nullptr)
            continue;
        const auto *subflowState = static_cast<const TcpTahoeRenoFamilyStateVariables *>(
                subflow->getState());
        maximumRate = std::max(maximumRate,
                getCwndInPackets(subflowState) / getRttInSeconds(subflowState));
    }

    // v0.96 computes alpha with integer division before applying the 1.5 cap.
    const long double alpha = std::floor(maximumRate / currentRate);
    const long double halfWindow = std::floor(currentCwnd / 2.0L);
    return std::floor(halfWindow * std::min(alpha, 1.5L));
}

void MpTcpBalia::increaseCongestionWindow()
{
    const long double additiveIncrease = calculateAdditiveIncreaseThreshold();
    conn->emit(additiveIncreaseSignal, static_cast<double>(additiveIncrease));

    // Match the v0.96 snd_cwnd_cnt ordering: test, then increment.
    if (ackCounter >= additiveIncrease) {
        if (state->snd_cwnd <= std::numeric_limits<uint32_t>::max() - state->snd_mss)
            state->snd_cwnd += state->snd_mss;
        ackCounter = 0.0L;
    }
    else {
        ackCounter += 1.0L;
    }
}

void MpTcpBalia::recalculateSlowStartThreshold()
{
    if (state->snd_mss == 0)
        return;
    const uint32_t cwndPackets = std::max(state->snd_cwnd / state->snd_mss, 1U);
    const long double decrease = calculateMultiplicativeDecrease();
    const uint32_t decreasePackets = static_cast<uint32_t>(
            std::min(decrease, static_cast<long double>(cwndPackets - 1)));
    const uint32_t thresholdPackets = std::max(cwndPackets - decreasePackets, 1U);
    state->ssthresh = thresholdPackets * state->snd_mss;
    ackCounter = 0.0L;

    conn->emit(multiplicativeDecreaseSignal, static_cast<double>(decreasePackets));
    conn->emit(ssthreshSignal, state->ssthresh);
    conn->emit(cwndSegSignal, cwndPackets);
}

} // namespace tcp
} // namespace inet

//
// Opportunistic Linked Increases Algorithm for MPTCP.
//

#include "MpTcpOlia.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <vector>

#include "../MpTcpConnection.h"

namespace inet {
namespace tcp {

Register_Class(MpTcpOlia);

simsignal_t MpTcpOlia::epsilonSignal = cComponent::registerSignal("oliaEpsilon");

namespace {

bool nearlyEqual(long double first, long double second)
{
    const long double scale = std::max({1.0L, std::fabs(first), std::fabs(second)});
    return std::fabs(first - second) <= std::numeric_limits<long double>::epsilon() * 32.0L * scale;
}

} // namespace

void MpTcpOlia::established(bool active)
{
    MpTcpReno::established(active);
    loss1 = loss2 = loss3 = state->snd_una;
    epsilonNumerator = 0;
    epsilonDenominator = 1;
    cwndAccumulator = 0.0L;
}

void MpTcpOlia::updateLossHistory()
{
    if (loss3 != loss2) {
        loss1 = loss2;
        loss2 = loss3;
    }
}

void MpTcpOlia::receivedDataAck(uint32_t firstSeqAcked)
{
    loss3 = state->snd_una;
    MpTcpReno::receivedDataAck(firstSeqAcked);
}

void MpTcpOlia::recalculateSlowStartThreshold()
{
    updateLossHistory();
    if (state->snd_mss == 0)
        return;
    const uint32_t cwndPackets = std::max(state->snd_cwnd / state->snd_mss, 1U);
    const uint32_t thresholdPackets = std::max(cwndPackets / 2, 2U);
    state->ssthresh = thresholdPackets * state->snd_mss;
    conn->emit(ssthreshSignal, state->ssthresh);
    conn->emit(cwndSegSignal, cwndPackets);
}

void MpTcpOlia::increaseCongestionWindow()
{
    struct PathInfo {
        MpTcpOlia *algorithm;
        long double cwnd;
        long double rtt;
        long double lossRate;
    };

    std::vector<PathInfo> paths;
    MpTcpConnection *metaConnection = getMetaConnection();
    if (metaConnection != nullptr) {
        for (SubflowConnection *subflow : metaConnection->getSubflows()) {
            if (!isEligibleSubflow(subflow))
                continue;
            auto *algorithm = dynamic_cast<MpTcpOlia *>(subflow->getTcpAlgorithm());
            if (algorithm == nullptr)
                continue;

            const auto *subflowState = static_cast<const TcpTahoeRenoFamilyStateVariables *>(
                    subflow->getState());
            const long double rtt = getRttInSeconds(subflowState);
            const uint32_t currentInterval = algorithm->loss3 - algorithm->loss2;
            const uint32_t previousInterval = algorithm->loss2 - algorithm->loss1;
            const long double interLoss = std::max(currentInterval, previousInterval);
            const long double effectiveCwnd = subflowState->lossRecovery ?
                    static_cast<long double>(subflowState->ssthresh) / subflowState->snd_mss :
                    getCwndInPackets(subflowState);
            paths.push_back({algorithm, effectiveCwnd, rtt,
                    interLoss / (rtt * rtt)});
        }
    }

    if (paths.empty())
        return;

    long double maxCwnd = 0.0L;
    long double bestLossRate = -1.0L;
    long double sumRates = 0.0L;
    for (const PathInfo& path : paths) {
        maxCwnd = std::max(maxCwnd, path.cwnd);
        bestLossRate = std::max(bestLossRate, path.lossRate);
        sumRates += path.cwnd / path.rtt;
    }

    uint32_t maxWindowPaths = 0;
    uint32_t bestNonMaxPaths = 0;
    for (const PathInfo& path : paths) {
        if (nearlyEqual(path.cwnd, maxCwnd))
            maxWindowPaths++;
        else if (nearlyEqual(path.lossRate, bestLossRate))
            bestNonMaxPaths++;
    }

    epsilonNumerator = 0;
    epsilonDenominator = 1;
    const PathInfo *currentPath = nullptr;
    for (const PathInfo& path : paths) {
        if (path.algorithm != this)
            continue;

        currentPath = &path;
        if (bestNonMaxPaths != 0) {
            if (!nearlyEqual(path.cwnd, maxCwnd) && nearlyEqual(path.lossRate, bestLossRate)) {
                epsilonNumerator = 1;
                epsilonDenominator = static_cast<uint32_t>(paths.size()) * bestNonMaxPaths;
            }
            else if (nearlyEqual(path.cwnd, maxCwnd)) {
                epsilonNumerator = -1;
                epsilonDenominator = static_cast<uint32_t>(paths.size()) * maxWindowPaths;
            }
        }
        break;
    }

    if (currentPath == nullptr || currentPath->cwnd <= 0.0L || sumRates <= 0.0L)
        return;

    const long double baseIncrease =
            (currentPath->cwnd / (currentPath->rtt * currentPath->rtt)) /
            (sumRates * sumRates);
    const long double epsilon = static_cast<long double>(epsilonNumerator) /
            (epsilonDenominator * currentPath->cwnd);
    cwndAccumulator += baseIncrease + epsilon;
    conn->emit(epsilonSignal, static_cast<double>(epsilon));

    if (cwndAccumulator >= 1.0L) {
        if (state->snd_cwnd <= std::numeric_limits<uint32_t>::max() - state->snd_mss)
            state->snd_cwnd += state->snd_mss;
        cwndAccumulator = 0.0L;
    }
    else if (cwndAccumulator <= -1.0L) {
        if (state->snd_cwnd > state->snd_mss)
            state->snd_cwnd -= state->snd_mss;
        else
            state->snd_cwnd = state->snd_mss;
        cwndAccumulator = 0.0L;
    }
}

} // namespace tcp
} // namespace inet

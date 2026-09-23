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

#include "MpTcpPacketScheduler.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <vector>

#include "MpTcpConnection.h"
#include "SubflowConnection.h"

namespace inet {
namespace tcp {

MpTcpPacketScheduler::MpTcpPacketScheduler(MpTcpConnection *connection) : connection(connection)
{
}

void MpTcpPacketScheduler::setConnection(MpTcpConnection *connection)
{
    this->connection = connection;
}

void MpTcpPacketScheduler::setSchedulingMode(const char *mode)
{
    schedulingMode = mode != nullptr ? mode : "default";
    if (schedulingMode != "lowestRtt" && schedulingMode != "directPull" &&
            schedulingMode != "defaultCwnd")
        schedulingMode = "default";

    lastSubflow = nullptr;
    remainingBurstBytes = 0;
    skippedCwndBursts.clear();
}

bool MpTcpPacketScheduler::usesDirectPullMode() const
{
    return schedulingMode == "directPull";
}

bool MpTcpPacketScheduler::usesLowestRttScheduling() const
{
    return schedulingMode == "lowestRtt";
}

bool MpTcpPacketScheduler::usesCwndBoundedScheduling() const
{
    return schedulingMode == "defaultCwnd";
}

uint32_t MpTcpPacketScheduler::getBoundedAssignmentSpace(SubflowConnection *subflow, uint32_t segmentBytes) const
{
    return subflow->getSchedulerAvailableBytes();
}

SubflowConnection *MpTcpPacketScheduler::schedulePacket(SubflowConnection *requester, uint32_t bytes)
{
    if (connection == nullptr || bytes == 0)
        return nullptr;

    if (connection->hasPendingMetaRetransmission()) {
        SubflowConnection *target = connection->dispatchPendingMetaRetransmission(requester, bytes);
        return target;
    }

    const uint32_t schedulableBytes = connection->getSegment(bytes);
    if (schedulableBytes == 0 ||
            (schedulableBytes < bytes && !connection->canSchedulePartialSegment(schedulableBytes)))
        return nullptr;

    if (usesLowestRttScheduling())
        return scheduleLowestRtt(requester, schedulableBytes);

    return scheduleDefault(requester, schedulableBytes);
}

void MpTcpPacketScheduler::pushPendingData(uint32_t bytes)
{
    if (connection == nullptr || bytes == 0)
        return;

    if (usesDirectPullMode()) {
        for (SubflowConnection *subflow : connection->getSubflows()) {
            if (subflow != nullptr && subflow->canAcceptScheduledData(bytes))
                subflow->invokeSendCommand();
        }
        return;
    }

    // There is no requester in this path: the meta connection is re-entering
    // the scheduler after a DATA_ACK opened space, so wake whichever subflows
    // the configured scheduler selects.
    schedulePacket(nullptr, bytes);
}

SubflowConnection *MpTcpPacketScheduler::selectRetransmissionSubflow(SubflowConnection *source, uint32_t bytes,
        bool requireIdle) const
{
    if (connection == nullptr || bytes == 0)
        return nullptr;

    auto select = [&](bool requireIdle, bool excludeSource) {
        SubflowConnection *bestSubflow = nullptr;
        simtime_t bestRtt = SIMTIME_MAX;

        for (SubflowConnection *subflow : connection->getSubflows()) {
            if (subflow == nullptr || (excludeSource && subflow == source))
                continue;

            const bool available = requireIdle ? subflow->canAcceptRetransmission(bytes)
                                               : subflow->canAcceptScheduledData(bytes);
            if (!available)
                continue;

            // The variant also bounds timer reinjection; otherwise an idle
            // tiny-window path could still receive a 64 KiB recovery fragment.
            if (usesCwndBoundedScheduling() && getBoundedAssignmentSpace(subflow, bytes) < bytes)
                continue;

            if (!usesLowestRttScheduling())
                return subflow;

            const simtime_t candidateRtt = subflow->getSchedulingRtt();
            if (bestSubflow == nullptr || candidateRtt < bestRtt) {
                bestSubflow = subflow;
                bestRtt = candidateRtt;
            }
        }
        return bestSubflow;
    };

    if (requireIdle)
        return select(true, false);

    // Closing a subflow requeues its outstanding meta data onto any remaining
    // subflow with send-window space, matching Linux's close/failover path.
    return select(false, true);
}

void MpTcpPacketScheduler::forgetSubflow(SubflowConnection *subflow)
{
    if (subflow == nullptr)
        return;

    avgPacingRates.erase(subflow);
    skippedCwndBursts.erase(subflow);
    if (lastSubflow == subflow) {
        lastSubflow = nullptr;
        remainingBurstBytes = 0;
    }
}

SubflowConnection *MpTcpPacketScheduler::scheduleLowestRtt(SubflowConnection *requester, uint32_t bytes)
{
    SubflowConnection *bestSubflow = nullptr;
    simtime_t bestRtt = SIMTIME_MAX;

    for (SubflowConnection *subflow : connection->getSubflows()) {
        if (subflow == nullptr || !subflow->canAcceptScheduledData(bytes))
            continue;

        const simtime_t candidateRtt = subflow->getSchedulingRtt();
        if (bestSubflow == nullptr || candidateRtt < bestRtt) {
            bestSubflow = subflow;
            bestRtt = candidateRtt;
        }
    }

    if (bestSubflow == nullptr)
        return nullptr;

    bestSubflow->enqueueScheduledData(bytes);

    EV_INFO << "MPTCP scheduler selected subflow " << bestSubflow->getSocketId()
            << " for " << bytes << " bytes (srtt=" << bestSubflow->getSchedulingRtt() << ")\n";

    if (bestSubflow != requester)
        bestSubflow->invokeSendCommand();

    return bestSubflow;
}

SubflowConnection *MpTcpPacketScheduler::scheduleDefault(SubflowConnection *requester, uint32_t bytes)
{
    // snd_burst belongs to one Linux push pass. A later ACK/pacing callback
    // must rank the paths again, even if the previous pass stopped part-way
    // through a burst because the meta window or buffer was full.
    lastSubflow = nullptr;
    remainingBurstBytes = 0;

    SubflowConnection *firstSubflow = nullptr;
    bool queuedOnRequester = false;
    std::vector<SubflowConnection *> activatedSubflows;

    // Linux keeps pushing pending MPTCP data while socket memory is
    // available. Dispatch complete 64 KiB bursts here instead of waiting for
    // one future pacing callback per MSS; otherwise every subflow becomes
    // scheduler-limited before it can fill its congestion window.
    while (true) {
        const uint32_t schedulableBytes = connection->getSegment(bytes);
        if (schedulableBytes == 0 ||
                (schedulableBytes < bytes && !connection->canSchedulePartialSegment(schedulableBytes)))
            break;

        SubflowConnection *subflow = selectDefaultSubflow(schedulableBytes);
        if (subflow == nullptr)
            break;

        subflow->enqueueScheduledData(schedulableBytes);
        consumeBurst(schedulableBytes);

        if (firstSubflow == nullptr)
            firstSubflow = subflow;
        if (subflow == requester)
            queuedOnRequester = true;
        else if (std::find(activatedSubflows.begin(), activatedSubflows.end(), subflow) ==
                activatedSubflows.end())
            activatedSubflows.push_back(subflow);
    }

    for (SubflowConnection *subflow : activatedSubflows)
        subflow->invokeSendCommand();

    return queuedOnRequester ? requester : firstSubflow;
}

SubflowConnection *MpTcpPacketScheduler::selectDefaultSubflow(uint32_t bytes)
{
    if (usesCwndBoundedScheduling())
        return selectCwndBoundedSubflow(bytes);

    if (lastSubflow != nullptr && remainingBurstBytes > 0 &&
            lastSubflow->canUseDefaultScheduler(bytes))
        return lastSubflow;

    SubflowConnection *bestSubflow = nullptr;
    double bestLingerTime = std::numeric_limits<double>::infinity();

    for (SubflowConnection *subflow : connection->getSubflows()) {
        if (subflow == nullptr || !subflow->isActiveForDefaultScheduler())
            continue;

        const double pacingRate = getAveragePacingRate(subflow);
        if (pacingRate <= 0.0)
            continue;

        const double lingerTime = static_cast<double>(subflow->getSchedulerQueuedBytes()) / pacingRate;
        if (bestSubflow == nullptr || lingerTime < bestLingerTime) {
            bestSubflow = subflow;
            bestLingerTime = lingerTime;
        }
    }

    // Linux chooses the lowest-linger active subflow first, then applies the
    // stream write-memory check to that selected subflow.
    if (bestSubflow == nullptr || !bestSubflow->canUseDefaultScheduler(bytes))
        return nullptr;

    const uint32_t queuedBytesBeforeEnqueue = bestSubflow->getSchedulerQueuedBytes();
    const double currentPacingRate = bestSubflow->getSchedulerPacingRateBytesPerSecond();
    startBurst(bestSubflow, queuedBytesBeforeEnqueue, currentPacingRate);

    EV_INFO << "MPTCP default scheduler selected subflow " << bestSubflow->getSocketId()
            << " with linger_time=" << bestLingerTime << "s\n";

    return bestSubflow;
}

SubflowConnection *MpTcpPacketScheduler::selectCwndBoundedSubflow(uint32_t bytes)
{
    // Recheck admission for every segment, including a cached burst. A window
    // reduction must never be bypassed by a previous scheduling decision.
    if (lastSubflow != nullptr && remainingBurstBytes >= bytes &&
            lastSubflow->isActiveForDefaultScheduler() &&
            getBoundedAssignmentSpace(lastSubflow, bytes) >= bytes)
        return lastSubflow;

    SubflowConnection *bestSubflow = nullptr;
    SubflowConnection *overdueSubflow = nullptr;
    double bestLingerTime = std::numeric_limits<double>::infinity();
    std::vector<SubflowConnection *> eligible;

    for (SubflowConnection *subflow : connection->getSubflows()) {
        if (subflow == nullptr)
            continue;

        if (!subflow->isActiveForDefaultScheduler() ||
                getBoundedAssignmentSpace(subflow, bytes) < bytes) {
            skippedCwndBursts.erase(subflow);
            continue;
        }

        const double pacingRate = getAveragePacingRate(subflow);
        if (pacingRate <= 0.0) {
            skippedCwndBursts.erase(subflow);
            continue;
        }

        eligible.push_back(subflow);
        const uint32_t skipped = skippedCwndBursts[subflow];
        const double lingerTime = static_cast<double>(subflow->getSchedulerQueuedBytes()) / pacingRate;
        // Keep the default queued-memory drain score. Break exact ties
        // with the path that has missed more selections.
        if (bestSubflow == nullptr || lingerTime < bestLingerTime ||
                (lingerTime == bestLingerTime && skipped > skippedCwndBursts[bestSubflow])) {
            bestSubflow = subflow;
            bestLingerTime = lingerTime;
        }
        if (skipped >= CWND_MAX_SKIPPED_BURSTS &&
                (overdueSubflow == nullptr || skipped > skippedCwndBursts[overdueSubflow]))
            overdueSubflow = subflow;
    }

    if (bestSubflow == nullptr)
        return nullptr;
    if (overdueSubflow != nullptr)
        bestSubflow = overdueSubflow;

    // Never require a full default-size burst: even a one-MSS window remains
    // usable. Round down to whole scheduling segments so a soft burst tail
    // cannot cross the cap. A permitted short final segment uses its own size.
    uint32_t burstLimit = std::min(std::max(DEFAULT_SEND_BURST_SIZE, bytes),
            getBoundedAssignmentSpace(bestSubflow, bytes));
    burstLimit -= burstLimit % bytes;
    if (overdueSubflow != nullptr)
        burstLimit = bytes;
    startBurst(bestSubflow, bestSubflow->getSchedulerQueuedBytes(),
            bestSubflow->getSchedulerPacingRateBytesPerSecond(), burstLimit);

    for (SubflowConnection *subflow : eligible) {
        uint32_t& skipped = skippedCwndBursts[subflow];
        if (subflow == bestSubflow)
            skipped = 0;
        else if (skipped < std::numeric_limits<uint32_t>::max())
            ++skipped;
    }

    EV_INFO << "MPTCP " << schedulingMode << " scheduler selected subflow " << bestSubflow->getSocketId()
            << " with burst=" << remainingBurstBytes
            << " bytes, fairness turn=" << (overdueSubflow != nullptr) << "\n";
    return bestSubflow;
}

double MpTcpPacketScheduler::getAveragePacingRate(SubflowConnection *subflow)
{
    auto it = avgPacingRates.find(subflow);
    if (it != avgPacingRates.end())
        return it->second;

    const double pacingRate = subflow->getSchedulerPacingRateBytesPerSecond();
    if (pacingRate > 0.0)
        avgPacingRates[subflow] = pacingRate;
    return pacingRate;
}

void MpTcpPacketScheduler::startBurst(SubflowConnection *subflow,
        uint32_t queuedBytesBeforeEnqueue, double currentPacingRate, uint32_t burstLimit)
{
    const uint32_t recoveryBytes = connection->getPendingRecoveryBytes();
    const uint32_t burst = recoveryBytes > 0 ? std::min(burstLimit, recoveryBytes) :
            std::min({burstLimit,
                    connection->getSendWindowRemaining(), connection->getSendBufferRemaining()});
    const double previousPacingRate = getAveragePacingRate(subflow);
    const uint32_t totalWeight = queuedBytesBeforeEnqueue + burst;

    if (currentPacingRate > 0.0 && totalWeight > 0)
        avgPacingRates[subflow] = (previousPacingRate * queuedBytesBeforeEnqueue + currentPacingRate * burst) / totalWeight;
    else if (currentPacingRate > 0.0)
        avgPacingRates[subflow] = currentPacingRate;

    lastSubflow = subflow;
    remainingBurstBytes = burst;
}

void MpTcpPacketScheduler::consumeBurst(uint32_t bytes)
{
    // Linux tests snd_burst after pushing a data fragment, so the limit is
    // soft: the final simulator segment may take the counter below one MSS.
    remainingBurstBytes = remainingBurstBytes > bytes ? remainingBurstBytes - bytes : 0;
}

} // namespace tcp
} // namespace inet

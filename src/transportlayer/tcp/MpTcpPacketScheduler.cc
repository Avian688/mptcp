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
#include <limits>

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
    if (schedulingMode != "lowestRtt" && schedulingMode != "directPull")
        schedulingMode = "default";

    lastSubflow = nullptr;
    remainingBurstBytes = 0;
}

bool MpTcpPacketScheduler::usesDirectPullMode() const
{
    return schedulingMode == "directPull";
}

bool MpTcpPacketScheduler::usesLowestRttScheduling() const
{
    return schedulingMode == "lowestRtt";
}

SubflowConnection *MpTcpPacketScheduler::schedulePacket(SubflowConnection *requester, uint32_t bytes)
{
    if (connection == nullptr || bytes == 0 || connection->getSegment(bytes) < bytes)
        return nullptr;

    if (usesLowestRttScheduling())
        return scheduleLowestRtt(requester, bytes);

    return scheduleDefault(requester, bytes);
}

SubflowConnection *MpTcpPacketScheduler::selectRetransmissionSubflow(SubflowConnection *source, uint32_t bytes) const
{
    if (connection == nullptr || bytes == 0)
        return nullptr;

    SubflowConnection *bestSubflow = nullptr;
    simtime_t bestRtt = SIMTIME_MAX;

    for (SubflowConnection *subflow : connection->getSubflows()) {
        if (subflow == nullptr || subflow == source || !subflow->canAcceptRetransmission(bytes))
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
}

void MpTcpPacketScheduler::forgetSubflow(SubflowConnection *subflow)
{
    if (subflow == nullptr)
        return;

    avgPacingRates.erase(subflow);
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
        if (bestSubflow == nullptr || candidateRtt < bestRtt ||
                (candidateRtt == bestRtt && subflow == requester))
        {
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
    if (lastSubflow != nullptr && remainingBurstBytes >= bytes &&
            lastSubflow->canUseDefaultScheduler(bytes))
    {
        const uint32_t queuedBytesBeforeEnqueue = lastSubflow->getSchedulerQueuedBytes();
        const double currentPacingRate = lastSubflow->getSchedulerPacingRateBytesPerSecond();
        lastSubflow->enqueueScheduledData(bytes);
        updateBurstState(lastSubflow, bytes, queuedBytesBeforeEnqueue, currentPacingRate);

        EV_INFO << "MPTCP default scheduler reusing subflow " << lastSubflow->getSocketId()
                << " with burst budget " << remainingBurstBytes << " bytes\n";

        if (lastSubflow != requester)
            lastSubflow->invokeSendCommand();

        return lastSubflow;
    }

    SubflowConnection *bestSubflow = nullptr;
    double bestLingerTime = std::numeric_limits<double>::infinity();

    for (SubflowConnection *subflow : connection->getSubflows()) {
        if (subflow == nullptr || !subflow->canUseDefaultScheduler(bytes))
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

    if (bestSubflow == nullptr)
        return nullptr;

    const uint32_t queuedBytesBeforeEnqueue = bestSubflow->getSchedulerQueuedBytes();
    const double currentPacingRate = bestSubflow->getSchedulerPacingRateBytesPerSecond();
    bestSubflow->enqueueScheduledData(bytes);
    updateBurstState(bestSubflow, bytes, queuedBytesBeforeEnqueue, currentPacingRate);

    EV_INFO << "MPTCP default scheduler selected subflow " << bestSubflow->getSocketId()
            << " with linger_time=" << bestLingerTime << "s\n";

    if (bestSubflow != requester)
        bestSubflow->invokeSendCommand();

    return bestSubflow;
}

double MpTcpPacketScheduler::getAveragePacingRate(SubflowConnection *subflow) const
{
    auto it = avgPacingRates.find(subflow);
    if (it != avgPacingRates.end())
        return it->second;

    return subflow->getSchedulerPacingRateBytesPerSecond();
}

void MpTcpPacketScheduler::updateBurstState(SubflowConnection *subflow, uint32_t bytes,
        uint32_t queuedBytesBeforeEnqueue, double currentPacingRate)
{
    const uint32_t burst = std::min(DEFAULT_SEND_BURST_SIZE, connection->getSendWindowRemaining());
    const double previousPacingRate = getAveragePacingRate(subflow);
    const uint32_t totalWeight = queuedBytesBeforeEnqueue + burst;

    if (currentPacingRate > 0.0 && totalWeight > 0)
        avgPacingRates[subflow] = (previousPacingRate * queuedBytesBeforeEnqueue + currentPacingRate * burst) / totalWeight;
    else if (currentPacingRate > 0.0)
        avgPacingRates[subflow] = currentPacingRate;

    lastSubflow = subflow;
    remainingBurstBytes = burst > bytes ? burst - bytes : 0;
}

} // namespace tcp
} // namespace inet

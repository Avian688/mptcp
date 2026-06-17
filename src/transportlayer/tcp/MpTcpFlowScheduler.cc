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

#include "MpTcpFlowScheduler.h"

#include <algorithm>
#include <string>

#include "MpTcpConnection.h"
#include "SubflowConnection.h"

namespace inet {
namespace tcp {

MpTcpFlowScheduler::MpTcpFlowScheduler(MpTcpConnection *connection) : connection(connection)
{
}

MpTcpFlowScheduler::~MpTcpFlowScheduler()
{
    cancelPendingSubflowCreations();
}

void MpTcpFlowScheduler::setConnection(MpTcpConnection *connection)
{
    this->connection = connection;
}

void MpTcpFlowScheduler::initialize(int subflowsMax, bool createAllSubflowsAtStart, const char *subflowStartTimes)
{
    cancelPendingSubflowCreations();
    this->subflowsMax = std::max(1, subflowsMax);
    this->createAllSubflowsAtStart = createAllSubflowsAtStart;
    initialSubflowsCreated = false;
    scheduledSubflows.clear();
    parseSubflowStartTimes(subflowStartTimes);
}

bool MpTcpFlowScheduler::shouldCreateAllSubflowsAtStart() const
{
    return createAllSubflowsAtStart;
}

bool MpTcpFlowScheduler::canCreateSubflow() const
{
    return connection != nullptr && static_cast<int>(scheduledSubflows.size()) < subflowsMax;
}

void MpTcpFlowScheduler::createInitialSubflows()
{
    if (connection == nullptr || initialSubflowsCreated)
        return;

    initialSubflowsCreated = true;

    const int initialSubflowCount = createAllSubflowsAtStart ? subflowsMax : 1;
    for (int slot = 0; slot < initialSubflowCount; ++slot) {
        if (connection->isActiveSide()) {
            const omnetpp::simtime_t offset = getSubflowStartOffset(slot);
            if (offset > SIMTIME_ZERO) {
                scheduleSubflowCreation(slot, offset);
                continue;
            }
        }

        createSubflow(slot);
    }
}

SubflowConnection *MpTcpFlowScheduler::createSubflow()
{
    const int slot = findNextAvailableSlot();
    if (slot < 0)
        return nullptr;

    return createSubflow(slot);
}

bool MpTcpFlowScheduler::closeSubflow(SubflowConnection *subflow)
{
    if (subflow == nullptr)
        return false;

    switch (subflow->getFsmState()) {
        case TCP_S_INIT:
        case TCP_S_LISTEN:
            return subflow->destroyFlow();

        case TCP_S_SYN_SENT:
        case TCP_S_SYN_RCVD:
            return subflow->abortFlow();

        case TCP_S_ESTABLISHED:
        case TCP_S_CLOSE_WAIT:
            return subflow->closeFlow();

        default:
            return false;
    }
}

void MpTcpFlowScheduler::closeAllSubflows(SubflowConnection *exceptSubflow)
{
    cancelPendingSubflowCreations();

    std::vector<SubflowConnection *> subflows;
    subflows.reserve(scheduledSubflows.size());
    for (const auto& entry : scheduledSubflows) {
        if (entry.second != nullptr && entry.second != exceptSubflow)
            subflows.push_back(entry.second);
    }

    for (SubflowConnection *subflow : subflows)
        closeSubflow(subflow);
}

void MpTcpFlowScheduler::subflowStateChanged(SubflowConnection *subflow, int oldState, int newState)
{
    if (subflow == nullptr || newState != TCP_S_CLOSED)
        return;

    for (auto it = scheduledSubflows.begin(); it != scheduledSubflows.end(); ++it) {
        if (it->second == subflow) {
            scheduledSubflows.erase(it);
            break;
        }
    }

    if (oldState == TCP_S_INIT)
        initialSubflowsCreated = !scheduledSubflows.empty();
}

bool MpTcpFlowScheduler::processTimer(omnetpp::cMessage *msg)
{
    if (msg == nullptr)
        return false;

    for (auto it = pendingSubflowTimers.begin(); it != pendingSubflowTimers.end(); ++it) {
        if (it->second == msg) {
            const int slot = it->first;

            if (slot > 0 && !isMasterSubflowEstablished()) {
                connection->scheduleAfter(omnetpp::SimTime(1, omnetpp::SIMTIME_MS), msg);
                return true;
            }

            pendingSubflowTimers.erase(it);
            createSubflow(slot);
            delete msg;
            return true;
        }
    }

    return false;
}

void MpTcpFlowScheduler::cancelPendingSubflowCreations()
{
    for (auto& entry : pendingSubflowTimers) {
        omnetpp::cMessage *timer = entry.second;
        if (timer == nullptr)
            continue;

        if (connection != nullptr && timer->isScheduled())
            connection->cancelEvent(timer);

        delete timer;
    }

    pendingSubflowTimers.clear();
}

int MpTcpFlowScheduler::findNextAvailableSlot() const
{
    for (int slot = 0; slot < subflowsMax; ++slot) {
        if (scheduledSubflows.find(slot) == scheduledSubflows.end())
            return slot;
    }

    return -1;
}

bool MpTcpFlowScheduler::isMasterSubflowEstablished() const
{
    auto it = scheduledSubflows.find(0);
    if (it == scheduledSubflows.end() || it->second == nullptr)
        return false;

    return it->second->getFsmState() == TCP_S_ESTABLISHED;
}

void MpTcpFlowScheduler::parseSubflowStartTimes(const char *subflowStartTimes)
{
    subflowStartOffsets.clear();

    if (subflowStartTimes == nullptr || *subflowStartTimes == '\0')
        return;

    omnetpp::cStringTokenizer tokenizer(subflowStartTimes);
    while (const char *token = tokenizer.nextToken())
        subflowStartOffsets.push_back(omnetpp::SimTime::parse(token));
}

omnetpp::simtime_t MpTcpFlowScheduler::getSubflowStartOffset(int slot) const
{
    if (slot < 0 || slot >= static_cast<int>(subflowStartOffsets.size()))
        return SIMTIME_ZERO;

    return subflowStartOffsets[slot];
}

void MpTcpFlowScheduler::scheduleSubflowCreation(int slot, omnetpp::simtime_t offset)
{
    if (connection == nullptr || pendingSubflowTimers.find(slot) != pendingSubflowTimers.end())
        return;

    std::string timerName = "MPTCP-SUBFLOW-START-" + std::to_string(slot);
    omnetpp::cMessage *timer = new omnetpp::cMessage(timerName.c_str());
    pendingSubflowTimers[slot] = timer;
    connection->scheduleAfter(offset, timer);
}

SubflowConnection *MpTcpFlowScheduler::createSubflow(int slot)
{
    if (connection == nullptr || slot < 0 || slot >= subflowsMax)
        return nullptr;

    if (scheduledSubflows.find(slot) != scheduledSubflows.end())
        return scheduledSubflows[slot];

    const int localPort = connection->getLocalPortNumber() + slot + 1;
    const bool isMaster = slot == 0;

    if (connection->isActiveSide()) {
        if (connection->getRemoteAddressForSubflows().isUnspecified() || connection->getRemotePortNumber() < 0)
            return nullptr;
    }

    SubflowConnection *subflow = connection->createManagedSubflow(isMaster);
    if (subflow == nullptr)
        return nullptr;

    bool opened = false;
    if (connection->isActiveSide()) {
        const int remotePort = connection->getRemotePortNumber() + slot + 1;
        const L3Address localAddress = connection->getLocalAddressForSubflow(slot);
        const L3Address remoteAddress = connection->getRemoteAddressForSubflow(slot);
        opened = subflow->openActive(localAddress,
                                     remoteAddress,
                                     localPort, remotePort);
    }
    else {
        const L3Address localAddress = connection->getLocalAddressForSubflow(slot);
        opened = subflow->openPassive(localAddress, localPort);
    }

    if (!opened)
        return nullptr;

    scheduledSubflows[slot] = subflow;
    return subflow;
}

} // namespace tcp
} // namespace inet

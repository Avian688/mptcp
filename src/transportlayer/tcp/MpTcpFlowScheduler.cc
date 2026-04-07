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

#include "MpTcpConnection.h"
#include "SubflowConnection.h"

namespace inet {
namespace tcp {

MpTcpFlowScheduler::MpTcpFlowScheduler(MpTcpConnection *connection) : connection(connection)
{
}

void MpTcpFlowScheduler::setConnection(MpTcpConnection *connection)
{
    this->connection = connection;
}

void MpTcpFlowScheduler::initialize(int subflowsMax, bool createAllSubflowsAtStart)
{
    this->subflowsMax = std::max(1, subflowsMax);
    this->createAllSubflowsAtStart = createAllSubflowsAtStart;
    initialSubflowsCreated = false;
    scheduledSubflows.clear();
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
    for (int slot = 0; slot < initialSubflowCount; ++slot)
        createSubflow(slot);
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

int MpTcpFlowScheduler::findNextAvailableSlot() const
{
    for (int slot = 0; slot < subflowsMax; ++slot) {
        if (scheduledSubflows.find(slot) == scheduledSubflows.end())
            return slot;
    }

    return -1;
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
        opened = subflow->openActive(connection->getLocalAddressForSubflows(),
                                     connection->getRemoteAddressForSubflows(),
                                     localPort, remotePort);
    }
    else {
        opened = subflow->openPassive(connection->getLocalAddressForSubflows(), localPort);
    }

    if (!opened)
        return nullptr;

    scheduledSubflows[slot] = subflow;
    return subflow;
}

} // namespace tcp
} // namespace inet

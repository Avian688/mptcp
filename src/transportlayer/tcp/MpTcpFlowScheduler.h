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

#ifndef TRANSPORTLAYER_TCP_MPTCPFLOWSCHEDULER_H_
#define TRANSPORTLAYER_TCP_MPTCPFLOWSCHEDULER_H_

#include <omnetpp.h>

#include <map>
#include <vector>

namespace inet {
namespace tcp {

class MpTcpConnection;
class SubflowConnection;

class MpTcpFlowScheduler
{
  public:
    explicit MpTcpFlowScheduler(MpTcpConnection *connection = nullptr);
    ~MpTcpFlowScheduler();

    void setConnection(MpTcpConnection *connection);

    void initialize(int subflowsMax, bool createAllSubflowsAtStart, const char *subflowStartTimes);

    bool shouldCreateAllSubflowsAtStart() const;

    bool canCreateSubflow() const;

    void createInitialSubflows();

    SubflowConnection *createSubflow();

    bool closeSubflow(SubflowConnection *subflow);

    void closeAllSubflows(SubflowConnection *exceptSubflow = nullptr);

    void subflowStateChanged(SubflowConnection *subflow, int oldState, int newState);

    bool processTimer(omnetpp::cMessage *msg);

    void cancelPendingSubflowCreations();

  protected:
    int findNextAvailableSlot() const;
    bool isMasterSubflowEstablished() const;

    SubflowConnection *createSubflow(int slot);

    void parseSubflowStartTimes(const char *subflowStartTimes);

    omnetpp::simtime_t getSubflowStartOffset(int slot) const;

    void scheduleSubflowCreation(int slot, omnetpp::simtime_t offset);

    MpTcpConnection *connection = nullptr;
    int subflowsMax = 1;
    bool createAllSubflowsAtStart = true;
    bool initialSubflowsCreated = false;
    std::map<int, SubflowConnection *> scheduledSubflows;
    std::map<int, omnetpp::cMessage *> pendingSubflowTimers;
    std::vector<omnetpp::simtime_t> subflowStartOffsets;
};

} // namespace tcp
} // namespace inet

#endif // TRANSPORTLAYER_TCP_MPTCPFLOWSCHEDULER_H_

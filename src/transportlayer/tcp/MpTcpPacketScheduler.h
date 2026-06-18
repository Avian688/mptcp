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

#ifndef TRANSPORTLAYER_TCP_MPTCPPACKETSCHEDULER_H_
#define TRANSPORTLAYER_TCP_MPTCPPACKETSCHEDULER_H_

#include <cstdint>
#include <map>
#include <string>

namespace inet {
namespace tcp {

class MpTcpConnection;
class SubflowConnection;

class MpTcpPacketScheduler
{
  public:
    explicit MpTcpPacketScheduler(MpTcpConnection *connection = nullptr);

    void setConnection(MpTcpConnection *connection);

    void setSchedulingMode(const char *mode);

    bool usesDirectPullMode() const;

    bool usesLowestRttScheduling() const;

    SubflowConnection *schedulePacket(SubflowConnection *requester, uint32_t bytes);

    SubflowConnection *selectRetransmissionSubflow(SubflowConnection *source, uint32_t bytes) const;

    void forgetSubflow(SubflowConnection *subflow);

  protected:
    static constexpr uint32_t DEFAULT_SEND_BURST_SIZE = 65428;

    SubflowConnection *scheduleDefault(SubflowConnection *requester, uint32_t bytes);

    SubflowConnection *scheduleLowestRtt(SubflowConnection *requester, uint32_t bytes);

    double getAveragePacingRate(SubflowConnection *subflow);

    void startBurst(SubflowConnection *subflow, uint32_t bytes,
                    uint32_t queuedBytesBeforeEnqueue, double currentPacingRate);

    void consumeBurst(uint32_t bytes);

    MpTcpConnection *connection = nullptr;
    std::string schedulingMode = "default";
    SubflowConnection *lastSubflow = nullptr;
    uint32_t remainingBurstBytes = 0;
    std::map<SubflowConnection *, double> avgPacingRates;
};

} // namespace tcp
} // namespace inet

#endif // TRANSPORTLAYER_TCP_MPTCPPACKETSCHEDULER_H_

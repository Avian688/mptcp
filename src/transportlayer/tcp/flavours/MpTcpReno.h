//
// Reno congestion control adapted to the paced MPTCP subflow connection.
//

#ifndef TRANSPORTLAYER_TCP_FLAVOURS_MPTCPRENO_H_
#define TRANSPORTLAYER_TCP_FLAVOURS_MPTCPRENO_H_

#include "MpTcpFamily.h"

namespace inet {
namespace tcp {

// TcpReno itself is not paced. This adapter keeps INET's Tahoe/Reno state and
// Reno control rules while retaining the TcpPacedFamily API required by MPTCP.
class INET_API MpTcpReno : public MpTcpFamily
{
  protected:
    static simsignal_t cwndSegSignal;
    static simsignal_t recoveryPointSignal;
    static simsignal_t sndUnaSignal;

    long double congestionAvoidanceAckCounter = 0.0L;
    bool wasCwndLimited = false;
    uint32_t maxBytesInFlightForCwnd = 0;
    uint32_t cwndUsageSeq = 0;

    virtual TcpStateVariables *createStateVariables() override
    {
        return new TcpTahoeRenoFamilyStateVariables();
    }

    virtual void increaseCongestionWindow();

    virtual void updatePacing();

    virtual void recordCwndUsage(bool cwndLimitedSample);

    virtual bool isConnectionCwndLimited();

    virtual void setRecoveryCongestionWindow() override;

  public:
    virtual void initialize() override;

    virtual void established(bool active) override;

    virtual void dataSent(uint32_t fromseq) override;

    virtual void recalculateSlowStartThreshold();

    virtual void processRexmitTimer(TcpEventCode& event) override;

    virtual void rackLossDetected() override;

    virtual void receivedDataAck(uint32_t firstSeqAcked) override;

    virtual void receivedDuplicateAck() override;
};

} // namespace tcp
} // namespace inet

#endif

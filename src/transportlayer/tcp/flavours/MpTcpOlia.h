//
// Opportunistic Linked Increases Algorithm for MPTCP.
//

#ifndef TRANSPORTLAYER_TCP_FLAVOURS_MPTCPOLIA_H_
#define TRANSPORTLAYER_TCP_FLAVOURS_MPTCPOLIA_H_

#include "MpTcpCoupled.h"

namespace inet {
namespace tcp {

class INET_API MpTcpOlia : public MpTcpCoupled
{
  protected:
    static simsignal_t epsilonSignal;

    uint32_t loss1 = 0;
    uint32_t loss2 = 0;
    uint32_t loss3 = 0;
    int epsilonNumerator = 0;
    uint32_t epsilonDenominator = 1;
    long double cwndAccumulator = 0.0L;

    virtual void increaseCongestionWindow() override;

    virtual void updateLossHistory();

  public:
    virtual void established(bool active) override;

    virtual void receivedDataAck(uint32_t firstSeqAcked) override;

    virtual void recalculateSlowStartThreshold() override;
};

} // namespace tcp
} // namespace inet

#endif

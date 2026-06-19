//
// Balanced Linked Adaptation congestion control for MPTCP.
//

#ifndef TRANSPORTLAYER_TCP_FLAVOURS_MPTCPBALIA_H_
#define TRANSPORTLAYER_TCP_FLAVOURS_MPTCPBALIA_H_

#include "MpTcpCoupled.h"

namespace inet {
namespace tcp {

class INET_API MpTcpBalia : public MpTcpCoupled
{
  protected:
    static simsignal_t additiveIncreaseSignal;
    static simsignal_t multiplicativeDecreaseSignal;

    long double ackCounter = 0.0L;

    virtual long double calculateAdditiveIncreaseThreshold() const;

    virtual long double calculateMultiplicativeDecrease() const;

    virtual void increaseCongestionWindow() override;

  public:
    virtual void recalculateSlowStartThreshold() override;
};

} // namespace tcp
} // namespace inet

#endif

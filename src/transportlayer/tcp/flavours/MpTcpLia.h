//
// Linked Increases Algorithm for MPTCP (RFC 6356).
//

#ifndef TRANSPORTLAYER_TCP_FLAVOURS_MPTCPLIA_H_
#define TRANSPORTLAYER_TCP_FLAVOURS_MPTCPLIA_H_

#include "MpTcpCoupled.h"

namespace inet {
namespace tcp {

class INET_API MpTcpLia : public MpTcpCoupled
{
  protected:
    static simsignal_t alphaSignal;

    long double cwndAccumulator = 0.0L;
    long double ackedPackets = 1.0L;

    virtual void increaseCongestionWindow() override;

  public:
    virtual void established(bool active) override;

    virtual void receivedDataAck(uint32_t firstSeqAcked) override;

    virtual void recalculateSlowStartThreshold() override;
};

} // namespace tcp
} // namespace inet

#endif

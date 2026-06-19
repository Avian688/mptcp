//
// Cross-subflow helpers shared by coupled MPTCP congestion controls.
//

#ifndef TRANSPORTLAYER_TCP_FLAVOURS_MPTCPCOUPLED_H_
#define TRANSPORTLAYER_TCP_FLAVOURS_MPTCPCOUPLED_H_

#include "MpTcpReno.h"

namespace inet {
namespace tcp {

class MpTcpConnection;
class SubflowConnection;

class INET_API MpTcpCoupled : public MpTcpReno
{
  protected:
    virtual void increaseCongestionWindow() override = 0;

    virtual MpTcpConnection *getMetaConnection() const;

    virtual bool isEligibleSubflow(const SubflowConnection *subflow) const;

    static long double getCwndInPackets(const TcpTahoeRenoFamilyStateVariables *subflowState);

    static long double getRttInSeconds(const TcpTahoeRenoFamilyStateVariables *subflowState);
};

} // namespace tcp
} // namespace inet

#endif

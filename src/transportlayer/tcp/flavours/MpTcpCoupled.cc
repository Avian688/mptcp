//
// Cross-subflow helpers shared by coupled MPTCP congestion controls.
//

#include "MpTcpCoupled.h"

#include "../MpTcpConnection.h"

namespace inet {
namespace tcp {

MpTcpConnection *MpTcpCoupled::getMetaConnection() const
{
    auto *subflow = dynamic_cast<SubflowConnection *>(conn);
    return subflow != nullptr ? subflow->getMetaConnection() : nullptr;
}

bool MpTcpCoupled::isEligibleSubflow(const SubflowConnection *subflow) const
{
    if (subflow == nullptr || subflow->getState() == nullptr)
        return false;

    const int tcpState = subflow->getFsmState();
    const auto *subflowState = static_cast<const TcpTahoeRenoFamilyStateVariables *>(
            subflow->getState());
    return (tcpState == TCP_S_ESTABLISHED || tcpState == TCP_S_CLOSE_WAIT) &&
            subflowState->snd_mss > 0 && getRttInSeconds(subflowState) > 0.0L;
}

long double MpTcpCoupled::getCwndInPackets(const TcpTahoeRenoFamilyStateVariables *subflowState)
{
    if (subflowState == nullptr || subflowState->snd_mss == 0)
        return 0.0L;
    return static_cast<long double>(subflowState->snd_cwnd) / subflowState->snd_mss;
}

long double MpTcpCoupled::getRttInSeconds(const TcpTahoeRenoFamilyStateVariables *subflowState)
{
    return subflowState != nullptr ? subflowState->srtt.dbl() : 0.0L;
}

} // namespace tcp
} // namespace inet

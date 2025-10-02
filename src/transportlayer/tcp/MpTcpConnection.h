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

#ifndef TRANSPORTLAYER_TCP_MPTCPCONNECTION_H_
#define TRANSPORTLAYER_TCP_MPTCPCONNECTION_H_

#include <queue>
#include <inet/common/INETUtils.h>
#include <inet/networklayer/common/EcnTag_m.h>
#include <inet/transportlayer/common/L4Tools.h>
#include <inet/networklayer/common/DscpTag_m.h>
#include <inet/networklayer/common/HopLimitTag_m.h>
#include <inet/networklayer/common/TosTag_m.h>
#include <inet/networklayer/common/L3AddressTag_m.h>
#include <inet/networklayer/contract/IL3AddressType.h>
#include <inet/common/socket/SocketMap.h>

#include "../../../../tcpPaced/src/transportlayer/tcp/TcpPacedConnection.h"
#include "SubflowConnection.h"
namespace inet {
namespace tcp {

class MpTcpConnection : public TcpPacedConnection {
public:
    typedef std::vector<SubflowConnection*> SubflowList;

    MpTcpConnection();
    virtual ~MpTcpConnection();

protected:
    typedef enum {
        Established, /* contains ESTABLISHED/CLOSE_WAIT */
        Syn,         /**< Composed of SYN_RCVD, SYN_SENT */
        Close,       /**< CLOSE_WAIT, FIN_WAIT */
        mptcp_state_count  // sentinel: number of states
    } mptcp_states_t;

    SubflowList m_subflows[mptcp_state_count];

    virtual void process_OPEN_ACTIVE(TcpEventCode& event, TcpCommand *tcpCommand, cMessage *msg) override;

    virtual void addSubflow(bool isMaster);
};

}
}

#endif /* TRANSPORTLAYER_BBR_BBRCONNECTION_H_ */

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

#ifndef TRANSPORTLAYER_TCP_MPTCP_H_
#define TRANSPORTLAYER_TCP_MPTCP_H_

#include <inet/transportlayer/tcp/TcpConnection.h>
#include "../../../../tcpPaced/src/transportlayer/tcp/TcpPaced.h"
#include "MpTcpConnection.h"

namespace inet {
namespace tcp {

class MpTcp : public TcpPaced {
public:
    MpTcp();
    virtual ~MpTcp();

    virtual MpTcpConnection* getMetaConnection();
protected:

    virtual void initialize(int stage) override;

    /** Factory method; may be overriden for customizing Tcp */
    virtual TcpConnection* createConnection(int socketId) override;

    virtual TcpConnection* createSubflowConnection(int socketId, L3Address src, L3Address dest, int srcPort, int destPort);

    virtual void handleUpperCommand(cMessage *message) override;

    int mainSocketId;
    bool baseConnectionStarted;

    bool masterCreated;

};

} // namespace tcp
} // namespace inet

#endif /* TRANSPORTLAYER_BBR_BBR_H_ */

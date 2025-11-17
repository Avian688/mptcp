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

#ifndef TRANSPORTLAYER_TCP_MPTCPCONNECTIONBASE_H_
#define TRANSPORTLAYER_TCP_MPTCPCONNECTIONBASE_H_

#include <inet/transportlayer/tcp/TcpSendQueue.h>
#include <inet/transportlayer/tcp/TcpAlgorithm.h>
#include <inet/transportlayer/tcp/TcpReceiveQueue.h>
#include <inet/transportlayer/tcp/TcpSackRexmitQueue.h>
#include "../../../../tcpPaced/src/transportlayer/tcp/TcpPacedConnection.h"

namespace inet {
namespace tcp {

/**
 * Base class for all MPTCP-related TCP connections.
 *
 * MpTcpConnection (meta connection) and SubflowConnection
 * both inherit from this to allow congestion control
 * algorithms and scheduling code to treat them uniformly
 * while still identifying whether they represent the meta
 * or a subflow connection.
 */
class MpTcpConnectionBase : public TcpPacedConnection
{
  public:
    MpTcpConnectionBase();
    virtual ~MpTcpConnectionBase();

    /** Returns true for the meta MpTcpConnection, false for subflows. */
    virtual bool isMeta() const;

  protected:

    /** Utility: creates send/receive queues and tcpAlgorithm */
    virtual void initConnection(TcpOpenCommand *openCmd) override;
};

} // namespace tcp
} // namespace inet

#endif // TRANSPORTLAYER_TCP_MPTCPCONNECTIONBASE_H_

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

#include "inet/common/socket/SocketTag_m.h"
#include "TcpOpenSubflowCommand_m.h"
#include <inet/networklayer/ipv4/Ipv4Header_m.h>

#include "MpTcp.h"
namespace inet {
namespace tcp {

Define_Module(MpTcp);

MpTcp::MpTcp() {
    // TODO Auto-generated constructor stub

}

MpTcp::~MpTcp() {
    // TODO Auto-generated destructor stub
}

void MpTcp::initialize(int stage)
{
    Tcp::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        baseConnectionStarted = false;
        mainSocketId = -1;
    }
}

void MpTcp::handleUpperCommand(cMessage *msg)
{
    int socketId = check_and_cast<ITaggedObject *>(msg)->getTags().getTag<SocketReq>()->getSocketId();
    TcpConnection *conn = findConnForApp(socketId);

    if (!conn) {
        if(!baseConnectionStarted){
            conn = createConnection(socketId); //Creating Meta Socket
        }
        else{
            MpTcpConnection *metaConn = getMetaConnection();
            conn = createSubflowConnection(socketId, metaConn, metaConn != nullptr && metaConn->getSubflows().empty());
        }

        // add into appConnMap here; it'll be added to connMap during processing
        // the OPEN command in TcpConnection's processAppCommand().
        tcpAppConnMap[socketId] = conn;

        EV_INFO << "Tcp connection created for " << msg << "\n";
    }

    if (!conn->processAppCommand(msg)){
        std::cout << "\n REMOVING CONNECTION: " << conn->getClassAndFullName() << endl;
        std::cout << "\n MSG: " << msg->str() << endl;
        removeConnection(conn);
    }
}

TcpConnection* MpTcp::createConnection(int socketId)
{
    baseConnectionStarted = true;
    auto moduleType = cModuleType::get("mptcp.transportlayer.tcp.MpTcpConnection");
    char submoduleName[24];
    sprintf(submoduleName, "conn-%d", socketId);
    auto module = check_and_cast<TcpConnection*>(moduleType->createScheduleInit(submoduleName, this));
    module->initConnection(this, socketId);
    mainSocketId = socketId;
    return module;
}

SubflowConnection* MpTcp::createSubflowConnection(int socketId, MpTcpConnection *metaConn, bool isMaster)
{
    auto moduleType = cModuleType::get("mptcp.transportlayer.tcp.SubflowConnection");
    char submoduleName[24];
    sprintf(submoduleName, "conn-%d", socketId);
    auto module = check_and_cast<SubflowConnection*>(moduleType->createScheduleInit(submoduleName, this));
    module->initSubflowConnection(this, socketId, metaConn, isMaster);
    tcpAppConnMap[socketId] = module;
    return module;
}

SubflowConnection* MpTcp::createManagedSubflowConnection(MpTcpConnection *metaConn, bool isMaster)
{
    return createSubflowConnection(getEnvir()->getUniqueNumber(), metaConn, isMaster);
}

MpTcpConnection* MpTcp::getMetaConnection()
{
 return check_and_cast<MpTcpConnection*>(tcpAppConnMap[mainSocketId]);
}

}
}

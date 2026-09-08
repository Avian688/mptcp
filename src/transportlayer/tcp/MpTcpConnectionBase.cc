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

#include "MpTcpConnectionBase.h"

#include <string>

namespace inet {
namespace tcp {

Define_Module(MpTcpConnectionBase);

MpTcpConnectionBase::MpTcpConnectionBase() {
    // TODO Auto-generated constructor stub

}

MpTcpConnectionBase::~MpTcpConnectionBase() {
    // TODO Auto-generated destructor stub
}

void MpTcpConnectionBase::initConnection(TcpOpenCommand *openCmd)
{
    const char *configuredAlgorithm = openCmd->getTcpAlgorithmClass();
    std::string tcpAlgorithmClass;
    if (opp_isempty(configuredAlgorithm))
        tcpAlgorithmClass = tcpMain->par("tcpAlgorithmClass").stringValue();
    else
        tcpAlgorithmClass = configuredAlgorithm;

    if (tcpAlgorithmClass == "MpTcpMetaCubic" && !this->isMeta()) {
        tcpAlgorithmClass = "MpTcpSubflowCubic";
    }
    else if (tcpAlgorithmClass == "MpTcpLia" && this->isMeta()) {
        tcpAlgorithmClass = "MpTcpMetaCubic";
    }
    else if (tcpAlgorithmClass == "MpTcpOlia" && this->isMeta()) {
        tcpAlgorithmClass = "MpTcpMetaCubic";
    }
    else if (tcpAlgorithmClass == "MpTcpBalia" && this->isMeta()) {
        tcpAlgorithmClass = "MpTcpMetaCubic";
    }
    else if (tcpAlgorithmClass == "MpTcpReno" && this->isMeta()) {
        tcpAlgorithmClass = "MpTcpMetaCubic";
    }

    // Keep MPTCP's meta/subflow algorithm mapping, then let tcpPaced own all
    // queue, state, RACK, PRR, pacing, and accounting initialization.
    openCmd->setTcpAlgorithmClass(tcpAlgorithmClass.c_str());
    TcpPacedConnection::initConnection(openCmd);

    if (openCmd->getUserId() > 0)
        state->sendQueueLimit = openCmd->getUserId();
    else if (tcpMain != nullptr && tcpMain->hasPar("sendQueueLimit"))
        state->sendQueueLimit = tcpMain->par("sendQueueLimit").intValue();

    // tcpPaced records receive goodput on cloned passive sockets. MPTCP does
    // not use that clone path, so start the same timer on each real subflow.
    if (!isMeta() && !throughputTimer->isScheduled())
        scheduleAt(simTime() + throughputInterval, throughputTimer);
}

bool MpTcpConnectionBase::isMeta() const
{
    return false;
}

}
}

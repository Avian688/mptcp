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

package mptcp.transportlayer.tcp;

import tcppaced.transportlayer.tcp.TcpPacedConnection;

simple MpTcpConnection extends TcpPacedConnection
{
    parameters:
        @class("inet::tcp::MpTcpConnection");
        int numberOfSubflows = default(1);
        bool startAllSubflowsAtBeginning = default(true);
        string schedulerMode = default("default");
        string subflowStartTimes = default("");

        @signal[holBlockedBytes];
        @statistic[holBlockedBytes](record=vector; interpolationmode=sample-hold);
        @signal[metaExpectedDsn];      // next meta-level DSN the receiver is waiting for
        @signal[metaArrivedDsnStart];  // DSN start of the chunk that just arrived at the meta receiver
        @signal[metaDsnGapBytes];      // arrived DSN start minus expected DSN when the arrival is ahead
        @signal[metaReinjectedBytes];  // cumulative bytes retransmitted at the MPTCP data level
        @signal[metaReinjections];     // cumulative MPTCP data-level retransmission count
        @statistic[metaExpectedDsn](record=vector; interpolationmode=sample-hold);
        @statistic[metaArrivedDsnStart](record=vector; interpolationmode=sample-hold);
        @statistic[metaDsnGapBytes](record=vector; interpolationmode=sample-hold);
        @statistic[metaReinjectedBytes](record=vector; interpolationmode=sample-hold);
        @statistic[metaReinjections](record=vector; interpolationmode=sample-hold);
        
}

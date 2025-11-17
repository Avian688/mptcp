//
// Copyright (C) 2004 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package mptcp.applications.tcpapp;

import inet.applications.tcpapp.TcpSinkApp;
//
// Accepts any number of incoming MPTCP connections, and discards whatever
// arrives on them. Compatible with both ~Ipv4 and ~Ipv6.
//
module MpTcpSinkApp extends TcpSinkApp
{
	parameters:
        @class(inet::MpTcpSinkApp);
}



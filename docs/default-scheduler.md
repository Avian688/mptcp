# Default scheduler: upstream comparison

Reviewed on 2026-09-11 against Linux mainline commit
`08df884136f1c1197bab2a27814404fd329d9aac` (2026-09-10).
MPORB inherits this scheduler and transport recovery from MPTCP.

Sources:

- [Scheduling and retransmission](https://github.com/torvalds/linux/blob/08df884136f1c1197bab2a27814404fd329d9aac/net/mptcp/protocol.c):
  `mptcp_subflow_get_send`, `__mptcp_push_pending`,
  `mptcp_subflow_get_retrans`, `__mptcp_retransmit_pending_data`,
  `__mptcp_retrans`, `mptcp_timeout_from_subflow`.
- [Stale-path recovery](https://github.com/torvalds/linux/blob/08df884136f1c1197bab2a27814404fd329d9aac/net/mptcp/pm.c):
  `mptcp_pm_chk_stale`, `mptcp_pm_subflow_chk_stale`.
- [Write-memory admission](https://github.com/torvalds/linux/blob/08df884136f1c1197bab2a27814404fd329d9aac/include/net/sock.h):
  `__sk_stream_memory_free`.

## Policy retained

The default ranks active subflows by queued TCP bytes divided by their
weighted average pacing rate. Queued bytes include both unsent and TCP-unacked
data. It selects the smallest drain time, then checks that selected subflow's
write space. It does not fall back to a worse-ranked path merely because the
best path has no write space, and does not use a minimum-RTT ranking.
TCP subsequently enforces cwnd/rwnd when transmitting admitted bytes.

The send burst is 65,428 bytes, with the final simulator segment allowed to
cross the soft burst boundary. Burst accounting is local to a push pass;
an ACK or pacing callback starting a later pass ranks the paths afresh.

## Corrections

- Stale-path and non-master subflow-close recovery requeue the entire outstanding
  DSN range through normal scheduling, including assigned but unsent TCP data.
  Busy writable subflows can carry this recovery; an idle subflow is not required.
- Recovery has a persistent cursor. Lack of subflow write space pauses it;
  later ACKs or the meta retransmission timer retry it. DATA_ACK advancement
  skips already acknowledged recovery bytes.
- Reassigning a DSN preserves its payload and does not advance the connection's
  new-data high-water mark or consume the meta window/send budget a second time.
  It works with a full meta buffer and with application `sendingEnabled=false`.
- Ordinary timer reinjection still selects idle transports, including an idle
  stale transport. Actual fragment size is bounded after selection, so a large
  outstanding range cannot disqualify a usable transport. The timer can repair
  successive fragments through multiple idle transports in the same pass.
- Staleness is checked once per meta timeout, separately from target selection.
  The timer retries pending scheduling even when no idle reinjection target exists.
- A positive remaining TCP retransmission timeout is used as-is; the 200 ms
  fallback applies only when no eligible pending TCP timer supplies a delay.
- Unpaced TCP uses its current RTT/window to estimate a scheduling rate, rather
  than exposing the simulator's bootstrap pacing interval after the first ACK.
- Application SEND invokes meta scheduling directly, including while the
  master is congested. A subflow becoming established wakes scheduling after
  its FSM transition; its earlier `established()` callback is still in SYN state.
- The default scheduler's unpaced TCP adapter drains the available send window
  on a push, rather than sending one segment and waiting for its ACK. Paced
  MPORB continues to obey its pacing timer.

## Experiment 2 interpretation

With eight equal 100 Mbps paths, A uses shared paths 1-4, B uses shared paths
1-2 and private paths 5-6, and C uses shared paths 3-4 and private paths 7-8.
An idealized uncoupled per-subflow equal-share allocation is A=200, B=300,
C=300 Mbps before transport overhead. The private paths are already full.
Connection-level proportional fairness instead gives 266.67 Mbps each;
that requires coupled congestion control and is not a default-scheduler promise.

Experiment 2's generator and plot capacity now match the existing 100 Mbps
topology. The stated one-BDP buffers are 346 packets at 40 ms RTT and 1448-byte
MSS, and the generated initial ssthresh is 173 MSS. MPORB currently overrides
its initial ssthresh in `MpOrbUncoupled::established()`; this transport review
does not change that CCA startup rule. Earlier 30 Mbps reports and 104-packet
input files should not be treated as the updated experiment configuration.

`metaReinjectedBytes` includes both timer reinjection and failover reassignment.
`metaReinjections` counts enqueue operations, whose sizes differ between these
paths; it is not a count of path failures or TCP retransmissions on the wire.

## Fidelity and verification limits

This is a simulator adaptation for ordinary non-backup subflows. It does not
model Linux skb truesize/GSO/page-fragment accounting, send-buffer autotuning,
backup flags, shared receive-window signalling, or kernel workqueue timing
exactly. Configured byte limits stand in for socket memory limits. The meta
connection still uses its configured receive-buffer contract; master-subflow
closure still follows the existing simulator connection-lifetime model.

Linux's default mitigates HoL through drain-time selection and recovery; it does
not guarantee zero HoL. A slow path receiving ACKs need not become stale, and
previously assigned data can still block in-order delivery. No RTT penalty,
Alpha coupling change, or separate BLEST/ECF policy was added.

Validation performed: C++ syntax checks against the local OMNeT++/INET headers
and `git diff --check`. Experiment 2 generation was checked across all 10 INIs
and 50 configurations, preserving seeds, start times and protocol selection.
Python syntax was checked; plots were not rendered. No libraries were built
and no simulations were run.
Runtime regression cases to check after rebuilding:

| Case | Required observation |
| --- | --- |
| Meta window fills mid-burst; relative path drain times then change | Next push chooses the current lowest-drain path |
| One path stops receiving; another has TCP data outstanding but write space | Stale-path recovery queues old DSNs on the usable path |
| All alternatives temporarily fill their write buffers | Recovery resumes when space returns, without assigning new DSNs first |
| Path closes with DSNs assigned but not transmitted | Those DSNs remain recoverable through the surviving paths |
| DATA_ACK advances during paused recovery, including across 32-bit wrap | Resume at the first still-unacknowledged DSN |
| Meta buffer is full or application sending is stopped | Recovery remains eligible; fresh application data obeys the existing gates |
| Idle target has less write space than the total outstanding DSN range | A bounded reinjection fragment is admitted |
| New application SEND while only an alternative path can send | Meta scheduling immediately considers the alternative |
| A new subflow completes its handshake while another path is blocked | Scheduler is woken after the new path becomes eligible |
| Default mode with pacing disabled and several MSS of cwnd available | A push transmits multiple segments up to the TCP window |
| Unequal RTT paths with continued ACK progress | Assess residual HoL; do not expect stale-path logic to disable the slower path |

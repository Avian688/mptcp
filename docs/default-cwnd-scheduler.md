# Cwnd-bounded default scheduler

Select the new mode on the meta connection (also inherited by MPORB):

```ini
**.tcp.*.schedulerMode = "defaultCwnd"
```

Place this before any more-specific or earlier wildcard setting that assigns
`schedulerMode`. The existing `default`, `lowestRtt`, and `directPull` modes
remain available; the default configuration is still `default`.

## Admission and bursts

`defaultCwnd` keeps the default scheduler's ranking:

```
score = (unsent bytes + TCP-unacknowledged bytes) / average pacing rate
```

It first excludes paths that cannot accept the next scheduling segment. For
each active path, the remaining admission space is:

```
space = max(0, min(cwnd, advertised TCP window, write limit) - queued bytes)
```

`queued bytes` already includes both unsent and TCP-unacknowledged data; adding
bytes in flight again would double-count it. This is deliberately conservative
during SACK recovery: cumulatively unacknowledged queue contents stay charged.

The selected burst is capped to that space and the usual 65,428-byte target,
rounded down to whole scheduling segments. A single segment larger than the
target is still allowed if it fits the window. Meta send-buffer/receive-window
limits, application data availability and permitted final partial segments
remain enforced. Admission is rechecked before every segment, including inside
a cached burst. There is no soft overshoot of the window limit.

A full 64 KiB window is **not** required: a two-MSS window can receive two MSS,
and a one-MSS window can receive one MSS. A full low-score path is skipped so
another eligible path can be selected. Once all paths are full, scheduling
waits for the existing ACK/pacing/application/recovery events.

## Avoiding scheduler starvation

Among equal scores, the path that has missed more burst selections wins. In
addition, after 16 missed eligible burst selections, a path becomes overdue.
The most overdue path gets one scheduling segment, even if another path has a
lower score. The segment still has to fit its cwnd, receive window and write
space. Its missed-selection counter is then reset. Ineligible paths lose their
counter, and closed paths are removed from scheduler state.

This protects continuously eligible paths even when scores never tie. For a
fixed set of N eligible paths, an overdue path is served within at most N more
burst selections, assuming pending data and connection-level space persist.
It is an opportunity bound, not a wall-clock timer or a minimum throughput
guarantee. Empty application queues, full meta buffers, zero receive windows,
stale paths and windows smaller than the next permitted segment do not qualify.
The mechanism uses ordinary data, so a fairness turn can still cause reordering.

## Recovery and wakeups

Failover reassignment uses the same bounded normal scheduling path. Timer
reinjection retains the default idle-transport selection rule (including its
ability to try an idle stale transport), but the variant checks available window
space and caps the recovery fragment to it. An idle path with no space is skipped
rather than preventing another idle path from repairing the data. A short
recovery tail is checked at its actual size.

The subflow send path retries scheduling after TCP ACK processing has freed an
empty queue. This matters for unpaced one-MSS windows: connection-level DATA_ACK
processing can run before the subflow's TCP ACK frees that last MSS. Existing
pacing and TCP recovery continue to control actual transmission.

## Scope and validation

This is a new simulator policy, not an assertion about the Linux default.
There are no CCA, RTT-ranking, route prediction or handover changes. An empty
slow path still has a zero score; the change limits the amount assigned to it.
Data already queued when cwnd shrinks is not removed or reassigned by this check.
Consequently it cannot guarantee zero HoL or repair every pre-existing stall.

Source validation uses C++ syntax checks and NED validation. The simulation
libraries and experiments must be rebuilt/run separately before making runtime
claims. Useful regression cases are:

| Case | Required observation |
| --- | --- |
| Empty path with cwnd = 2 MSS | At most 2 MSS queued, not a default-sized burst |
| Outstanding 1 MSS and unsent 1 MSS, cwnd = 2 MSS | No additional assignment |
| Window fills on the best-score path | Next eligible path can be selected |
| Non-MSS-aligned available window | No partial packet merely to fill the leftover space |
| Cwnd falls below existing queued bytes | No new assignment until space returns |
| Eligible high-score path repeatedly passed over | One-segment turn after aging, still within its window |
| All paths are full or stale | Return without spinning or forcing traffic |
| TCP ACK frees an unpaced one-MSS window | New assignment resumes after the ACK |
| Idle tiny-window reinjection target | Recovery fragment also fits the window |
| Short final recovery range | Selection uses its actual size |
| Mode reset or subflow removal | No stale fairness state is retained |


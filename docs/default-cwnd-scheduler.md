# defaultCwnd scheduler

Select this scheduler on the connection module:

```ini
**.tcp.conn-*.schedulerMode = "defaultCwnd"
```

It keeps the default queued-bytes / average-pacing-rate ranking and burst
bookkeeping. The current variant uses a **burst-only** cwnd cap, shared with
MpORB's `intInformed` through `MpTcpPacketScheduler::getBoundedAssignmentSpace()`:

```text
writeSpace = max(0, writeLimit - queuedBytes)
cap = min(max(cwnd, MSS), writeSpace)
burst = min(defaultBurst, cap), rounded down to scheduling segments
```

The usual burst target is 65,428 bytes. `queuedBytes` includes unsent bytes and
retained TCP-unacknowledged bytes. Those bytes consume write memory but are not
subtracted from cwnd for this cap. It is not a cumulative backlog bound: repeated
selections may queue more than one cwnd. For example, a one-MSS cwnd permits a
one-MSS burst on each selection while write memory remains available.

TCP still enforces its actual cwnd and advertised receive window on transmission.
Connection-level send-window and send-buffer checks remain in the shared push
path. The scheduler rechecks the cap/write memory within cached bursts. Its
starvation turn requests one segment, still subject to admission. The threshold
is the compiled `CWND_MAX_SKIPPED_BURSTS`, not a time-based probing guarantee.

Timer reinjection retains the idle-target rule and uses the shared burst cap.
Queued data is not removed when cwnd shrinks. The bounded-scheduler empty-queue
refill path remains enabled. `lowestRtt` retains its separate admission policy.

This is a simulator extension to the default scheduler, not a claim of exact
upstream Linux scheduling behaviour. Earlier versions of this variant subtracted
unsent and unacknowledged bytes from cwnd; that cumulative restriction has been
removed at the user's request for both `defaultCwnd` and `intInformed`.

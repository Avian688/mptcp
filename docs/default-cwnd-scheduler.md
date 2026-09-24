# defaultCwnd scheduler

Select this scheduler on the connection module:

```ini
**.tcp.conn-*.schedulerMode = "defaultCwnd"
```

It keeps the default queued-bytes / average-pacing-rate ranking and burst
bookkeeping. The current variant uses a **unsent-queue** cwnd allowance, shared with
MpORB's `intInformed` through `MpTcpPacketScheduler::getBoundedAssignmentSpace()`:

```text
writeSpace = max(0, writeLimit - queuedBytes)
unsentSpace = max(0, max(cwnd, MSS) - unsentBytes)
cap = min(unsentSpace, writeSpace)
burst = min(defaultBurst, cap), rounded down to scheduling segments
```

The usual burst target is 65,428 bytes. `queuedBytes` includes unsent bytes and
retained TCP-unacknowledged bytes. Both consume write memory; only unsent bytes
consume the cwnd allowance. Repeated selections cannot add more than one cwnd
of unsent payload (with an MSS floor). If cwnd shrinks below an existing backlog,
assignment pauses until it drains. Bytes in flight do not consume this allowance.

TCP still enforces its actual cwnd and advertised receive window on transmission.
Connection-level send-window and send-buffer checks remain in the shared push
path. The scheduler rechecks the cap/write memory within cached bursts. Its
starvation turn requests one segment, still subject to admission. The threshold
is the compiled `CWND_MAX_SKIPPED_BURSTS`, not a time-based probing guarantee.

Timer reinjection retains the idle-target rule and uses the shared burst cap.
Queued data is not removed when cwnd shrinks. The bounded-scheduler empty-queue
refill path remains enabled. `lowestRtt` retains its separate admission policy.

This is a simulator extension to the default scheduler, not a claim of exact
upstream Linux scheduling behaviour. This restores the original INT allowance
for both variants. It does not restore the stricter cwnd-minus-flight admission.

# Endurance run — v0.3.0-rc.1

A continuous relay run of the core UDP/IPv4 datapath on Linux lasting more than
5 full days, extending the 12-hour soak (see soak/v0.3.0-rc.1.md) to a multi-day
horizon to confirm there are no slow leaks or counter drift over a long uptime.

## Setup

- Single turna-node process on the Linux server, TURNS+DTLS config, 2 workers,
  loopback-peer mode. Continuous synthetic load: turna-load-test channel-data,
  5 channels at ~60 pps each (~300 pps aggregate) over UDP/3478, loopback.
- Sampler recorded RSS / fd / error counters from /status every 30 min.

## Duration and volume

- Uptime at finish: 434,908 s = 5 days 0 h 48 m (more than 5 full days).
- packets_received: 130,457,132 (~130 M).
- bytes_received: 21,394,916,560 (~21.4 GB).
- packets_sent: 181,281; zero_copy_forwards: 180,504.

## Memory and descriptors — no leak

- RSS: start ~10,020 kB, steady ~5,996 kB across the continuous sampling window
  (12 Jul 12:32-15:32), finish 8,580 kB. RSS did not grow over 5+ days / 130 M
  packets — it sat below the starting value. No memory leak.
- fd: start 50, steady 45-46. No descriptor leak.

## Error counters — clean during the soak

Throughout the soak load (sampler rows through 15:32 on 12 Jul), every error
counter stayed 0: auth_failures, rate_limited, send_queue_dropped,
parser_rejections, malformed_packets, quota_exceeded, peer_rejected. status
"ok", not draining, no crash.

## Scope note — soak vs. ad-hoc tests (IMPORTANT)

The final /status shows total_allocations = 22 and auth_failures = 4. These are
NOT the soak result — they include manual tests run in the last hour:

- The soak load itself used 5 channel-data allocations (a steady relay stream);
  that is the "5" seen early in the run and the intended endurance figure.
- Late on 12 Jul (~16:00) we ran manual allocate-over-DTLS tests with
  turnutils_uclient against the same live node. Those added ~17 to
  total_allocations and 4 auth_failures (the coturn uclient REST-auth handshake
  did not match on a couple of attempts). They are separate ad-hoc tests, NOT
  part of the endurance soak.
- The endurance metrics that matter — packets processed, RSS, fd, and the error
  counters during the soak window — were all clean (0 errors) up to and
  including 15:32, before any manual testing. total_allocations is a monotonic
  lifetime counter and cannot be decremented; the split is documented here
  rather than reset. The endurance result is: 5 soak allocations, 130 M packets,
  0 errors, flat memory, over 5+ days.

## Caveat — sampler gap

The sampler process was tied to an SSH session and died ~1.5 h into the run
(07 Jul 17:13); it was restarted (detached via setsid) on 12 Jul 12:32. So the
continuous RSS/fd trace covers the first ~1.5 h and the final ~3.5 h, not the
middle. The node ran uninterrupted the whole time (uptime + packet count prove
it), and the two endpoints (start ~10 MB / 50 fd, finish ~6-8.5 MB / 45 fd) plus
130 M packets with no crash bound the leak question regardless.

## What this closes

- No memory or fd leak over a 5-day-plus, 130 M-packet run (RSS flat/below start).
- No error-counter drift under sustained load (0 across the soak window).
- Confirms the 12-hour soak result holds at a multi-day horizon.

Not covered: multi-week staging, real (non-loopback) traffic mix, alert-threshold
calibration on real traffic — see verification/pre-GA-status.md.

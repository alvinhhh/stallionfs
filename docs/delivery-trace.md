# Delivery diagnostics

`STALLION_MOUNT_TRACE` enables the separate `SMD1` channel, emitted by the
StallionFS process with subsystem `com.alvinhhh.stallionfs.delivery` and category
`delivery-v1`. SMT1 and SMA1 formats, counters and decoders are unchanged.
Without that build flag, this channel and its storage are absent. Test capture
and reset methods additionally require `STALLION_ADAPTER_CHECK`.

Each row starts with `SMD1 l=<lane> q=<reservation>`. Decimal scalars are used
except `f`, which is unsigned hexadecimal preserving the raw sync flag bits.
Error pairs are `domain,code`: domain 0 = no error, 1 = POSIX, 2 = other.
Domain names, descriptions, paths, file names, contents, credentials and caller
identities are never included. `vol` is a process-local numeric volume ID from
an independent allocator; it remains available after SMT1 reaches its cap.

- Lane 1: first retained delivery failure for a volume. Fields: `vol`, `site`
  (source line calling the first-error recorder), `origin` (enqueue or mutation
  caller source line when available; otherwise zero), `err` (original error
  pair), `x`/`p`/`e` (status/phase/errno of the **supplied retained receipt**).
  That receipt may come from an earlier operation or be zero/default. Nonzero
  fields never establish freshness or causation for this first delivery error;
  a zero receipt does not establish that a core operation was attempted.
  Source lines must be interpreted against the exact compiled source. The
  retained error's existing POSIX reconstruction behavior is unchanged.
- Lane 2: synchronize success. Lane 3: synchronize error. Fields: `vol`, `s`
  (1 = enqueue refusal, 2 = admitted body), `k` (last own check reached:
  0 = skipped, 1 = ready, 2 = core information, 3 = active transaction guard),
  `f` (raw flags), `v` (validation), `a` (enqueue error before sticky override),
  `r` (retained delivery error), `b` (preexisting volume error), `c` (own check
  error), `h` (final delivery recheck), `out` (reply error). Unobserved stages
  have zero error pairs. At enqueue, `a` includes validation when it takes
  precedence over admission. These rows cover the writes-enabled sync path.

The process has independent budgets of 8, 8 and 16 rows for lanes 1, 2 and 3.
The last row of each budget is only `SMD1 l=<lane> q=<limit> cap=1`, replacing
that observation. Thus at most 32 rows are emitted, each at most 512 UTF-8
bytes. Repeated sync errors cannot consume the first-failure budget. A cap or
missing row is inconclusive; this is bounded sampling, not a complete history.
No production arrays retain observations. The test capture holds at most 32
strings. Error observations do not change flags, admission, error precedence,
queue order, recovery, durability or replies.

The emitter serializes its counters and output under its own lock. It never
acquires a volume submission lock or the SMT1 lock, calls back into a volume,
or invokes a reply handler. Callers may hold the submission lock, creating only
the one-way edge `submissionLock -> DeliveryTrace.lock`. Per-volume first-error
selection remains protected by the original submission lock.

The focused direct-callback test is
`PYTHONPATH=tests python3 -m unittest test_fskit.FSKitInterfaces.test_delivery_trace_focused`
with Xcode's SDK 27 selected through `DEVELOPER_DIR`. It uses fresh synthetic
fixtures and compiles traced and untraced
contextual production profiles without adapter hooks. It does not establish
installed callback routing or determine the cause of a real mount failure.

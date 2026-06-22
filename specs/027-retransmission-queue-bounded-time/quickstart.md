# Quickstart: verifying the bounded-time retransmission queue

## Build / lint / baseline
```bash
# BASELINE (before refactor): the existing suite is the behavioral characterization.
cargo test -p async-opcua-server           # must be green before US1 lands
# after refactor:
cargo test -p async-opcua-server           # must still be green (SC-003)
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features -p async-opcua -p async-opcua-types -p async-opcua-crypto -p async-opcua-server -- -D warnings
```

## New tests (authored by Claude, alongside `retransmission_queue.rs`)
1. **Eviction is global-FIFO** — interleave entries from two subscriptions, exceed capacity, assert
   the globally oldest (by push order) is the one dropped, not the lowest `(sub,seq)`.
2. **Ack semantics** — `ack` returns `Some` for a present `(sub,seq)` and removes it; `None` for an
   absent seq; queue otherwise unchanged. (Status-code mapping verified at the session level / by the
   existing suite.)
3. **available_sequence_numbers** — returns the subscription's seqs in insertion order; `None` when
   empty or sub absent.
4. **remove_subscription** — returns that sub's entries in insertion order; other subs untouched;
   empty for unknown sub.
5. **Republish lookup** — `get_message` hit returns the stored message; miss returns `None`.
6. **Reclaim** — eviction/ack/remove reclaim entries to the pool (assert via pool reuse or count).
7. **Scaling (SC-001)** — push N≈50k entries, then (a) one ack-flood of many keys and (b) a
   subscription teardown; assert each completes within a generous absolute wall-clock bound (a
   quadratic impl misses it by orders of magnitude). Absolute bound, not a ratio → CI-robust.
8. Port the two existing tests (`keep_alive_messages_are_not_queued…`,
   `status_change_messages_are_queued…`) to the struct API.

## Done criteria
- Existing server suite green before and after (no assertion weakened); new behavior + scaling tests
  pass; clippy legs clean; no new dependency; fork CI green.

# Snapshot/SPSC Baseline: Subscription Route Index

## Candidate

The selected P3 follow-up candidate is a subscription route index snapshot/SPSC design. The current
implementation already snapshots matching notification routes under the subscription-cache guard and
then performs sampling closures and actor queue pushes after the guard is released. A future design may
replace the guarded route lookup with a versioned immutable route table, and may use bounded SPSC lanes
to hand route update or notification fanout work to a single owner.

This task is a measurement gate only. No snapshot/SPSC implementation, dependency, benchmark harness,
or production-code change is made here.

## OPC UA Grounding

- OPC-10000-4 5.13 constrains monitored-item lifecycle, sampling, monitoring mode, deletion races, and
  monitored-item queues. Any route snapshot must preserve create/modify/delete behavior and queue
  semantics, including notifications already in flight.
- OPC-10000-4 5.14 constrains subscription notification and Publish behavior. Any route snapshot or
  queue fanout must preserve NotificationMessage packaging, sequence/retransmission behavior, and
  Publish acknowledgement semantics.

## Baseline Command

```bash
cargo test -p async-opcua-server subscription_route -- --nocapture
```

## Baseline Result

Recorded on 2026-06-30 before any snapshot/SPSC follow-up implementation.

- Result: PASS, exit code 0.
- Build and test profile completed successfully in 0.08s.
- Matching focused tests passed:
  - `subscription_route_snapshot_releases_cache_guard_before_actor_enqueue`
  - `subscription_route_snapshot_no_match_path_is_allocation_light`
  - `subscription_route_lookup_releases_cache_guard_before_sampling`
- Failures: none.
- Warnings: existing dead-code warnings were emitted in `async-opcua-client` and
  `async-opcua-server`.

## Future Acceptance Requirements

Before accepting any subscription route index snapshot/SPSC implementation, future work must add or
name the benchmark/tracing measurement used for comparison and include tests for stale snapshots,
monitored-item create/modify/delete races, and bounded-queue backpressure behavior.

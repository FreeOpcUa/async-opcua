# Benchmark Baseline — Feature 009 (PERF-P12 / FR-030 / SC-006 / SC-007)

Criterion micro-benchmarks added as performance regression guards for the hot
encode/decode and secure-channel paths. These numbers establish the **post-009
(optimized) baseline** — i.e. the codebase *after* the P1–P10 perf work (US5/US6)
landed — so future changes can be compared against them.

## How to run

```bash
cargo bench -p async-opcua-types --bench encoding
cargo bench -p async-opcua-core  --bench secure_channel
```

Criterion writes full statistics + HTML reports under `target/criterion/`. A
re-run compares against the previous run and reports regressions/improvements.

## Baseline numbers

> Indicative figures from a short run (`--warm-up-time 1 --measurement-time 2`) on
> the development machine (Linux x86-64, dev profile = `bench` optimized). Absolute
> values are hardware-dependent; the point is the **relative** signal on re-run and
> the cross-case ratios. Re-capture on the target host for authoritative numbers.

### `async-opcua-types` — `encoding` (FR-030 / PERF-P5)

| Case | Encode | Decode |
|------|--------|--------|
| `small_read_request` | ~100 ns | ~134 ns |
| `large_array_data_value` (10k × i32) | ~26 µs | ~78 µs |
| `big_byte_string_1mib` (1 MiB) | ~20 µs | ~20 µs |

Note: `big_byte_string` decode (~20 µs for 1 MiB) reflects the PERF-P5
`Bytes`-backed zero-copy `ByteString` decode — it tracks the array-copy cost, not
per-element work, confirming the zero-copy path.

### `async-opcua-core` — `secure_channel` round-trip (FR-030 / PERF-P1–P4)

`Chunker::encode → apply_security → verify_and_remove_security → Chunker::decode`
for a small `GetEndpointsRequest`:

| Security | Round-trip |
|----------|-----------|
| `None` | ~606 ns |
| `Sign` (Basic256Sha256) | ~1.20 µs |
| `SignAndEncrypt` (Basic256Sha256) | ~1.35 µs |

## SC-006 / SC-007 status (T090 / T098)

The P1–P10 optimizations (allocation-free transmit path, AES key-schedule caching,
O(1) primitive-array `byte_len`, `Bytes`-backed `ByteString`, `Arc`-shared
retransmission) were landed and validated **functionally** (round-trip + unit tests)
in US5/US6 before these benches existed. Because the benches were added *after* those
changes, they capture the optimized state as the going-forward baseline rather than a
strict before/after delta. A rigorous pre-009-vs-post-009 comparison would require
checking out the pre-009 commit and re-running the same benches — recorded as a
follow-up; the benches here are the regression guard from this point on.

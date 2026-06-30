# Research: Controlled Hot Path Benchmark Harness

## Decision: Build the first controlled harness as a Rust workspace tool

**Rationale**: The immediate need is an in-repository harness that every contributor can run from a clean checkout. A Rust tool can reuse the repository's async-opcua client and server APIs, stays versioned with the code being optimized, and avoids relying on `../scratch` or a separately built C load generator.

**Alternatives considered**:

- Keep using `../scratch/opcua-localhost-bench`: useful for comparison, but not controlled by this repository and easy to lose or drift.
- Import the scratch C/open62541 client into the workspace immediately: better for cross-stack comparisons, but adds external build complexity before we have the async-opcua-controlled baseline.

## Decision: Provide `run`, `server`, and `client` modes

**Rationale**: One-shot `run` mode makes a quick sample easy and deterministic. Separate `server` and `client` modes preserve the existing profiler workflow where `perf` attaches only to the server process. Keeping both modes in one binary avoids duplicated setup logic.

**Alternatives considered**:

- Only one-shot mode: too hard to profile server-only CPU costs.
- Only server/client mode: too much ceremony for short correctness and smoke checks.

## Decision: Emit one stable JSON object per measured sample

**Rationale**: JSON output is easy to archive, diff, and parse from scripts. One object per sample keeps output stable for automation and avoids prose parsing.

**Alternatives considered**:

- Human-readable tables: nice interactively, but brittle for automation.
- Criterion benchmark output: useful for microbenchmarks, but less natural for localhost end-to-end server/client throughput and server-only perf capture.

## Decision: Use a deterministic writable scalar node

**Rationale**: OPC UA Part 4 Read and Write service behavior is defined over Attributes of Nodes. A stable writable `Int32` Value Attribute gives both operations a valid target and makes status handling unambiguous.

**Alternatives considered**:

- Read `ServerStatus.CurrentTime`: good for read-only comparisons, but cannot support write samples.
- Reuse arbitrary sample-server nodes: less deterministic because namespace indexes and write permissions vary by sample configuration.

## Decision: Do not set CI throughput thresholds in the first harness PR

**Rationale**: Throughput gates are flaky until the project owns enough baseline history across runners. The first deliverable should prove the harness runs, reports stable fields, and fails on service errors. Threshold policy can be added after baseline data exists.

**Alternatives considered**:

- Add immediate ops/s minimums: attractive, but likely to fail for machine load rather than regressions.
- Keep the harness entirely manual: misses smoke coverage for command drift and JSON output stability.

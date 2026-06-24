# A "Better Than UACTT" Conformance Tester — Plan

Goal: an OPC UA conformance suite for async-opcua that is **open, free, CI-runnable, multi-stack, and
data-driven** — the axes where the official UA Compliance Test Tool (UACTT) is weak (gated behind
corporate membership, GUI-driven, single reference stack, not in CI). We don't need UACTT's
member-only TestCases (Compliance Part 8/9): we author checks per Conformance Unit and ground them in
**MIT-licensed** OPC Foundation artifacts.

## Architecture: index → oracles → drivers

**Index — what must be tested.** OPC UA Part 7 defines Profiles built from *Conformance Units* (CUs);
each CU "can be used as a test category" (Part 7 §4.2). The `opc-ua-reference` MCP exposes the full CU
catalog mapped to spec sections (the requirements). We build a CU registry and map each CU → concrete
checks, tracking coverage. This is the backbone UACTT has and our ad-hoc harnesses lack.

**Oracles — the source of truth each check compares against** (all MIT, vendored under
`samples/demo-server/interop/<area>/vendor/` with the license header retained):

| Area | Oracle artifact | Source repo |
|---|---|---|
| Address space | `Schema/Opc.Ua.NodeSet2.xml` (Core, 4.1 MB) + `NodeIds.csv` (14,770 nodes) | UA-Nodeset |
| StatusCodes / Attributes | `StatusCode.csv` (272), `AttributeIds.csv` (27) | UA-Nodeset |
| Encoding (binary/JSON/XML) | `Fuzzing/Opc.Ua.Encoders.Fuzz.Corpus/` golden vectors (built-in types + service messages, format-parallel) | UA-.NETStandard |
| HA aggregates (Part 13) | `AggregateTester` dataset + per-aggregate reference outputs ("creates the Part 13 examples") | Misc-Tools |
| ECC signature encoding | `OPCUA-ECC-CodeFragments/ecdsa-conversion/{convert.c,test.sh}` — P1363↔DER, 4 curves | OPCUA-ECC-CodeFragments |

**Drivers — how the server is exercised:**
- The 4 existing interop stacks (node-opcua, open62541, asyncua, .NET reference) — behavioral cross-stack agreement.
- A new Rust-native conformance runner that loads the **TestData nodeset** (UA-.NETStandard
  `Applications/Quickstarts.Servers/TestData/Generated/TestDataDesign.xml` — every datatype in
  scalar/array/static/dynamic/history forms) into the demo server and walks it under operation limits,
  porting the logic of `Tests/Opc.Ua.Server.TestFramework/CommonTestWorkers.cs`
  (BrowseFullAddressSpace → TranslateBrowsePath → Subscription → Read/Write/History).

**Coverage reference:** `Applications/UAReferenceServer.ctt.xml` (an actual UACTT project file) and
`Docs/Profiles.md` show exactly what UACTT covers and which profiles the reference impl claims — our
checklist to match and exceed.

## Why this beats UACTT
- **Accessible**: no membership; anyone can run it. **Reproducible/CI**: runs on every PR (UACTT is manual GUI).
- **Multi-stack**: 4 independent stacks agreeing > UACTT's single .NET-based driver.
- **Data-driven & extensible**: oracles are vendored MIT data; adding a companion spec = drop in its NodeSet2.

## Phased roadmap (each phase = one PR)

1. **Encoding corpus conformance** *(highest leverage / lowest effort, first slice)* — vendor the
   `Encoders.Fuzz.Corpus` binary/JSON/XML vectors; Rust test decodes each, round-trips, and asserts
   cross-format equivalence against async-opcua-types. Foundational layer, fully local, no server.
2. **Address-space oracle** — vendor Core `NodeSet2.xml` + CSVs; parser builds a reference map; a runner
   browses/reads the live demo server and diffs nodes/attributes/references/status-codes. The big
   coverage multiplier.
3. **CU registry + coverage map** — encode Part 7 Profiles→CUs (from the MCP) as a registry; tag every
   existing + new check with its CU; emit a coverage report (which CUs are covered, by which driver).
4. **Address-space walk runner** — load the TestData nodeset; port CommonTestWorkers; exercise every
   datatype/service under operation limits.
5. **HA aggregates** — vendor AggregateTester Part-13 vectors; test HistoryRead ReadProcessed.
6. **ECC signature vectors** — port `convert.c` / run `test.sh` as a differential oracle for our ECC encode/decode.
7. **Discovery** — use UA-LDS as the mDNS counterparty to finally cover the deferred FindServersOnNetwork.

## Licensing
All source artifacts are OPC Foundation MIT License 1.00. Vendored files keep their headers; record
provenance (repo + commit) in a `vendor/PROVENANCE.md` per area.

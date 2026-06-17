<!--
SYNC IMPACT REPORT
==================
Version change: (unversioned template) → 1.0.0
Rationale: Initial ratification of the project constitution. MAJOR bump from an
uninstantiated template to a concrete, governing v1.0.0.

Principles defined (all new, from user input):
  I.   Correctness Over Completion (NON-NEGOTIABLE)
  II.  Do It Right Once
  III. Individual Task Discipline
  IV.  Security Is Paramount
  V.   Leave It Better Than You Found It

Sections added:
  - Security & Network-Facing Requirements (expands Principle IV)
  - Development Workflow & Quality Gates (operationalizes I, II, III, V)
  - Governance

Sections removed: none (template placeholders fully replaced)

Templates / artifacts reviewed for alignment:
  ✅ .specify/templates/plan-template.md   — Constitution Check gate references this file generically; compatible, no edit required
  ✅ .specify/templates/spec-template.md   — security/correctness requirements fit the existing "Requirements" structure; no edit required
  ✅ .specify/templates/tasks-template.md  — task-list structure is already one-task-per-line; Principle III reinforced via Governance, no structural edit required
  ✅ .einarmo_guidelines.md                — existing repo coding conventions; consistent with Principles I/II/V

Deferred TODOs: none. RATIFICATION_DATE set to initial adoption date (2026-06-16).
-->

# async-opcua Constitution

async-opcua is a network-facing OPC UA protocol stack (client, server, and pub/sub) written in
Rust and consumed as a library by other systems. It decodes untrusted bytes from remote peers and
performs cryptographic operations on behalf of its users. These principles are non-negotiable
constraints on how work is done in this repository; they exist to keep that surface correct, safe,
and durable.

## Core Principles

### I. Correctness Over Completion (NON-NEGOTIABLE)
Code correctness MUST take precedence over finishing a task. A change is not "done" because it
compiles, the happy path works, or a deadline is near — it is done when it is demonstrably correct,
including edge cases, error paths, and untrusted input. Contributors MUST NOT trade a known
correctness gap for speed of delivery, and MUST NOT report work as complete while a known defect
remains. When correctness and completion conflict, completion yields.

**Rationale:** This library sits on the wire and in the trust path of other systems; an incorrect
decode, an off-by-one in chunking, or a skipped validation becomes a remote crash or a security
hole in every downstream deployment. A late-but-correct change is cheap; a shipped-but-wrong one is
not.

### II. Do It Right Once
Work MUST be done properly the first time so it does not have to be redone. Shortcuts that create
predictable rework — suppressing a warning instead of fixing its cause, copy-paste instead of a
shared abstraction, a `// TODO` on a reachable path, or papering over a failing test — are
prohibited. Where a genuine, deliberate shortcut is unavoidable, it MUST be recorded explicitly
(issue, code comment with rationale, or spec note) together with the conditions for completing it.
Root causes are fixed, not symptoms.

**Rationale:** Rework is the most expensive form of work and the largest source of regressions.
Doing it right once is faster across the life of the codebase than doing it twice.

### III. Individual Task Discipline
Tasks MUST be assigned, executed, and verified individually — never batched. Each unit of work is a
single, self-contained, independently verifiable change with its own clear acceptance criteria. A
contributor (human or agent) works one task to completion before starting the next; multiple
distinct tasks MUST NOT be bundled into a single undifferentiated change. Task lists produced by the
planning workflow MUST keep one task per line item, and execution MUST proceed one item at a time.

**Rationale:** Batched work hides defects, makes review and rollback coarse-grained, and obscures
which change caused a regression. One task at a time keeps each change reviewable, attributable, and
reversible — which directly serves Principles I and II.

### IV. Security Is Paramount
Security is the highest-priority quality attribute of this library, because it is network-facing and
processes untrusted, attacker-controllable input. Every change MUST be evaluated for its security
impact. Specifically:
- Code on a path reachable from network input MUST NOT panic, MUST bound all attacker-influenced
  allocations and recursion, and MUST reject malformed input with an error rather than undefined or
  abortive behavior.
- Cryptographic and authentication code MUST fail closed, MUST default to the safe option, and MUST
  NOT weaken or downgrade protections silently.
- Secrets (keys, passwords, nonces) MUST NOT be logged, and SHOULD be zeroized where practical.
- A change that improves a feature but regresses security is not acceptable; security wins.

**Rationale:** A vulnerability here is not local — it is exploitable in every system that embeds the
library. The cost of a security failure dominates the cost of any feature it might have blocked.

### V. Leave It Better Than You Found It
Every change MUST leave the touched code at least as healthy as it was found, and SHOULD leave it
better. When working in an area, fix the small adjacent defect, delete the dead code, correct the
misleading comment, remove the stray debris, and tighten the weak test — within the scope of the
task. Contributors MUST NOT degrade structure, clarity, test coverage, or documentation to land a
change, and MUST NOT leave behind temporary scaffolding, throwaway scripts, or commented-out code.

**Rationale:** Codebases decay one expedient change at a time and improve the same way. Continuous,
in-scope improvement keeps the project maintainable without requiring dedicated cleanup projects.

## Security & Network-Facing Requirements

These requirements operationalize Principle IV and are binding on all changes:

- **Untrusted input:** All decoders and parsers that consume bytes from a remote peer MUST enforce
  configured size, length, and recursion limits before allocating, and MUST be free of reachable
  `panic!`/`unwrap`/`expect`/indexing panics on the decode path.
- **Fail-closed defaults:** Security-relevant defaults (certificate trust, legacy/deprecated
  cryptography, authentication) MUST default to the safe choice; enabling a weaker option MUST be an
  explicit, logged opt-in.
- **Dependencies:** New or upgraded dependencies that touch crypto, TLS, parsing, or the network
  MUST be checked against known advisories; pulling in unmaintained or known-vulnerable crates on a
  reachable path is prohibited without explicit, recorded justification.
- **Resource limits:** Server-side request handling MUST bound per-peer resource consumption
  (connections, sessions, in-flight requests, subscriptions, chunks) to resist denial of service.
- **No secret leakage:** Key material and credentials MUST NOT appear in logs, debug output, or
  committed files.

## Development Workflow & Quality Gates

- **One task at a time (Principle III):** Plans decompose work into individually verifiable tasks;
  each is completed and verified before the next begins.
- **Tests accompany fixes (Principles I, II):** A bug fix SHOULD be accompanied by a regression test
  that fails before the fix and passes after. Correctness-critical paths MUST be covered by tests.
- **Green before done (Principle I):** A change MUST build warning-free and pass the test suite
  before it is considered complete; failing or skipped tests MUST be reported, never hidden.
- **No debris (Principle V):** Throwaway scripts, scratch files, commented-out code, and temporary
  instrumentation MUST be removed before a change lands.
- **Security review (Principle IV):** Changes touching decode/parse paths, cryptography,
  authentication, or transport MUST receive a security-focused review.
- **Existing conventions:** Contributors MUST follow the repository's established coding conventions
  (see `.einarmo_guidelines.md`) — including sorted imports, using the existing decoding framework
  over ad-hoc parsing, and correct lock/drop discipline.

## Governance

This constitution supersedes ad-hoc practice. Where another document or habit conflicts with it,
this constitution governs.

- **Compliance:** All changes, reviews, plans, and task lists MUST verify compliance with these
  principles. A reviewer MUST reject a change that violates a principle without a recorded, justified
  exception.
- **Amendments:** Amendments MUST be made by editing this file, with a Sync Impact Report recording
  the change, a semantic-version bump, and propagation to any dependent templates. MAJOR =
  backward-incompatible governance/principle removal or redefinition; MINOR = a new principle or
  materially expanded guidance; PATCH = clarifications and non-semantic refinements.
- **Exceptions:** Any deviation from a principle MUST be explicit, justified in writing, and scoped;
  silent exceptions are violations. Complexity and shortcuts MUST be justified against Principles I
  and II.
- **Runtime guidance:** Use `.einarmo_guidelines.md` and the active feature's
  `specs/<feature>/plan.md` for day-to-day development guidance; this constitution sets the
  non-negotiable boundaries within which that guidance operates.

**Version**: 1.0.0 | **Ratified**: 2026-06-16 | **Last Amended**: 2026-06-16

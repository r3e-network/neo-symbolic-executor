# Neo DApp Detector Expansion Design

## Goal

Expand Neo Symbolic Executor so it reports more actionable DApp, DeFi, and NFT attack-like issues while staying honest about its scope: this is a Neo N3 NEF/manifest analyzer, not a generic EVM scanner.

The first expansion should add protocol-aware detectors that reuse existing symbolic execution telemetry, manifest ABI data, path conditions, storage operations, and external call records. It should not add new dependencies or introduce a second analysis pipeline.

## Selected Approach

Use a detector-pack expansion inside `Neo.SymbolicExecutor.Detectors`.

Rejected alternatives:

- Label-only taxonomy: easy to ship, but does not improve detection capability.
- Engine-first taint overhaul: potentially valuable, but too broad for the first pass and riskier against the existing stable test suite.
- Generic cross-chain scanner language: misleading because the bytecode and manifest model are Neo N3-specific.

## Architecture

Add small stateless detectors under `src/Neo.SymbolicExecutor.Detectors/Detectors/` and register them in `DefaultDetectorSet`.

Each detector should follow the existing pattern:

- inherit `BaseDetector`
- consume `AnalysisContext`
- emit calibrated `Finding` values through `MakeFinding`
- tag findings with stable machine-readable tags
- avoid shared mutable state

Shared helper logic may be added only if two or more detectors need the same domain predicates, such as "token transfer call", "privileged method name", "oracle/price method name", or "balance/owner storage key".

## Detector Scope

First pass detectors should focus on signals that can be inferred without whole-program semantic recovery:

- DeFi slippage/oracle risk: flag swap-like or price-dependent paths that make external token/router calls and mutate state without apparent min-out, slippage, or oracle freshness signals.
- Token transfer ordering: strengthen callback/re-entry coverage around external `transfer` calls followed by balance, vault, pool, or NFT ownership state writes.
- NFT ownership/approval risk: flag NEP-11 transfer, burn, or ownership-changing flows without an enforced witness, caller-hash, or signature check before the state change.
- Public privileged methods: flag manifest-exposed methods with privileged names such as `mint`, `burn`, `pause`, `setFee`, `setOracle`, `withdraw`, `upgrade`, or `sweep` when the corresponding execution path reaches storage writes or external calls without early auth.
- Replay/domain separation: extend replay detection for signed state changes that lack nonce-like reads and contract/domain-bound key material.

Existing detectors remain responsible for generic access control, dangerous call flags, dynamic calls, replay, callback re-entry, and NEP-17/NEP-11 compliance. New detectors should either fill a domain gap or add severity/context where a generic detector is too vague.

## Data Flow

1. The existing engine explores NEF bytecode and records telemetry.
2. `DetectorEngine` builds an `AnalysisContext` with states, manifest, NEF, native registry, and optional SMT backend.
3. New detectors scan final states and manifest ABI metadata.
4. Findings are deduped and reported through the existing report generator and CLI.
5. With `--smt`, existing path validation should continue to apply to findings that carry path conditions.

## Error Handling

Detectors should be conservative:

- missing manifest data should skip manifest-only checks
- dynamic or unknown call targets should produce lower-confidence heuristic findings only when paired with sensitive state changes
- static manifest findings should use `state: null`
- path findings should include the relevant `ExecutionState` so confidence and SMT filtering work

No detector should throw on malformed manifests, absent telemetry, dynamic values, or incomplete exploration.

## Testing

Use test-first changes in `tests/Neo.SymbolicExecutor.Tests`.

Required tests:

- each new detector has at least one positive and one negative regression test
- `DefaultDetectorSet` includes the new detector names
- README detector count and test count are updated after the full suite passes
- report generation continues to serialize the new findings without schema changes

Verification commands:

- `dotnet build Neo.SymbolicExecutor.sln`
- `dotnet test Neo.SymbolicExecutor.sln --no-build`
- `dotnet format Neo.SymbolicExecutor.sln --verify-no-changes --no-restore`
- `git diff --check`

## Non-Goals

- no generic EVM bytecode support
- no new package dependencies
- no ML or external vulnerability database
- no source-code parser for C#, Solidity, or Python
- no broad refactor of the symbolic engine unless a detector test exposes a precise missing telemetry signal

## Success Criteria

The project is more powerful when the default detector set surfaces at least three additional domain-specific attack classes for Neo DApps, DeFi contracts, and NFT contracts, with passing regression tests and concise documentation that explains the new coverage.

# Neo Symbolic Executor

Symbolic execution and security analysis for Neo N3 smart contracts. Designed to ship as a
Neo DevPack submodule so contracts can run `neo-sym analyze` automatically after compile.

## Status

| Component | LOC |
|---|---|
| Engine + decoder + types | ~4,900 |
| NEF + manifest parsers | ~400 |
| 24 detectors + framework | ~3,000 |
| Reports + gates + CLI | ~750 |
| SMT-LIB layer | ~1,700 |
| Fuzzer (22 targets, multi-worker) | ~3,500 |
| **Total** | **~13,600** |

**Tests:** 259 xUnit cases passing (smoke + audit-regression + per-detector + parser
edge cases + end-to-end vulnerability showcase + property-style fuzz harness +
locale-stability + clone-isolation regressions).

The CLI's `analyze` command runs the engine once per manifest ABI entrypoint, seeding the eval
stack with one fresh symbolic value per declared parameter. Without a manifest the engine runs
once from offset 0 with an empty stack — useful for ad-hoc bytecode but not for real DevPack
contracts whose dispatcher needs the method-name argument.

## Layout

```
neo-symbolic-executor/
├── Neo.SymbolicExecutor.sln
├── Directory.Build.props
├── global.json                 — pin .NET 10
├── NuGet.Config                — NuGet.org package source
├── src/
│   ├── Neo.SymbolicExecutor/   — engine + decoder + IR + NEF/manifest parsers
│   ├── Neo.SymbolicExecutor.Detectors/  — 24 detectors + reports + gates
│   ├── Neo.SymbolicExecutor.Smt/        — SMT-LIB translator + Z3/portable backend
│   └── Neo.SymbolicExecutor.Cli/        — `neo-sym` command-line tool
├── tests/Neo.SymbolicExecutor.Tests/    — xUnit + FluentAssertions
└── devpack-integration/        — MSBuild .props/.targets for DevPack contracts
```

## Build

```bash
dotnet build
dotnet test
```

## Run

```bash
# Disassemble
neo-sym decode contract.nef

# Symbolic exploration without detectors
neo-sym explore contract.nef

# Full analysis
neo-sym analyze contract.nef \
  --manifest contract.manifest.json \
  --source ./src \
  --format markdown \
  --out report.md \
  --fail-on-max-severity high

# With SMT path validation (external z3 when available, portable fallback otherwise)
neo-sym analyze contract.nef --manifest contract.manifest.json --smt --smt-drop-unsat
```

If `z3` is on `PATH`, the SMT layer uses it for full SMT-LIB queries. Without `z3`, it falls
back to a conservative in-process solver that proves scaled single-symbol linear constraints,
bounded two-symbol affine constraints, symbol-offset equalities, and bounds, then returns `Unknown`
for formulas it cannot prove safely.

## CLI exit codes

| Code | Meaning                                  |
|------|------------------------------------------|
| 0    | OK / gate passed                         |
| 1    | Analyzer error (parse failure, etc.)     |
| 2    | Bad arguments                            |
| 3    | Gate violation (analysis ok, gate fired) |

Budget-aware gating: pass `--fail-on-budget-exceeded` to make the gate fire (exit 3)
when the engine hit `--max-paths`, `--max-steps`, or `--per-run-deadline-ms` on any
manifest entrypoint. Useful in CI to flag analyses that would otherwise pass silently
with incomplete coverage.

## JSON output schema

`--format json` emits a stable, byte-deterministic document — CI consumers can SHA-256 it
as an artifact key. Top-level shape:

```jsonc
{
  "meta": {
    "tool": "Neo.SymbolicExecutor",
    "version": "0.4.0",                  // assembly InformationalVersion (no commit suffix)
    "states_explored": 168,
    "steps_executed": 12340,
    "budget_exceeded": false,
    "budget_reason": null,
    "smt_available": true,
    "smt_engaged": true,
    "smt_stats": {                       // present iff --smt was passed
      "queries": 42, "cache_hits": 12,
      "sat": 18, "unsat": 8, "unknowns": 4, "timeouts": 0
    }
  },
  "risk_profile": {
    "overall_max_severity": "high",      // info|low|medium|high|critical
    "total_findings": 7,
    "weighted_score": 73,
    "confidence_weighted_score": 58,
    "severity_counts":            { "critical": 1, "high": 2, "medium": 3, "low": 1 },
    "detector_max_severity":      { "access_control": "high", "reentrancy": "critical" },
    "detector_average_confidence":{ "access_control": 0.85,   "reentrancy": 0.72 }
  },
  "gate_evaluation": {
    "passed": false,
    "policies":   { "fail-on-max-severity": "high" },
    "violations": [ "max severity high >= threshold high" ]
  },
  "findings": [
    {
      "detector": "reentrancy",
      "severity": "critical",
      "title": "External call before state write",
      "description": "...",
      "offset": 256,
      "confidence": 0.85,
      "confidence_reason": "path uncertainty=2, base 0.95 -> 0.81",
      "tags": [ "checks-effects-interactions" ],
      "path_satisfiable": true,           // null when --smt not engaged
      "witness": { "amount": "1000" }     // null absent SAT witness
    }
  ]
}
```

Severity-keyed dicts emit critical-first; detector-keyed dicts emit ordinal-sorted. Both
JSON and Markdown render numerics with InvariantCulture so reports diff cleanly across
machine locales.

## DevPack integration

See `devpack-integration/README.md` — provides MSBuild `.props` + `.targets`
that drop into a Neo DevPack contract project and run `neo-sym analyze` after build.

## Fuzzing

Multi-target multi-worker fuzzer for the engine, parsers, detectors, reports, and
SMT translator. Designed for days/weeks of continuous operation with persistent
corpus and unique-crash deduplication.

```bash
# Smoke run (60 seconds, all targets)
src/Neo.SymbolicExecutor.Fuzzer/bin/Release/net10.0/neo-sym-fuzz --seconds 60

# Long run with the wrapper (restarts daily, daily summaries, signal-handling)
nohup scripts/run-fuzzer-forever.sh ./fuzz-corpus 8 > /dev/null 2>&1 &
disown
```

See `src/Neo.SymbolicExecutor.Fuzzer/README.md` for target list, throughput baselines,
crash-artifact layout, and the systemd unit example. The first 90 seconds of fuzzing
surfaced 58 unique crashes covering two engine bug classes; both fixed and locked in
by `FuzzerRegressionTests`.

## Detectors

24 detectors are wired in `DefaultDetectorSet`:

- `reentrancy` — checks-effects-interactions with audit-driven amplification scoring
- `access_control` — missing / unenforced / late authorization, with `manifest.safe` respect
- `overflow` — symbolic-operand arithmetic + divide-by-zero
- `unchecked_return` — external call return value not consumed by ASSERT/branch
- `dynamic_call_target` — runtime-determined target hash and/or method selector
- `dangerous_call_flags` — CallFlags.All and bit-count >= 3 broad grants
- `dos` — recursion, iterator scans, excessive writes, capped-loop signals
- `gas_exhaustion` — paths over a configurable threshold
- `randomness` — timestamp-derived as HIGH; `Runtime.GetRandom` as INFO
- `timestamp` — INFO triage signal
- `storage_collision` — separator-aware prefix overlap detection
- `upgradeability` — `ContractManagement.Update`/`Destroy` reachability + auth posture
- `permissions` — manifest wildcards, partial wildcards, `trusts`, group misconfig
- `admin_centralization` — single-witness privileged ops (LOW)
- `nep17_compliance` — NEP-17 ABI / events / safe-flag conformance
- `nep11_compliance` — NEP-11 NFT ABI / events conformance
- `callback_reentry` — onNEP17Payment / onNEP11Payment recipient-callback re-entry
- `crypto_verification_bypass` — CheckSig / CheckMultisig result not consumed
- `replay_attack` — signature-gated state change without an apparent nonce
- `taint_flow_upgrade` — `Contract.Update` with caller-supplied NEF / manifest
- `public_privileged_method` — manifest-exposed mint/burn/withdraw/upgrade-like entrypoints without early auth
- `defi_slippage_oracle` — swap-like or reserve/vault-mutating token flows lacking min-out/slippage or oracle freshness signals
- `nft_ownership_authorization` — NEP-11 ownership/approval or dynamic-key writes before owner/operator authorization
- `unknown_instructions` — coverage gap surface (INFO)

With `--source <file-or-dir>`, protocol detectors use method-local C# source hints to recover
intent that NEF bytecode does not preserve, such as reserve, amount-out, deadline, owner, and
approval naming. The source matcher is lexical and dependency-free (no Roslyn) and disambiguates
overloads by parameter arity, so a privileged ABI method can no longer be silently exonerated by
a benign same-named overload elsewhere in the project. `[DisplayName("foo")]` attributes on
methods are recognised, so an ABI-named entrypoint resolves to its underlying C# implementation
even when the source identifier differs. Generated and dependency directories (`bin`, `obj`,
`.git`, `.vs`, `.omx`, `node_modules`, `packages`) are skipped during enumeration.

With `--smt`, each finding is validated for path satisfiability; infeasible findings are dropped
(or downgraded), and SAT findings include a concrete witness reproducer.

## Audit traceability

Every detector and every fix in this codebase carries a reference to the underlying audit
finding in its XML doc comments. Examples baked in from day one:

- PUSHA target=0 always uses resolved `Target` field (audit CRIT-1)
- Cross-type primitive equality via canonical bytes (audit HIGH-2)
- Witness-enforcement marker scoped to the branch that proceeds *because* the witness
  passed; the unauth branch stays unenforced (audit C8/C9)
- `System.Contract.CallNative` recorded as `ExternalCall` (audit C5)
- Reentrancy guard suppression hook + last-write-offset semantics (audit C1)
- Overflow false-positive cap + `INC`/`DEC`/`SHL`/`POW` tracked (audit overflow.py finding)
- `manifest.abi_methods.safe` consulted by access_control (audit detector audit #18)
- Native read-only allowlist (`Ledger`, `StdLib`, `CryptoLib`, etc.) used by reentrancy
  + access_control (audit detector audit #1, biggest precision win)
- 5 new detectors covering audit gaps: NEP-11, callback re-entry, replay, crypto bypass,
  taint-flow upgrade
- 3 Neo protocol-risk detectors:
  - `public_privileged_method` — manifest-exposed mint/burn/withdraw/upgrade-like entrypoints without early auth
  - `defi_slippage_oracle` — swap/vault token flows lacking min-out/slippage or oracle freshness signals
  - `nft_ownership_authorization` — NEP-11 ownership/approval writes before owner/operator authorization
- Method-local C# source hints (lexical + arity-aware) used by the protocol-risk detectors

## License

MIT.

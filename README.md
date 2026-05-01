# Neo Symbolic Executor

Symbolic execution and security analysis for Neo N3 smart contracts. Designed to ship as a
Neo DevPack submodule so contracts can run `neo-sym analyze` automatically after compile.

## Status

| Component | LOC | Tests |
|---|---|---|
| Engine + decoder + types | ~4,600 | 11 smoke + 6 fuzz |
| NEF + manifest parsers | ~400 | 5 |
| 24 detectors + framework | ~2,700 | 26 |
| Reports + gates + CLI | ~700 | 7 |
| SMT-LIB layer | ~1,700 | 15 |
| Fuzzer (21 targets, multi-worker) | ~3,400 | 16 regressions + 6 fuzz |
| **Total** | **~13,100** | **171 passing** |

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
├── tests/Neo.SymbolicExecutor.Tests/    — xUnit + FluentAssertions, 171 tests total
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
- `defi_slippage_oracle` — swap-like token flows lacking min-out/slippage or oracle freshness signals
- `nft_ownership_authorization` — NEP-11 ownership/approval writes before owner/operator authorization
- `unknown_instructions` — coverage gap surface (INFO)

With `--smt`: each finding is validated for path satisfiability; infeasible findings are
dropped (or downgraded), and SAT findings include a concrete witness reproducer.

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
- 3 Neo protocol-risk detectors covering DApp privileged methods, DeFi slippage/oracle
  safety, and NEP-11 ownership authorization

## License

MIT.

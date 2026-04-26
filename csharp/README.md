# Neo Symbolic Executor (C#)

Symbolic execution and security analysis for Neo N3 smart contracts. Targets integration as
a Neo DevPack submodule so DevPack contracts can run `neo-sym analyze` automatically after compile.

## Status

| Component | LOC | Tests |
|---|---|---|
| Engine + decoder + types | ~3,500 | 11 smoke + 6 fuzz |
| NEF + manifest parsers | ~400 | 5 |
| 21 detectors + framework | ~1,500 | 19 |
| Reports + gates + CLI | ~600 | 7 |
| Z3 SMT layer | ~400 | 6 (skipped when libz3 missing) |
| **Total** | **~6,400** | **64 passing + 5 skipped** |

## Layout

```
csharp/
├── Neo.SymbolicExecutor.sln
├── Directory.Build.props
├── global.json                 — pin .NET 10
├── NuGet.Config                — Neo MyGet feed
├── src/
│   ├── Neo.SymbolicExecutor/   — engine + decoder + IR + NEF/manifest parsers
│   ├── Neo.SymbolicExecutor.Detectors/  — 21 detectors + reports + gates
│   ├── Neo.SymbolicExecutor.Smt/        — Z3-backed translator + backend (optional)
│   └── Neo.SymbolicExecutor.Cli/        — `neo-sym` command-line tool
├── tests/Neo.SymbolicExecutor.Tests/    — xUnit + FluentAssertions, 69 tests total
└── devpack-integration/        — MSBuild .props/.targets for DevPack contracts
```

## Build

```bash
cd csharp
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

# With Z3 SMT layer (optional)
neo-sym analyze contract.nef --manifest contract.manifest.json --smt --smt-drop-unsat
```

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

## Audit traceability

This C# implementation is the rewrite target for a Python codebase that received a 5-agent
audit on 2026-04-26. Every audit finding is either:

- **Fixed by construction** (the C# port doesn't repeat the bug), or
- **Carried as an open task** with the audit reference in the relevant XML doc comment

Examples: PUSHA target=0 (audit CRIT-1), cross-type equality via canonical bytes (HIGH-2),
witness-enforcement scoping (C8/C9), CallNative as ExternalCall (C5), 50 missing compound /
splice / type opcode handlers (largest analyzer correctness gap), reentrancy guard
suppression hook (C1), overflow false-positive cap (overflow.py finding), manifest.safe
respect in access_control (audit detector audit #18), native read-only allowlist
(biggest precision win across detectors), NEP-11 + callback-reentry + replay + crypto-bypass
+ taint-flow upgrade detectors (5 audit-derived coverage gaps).

## License

MIT.

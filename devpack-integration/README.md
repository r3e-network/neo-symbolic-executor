# Neo.SymbolicExecutor — DevPack Integration

This directory ships MSBuild integration assets so a Neo DevPack contract project
can run `neo-sym analyze` automatically after compile.

## Install the tool

```bash
dotnet tool install --global Neo.SymbolicExecutor.Cli
# or, from a local source build:
dotnet pack /path/to/neo-symbolic-executor/src/Neo.SymbolicExecutor.Cli -c Release
dotnet tool install --global --add-source /path/to/output Neo.SymbolicExecutor.Cli
```

`neo-sym --help` should now work from any directory.

## Wire into a contract

In the contract's `.csproj` (or a sibling `Directory.Build.props`):

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <Import Project="path/to/Neo.SymbolicExecutor.props" />
  <!-- normal contract config ... -->
  <Import Project="path/to/Neo.SymbolicExecutor.targets" />
</Project>
```

Or, simpler: drop both `.props` and `.targets` files into the contract project's
directory; MSBuild auto-imports `Directory.Build.{props,targets}` sibling pairs.

## Defaults

| Property                        | Default       | Meaning                                      |
|---------------------------------|---------------|----------------------------------------------|
| `NeoSymEnabled`                 | `true`        | Toggle the analyzer entirely                 |
| `NeoSymToolPath`                | `neo-sym`     | Override if the global tool is renamed       |
| `NeoSymFormat`                  | `markdown`    | `markdown` or `json`                         |
| `NeoSymOutputDir`               | `$(OutputPath)neo-sym/` | Where to write the report          |
| `NeoSymFailOnMaxSeverity`       | `high`        | Build fails when a finding meets/exceeds this severity |
| `NeoSymUseSmt`                  | `false`       | Engage SMT path pruning + finding validation           |
| `NeoSymSourceDir`               | `$(MSBuildProjectDirectory)` | C# source hint directory for protocol detectors |

To override, set the property in the contract's `.csproj` before importing the targets:

```xml
<PropertyGroup>
  <NeoSymFailOnMaxSeverity>critical</NeoSymFailOnMaxSeverity>
  <NeoSymUseSmt>true</NeoSymUseSmt>
  <NeoSymSourceDir>$(MSBuildProjectDirectory)</NeoSymSourceDir>
</PropertyGroup>
```

## Reports

After build, look at `bin/<config>/<tfm>/neo-sym/<contract>.md` (or `.json`).
Failing builds also surface gate violations on stderr.

## CI

In CI, run the build with `--no-restore` after a separate restore step. The
build will fail with exit 3 if any gate fires; CI logs surface the violation.

```yaml
# Example GitHub Actions step
- name: Build + analyze
  run: dotnet build src/MyContract/MyContract.csproj -c Release
- name: Upload analysis report
  uses: actions/upload-artifact@v4
  with:
    name: neo-sym-report
    path: src/MyContract/bin/Release/**/neo-sym/*
```

## What's analyzed

`neo-sym analyze` runs the symbolic executor over the contract's emitted
`.nef`, parses the manifest sidecar, reads C# source hints from `NeoSymSourceDir`,
then runs all 24 detectors:

- Reentrancy (with audit-driven amplification scoring)
- Access control (manifest `safe` flag respected)
- Overflow / divide-by-zero
- Unchecked external call return
- Dynamic call target
- Dangerous call flags (CallFlags.All + bit-count threshold)
- DOS (recursion, iterator scans, excessive writes)
- Gas exhaustion
- Randomness (timestamp-derived) / Timestamp
- Storage key collision (separator-aware)
- Upgradeability (ContractManagement.Update / Destroy)
- Manifest permissions / wildcards
- Admin centralization
- NEP-17 ABI compliance
- NEP-11 ABI compliance
- Token callback re-entry
- Crypto verification bypass
- Replay attack (missing nonce)
- Taint-flow upgrade (caller-controlled NEF/manifest)
- Public privileged DApp methods without early auth
- DeFi slippage / oracle freshness gaps
- NEP-11 ownership authorization gaps
- Unknown instructions (coverage gap surface)

With `--smt`: each finding is validated for path satisfiability, infeasible
findings are dropped (or downgraded), and SAT findings include a concrete
witness reproducer.

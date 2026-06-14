# Neo.SymbolicExecutor — DevPack Integration

This directory ships MSBuild integration assets so a Neo DevPack contract project
can run `neo-sym analyze` and the `neo-n3-security` proof profile automatically
after compile.

## Install the tool

```bash
dotnet tool install --global Neo.SymbolicExecutor.Cli
# or, from a local source build:
dotnet pack /path/to/neo-symbolic-executor/src/Neo.SymbolicExecutor.Cli -c Release -o /path/to/output
dotnet tool install --global --add-source /path/to/output Neo.SymbolicExecutor.Cli
```

`neo-sym --help` should now work from any directory.

## Wire into a contract

Reference the CLI package from the contract project to import the MSBuild assets
through NuGet `buildTransitive`, and make sure `neo-sym` is available on `PATH`
or set `NeoSymToolPath`:

```xml
<ItemGroup>
  <PackageReference Include="Neo.SymbolicExecutor.Cli" Version="0.8.0" PrivateAssets="all" />
</ItemGroup>
```

For direct source-tree usage, import both files from the contract's `.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <Import Project="path/to/Neo.SymbolicExecutor.props" />
  <!-- normal contract config ... -->
  <Import Project="path/to/Neo.SymbolicExecutor.targets" />
</Project>
```

For repository-wide setup, add those same imports to files that MSBuild already
auto-loads, such as a sibling `Directory.Build.props` and `Directory.Build.targets`.
MSBuild does not auto-import arbitrary filenames like `Neo.SymbolicExecutor.props`
or `Neo.SymbolicExecutor.targets`.

## Defaults

| Property                        | Default       | Meaning                                      |
|---------------------------------|---------------|----------------------------------------------|
| `NeoSymEnabled`                 | `true`        | Toggle the analyzer entirely                 |
| `NeoSymToolPath`                | `neo-sym`     | Override if the global tool is renamed       |
| `NeoSymFormat`                  | `markdown`    | `markdown` or `json`                         |
| `NeoSymNefDir`                  | auto-detects `$(OutputPath)sc/` or `$(MSBuildProjectDirectory)/bin/sc/` | Directory containing `.nef` artifacts |
| `NeoSymOutputDir`               | `$(OutputPath)neo-sym/` | Where to write the report          |
| `NeoSymFailOnMaxSeverity`       | `high`        | Build fails when a finding meets/exceeds this severity |
| `NeoSymFailOnIncompleteCoverage`| `true`        | Build fails when manifest entrypoints are skipped      |
| `NeoSymFailOnBudgetExceeded`    | `true`        | Build fails when analysis hits a budget cap            |
| `NeoSymRequireArtifacts`        | `true`        | Build fails when no `.nef` artifact is found; set `false` only for intentionally artifact-free builds |
| `NeoSymUseSmt`                  | `false`       | Engage SMT path pruning + finding validation           |
| `NeoSymSmtDropUnsat`            | `false`       | When SMT is on, drop UNSAT findings entirely instead of downgrading |
| `NeoSymSourceDir`               | `$(MSBuildProjectDirectory)` | C# source hint directory for protocol detectors |
| `NeoSymVerifyEnabled`           | `true`        | Run the formal proof gate; set `false` only for analyze-only builds |
| `NeoSymVerifyProfile`           | `neo-n3-security` | Run `neo-sym verify --profile`; the `neo-n3-security` proof profile runs by default |
| `NeoSymVerifySpec`              | _(unset)_     | Run `neo-sym verify --spec` with a custom proof spec             |
| `NeoSymVerifyDependencyProofSummaries` | _(unset)_ | Semicolon-separated paths passed as repeated `--dependency-proof-summary` flags |
| `NeoSymVerifyDependencyProofArtifacts` | _(unset)_ | Semicolon-separated `<hash=program,manifest>` bindings passed as repeated `--dependency-proof-artifact` flags |
| `NeoSymVerifyTrustDependencyProofSummaries` | `false` | Pass `--trust-dependency-proof-summaries` after reviewing bound dependency artifacts |
| `NeoSymVerifyAllowUnboundDependencyProofSummaries` | `false` | Pass `--allow-unbound-dependency-proof-summaries` only for legacy/offline checked summaries; results become assumption-backed and still fail the default unqualified-proof gate unless `NeoSymVerifyAllowAssumptionBackedProofs=true` |
| `NeoSymVerifyEmitDependencyProofSummary` | _(unset)_ | Pass `--emit-dependency-proof-summary` to write a reusable dependency proof summary; valid only when exactly one `.nef` artifact is discovered so batched builds cannot overwrite one summary with another |
| `NeoSymDeploySenderHash`        | _(unset)_     | Passes `--deploy-sender-hash` to formal verification for Neo N3 contract identity; required for the default proof gate to pass on NEF artifacts |
| `NeoSymVerifyAllowUnproved`     | `false`       | Let formal verification emit a report without failing on unproved properties |
| `NeoSymVerifyRequireExternalSmt`| `false`       | Fail verification when it falls back to the portable SMT backend |
| `NeoSymVerifyRequireUnqualifiedProofs` | `true` | Fail verification when a proof depends on explicit assumptions |
| `NeoSymVerifyAllowAssumptionBackedProofs` | `false` | Pass `--allow-assumption-backed-proofs` to accept explicitly qualified proofs |
| `NeoSymMaxEntrypoints`          | _(unset)_     | Manifest ABI entrypoint fanout cap (CLI default 128) |
| `NeoSymMaxPaths`                | _(unset)_     | Per-entrypoint terminal-path cap (default 512)         |
| `NeoSymMaxSteps`                | _(unset)_     | Per-entrypoint symbolic-step cap (default 200000)      |
| `NeoSymPerRunDeadlineMs`        | _(unset)_     | Per-entrypoint wall-clock deadline in milliseconds      |

To override, set the property in the contract's `.csproj` before importing the targets:

```xml
<PropertyGroup>
  <NeoSymFailOnMaxSeverity>critical</NeoSymFailOnMaxSeverity>
  <NeoSymFailOnIncompleteCoverage>true</NeoSymFailOnIncompleteCoverage>
  <NeoSymFailOnBudgetExceeded>true</NeoSymFailOnBudgetExceeded>
  <NeoSymRequireArtifacts>true</NeoSymRequireArtifacts>
  <NeoSymUseSmt>true</NeoSymUseSmt>
  <NeoSymSourceDir>$(MSBuildProjectDirectory)</NeoSymSourceDir>
  <NeoSymVerifyProfile>neo-n3-security</NeoSymVerifyProfile>
  <NeoSymVerifyEnabled>true</NeoSymVerifyEnabled>
  <NeoSymVerifyDependencyProofSummaries>$(MSBuildProjectDirectory)/proofs/token.neo-sym.proof.json</NeoSymVerifyDependencyProofSummaries>
  <NeoSymVerifyDependencyProofArtifacts>0x1111111111111111111111111111111111111111=$(MSBuildProjectDirectory)/deps/Token.nef,$(MSBuildProjectDirectory)/deps/Token.manifest.json</NeoSymVerifyDependencyProofArtifacts>
  <NeoSymDeploySenderHash>00112233445566778899aabbccddeeff00112233</NeoSymDeploySenderHash>
  <NeoSymMaxEntrypoints>128</NeoSymMaxEntrypoints>
</PropertyGroup>
```

Set `NeoSymFailOnIncompleteCoverage` to `false` only for exploratory runs against
known-stale manifests; the target passes `--allow-incomplete-coverage` explicitly
because the CLI fails incomplete manifest coverage by default.
Set `NeoSymDeploySenderHash` for proof-grade `neo-n3-security` builds; without it the verify
report records `security.contract_identity.*` as incomplete because Neo N3 contract hashes depend
on the deployment sender. Use `NeoSymVerifyAllowUnproved=true` only for exploratory proof reports
that are allowed to keep that identity gap.
Set `NeoSymRequireArtifacts` to `false` only for intentionally artifact-free builds;
by default the MSBuild target fails closed when neither `NeoSymNefDir`, `$(OutputPath)sc`,
nor `$(MSBuildProjectDirectory)/bin/sc` contains a `.nef`.
If both default discovery roots contain `.nef` artifacts, the target also fails closed; set
`NeoSymNefDir` to the intended single artifact directory so stale fallback artifacts cannot
overwrite or be mistaken for current detector/proof reports.
Set `NeoSymVerifyEnabled` to `false` only when you intentionally want an analyze-only
build; otherwise DevPack builds run the default `neo-n3-security` proof profile and
write a proof report next to the detector report.
If `NeoSymVerifyEnabled=true`, either `NeoSymVerifyProfile` or `NeoSymVerifySpec` must be set;
the target fails closed instead of silently skipping formal verification.
Boolean properties must be exactly `true` or `false` so misspelled gate settings cannot be
quietly treated as disabled.
Use `NeoSymVerifyDependencyProofSummaries` together with
`NeoSymVerifyDependencyProofArtifacts` and `NeoSymVerifyTrustDependencyProofSummaries=true`
only after reviewing the dependency contract's bound NEF and manifest hashes. Set
`NeoSymVerifyEmitDependencyProofSummary` on a dependency project that should publish a reusable
proof summary for downstream contracts.

## Reports

After build, look at `bin/<config>/<tfm>/neo-sym/<contract>.md` (or `.json`).
Failing builds also surface gate violations on stderr.
Formal verification is enabled by default through `NeoSymVerifyProfile=neo-n3-security`.
the MSBuild target still writes `<contract>.verify.md` or `<contract>.verify.json`
before failing the build if the earlier analyze gate fires, so CI artifacts include
both the detector report and the proof report.

## CI

In CI, run the build with `--no-restore` after a separate restore step. The
build will fail with exit 3 if any gate fires; CI logs surface the violation.
The target validates format, severity, numeric budget, and single-identifier verification
profile properties before building the `Exec` command so malformed MSBuild properties fail early
instead of changing CLI argument structure.

```yaml
# Example GitHub Actions step
- name: Build + analyze + verify
  run: dotnet build src/MyContract/MyContract.csproj -c Release
- name: Upload analysis report
  uses: actions/upload-artifact@<full-commit-sha>
  with:
    name: neo-sym-report
    path: src/MyContract/bin/Release/**/neo-sym/*
```

Pin GitHub Actions to reviewed full commit SHAs in production workflows.

## What's analyzed

`neo-sym analyze` runs the symbolic executor over the contract's emitted
`.nef`, parses the manifest sidecar, reads C# source hints from `NeoSymSourceDir`,
then runs all 37 detectors. Unless `NeoSymVerifyEnabled=false`, the target also
runs `neo-sym verify --profile neo-n3-security` over the same NEF and manifest:

- `access_control`
- `admin_centralization`
- `callback_reentry`
- `crypto_verification_bypass`
- `dangerous_call_flags`
- `defi_slippage_oracle`
- `dos`
- `dynamic_call_target`
- `entry_script_auth`
- `gas_exhaustion`
- `nep11_compliance`
- `nep24_compliance`
- `nep26_compliance`
- `nep27_compliance`
- `nep17_amount_validation`
- `nep17_compliance`
- `nep17_transfer_to_self`
- `nep17_zero_address`
- `nft_ownership_authorization`
- `oracle_response_validation`
- `overflow`
- `permissions`
- `public_privileged_method`
- `randomness`
- `reentrancy`
- `replay_attack`
- `signature_malleability`
- `storage_collision`
- `supported_standards_coverage`
- `taint_flow_upgrade`
- `timestamp`
- `toctou_storage`
- `unchecked_return`
- `unknown_instructions`
- `unprotected_deploy`
- `unsafe_deserialization`
- `upgradeability`

With `--smt`: each finding is validated for path satisfiability, infeasible
findings are dropped (or downgraded), and SAT findings include a concrete
witness reproducer.

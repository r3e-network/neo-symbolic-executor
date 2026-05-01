# Neo DApp Detector Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Neo N3-focused DApp/DeFi/NFT detector pack that catches more attack-like protocol risks without adding dependencies or claiming generic EVM support.

**Architecture:** Keep the existing symbolic executor pipeline intact. Add stateless detectors under `Neo.SymbolicExecutor.Detectors`, backed by one internal helper for method, storage-key, auth, and DeFi/NFT predicate logic. Register detectors in `DefaultDetectorSet`, cover each with positive and negative tests, and update README counts and detector documentation after verification.

**Tech Stack:** C#/.NET 10, xUnit, FluentAssertions, existing `AnalysisContext`, `ExecutionState`, `Telemetry`, `ContractManifest`, and `BaseDetector`.

---

## File Structure

- Create `src/Neo.SymbolicExecutor.Detectors/Detectors/ProtocolRiskHelpers.cs`
  - Internal helper predicates shared by new detectors.
  - Converts concrete storage keys to text, finds likely manifest method for a state, checks auth-before-offset, detects transfer calls, DeFi/slippage/oracle/freshness signals, and NFT ownership keys.
- Create `src/Neo.SymbolicExecutor.Detectors/Detectors/PublicPrivilegedMethodDetector.cs`
  - Flags manifest-exposed privileged methods that reach storage writes or external calls before authorization.
- Create `src/Neo.SymbolicExecutor.Detectors/Detectors/DefiSlippageOracleDetector.cs`
  - Flags swap/price-dependent paths that perform external calls and state writes without min-out/slippage or oracle freshness signals.
- Create `src/Neo.SymbolicExecutor.Detectors/Detectors/NftOwnershipAuthorizationDetector.cs`
  - Flags NEP-11 ownership/approval-changing paths without early auth.
- Modify `src/Neo.SymbolicExecutor.Detectors/DefaultDetectorSet.cs`
  - Register the three new detectors.
- Modify `tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs`
  - Add positive and negative tests for each detector.
  - Extend `DefaultDetectorSet_HasAllAuditDrivenDetectors`.
- Modify `README.md`
  - Update detector count, detector list, test count, and audit traceability notes after full verification.

---

### Task 1: Add Shared Protocol-Risk Helper

**Files:**
- Create: `src/Neo.SymbolicExecutor.Detectors/Detectors/ProtocolRiskHelpers.cs`
- Test: covered through detector tests in later tasks

- [ ] **Step 1: Create the helper file**

Add this file:

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

internal static class ProtocolRiskHelpers
{
    private static readonly string[] PrivilegedNames =
    {
        "mint", "burn", "pause", "unpause", "setFee", "setFees", "setOracle", "setOwner",
        "setAdmin", "withdraw", "sweep", "upgrade", "update", "destroy", "claim", "rescue"
    };

    private static readonly string[] SwapNames =
    {
        "swap", "exchange", "trade", "buy", "sell", "addLiquidity", "removeLiquidity",
        "deposit", "withdraw", "mint", "redeem"
    };

    private static readonly string[] SlippageHints =
    {
        "min", "minout", "amountoutmin", "amountmin", "slippage", "limit", "deadline"
    };

    private static readonly string[] OracleHints =
    {
        "oracle", "price", "twap", "round", "feed", "rate"
    };

    private static readonly string[] FreshnessHints =
    {
        "timestamp", "updated", "updatedat", "height", "round", "deadline", "ttl", "expiry"
    };

    private static readonly string[] NftKeyHints =
    {
        "owner", "approval", "approved", "token", "nft", "nep11"
    };

    public static ContractMethodDescriptor? MethodForState(AnalysisContext context, ExecutionState state)
    {
        var methods = context.Manifest?.Abi.Methods;
        if (methods is null || methods.Count == 0 || state.Path.Count == 0) return null;

        int firstVisited = state.Path.Min();
        return methods
            .Where(m => m.Offset <= firstVisited)
            .OrderByDescending(m => m.Offset)
            .FirstOrDefault();
    }

    public static bool IsPrivilegedMethodName(string name) =>
        PrivilegedNames.Any(h => ContainsFolded(name, h));

    public static bool IsSwapLikeMethodName(string name) =>
        SwapNames.Any(h => ContainsFolded(name, h));

    public static bool HasAuthBefore(ExecutionState state, int offset) =>
        state.Telemetry.WitnessChecksEnforced.Any(o => o < offset)
        || state.Telemetry.CallerHashChecks.Any(o => o < offset)
        || state.Telemetry.SignatureChecks.Any(o => o < offset);

    public static IEnumerable<(int Offset, string Kind)> SensitiveOps(ExecutionState state)
    {
        foreach (var op in state.Telemetry.StorageOps)
        {
            if (op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                yield return (op.Offset, "storage-write");
        }

        foreach (var call in state.Telemetry.ExternalCalls)
            yield return (call.Offset, "external-call");
    }

    public static bool IsTokenTransferCall(ExternalCall call) =>
        string.Equals(call.Method, "transfer", StringComparison.OrdinalIgnoreCase)
        && call.TargetHash?.AsConcreteBytes() is { Length: 20 };

    public static bool HasSlippageSignal(ExecutionState state)
    {
        if (AnySymbolContains(state, SlippageHints)) return true;
        return state.Telemetry.StorageOps.Any(op => KeyContainsAny(op, SlippageHints));
    }

    public static bool HasOracleFreshnessSignal(ExecutionState state)
    {
        if (state.Telemetry.TimeAccesses.Count > 0) return true;
        if (AnySymbolContains(state, FreshnessHints)) return true;
        if (state.Telemetry.StorageOps.Any(op => KeyContainsAny(op, OracleHints) || KeyContainsAny(op, FreshnessHints)))
            return true;
        return state.Telemetry.ExternalCalls.Any(call =>
            OracleHints.Any(h => ContainsFolded(call.Method, h))
            || FreshnessHints.Any(h => ContainsFolded(call.Method, h)));
    }

    public static bool IsNftOwnershipWrite(StorageOp op) =>
        op.Kind is StorageOpKind.Put or StorageOpKind.Delete
        && KeyContainsAny(op, NftKeyHints);

    public static bool KeyContainsAny(StorageOp op, IReadOnlyList<string> hints)
    {
        string? text = StorageKeyText(op);
        return text is not null && hints.Any(h => ContainsFolded(text, h));
    }

    private static bool AnySymbolContains(ExecutionState state, IReadOnlyList<string> hints) =>
        state.PathConditions
            .SelectMany(c => c.FreeSymbols())
            .Any(symbol => hints.Any(h => ContainsFolded(symbol, h)));

    private static string? StorageKeyText(StorageOp op)
    {
        var bytes = op.Key.AsConcreteBytes();
        if (bytes is null || bytes.Length == 0) return null;
        if (bytes.Any(b => b < 0x20 || b > 0x7E)) return null;
        return Encoding.UTF8.GetString(bytes);
    }

    private static bool ContainsFolded(string value, string hint) =>
        value.Replace("_", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal)
            .Contains(hint.Replace("_", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal),
                StringComparison.OrdinalIgnoreCase);
}
```

- [ ] **Step 2: Build after adding the helper**

Run:

```bash
dotnet build src/Neo.SymbolicExecutor.Detectors/Neo.SymbolicExecutor.Detectors.csproj
```

Expected: PASS with `0 Error(s)`.

- [ ] **Step 3: Commit**

Use the Lore protocol:

```bash
git add src/Neo.SymbolicExecutor.Detectors/Detectors/ProtocolRiskHelpers.cs
git commit -m "Share protocol-risk detector predicates" -m "The DApp detector pack needs consistent predicates for manifest method matching, auth ordering, token transfers, storage-key hints, and DeFi/NFT naming signals." -m "Constraint: No new dependencies; helpers must stay telemetry-based\nConfidence: high\nScope-risk: narrow\nTested: dotnet build src/Neo.SymbolicExecutor.Detectors/Neo.SymbolicExecutor.Detectors.csproj"
```

---

### Task 2: Add Public Privileged Method Detector

**Files:**
- Create: `src/Neo.SymbolicExecutor.Detectors/Detectors/PublicPrivilegedMethodDetector.cs`
- Modify: `tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs`

- [ ] **Step 1: Write failing tests**

Append these tests before `DefaultDetectorSet_HasAllAuditDrivenDetectors`:

```csharp
[Fact]
public void PublicPrivilegedMethod_FlagsUnauthedMintStateChange()
{
    var manifest = Nef.ContractManifest.FromJson("""
        {"name":"Dapp","groups":[],"features":{},"supportedstandards":[],
         "abi":{"methods":[{"name":"mint","parameters":[],"returntype":"Void","offset":256,"safe":false}],
                "events":[]},
         "permissions":[],"trusts":[]}
    """);
    var s = NewState();
    s.Path.Add(0x100);
    s.Telemetry.StorageOps.Add(new StorageOp(0x120, StorageOpKind.Put,
        SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("supply")), SymbolicValue.Int(1), false, false));

    var findings = new PublicPrivilegedMethodDetector()
        .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
        .ToList();

    findings.Should().ContainSingle();
    findings[0].Severity.Should().Be(Severity.High);
    findings[0].Tags.Should().Contain(new[] { "dapp", "privileged-method", "missing-auth" });
}

[Fact]
public void PublicPrivilegedMethod_SkipsWhenAuthPrecedesStateChange()
{
    var manifest = Nef.ContractManifest.FromJson("""
        {"name":"Dapp","groups":[],"features":{},"supportedstandards":[],
         "abi":{"methods":[{"name":"withdraw","parameters":[],"returntype":"Void","offset":256,"safe":false}],
                "events":[]},
         "permissions":[],"trusts":[]}
    """);
    var s = NewState();
    s.Path.Add(0x100);
    s.Telemetry.WitnessChecksEnforced.Add(0x105);
    s.Telemetry.StorageOps.Add(new StorageOp(0x120, StorageOpKind.Put,
        SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("vault")), SymbolicValue.Int(1), false, false));

    new PublicPrivilegedMethodDetector()
        .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
        .Should().BeEmpty();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter "PublicPrivilegedMethod" --logger "console;verbosity=normal"
```

Expected: FAIL because `PublicPrivilegedMethodDetector` does not exist.

- [ ] **Step 3: Implement detector**

Create `src/Neo.SymbolicExecutor.Detectors/Detectors/PublicPrivilegedMethodDetector.cs`:

```csharp
using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// DApp privileged-method surface detector. Generic access-control findings are useful, but
/// manifest-exposed methods named mint/burn/withdraw/upgrade/etc. need a domain-specific signal
/// because these functions are common attacker entrypoints in DApps, DeFi vaults, and NFT contracts.
/// </summary>
public sealed class PublicPrivilegedMethodDetector : BaseDetector
{
    public override string Name => "public_privileged_method";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.75;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;

        foreach (var state in context.States)
        {
            var method = ProtocolRiskHelpers.MethodForState(context, state);
            if (method is null || method.Safe) continue;
            if (!ProtocolRiskHelpers.IsPrivilegedMethodName(method.Name)) continue;

            var firstSensitive = ProtocolRiskHelpers.SensitiveOps(state)
                .OrderBy(op => op.Offset)
                .FirstOrDefault();
            if (firstSensitive == default) continue;
            if (ProtocolRiskHelpers.HasAuthBefore(state, firstSensitive.Offset)) continue;

            yield return MakeFinding(
                title: $"Public privileged method `{method.Name}` reaches sensitive operation without early auth",
                description: $"Manifest-exposed method `{method.Name}` reaches {firstSensitive.Kind} at "
                           + $"0x{firstSensitive.Offset:X4} before an enforced witness, caller-hash, or signature check. "
                           + "Privileged DApp entrypoints such as mint, burn, withdraw, sweep, oracle, fee, and upgrade "
                           + "methods should authorize before touching state or calling out.",
                offset: firstSensitive.Offset,
                severity: Severity.High,
                state: state,
                tags: new[] { "dapp", "privileged-method", "missing-auth" });
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter "PublicPrivilegedMethod" --logger "console;verbosity=normal"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/Neo.SymbolicExecutor.Detectors/Detectors/PublicPrivilegedMethodDetector.cs tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs
git commit -m "Detect unauthenticated privileged DApp entrypoints" -m "Manifest-exposed privileged methods are common attack surfaces, so they deserve domain-specific findings rather than only generic access-control reports." -m "Constraint: Detector stays manifest and telemetry based\nConfidence: high\nScope-risk: narrow\nTested: dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter PublicPrivilegedMethod"
```

---

### Task 3: Add DeFi Slippage and Oracle Detector

**Files:**
- Create: `src/Neo.SymbolicExecutor.Detectors/Detectors/DefiSlippageOracleDetector.cs`
- Modify: `tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs`

- [ ] **Step 1: Write failing tests**

Append these tests before `DefaultDetectorSet_HasAllAuditDrivenDetectors`:

```csharp
[Fact]
public void DefiSlippageOracle_FlagsSwapWithoutMinOutOrFreshOracleSignal()
{
    var manifest = Nef.ContractManifest.FromJson("""
        {"name":"Pool","groups":[],"features":{},"supportedstandards":[],
         "abi":{"methods":[{"name":"swap","parameters":[],"returntype":"Boolean","offset":512,"safe":false}],
                "events":[]},
         "permissions":[],"trusts":[]}
    """);
    var s = NewState();
    s.Path.Add(0x200);
    s.Telemetry.ExternalCalls.Add(new ExternalCall
    {
        Offset = 0x220,
        Method = "transfer",
        TargetHash = SymbolicValue.Bytes(new byte[20]),
        HasReturnValue = true,
    });
    s.Telemetry.StorageOps.Add(new StorageOp(0x240, StorageOpKind.Put,
        SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("pool:reserve0")), SymbolicValue.Int(100), false, false));

    var findings = new DefiSlippageOracleDetector()
        .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
        .ToList();

    findings.Should().ContainSingle();
    findings[0].Severity.Should().Be(Severity.High);
    findings[0].Tags.Should().Contain(new[] { "defi", "slippage", "oracle-freshness" });
}

[Fact]
public void DefiSlippageOracle_SkipsSwapWithMinOutAndFreshnessSignals()
{
    var manifest = Nef.ContractManifest.FromJson("""
        {"name":"Pool","groups":[],"features":{},"supportedstandards":[],
         "abi":{"methods":[{"name":"swap","parameters":[],"returntype":"Boolean","offset":512,"safe":false}],
                "events":[]},
         "permissions":[],"trusts":[]}
    """);
    var s = NewState();
    s.Path.Add(0x200);
    s.PathConditions = s.PathConditions.Add(Expr.Sym(Sort.Bool, "amountOutMin_ok"));
    s.Telemetry.TimeAccesses.Add(0x210);
    s.Telemetry.ExternalCalls.Add(new ExternalCall
    {
        Offset = 0x220,
        Method = "transfer",
        TargetHash = SymbolicValue.Bytes(new byte[20]),
        HasReturnValue = true,
    });
    s.Telemetry.StorageOps.Add(new StorageOp(0x240, StorageOpKind.Put,
        SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("pool:reserve0")), SymbolicValue.Int(100), false, false));

    new DefiSlippageOracleDetector()
        .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
        .Should().BeEmpty();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter "DefiSlippageOracle" --logger "console;verbosity=normal"
```

Expected: FAIL because `DefiSlippageOracleDetector` does not exist.

- [ ] **Step 3: Implement detector**

Create `src/Neo.SymbolicExecutor.Detectors/Detectors/DefiSlippageOracleDetector.cs`:

```csharp
using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// DeFi slippage/oracle heuristic. Neo contracts do not expose high-level source semantics here,
/// so this detector looks for swap-like manifest methods that call external token/router contracts
/// and mutate pool/vault state without observable min-out/slippage and freshness signals.
/// </summary>
public sealed class DefiSlippageOracleDetector : BaseDetector
{
    public override string Name => "defi_slippage_oracle";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.62;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            var method = ProtocolRiskHelpers.MethodForState(context, state);
            bool swapLike = method is not null && ProtocolRiskHelpers.IsSwapLikeMethodName(method.Name);
            if (!swapLike) continue;

            bool externalTransfer = state.Telemetry.ExternalCalls.Any(ProtocolRiskHelpers.IsTokenTransferCall);
            bool writesState = state.Telemetry.StorageOps.Any(o => o.Kind is StorageOpKind.Put or StorageOpKind.Delete);
            if (!externalTransfer || !writesState) continue;

            bool hasSlippageSignal = ProtocolRiskHelpers.HasSlippageSignal(state);
            bool hasFreshnessSignal = ProtocolRiskHelpers.HasOracleFreshnessSignal(state);
            if (hasSlippageSignal && hasFreshnessSignal) continue;

            int offset = state.Telemetry.ExternalCalls
                .Where(ProtocolRiskHelpers.IsTokenTransferCall)
                .Select(c => c.Offset)
                .DefaultIfEmpty(0)
                .Min();

            var missing = new List<string>();
            if (!hasSlippageSignal) missing.Add("min-out/slippage guard");
            if (!hasFreshnessSignal) missing.Add("oracle freshness/deadline signal");

            yield return MakeFinding(
                title: $"Swap-like method `{method!.Name}` lacks DeFi price-safety signals",
                description: $"Swap-like method `{method.Name}` performs token transfer(s) and mutates state, "
                           + $"but this path lacks {string.Join(" and ", missing)}. DeFi flows should bound "
                           + "received amount and avoid stale or manipulable price inputs before updating reserves, "
                           + "vault shares, or balances.",
                offset: offset,
                severity: Severity.High,
                state: state,
                tags: new[] { "defi", "slippage", "oracle-freshness" });
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter "DefiSlippageOracle" --logger "console;verbosity=normal"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/Neo.SymbolicExecutor.Detectors/Detectors/DefiSlippageOracleDetector.cs tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs
git commit -m "Detect unsafe DeFi swap price-safety gaps" -m "Swap-like paths that transfer tokens and mutate state need min-out and freshness signals, otherwise users can be exposed to sandwiching, stale-oracle, or reserve-manipulation style failures." -m "Constraint: Heuristic uses manifest names plus existing telemetry only\nConfidence: medium\nScope-risk: narrow\nTested: dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter DefiSlippageOracle"
```

---

### Task 4: Add NFT Ownership Authorization Detector

**Files:**
- Create: `src/Neo.SymbolicExecutor.Detectors/Detectors/NftOwnershipAuthorizationDetector.cs`
- Modify: `tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs`

- [ ] **Step 1: Write failing tests**

Append these tests before `DefaultDetectorSet_HasAllAuditDrivenDetectors`:

```csharp
[Fact]
public void NftOwnershipAuthorization_FlagsUnauthedNep11OwnershipWrite()
{
    var manifest = Nef.ContractManifest.FromJson("""
        {"name":"NFT","groups":[],"features":{},"supportedstandards":["NEP-11"],
         "abi":{"methods":[{"name":"transfer","parameters":[],"returntype":"Boolean","offset":768,"safe":false}],
                "events":[]},
         "permissions":[],"trusts":[]}
    """);
    var s = NewState();
    s.Path.Add(0x300);
    s.Telemetry.StorageOps.Add(new StorageOp(0x330, StorageOpKind.Put,
        SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("owner:token42")), SymbolicValue.Bytes(new byte[20]), false, false));

    var findings = new NftOwnershipAuthorizationDetector()
        .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
        .ToList();

    findings.Should().ContainSingle();
    findings[0].Severity.Should().Be(Severity.High);
    findings[0].Tags.Should().Contain(new[] { "nft", "nep11", "ownership-auth" });
}

[Fact]
public void NftOwnershipAuthorization_SkipsWhenAuthPrecedesOwnershipWrite()
{
    var manifest = Nef.ContractManifest.FromJson("""
        {"name":"NFT","groups":[],"features":{},"supportedstandards":["NEP-11"],
         "abi":{"methods":[{"name":"burn","parameters":[],"returntype":"Boolean","offset":768,"safe":false}],
                "events":[]},
         "permissions":[],"trusts":[]}
    """);
    var s = NewState();
    s.Path.Add(0x300);
    s.Telemetry.CallerHashChecks.Add(0x310);
    s.Telemetry.StorageOps.Add(new StorageOp(0x330, StorageOpKind.Delete,
        SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("owner:token42")), null, false, false));

    new NftOwnershipAuthorizationDetector()
        .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
        .Should().BeEmpty();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter "NftOwnershipAuthorization" --logger "console;verbosity=normal"
```

Expected: FAIL because `NftOwnershipAuthorizationDetector` does not exist.

- [ ] **Step 3: Implement detector**

Create `src/Neo.SymbolicExecutor.Detectors/Detectors/NftOwnershipAuthorizationDetector.cs`:

```csharp
using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// NEP-11 ownership/approval authorization detector. Generic missing-auth findings are useful,
/// but NFT transfer/burn/approval paths deserve a domain-specific signal because an ownership
/// write can directly move or destroy a unique asset.
/// </summary>
public sealed class NftOwnershipAuthorizationDetector : BaseDetector
{
    public override string Name => "nft_ownership_authorization";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.72;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;
        bool declaresNep11 = context.Manifest.SupportedStandards
            .Any(s => string.Equals(s, "NEP-11", System.StringComparison.OrdinalIgnoreCase));
        if (!declaresNep11) yield break;

        foreach (var state in context.States)
        {
            var method = ProtocolRiskHelpers.MethodForState(context, state);
            bool ownershipMethod = method is not null
                && (method.Name.Equals("transfer", System.StringComparison.OrdinalIgnoreCase)
                    || method.Name.Equals("burn", System.StringComparison.OrdinalIgnoreCase)
                    || method.Name.Contains("approve", System.StringComparison.OrdinalIgnoreCase));

            var firstOwnershipWrite = state.Telemetry.StorageOps
                .Where(ProtocolRiskHelpers.IsNftOwnershipWrite)
                .OrderBy(op => op.Offset)
                .FirstOrDefault();
            if (firstOwnershipWrite is null) continue;
            if (!ownershipMethod && method is not null && !ProtocolRiskHelpers.IsPrivilegedMethodName(method.Name)) continue;
            if (ProtocolRiskHelpers.HasAuthBefore(state, firstOwnershipWrite.Offset)) continue;

            yield return MakeFinding(
                title: "NEP-11 ownership or approval write lacks early authorization",
                description: $"NEP-11 path writes an ownership/approval-like storage key at "
                           + $"0x{firstOwnershipWrite.Offset:X4} before an enforced witness, caller-hash, or signature check. "
                           + "NFT transfer, burn, and approval flows should prove owner/operator authority before changing "
                           + "token ownership or approvals.",
                offset: firstOwnershipWrite.Offset,
                severity: Severity.High,
                state: state,
                tags: new[] { "nft", "nep11", "ownership-auth" });
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter "NftOwnershipAuthorization" --logger "console;verbosity=normal"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/Neo.SymbolicExecutor.Detectors/Detectors/NftOwnershipAuthorizationDetector.cs tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs
git commit -m "Detect unauthenticated NEP-11 ownership writes" -m "NFT ownership and approval writes directly affect unique assets, so NEP-11 paths need a dedicated signal when they happen before authorization." -m "Constraint: Detection relies on NEP-11 manifests and concrete storage-key hints\nConfidence: medium\nScope-risk: narrow\nTested: dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter NftOwnershipAuthorization"
```

---

### Task 5: Register Detectors and Verify Reporting

**Files:**
- Modify: `src/Neo.SymbolicExecutor.Detectors/DefaultDetectorSet.cs`
- Modify: `tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs`

- [ ] **Step 1: Update DefaultDetectorSet**

In `src/Neo.SymbolicExecutor.Detectors/DefaultDetectorSet.cs`, append the new detectors after `TaintFlowUpgradeDetector()`:

```csharp
        // Neo DApp / DeFi / NFT protocol-risk detectors.
        new PublicPrivilegedMethodDetector(),
        new DefiSlippageOracleDetector(),
        new NftOwnershipAuthorizationDetector(),
```

Update the XML doc count from `21` to `24` if present in the comment.

- [ ] **Step 2: Update DefaultDetectorSet test**

In `DefaultDetectorSet_HasAllAuditDrivenDetectors`, add:

```csharp
            // Neo DApp / DeFi / NFT protocol-risk detectors
            "public_privileged_method", "defi_slippage_oracle", "nft_ownership_authorization",
```

Change:

```csharp
detectors.Should().HaveCountGreaterThanOrEqualTo(21);
```

to:

```csharp
detectors.Should().HaveCountGreaterThanOrEqualTo(24);
```

- [ ] **Step 3: Add report serialization smoke test**

Append this test before `DefaultDetectorSet_HasAllAuditDrivenDetectors`:

```csharp
[Fact]
public void ProtocolRiskFindings_SerializeThroughJsonReport()
{
    var finding = new Finding(
        "defi_slippage_oracle",
        Severity.High,
        "Swap-like method `swap` lacks DeFi price-safety signals",
        "description",
        0x220,
        0.62,
        "test",
        System.Collections.Immutable.ImmutableHashSet.Create("defi", "slippage", "oracle-freshness"));
    var findings = System.Collections.Immutable.ImmutableArray.Create(finding);
    var risk = RiskProfile.FromFindings(findings);
    var gate = new GatePolicy().Evaluate(findings, risk);

    string json = ReportGenerator.ToJson(new AnalysisReport(findings, risk, gate, new AnalysisMeta()));

    json.Should().Contain("defi_slippage_oracle");
    json.Should().Contain("oracle-freshness");
}
```

- [ ] **Step 4: Run detector and report tests**

Run:

```bash
dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter "PublicPrivilegedMethod|DefiSlippageOracle|NftOwnershipAuthorization|DefaultDetectorSet_HasAllAuditDrivenDetectors|ProtocolRiskFindings_SerializeThroughJsonReport" --logger "console;verbosity=normal"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/Neo.SymbolicExecutor.Detectors/DefaultDetectorSet.cs tests/Neo.SymbolicExecutor.Tests/AdditionalDetectorTests.cs
git commit -m "Register Neo protocol-risk detectors" -m "The new DApp, DeFi, and NFT checks need to run by default and serialize through the existing report path without schema changes." -m "Constraint: Default detector set remains stateless and shared\nConfidence: high\nScope-risk: narrow\nTested: dotnet test tests/Neo.SymbolicExecutor.Tests/Neo.SymbolicExecutor.Tests.csproj --filter PublicPrivilegedMethod|DefiSlippageOracle|NftOwnershipAuthorization|DefaultDetectorSet_HasAllAuditDrivenDetectors|ProtocolRiskFindings_SerializeThroughJsonReport"
```

---

### Task 6: Update Documentation and Full Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README detector count and list**

Change these counts:

```markdown
| 21 detectors + framework | ~2,300 | 19 |
...
21 detectors are wired in `DefaultDetectorSet`:
```

to:

```markdown
| 24 detectors + framework | ~2,700 | 26 |
...
24 detectors are wired in `DefaultDetectorSet`:
```

Add these bullets to the detector list after `taint_flow_upgrade`:

```markdown
- `public_privileged_method` — manifest-exposed mint/burn/withdraw/upgrade-like entrypoints without early auth
- `defi_slippage_oracle` — swap-like token flows lacking min-out/slippage or oracle freshness signals
- `nft_ownership_authorization` — NEP-11 ownership/approval writes before owner/operator authorization
```

Update the total test count only after the full suite reports the final number.

- [ ] **Step 2: Run full verification**

Run:

```bash
dotnet build Neo.SymbolicExecutor.sln
dotnet test Neo.SymbolicExecutor.sln --no-build --logger "console;verbosity=minimal"
dotnet format Neo.SymbolicExecutor.sln --verify-no-changes --no-restore
git diff --check
```

Expected:

- build passes with `0 Error(s)`
- tests pass, with the new total count recorded for README
- format reports no changes
- diff check reports no whitespace errors

- [ ] **Step 3: Update README total test count if needed**

If the suite reports `171 passed`, update:

```markdown
| **Total** | **~12,700** | **164 passing** |
tests/Neo.SymbolicExecutor.Tests/    — xUnit + FluentAssertions, 164 tests total
```

to:

```markdown
| **Total** | **~13,100** | **171 passing** |
tests/Neo.SymbolicExecutor.Tests/    — xUnit + FluentAssertions, 171 tests total
```

- [ ] **Step 4: Run README/package sanity if package metadata is dirty in this workspace**

Run:

```bash
dotnet pack Neo.SymbolicExecutor.sln -c Release --no-build
```

Expected: PASS.

- [ ] **Step 5: Commit docs and verification updates**

```bash
git add README.md
git commit -m "Document Neo protocol-risk detector coverage" -m "The README needs to reflect the expanded default detector pack and the final verified test count." -m "Constraint: Documentation must not claim generic EVM support\nConfidence: high\nScope-risk: narrow\nTested: dotnet build Neo.SymbolicExecutor.sln; dotnet test Neo.SymbolicExecutor.sln --no-build; dotnet format Neo.SymbolicExecutor.sln --verify-no-changes --no-restore; git diff --check"
```

---

## Self-Review

- Spec coverage: the plan implements detector-pack expansion, no new dependencies, manifest/telemetry-only logic, default registration, tests, docs, and full verification.
- Placeholder scan: no unresolved marker text is present. Test counts are explicitly tied to the full test run result.
- Type consistency: detector names, class names, helper method names, and test names are consistent across tasks.
- Scope check: this remains a single coherent detector-pack implementation and does not attempt EVM bytecode support or engine-wide taint overhaul.

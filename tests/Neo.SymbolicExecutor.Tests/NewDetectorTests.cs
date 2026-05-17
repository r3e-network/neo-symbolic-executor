using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Pinned behavior for the Iter-3 coverage-pass detectors. Each detector ships a positive
/// (fires when it should) and a negative (silent when behavior is OK) case so future engine
/// telemetry refactors surface drift immediately.
/// </summary>
public class NewDetectorTests
{
    private static AnalysisContext Ctx(ExecutionState state, Nef.ContractManifest? manifest = null) =>
        new() { States = new[] { state }, Manifest = manifest };

    private static ExecutionState NewState()
    {
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        return s;
    }

    // ---- entry_script_auth -----------------------------------------------------------

    [Fact]
    public void EntryScriptAuth_FlagsWhenSymbolGatesPathReachingWrite()
    {
        var s = NewState();
        // Path-condition: GetEntryScriptHash result equality (the exact comparison shape is
        // irrelevant — the detector trips on the symbol's appearance in any branch).
        var entrySym = SymbolicValue.Symbol(Sort.Bytes, "System.Runtime.GetEntryScriptHash_16");
        var owner = SymbolicValue.Bytes(new byte[20]);
        s.PathConditions = s.PathConditions.Add(Expr.Eq(entrySym.Expression, owner.Expression));
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        var findings = new EntryScriptAuthDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("tx-origin-equivalent");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void EntryScriptAuth_SilentWhenCallingScriptHashUsedInstead()
    {
        var s = NewState();
        var callerSym = SymbolicValue.Symbol(Sort.Bytes, "caller_hash_16");
        var owner = SymbolicValue.Bytes(new byte[20]);
        s.PathConditions = s.PathConditions.Add(Expr.Eq(callerSym.Expression, owner.Expression));
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        new EntryScriptAuthDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void EntryScriptAuth_SilentWhenNoSensitiveOps()
    {
        // Pure read-only methods comparing entry script hash for read-side decisions are not
        // sensitive (no storage write or external call to gate). The detector skips them.
        var s = NewState();
        var entrySym = SymbolicValue.Symbol(Sort.Bytes, "System.Runtime.GetEntryScriptHash_16");
        s.PathConditions = s.PathConditions.Add(Expr.Eq(entrySym.Expression, SymbolicValue.Bytes(new byte[20]).Expression));

        new EntryScriptAuthDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    // ---- unsafe_deserialization ------------------------------------------------------

    [Fact]
    public void UnsafeDeserialization_FlagsStdLibDeserializeOfMethodArg()
    {
        var s = NewState();
        var stdLibHash = System.Convert.FromHexString("acce6fd80d44e1796aa0c2c625e9e4e0ce39efc0");
        var arg = SymbolicValue.Symbol(Sort.Bytes, "arg_blob");
        var call = new ExternalCall
        {
            Offset = 0x30,
            Method = "deserialize",
            TargetHash = SymbolicValue.Bytes(stdLibHash),
            HasReturnValue = true,
        };
        call.Args.Add(arg);
        s.Telemetry.ExternalCalls.Add(call);

        var findings = new UnsafeDeserializationDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("unsafe-deserialization");
        findings[0].Description.Should().Contain("method argument");
    }

    [Fact]
    public void UnsafeDeserialization_FlagsStorageValueAsUntrusted()
    {
        var s = NewState();
        var stdLibHash = System.Convert.FromHexString("acce6fd80d44e1796aa0c2c625e9e4e0ce39efc0");
        var fromStorage = SymbolicValue.Symbol(Sort.Bytes, "storage_value_50");
        var call = new ExternalCall
        {
            Offset = 0x40,
            Method = "jsonDeserialize",
            TargetHash = SymbolicValue.Bytes(stdLibHash),
            HasReturnValue = true,
        };
        call.Args.Add(fromStorage);
        s.Telemetry.ExternalCalls.Add(call);

        var findings = new UnsafeDeserializationDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("storage value");
    }

    [Fact]
    public void UnsafeDeserialization_SilentForConcreteInput()
    {
        // A deserialize call whose argument is a concrete BytesConst (e.g. a constant literal
        // baked into the contract) is not attacker-controlled.
        var s = NewState();
        var stdLibHash = System.Convert.FromHexString("acce6fd80d44e1796aa0c2c625e9e4e0ce39efc0");
        var literalBytes = SymbolicValue.Bytes(new byte[] { 0x40, 0x00 });
        var call = new ExternalCall
        {
            Offset = 0x30,
            Method = "deserialize",
            TargetHash = SymbolicValue.Bytes(stdLibHash),
            HasReturnValue = true,
        };
        call.Args.Add(literalBytes);
        s.Telemetry.ExternalCalls.Add(call);

        new UnsafeDeserializationDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void UnsafeDeserialization_SilentForNonStdLibTarget()
    {
        // A user-contract method coincidentally named "deserialize" is not the same risk class
        // as StdLib.deserialize. Don't fire when the target hash points elsewhere.
        var s = NewState();
        var userHash = System.Convert.FromHexString("1111111111111111111111111111111111111111");
        var call = new ExternalCall
        {
            Offset = 0x30,
            Method = "deserialize",
            TargetHash = SymbolicValue.Bytes(userHash),
            HasReturnValue = true,
        };
        call.Args.Add(SymbolicValue.Symbol(Sort.Bytes, "arg0"));
        s.Telemetry.ExternalCalls.Add(call);

        new UnsafeDeserializationDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    // ---- unprotected_deploy ----------------------------------------------------------

    [Fact]
    public void UnprotectedDeploy_FlagsWhenUpdateArgNeverBranchedOn()
    {
        var s = NewState();
        s.Path.Add(0xC0);  // entry: _deploy at 0xC0
        s.Telemetry.StorageOps.Add(new StorageOp(0xC4, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 0x4F }), SymbolicValue.Bytes(new byte[20]), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":[],
          "abi":{"methods":[
            {"name":"_deploy","parameters":[
              {"name":"data","type":"Any"},
              {"name":"update","type":"Boolean"}
            ],"returntype":"Void","offset":192,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        var findings = new UnprotectedDeployDetector().Analyze(Ctx(s, manifest)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("upgrade-hijack");
    }

    [Fact]
    public void UnprotectedDeploy_SilentWhenUpdateArgBranchesOnPath()
    {
        var s = NewState();
        s.Path.Add(0xC0);
        s.PathConditions = s.PathConditions.Add(
            Expr.Eq(SymbolicValue.Symbol(Sort.Bool, "arg_update").Expression, BoolConst.False));
        s.Telemetry.StorageOps.Add(new StorageOp(0xC4, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 0x4F }), SymbolicValue.Bytes(new byte[20]), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":[],
          "abi":{"methods":[
            {"name":"_deploy","parameters":[
              {"name":"data","type":"Any"},
              {"name":"update","type":"Boolean"}
            ],"returntype":"Void","offset":192,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        new UnprotectedDeployDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }

    [Fact]
    public void UnprotectedDeploy_SilentWhenNoDeployMethodDeclared()
    {
        var s = NewState();
        s.Path.Add(0x10);

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":[],
          "abi":{"methods":[
            {"name":"transfer","parameters":[],"returntype":"Boolean","offset":16,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        new UnprotectedDeployDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }

    // ---- nep17_amount_validation -----------------------------------------------------

    [Fact]
    public void Nep17AmountValidation_FlagsWhenAmountArgNeverBranchedOn()
    {
        var s = NewState();
        s.Path.Add(0xD0);  // entry: transfer at 0xD0
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("balance_from")),
            SymbolicValue.Int(0), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":["NEP-17"],
          "abi":{"methods":[
            {"name":"transfer","parameters":[
              {"name":"from","type":"Hash160"},
              {"name":"to","type":"Hash160"},
              {"name":"amount","type":"Integer"},
              {"name":"data","type":"Any"}
            ],"returntype":"Boolean","offset":208,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        var findings = new Nep17AmountValidationDetector().Analyze(Ctx(s, manifest)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("nep17");
        findings[0].Tags.Should().Contain("amount-validation");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Nep17AmountValidation_SilentWhenAmountIsCheckedOnPath()
    {
        var s = NewState();
        s.Path.Add(0xD0);
        // Amount appears in a branch (any branch suffices; a real transfer typically does
        // `if (amount < 0) throw;` near the top of the body).
        s.PathConditions = s.PathConditions.Add(
            Expr.Ge(SymbolicValue.Symbol(Sort.Int, "arg_amount").Expression, Expr.Int(0)));
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("balance_from")),
            SymbolicValue.Int(0), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":["NEP-17"],
          "abi":{"methods":[
            {"name":"transfer","parameters":[
              {"name":"from","type":"Hash160"},
              {"name":"to","type":"Hash160"},
              {"name":"amount","type":"Integer"},
              {"name":"data","type":"Any"}
            ],"returntype":"Boolean","offset":208,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        new Nep17AmountValidationDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }

    [Fact]
    public void Nep17AmountValidation_SilentWhenStateNeverWrites()
    {
        // A view-style codepath (e.g. balanceOf called via transfer's input-validation prelude)
        // that reverts before writing must not surface a finding — there's no balance to drain.
        var s = NewState();
        s.Path.Add(0xD0);
        // No StorageOps with Put/Delete.

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":["NEP-17"],
          "abi":{"methods":[
            {"name":"transfer","parameters":[
              {"name":"from","type":"Hash160"},
              {"name":"to","type":"Hash160"},
              {"name":"amount","type":"Integer"},
              {"name":"data","type":"Any"}
            ],"returntype":"Boolean","offset":208,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        new Nep17AmountValidationDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }

    [Fact]
    public void Nep17AmountValidation_SilentWhenContractDoesNotDeclareNep17()
    {
        var s = NewState();
        s.Path.Add(0xD0);
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(0), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":[],
          "abi":{"methods":[
            {"name":"transfer","parameters":[
              {"name":"from","type":"Hash160"},
              {"name":"to","type":"Hash160"},
              {"name":"amount","type":"Integer"},
              {"name":"data","type":"Any"}
            ],"returntype":"Boolean","offset":208,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        // Non-NEP-17 contracts use whatever transfer semantics they want — out of scope.
        new Nep17AmountValidationDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }
}

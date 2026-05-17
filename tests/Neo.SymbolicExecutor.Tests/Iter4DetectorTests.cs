using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Pinned behavior for the Iter-4 coverage-pass detectors (signature malleability, NEP-17
/// zero address, NEP-17 transfer-to-self, oracle response validation, TOCTOU storage).
/// Each detector ships a positive (fires when it should) and a negative (silent when behavior
/// is OK) case.
/// </summary>
public class Iter4DetectorTests
{
    private static AnalysisContext Ctx(ExecutionState state, Nef.ContractManifest? manifest = null) =>
        new() { States = new[] { state }, Manifest = manifest };

    private static ExecutionState NewState()
    {
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        return s;
    }

    // ---- signature_malleability -----------------------------------------------------

    [Fact]
    public void SignatureMalleability_FlagsSigArgUsedAsStorageKey()
    {
        var s = NewState();
        s.Telemetry.SignatureChecks.Add(0x10);
        var sigKey = SymbolicValue.Symbol(Sort.Bytes, "arg_signature");
        s.Telemetry.StorageOps.Add(new StorageOp(0x40, StorageOpKind.Put,
            sigKey, SymbolicValue.Bool(true), false, false));

        var findings = new SignatureMalleabilityDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("signature-malleability");
    }

    [Fact]
    public void SignatureMalleability_SilentWhenNoSignatureCheck()
    {
        var s = NewState();
        var sigKey = SymbolicValue.Symbol(Sort.Bytes, "arg_signature");
        s.Telemetry.StorageOps.Add(new StorageOp(0x40, StorageOpKind.Put,
            sigKey, SymbolicValue.Bool(true), false, false));

        new SignatureMalleabilityDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void SignatureMalleability_SilentWhenKeyIsNotSignatureArg()
    {
        var s = NewState();
        s.Telemetry.SignatureChecks.Add(0x10);
        var keyFromNonce = SymbolicValue.Symbol(Sort.Bytes, "arg_nonce");
        s.Telemetry.StorageOps.Add(new StorageOp(0x40, StorageOpKind.Put,
            keyFromNonce, SymbolicValue.Bool(true), false, false));

        new SignatureMalleabilityDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    // ---- nep17_zero_address ---------------------------------------------------------

    [Fact]
    public void Nep17ZeroAddress_FlagsWhenNeitherFromNorToChecked()
    {
        var s = NewState();
        s.Path.Add(0xD0);
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(0), false, false));

        var manifest = TransferManifest("NEP-17", "from", "to", "amount", "data");
        var findings = new Nep17ZeroAddressDetector().Analyze(Ctx(s, manifest)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("zero-address");
        findings[0].Description.Should().Contain("from").And.Contain("to");
    }

    [Fact]
    public void Nep17ZeroAddress_FlagsWhenOnlyOneSideChecked()
    {
        var s = NewState();
        s.Path.Add(0xD0);
        // Only `from` is checked.
        s.PathConditions = s.PathConditions.Add(
            new BinaryExpr(Sort.Bool, "len_eq",
                SymbolicValue.Symbol(Sort.Bytes, "arg_from").Expression,
                Expr.Int(20)));
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(0), false, false));

        var manifest = TransferManifest("NEP-17", "from", "to", "amount", "data");
        var findings = new Nep17ZeroAddressDetector().Analyze(Ctx(s, manifest)).ToList();
        findings.Should().ContainSingle();
        findings[0].Description.Should().Contain("to").And.NotContain("from /");
    }

    [Fact]
    public void Nep17ZeroAddress_SilentWhenBothChecked()
    {
        var s = NewState();
        s.Path.Add(0xD0);
        s.PathConditions = s.PathConditions
            .Add(new BinaryExpr(Sort.Bool, "len_eq", SymbolicValue.Symbol(Sort.Bytes, "arg_from").Expression, Expr.Int(20)))
            .Add(new BinaryExpr(Sort.Bool, "len_eq", SymbolicValue.Symbol(Sort.Bytes, "arg_to").Expression, Expr.Int(20)));
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(0), false, false));

        var manifest = TransferManifest("NEP-17", "from", "to", "amount", "data");
        new Nep17ZeroAddressDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }

    // ---- nep17_transfer_to_self -----------------------------------------------------

    [Fact]
    public void TransferToSelf_FlagsWhenFromToRelationshipNotGated()
    {
        var s = NewState();
        s.Path.Add(0xD0);
        // Two writes — one keyed on `from`, one keyed on `to` — representing the canonical
        // balance[from] -= amount; balance[to] += amount sequence.
        var fromKey = new BinaryExpr(Sort.Bytes, "concat",
            new BytesConst(new byte[] { 0x01 }),
            SymbolicValue.Symbol(Sort.Bytes, "arg_from").Expression);
        var toKey = new BinaryExpr(Sort.Bytes, "concat",
            new BytesConst(new byte[] { 0x01 }),
            SymbolicValue.Symbol(Sort.Bytes, "arg_to").Expression);
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            SymbolicValue.Of(fromKey), SymbolicValue.Int(0), false, false));
        s.Telemetry.StorageOps.Add(new StorageOp(0xD8, StorageOpKind.Put,
            SymbolicValue.Of(toKey), SymbolicValue.Int(0), false, false));

        var manifest = TransferManifest("NEP-17", "from", "to", "amount", "data");
        var findings = new Nep17TransferToSelfDetector().Analyze(Ctx(s, manifest)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("transfer-to-self");
    }

    [Fact]
    public void TransferToSelf_SilentWhenFromEqualsToBranched()
    {
        var s = NewState();
        s.Path.Add(0xD0);
        // Path condition relates from and to (any branch involving both symbols is sufficient).
        s.PathConditions = s.PathConditions.Add(
            Expr.Eq(
                SymbolicValue.Symbol(Sort.Bytes, "arg_from").Expression,
                SymbolicValue.Symbol(Sort.Bytes, "arg_to").Expression));
        var fromKey = new BinaryExpr(Sort.Bytes, "concat",
            new BytesConst(new byte[] { 0x01 }),
            SymbolicValue.Symbol(Sort.Bytes, "arg_from").Expression);
        var toKey = new BinaryExpr(Sort.Bytes, "concat",
            new BytesConst(new byte[] { 0x01 }),
            SymbolicValue.Symbol(Sort.Bytes, "arg_to").Expression);
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            SymbolicValue.Of(fromKey), SymbolicValue.Int(0), false, false));
        s.Telemetry.StorageOps.Add(new StorageOp(0xD8, StorageOpKind.Put,
            SymbolicValue.Of(toKey), SymbolicValue.Int(0), false, false));

        var manifest = TransferManifest("NEP-17", "from", "to", "amount", "data");
        new Nep17TransferToSelfDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }

    [Fact]
    public void TransferToSelf_SilentWhenOnlyOneArgUsedAsKey()
    {
        // Mint-style transfer that only writes the recipient slot doesn't have the canonical
        // debit-credit-on-stale-state bug; this detector intentionally requires both symbols
        // in storage keys.
        var s = NewState();
        s.Path.Add(0xD0);
        var toKey = SymbolicValue.Symbol(Sort.Bytes, "arg_to");
        s.Telemetry.StorageOps.Add(new StorageOp(0xD4, StorageOpKind.Put,
            toKey, SymbolicValue.Int(0), false, false));

        var manifest = TransferManifest("NEP-17", "from", "to", "amount", "data");
        new Nep17TransferToSelfDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }

    // ---- oracle_response_validation -------------------------------------------------

    [Fact]
    public void OracleResponse_FlagsWhenCodeNotChecked()
    {
        var s = NewState();
        s.Path.Add(0xE0);  // entry: onOracleResponse at 0xE0
        s.Telemetry.StorageOps.Add(new StorageOp(0xE4, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("price")),
            SymbolicValue.Symbol(Sort.Bytes, "arg_result"), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":[],
          "abi":{"methods":[
            {"name":"onOracleResponse","parameters":[
              {"name":"url","type":"String"},
              {"name":"userdata","type":"Any"},
              {"name":"code","type":"Integer"},
              {"name":"result","type":"ByteArray"}
            ],"returntype":"Void","offset":224,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        var findings = new OracleResponseValidationDetector().Analyze(Ctx(s, manifest)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("oracle");
        findings[0].Tags.Should().Contain("missing-code-check");
    }

    [Fact]
    public void OracleResponse_SilentWhenCodeBranched()
    {
        var s = NewState();
        s.Path.Add(0xE0);
        s.PathConditions = s.PathConditions.Add(
            Expr.Eq(SymbolicValue.Symbol(Sort.Int, "arg_code").Expression, Expr.Int(0)));
        s.Telemetry.StorageOps.Add(new StorageOp(0xE4, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("price")),
            SymbolicValue.Symbol(Sort.Bytes, "arg_result"), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":[],
          "abi":{"methods":[
            {"name":"onOracleResponse","parameters":[
              {"name":"url","type":"String"},
              {"name":"userdata","type":"Any"},
              {"name":"code","type":"Integer"},
              {"name":"result","type":"ByteArray"}
            ],"returntype":"Void","offset":224,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        new OracleResponseValidationDetector().Analyze(Ctx(s, manifest)).Should().BeEmpty();
    }

    // ---- toctou_storage -------------------------------------------------------------

    [Fact]
    public void Toctou_FlagsReadCallWriteWhenWriteValueDerivesFromRead()
    {
        var s = NewState();
        // Storage.Get at offset 0x10 emits symbol "storage_value_16".
        s.Telemetry.StorageOps.Add(new StorageOp(0x10, StorageOpKind.Get,
            SymbolicValue.Bytes(new byte[] { 1 }), null, false, false));
        // External call at 0x20.
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x20,
            Method = "callExternal",
            HasReturnValue = true,
        });
        // Storage.Put at 0x30 whose value contains the read symbol.
        var newValue = SymbolicValue.Of(
            new BinaryExpr(Sort.Int, "add",
                SymbolicValue.Symbol(Sort.Int, "storage_value_16").Expression,
                Expr.Int(1)));
        s.Telemetry.StorageOps.Add(new StorageOp(0x30, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), newValue, false, false));

        var findings = new ToctouStorageDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("toctou");
        findings[0].Offset.Should().Be(0x20);
    }

    [Fact]
    public void Toctou_SilentWhenExternalCallIsBenignNative()
    {
        var s = NewState();
        s.Telemetry.StorageOps.Add(new StorageOp(0x10, StorageOpKind.Get,
            SymbolicValue.Bytes(new byte[] { 1 }), null, false, false));
        // Ledger.getBlock is a benign read-only native — cannot re-enter / mutate any storage.
        var ledgerHash = System.Convert.FromHexString("da65b600f7124ce6c79950c1772a36403104f2be");
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x20,
            Method = "getBlock",
            TargetHash = SymbolicValue.Bytes(ledgerHash),
            HasReturnValue = true,
        });
        var newValue = SymbolicValue.Of(
            new BinaryExpr(Sort.Int, "add",
                SymbolicValue.Symbol(Sort.Int, "storage_value_16").Expression,
                Expr.Int(1)));
        s.Telemetry.StorageOps.Add(new StorageOp(0x30, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), newValue, false, false));

        new ToctouStorageDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void Toctou_SilentWhenWriteValueDoesNotDependOnRead()
    {
        var s = NewState();
        s.Telemetry.StorageOps.Add(new StorageOp(0x10, StorageOpKind.Get,
            SymbolicValue.Bytes(new byte[] { 1 }), null, false, false));
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x20,
            Method = "callExternal",
            HasReturnValue = true,
        });
        // Write value is a constant, independent of the read.
        s.Telemetry.StorageOps.Add(new StorageOp(0x30, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(42), false, false));

        new ToctouStorageDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    // ---- helpers --------------------------------------------------------------------

    private static Nef.ContractManifest TransferManifest(string standard, string from, string to, string amount, string data)
    {
        string json = $$"""
        {
          "name":"X","groups":[],"features":{},"supportedstandards":["{{standard}}"],
          "abi":{"methods":[
            {"name":"transfer","parameters":[
              {"name":"{{from}}","type":"Hash160"},
              {"name":"{{to}}","type":"Hash160"},
              {"name":"{{amount}}","type":"Integer"},
              {"name":"{{data}}","type":"Any"}
            ],"returntype":"Boolean","offset":208,"safe":false}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        return Nef.ContractManifest.FromJson(json);
    }
}

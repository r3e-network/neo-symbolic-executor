using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;

namespace Neo.SymbolicExecutor.Tests;

public class AdditionalDetectorTests
{
    private static AnalysisContext Ctx(params ExecutionState[] states) =>
        new() { States = states };

    private static ExecutionState NewState()
    {
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        return s;
    }

    [Fact]
    public void DangerousCallFlags_FlagsCallFlagsAll()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "x", CallFlags = 0x0F, HasReturnValue = true });
        var f = new DangerousCallFlagsDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.High);
        f[0].Tags.Should().Contain("callflags-all");
    }

    [Fact]
    public void DangerousCallFlags_FlagsBroadFlagsBitcountThree()
    {
        var s = NewState();
        // 0x07 = WriteStates|AllowCall|AllowNotify (3 bits) — audit fix: should fire even though != 0x0F.
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "x", CallFlags = 0x07, HasReturnValue = true });
        var f = new DangerousCallFlagsDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.Medium);
        f[0].Tags.Should().Contain("broad-call-flags");
    }

    [Fact]
    public void Dos_FlagsDeepRecursion()
    {
        var s = NewState();
        s.Telemetry.MaxCallStackDepth = 16;
        var f = new DosDetector().Analyze(Ctx(s)).ToList();
        f.Should().Contain(x => x.Tags.Contains("recursion-dos"));
    }

    [Fact]
    public void Randomness_FlagsTimestampInPathCondition()
    {
        var s = NewState();
        s.Telemetry.TimeAccesses.Add(0x10);
        // Review fix (#17): HIGH weak-randomness requires the timestamp to feed an entropy-shaped op
        // (modulo/bitwise-AND/shift) — the signature of "derive entropy from time" — e.g.
        // `timestamp % N`. A bare timestamp comparison (deadline/time-lock) is only an Info advisory.
        s.PathConditions = s.PathConditions.Add(Expr.Eq(
            Expr.Mod(Expr.Sym(Sort.Int, "timestamp"), Expr.Int(100)),
            Expr.Int(0)));
        var f = new RandomnessDetector().Analyze(Ctx(s)).ToList();
        f.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("weak-randomness"));
    }

    [Fact]
    public void Randomness_BareTimestampBranchIsInfoNotHigh()
    {
        var s = NewState();
        s.Telemetry.TimeAccesses.Add(0x10);
        // Review fix (#17): a bare timestamp comparison (e.g. a deadline / time-lock check) is a
        // benign use of block time, surfaced as an Info advisory rather than a HIGH false positive.
        s.PathConditions = s.PathConditions.Add(Expr.Eq(Expr.Sym(Sort.Int, "timestamp"), Expr.Int(123)));
        var f = new RandomnessDetector().Analyze(Ctx(s)).ToList();
        f.Should().Contain(x => x.Severity == Severity.Info && x.Tags.Contains("timestamp-branch"));
        f.Should().NotContain(x => x.Severity == Severity.High && x.Tags.Contains("weak-randomness"));
    }

    [Fact]
    public void Randomness_GetRandomIsInfo_NotMedium()
    {
        // Audit fix: GetRandom is Neo N3's secure VRF; should be INFO, not MEDIUM.
        var s = NewState();
        s.Telemetry.RandomnessAccesses.Add(0x20);
        var f = new RandomnessDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle(x => x.Severity == Severity.Info && x.Tags.Contains("vrf"));
    }

    [Fact]
    public void Upgradeability_CriticalWithoutAuth()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "update", HasReturnValue = false });
        var f = new UpgradeabilityDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Upgradeability_HighWhenAuthEnforced()
    {
        var s = NewState();
        s.Telemetry.WitnessChecksEnforced.Add(0x05);
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "destroy", HasReturnValue = false });
        var f = new UpgradeabilityDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Upgradeability_HighWhenCallerHashChecked()
    {
        // Precision fix: a contract that gates `update` with `GetCallingScriptHash() == ADMIN`
        // is legitimately auth-gated; severity should downgrade from Critical to High. Prior
        // implementation omitted CallerHashChecks from the predicate and flagged Critical.
        var s = NewState();
        s.Telemetry.CallerHashChecks.Add(0x05);
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "update", HasReturnValue = false });
        var f = new UpgradeabilityDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Upgradeability_HighWhenSignatureChecked()
    {
        var s = NewState();
        s.Telemetry.SignatureChecks.Add(0x05);
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "update", HasReturnValue = false });
        var f = new UpgradeabilityDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Permissions_FlagsFullWildcard()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"X","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[],"events":[]},
             "permissions":[{"contract":"*","methods":"*"}],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new PermissionsDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("permissions-wildcard"));
    }

    [Fact]
    public void Permissions_FlagsTrustsWildcard()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"X","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[],"events":[]},
             "permissions":[],"trusts":"*"}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new PermissionsDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Tags.Contains("trusts-wildcard"));
    }

    [Fact]
    public void Permissions_FlagsPartialWildcardSpecificContractAnyMethod()
    {
        // Permission contract=specific, methods="*" — partial wildcard, severity Medium not High.
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"X","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[],"events":[]},
             "permissions":[{"contract":"0x1111111111111111111111111111111111111111","methods":"*"}],
             "trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new PermissionsDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Severity == Severity.Medium && x.Tags.Contains("permissions-partial-wildcard"));
        f.Should().NotContain(x => x.Tags.Contains("permissions-wildcard"));
    }

    [Fact]
    public void Permissions_FlagsPartialWildcardAnyContractSpecificMethod()
    {
        // Permission contract="*", methods=[specific] — also partial wildcard.
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"X","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[],"events":[]},
             "permissions":[{"contract":"*","methods":["transfer"]}],
             "trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new PermissionsDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Tags.Contains("permissions-partial-wildcard"));
    }

    [Fact]
    public void Permissions_FlagsGroupWithEmptyPubKey()
    {
        // Audit detector audit #9 lineage: a group entry without a cryptographically-pinned
        // pubkey is a permission-grant for any signer claiming membership.
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"X",
             "groups":[{"pubkey":"","signature":""}],
             "features":{},"supportedstandards":[],
             "abi":{"methods":[],"events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new PermissionsDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("group-misconfigured"));
    }

    [Fact]
    public void Nep17_FiresWhenStandardDeclaredButMethodMissing()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-17"],
             "abi":{"methods":[{"name":"transfer","parameters":[],"returntype":"Boolean","offset":0,"safe":false}],
                    "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new Nep17ComplianceDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Title.Contains("symbol"));
        f.Should().Contain(x => x.Title.Contains("balanceOf"));
        f.Should().Contain(x => x.Title.Contains("Transfer event"));
    }

    [Fact]
    public void Nep17_FiresWhenStandardDeclaredWithoutHyphen()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["Nep17"],
             "abi":{"methods":[{"name":"transfer","parameters":[],"returntype":"Boolean","offset":0,"safe":false}],
                    "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        new Nep17ComplianceDetector().Analyze(ctx).Should()
            .Contain(x => x.Title.Contains("symbol"));
    }

    [Fact]
    public void Nep11_FiresOnlyWhenStandardDeclared()
    {
        var nep17Only = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-17"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctxNo = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = nep17Only };
        new Nep11ComplianceDetector().Analyze(ctxNo).Should().BeEmpty();

        var nep11 = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-11"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctxYes = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = nep11 };
        new Nep11ComplianceDetector().Analyze(ctxYes).Should().NotBeEmpty();
    }

    [Fact]
    public void Nep11_FlagsMissingOwnerOfForDeclaredStandard()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"NFT","groups":[],"features":{},"supportedstandards":["NEP-11"],
             "abi":{
               "methods":[
                 {"name":"symbol","parameters":[],"returntype":"String","offset":0,"safe":true},
                 {"name":"decimals","parameters":[],"returntype":"Integer","offset":1,"safe":true},
                 {"name":"totalSupply","parameters":[],"returntype":"Integer","offset":2,"safe":true},
                 {"name":"balanceOf","parameters":[{"name":"owner","type":"Hash160"}],"returntype":"Integer","offset":3,"safe":true},
                 {"name":"tokensOf","parameters":[{"name":"owner","type":"Hash160"}],"returntype":"InteropInterface","offset":4,"safe":true},
                 {"name":"transfer","parameters":[
                   {"name":"to","type":"Hash160"},
                   {"name":"tokenId","type":"ByteString"},
                   {"name":"data","type":"Any"}
                 ],"returntype":"Boolean","offset":5,"safe":false}
               ],
               "events":[{"name":"Transfer","parameters":[
                 {"name":"from","type":"Hash160"},
                 {"name":"to","type":"Hash160"},
                 {"name":"amount","type":"Integer"},
                 {"name":"tokenId","type":"ByteString"}
               ]}]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep11ComplianceDetector().Analyze(ctx).ToList();

        findings.Should().Contain(x => x.Severity == Severity.High && x.Title.Contains("ownerOf"));
    }

    [Fact]
    public void Nep11_FlagsTransferEventWithExtraParameter()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"NFT","groups":[],"features":{},"supportedstandards":["NEP-11"],
             "abi":{
               "methods":[
                 {"name":"symbol","parameters":[],"returntype":"String","offset":0,"safe":true},
                 {"name":"decimals","parameters":[],"returntype":"Integer","offset":1,"safe":true},
                 {"name":"totalSupply","parameters":[],"returntype":"Integer","offset":2,"safe":true},
                 {"name":"balanceOf","parameters":[{"name":"owner","type":"Hash160"}],"returntype":"Integer","offset":3,"safe":true},
                 {"name":"ownerOf","parameters":[{"name":"tokenId","type":"ByteString"}],"returntype":"Hash160","offset":4,"safe":true},
                 {"name":"tokensOf","parameters":[{"name":"owner","type":"Hash160"}],"returntype":"InteropInterface","offset":5,"safe":true},
                 {"name":"transfer","parameters":[
                   {"name":"to","type":"Hash160"},
                   {"name":"tokenId","type":"ByteString"},
                   {"name":"data","type":"Any"}
                 ],"returntype":"Boolean","offset":6,"safe":false}
               ],
               "events":[{"name":"Transfer","parameters":[
                 {"name":"from","type":"Hash160"},
                 {"name":"to","type":"Hash160"},
                 {"name":"amount","type":"Integer"},
                 {"name":"tokenId","type":"ByteString"},
                 {"name":"memo","type":"String"}
               ]}]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep11ComplianceDetector().Analyze(ctx).ToList();

        findings.Should().ContainSingle(x => x.Severity == Severity.High && x.Tags.Contains("event-shape"));
    }

    [Fact]
    public void Nep11_UsesStandardOverloadsWhenNonstandardOverloadsAppearFirst()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"NFT","groups":[],"features":{},"supportedstandards":["NEP-11"],
             "abi":{
               "methods":[
                 {"name":"symbol","parameters":[],"returntype":"String","offset":0,"safe":true},
                 {"name":"decimals","parameters":[],"returntype":"Integer","offset":1,"safe":true},
                 {"name":"totalSupply","parameters":[],"returntype":"Integer","offset":2,"safe":true},
                 {"name":"balanceOf","parameters":[],"returntype":"Boolean","offset":3,"safe":false},
                 {"name":"balanceOf","parameters":[{"name":"owner","type":"Hash160"}],"returntype":"Integer","offset":4,"safe":true},
                 {"name":"ownerOf","parameters":[],"returntype":"Boolean","offset":5,"safe":false},
                 {"name":"ownerOf","parameters":[{"name":"tokenId","type":"ByteArray"}],"returntype":"Hash160","offset":6,"safe":true},
                 {"name":"tokensOf","parameters":[{"name":"owner","type":"Hash160"}],"returntype":"InteropInterface","offset":7,"safe":true},
                 {"name":"transfer","parameters":[],"returntype":"Boolean","offset":8,"safe":true},
                 {"name":"transfer","parameters":[
                   {"name":"to","type":"Hash160"},
                   {"name":"tokenId","type":"ByteArray"},
                   {"name":"data","type":"Any"}
                 ],"returntype":"Boolean","offset":9,"safe":false}
               ],
               "events":[{"name":"Transfer","parameters":[
                 {"name":"from","type":"Hash160"},
                 {"name":"to","type":"Hash160"},
                 {"name":"amount","type":"Integer"},
                 {"name":"tokenId","type":"ByteArray"}
               ]}]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep11ComplianceDetector().Analyze(ctx).ToList();

        findings.Count.Should().Be(0, "detectors should select the standard NEP-11 overload, not the first same-name method");
    }

    [Fact]
    public void Nep24_FiresWhenStandardDeclaredButMethodAndEventMissing()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-24"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep24ComplianceDetector().Analyze(ctx).ToList();

        findings.Should().Contain(x => x.Severity == Severity.High && x.Title.Contains("royaltyInfo"));
        findings.Should().Contain(x => x.Severity == Severity.High && x.Title.Contains("RoyaltiesTransferred"));
    }

    [Fact]
    public void Nep24_FlagsWrongRoyaltyInfoAndRoyaltiesTransferredShapes()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-24"],
             "abi":{
               "methods":[
                 {"name":"royaltyInfo","parameters":[
                   {"name":"tokenId","type":"Hash160"},
                   {"name":"royaltyToken","type":"Hash160"}
                 ],"returntype":"Map","offset":0,"safe":false}
               ],
               "events":[
                 {"name":"RoyaltiesTransferred","parameters":[
                   {"name":"royaltyToken","type":"Hash160"},
                   {"name":"royaltyRecipient","type":"Hash160"},
                   {"name":"buyer","type":"Hash160"},
                   {"name":"amount","type":"Integer"}
                 ]}
               ]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep24ComplianceDetector().Analyze(ctx).ToList();

        findings.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("method-shape"));
        findings.Should().Contain(x => x.Severity == Severity.Medium && x.Tags.Contains("safe-flag"));
        findings.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("event-shape"));
    }

    [Fact]
    public void Nep24_UsesValidRoyaltyInfoOverloadWhenBadOverloadAppearsFirst()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-24"],
             "abi":{
               "methods":[
                 {"name":"royaltyInfo","parameters":[],"returntype":"Map","offset":0,"safe":false},
                 {"name":"royaltyInfo","parameters":[
                   {"name":"tokenId","type":"ByteArray"},
                   {"name":"royaltyToken","type":"Hash160"},
                   {"name":"salePrice","type":"Integer"}
                 ],"returntype":"Array","offset":1,"safe":true}
               ],
               "events":[
                 {"name":"RoyaltiesTransferred","parameters":[
                   {"name":"royaltyToken","type":"Hash160"},
                   {"name":"royaltyRecipient","type":"Hash160"},
                   {"name":"buyer","type":"Hash160"},
                   {"name":"tokenId","type":"ByteArray"},
                   {"name":"amount","type":"Integer"}
                 ]}
               ]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep24ComplianceDetector().Analyze(ctx).ToList();

        // The valid royaltyInfo overload satisfies the standard shape, so no royaltyInfo
        // method-shape / safe-flag finding fires even though a malformed overload appears first.
        findings.Should().NotContain(x => x.Tags.Contains("method-shape"));
        findings.Should().NotContain(x => x.Tags.Contains("safe-flag"));
        // Review fix (#58): this manifest declares NEP-24 but not the NEP-11 base standard that
        // NEP-24 requires, so the detector now (correctly) emits base-standard/base-ABI findings.
        findings.Should().Contain(x => x.Tags.Contains("missing-base-standard") || x.Tags.Contains("missing-base-abi"));
    }

    [Fact]
    public void Nep24_FlagsSafeFalseAndRenamedStandardParameters()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-24"],
             "abi":{
               "methods":[
                 {"name":"royaltyInfo","parameters":[
                   {"name":"id","type":"ByteString"},
                   {"name":"asset","type":"Hash160"},
                   {"name":"price","type":"Integer"}
                 ],"returntype":"Array","offset":0,"safe":false}
               ],
               "events":[
                 {"name":"RoyaltiesTransferred","parameters":[
                   {"name":"asset","type":"Hash160"},
                   {"name":"recipient","type":"Hash160"},
                   {"name":"purchaser","type":"Hash160"},
                   {"name":"id","type":"ByteString"},
                   {"name":"value","type":"Integer"}
                 ]}
               ]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep24ComplianceDetector().Analyze(ctx).ToList();

        // safe=false fails the royaltyInfo shape (which requires safe=true), so both the safe-flag and
        // method-shape findings still fire.
        findings.Should().Contain(x => x.Severity == Severity.Medium && x.Tags.Contains("safe-flag"));
        findings.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("method-shape"));
        // Round-2 fix (#20): the RoyaltiesTransferred event has renamed but correctly-typed parameters,
        // which is now compliant (NEP standards fix parameter types/arity, not the author's parameter
        // names), so there is no event-shape finding.
        findings.Should().NotContain(x => x.Tags.Contains("event-shape"));
    }

    [Fact]
    public void Nep27_FiresWhenStandardDeclaredButPaymentCallbackMissing()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-27"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var finding = new Nep27ComplianceDetector().Analyze(ctx).Should().ContainSingle().Subject;

        finding.Severity.Should().Be(Severity.High);
        finding.Title.Should().Contain("onNEP17Payment");
        finding.Tags.Should().Contain("nep27");
    }

    [Fact]
    public void Nep27_FlagsWrongPaymentCallbackShape()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-27"],
             "abi":{
               "methods":[
                 {"name":"onNEP17Payment","parameters":[
                   {"name":"from","type":"ByteString"},
                   {"name":"amount","type":"Integer"}
                 ],"returntype":"Boolean","offset":0,"safe":true}
               ],
               "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep27ComplianceDetector().Analyze(ctx).ToList();

        findings.Should().ContainSingle(x => x.Severity == Severity.High && x.Tags.Contains("method-shape"));
    }

    [Fact]
    public void Nep27_UsesValidPaymentCallbackOverloadWhenBadOverloadAppearsFirst()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-27"],
             "abi":{
               "methods":[
                 {"name":"onNEP17Payment","parameters":[],"returntype":"Boolean","offset":0,"safe":true},
                 {"name":"onNEP17Payment","parameters":[
                   {"name":"from","type":"Hash160"},
                   {"name":"amount","type":"Integer"},
                   {"name":"data","type":"Any"}
                 ],"returntype":"Void","offset":1,"safe":false}
               ],
               "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep27ComplianceDetector().Analyze(ctx).ToList();

        findings.Count.Should().Be(0, "the valid NEP-27 callback overload should satisfy the standard shape");
    }

    [Fact]
    public void Nep27_AcceptsRenamedPaymentCallbackParametersWithCorrectTypes()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-27"],
             "abi":{
               "methods":[
                 {"name":"onNEP17Payment","parameters":[
                   {"name":"sender","type":"Hash160"},
                   {"name":"value","type":"Integer"},
                   {"name":"payload","type":"Any"}
                 ],"returntype":"Void","offset":0,"safe":false}
               ],
               "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep27ComplianceDetector().Analyze(ctx).ToList();

        // Round-2 fix (#20): NEP standards fix the method name, parameter TYPES, arity, return type,
        // and Safe flag — NOT the author's parameter identifiers (dispatch is by name+arity). A
        // spec-compliant onNEP17Payment that renames its parameters (sender/value/payload instead of
        // from/amount/data) with correct types must NOT be flagged as a shape violation.
        findings.Should().NotContain(x => x.Tags.Contains("method-shape"));
    }

    [Fact]
    public void Nep26_FiresWhenStandardDeclaredButPaymentCallbackMissing()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-26"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var finding = new Nep26ComplianceDetector().Analyze(ctx).Should().ContainSingle().Subject;

        finding.Severity.Should().Be(Severity.High);
        finding.Title.Should().Contain("onNEP11Payment");
        finding.Tags.Should().Contain("nep26");
    }

    [Fact]
    public void Nep26_FlagsWrongPaymentCallbackShape()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-26"],
             "abi":{
               "methods":[
                 {"name":"onNEP11Payment","parameters":[
                   {"name":"from","type":"Hash160"},
                   {"name":"tokenId","type":"ByteString"},
                   {"name":"data","type":"Any"}
                 ],"returntype":"Void","offset":0,"safe":false}
               ],
               "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep26ComplianceDetector().Analyze(ctx).ToList();

        findings.Should().ContainSingle(x => x.Severity == Severity.High && x.Tags.Contains("method-shape"));
    }

    [Fact]
    public void Nep26_UsesValidPaymentCallbackOverloadWhenBadOverloadAppearsFirst()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-26"],
             "abi":{
               "methods":[
                 {"name":"onNEP11Payment","parameters":[],"returntype":"Boolean","offset":0,"safe":true},
                 {"name":"onNEP11Payment","parameters":[
                   {"name":"from","type":"Hash160"},
                   {"name":"amount","type":"Integer"},
                   {"name":"tokenId","type":"String"},
                   {"name":"data","type":"Any"}
                 ],"returntype":"Void","offset":1,"safe":false}
               ],
               "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep26ComplianceDetector().Analyze(ctx).ToList();

        findings.Count.Should().Be(0, "the valid NEP-26 callback overload should satisfy the standard shape");
    }

    [Fact]
    public void Nep26_AcceptsRenamedPaymentCallbackParametersWithCorrectTypes()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-26"],
             "abi":{
               "methods":[
                 {"name":"onNEP11Payment","parameters":[
                   {"name":"sender","type":"Hash160"},
                   {"name":"value","type":"Integer"},
                   {"name":"id","type":"String"},
                   {"name":"payload","type":"Any"}
                 ],"returntype":"Void","offset":0,"safe":false}
               ],
               "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep26ComplianceDetector().Analyze(ctx).ToList();

        // Round-2 fix (#20): a spec-compliant onNEP11Payment with correct parameter TYPES (Hash160,
        // Integer, String-as-tokenId, Any), arity, return type, and safe flag must NOT be flagged just
        // because the author renamed the parameters (sender/value/id/payload).
        findings.Should().NotContain(x => x.Tags.Contains("method-shape"));
    }

    [Fact]
    public void Nep26_AllowsReleasedCSharpStringTokenIdCallbackShape()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Receiver","groups":[],"features":{},"supportedstandards":["NEP-26"],
             "abi":{
               "methods":[
                 {"name":"onNEP11Payment","parameters":[
                   {"name":"from","type":"Hash160"},
                   {"name":"amount","type":"Integer"},
                   {"name":"tokenId","type":"String"},
                   {"name":"data","type":"Any"}
                 ],"returntype":"Void","offset":0,"safe":false}
               ],
               "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new Nep26ComplianceDetector().Analyze(ctx).ToList();

        findings.Count.Should().Be(0, "Neo.SmartContract.Framework 3.9.x declared INEP26 tokenId as C# string");
    }

    [Fact]
    public void SupportedStandardsCoverage_FlagsStandardsWithoutDedicatedRules()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-99"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var finding = new SupportedStandardsCoverageDetector().Analyze(ctx).Should().ContainSingle().Subject;
        finding.Severity.Should().Be(Severity.Info);
        finding.Title.Should().Contain("NEP-99");
        finding.Tags.Should().Contain("standard-coverage");
    }

    [Fact]
    public void SupportedStandardsCoverage_DoesNotFlagProofGradeKnownNepVariants()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["Nep17","nep_11"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        new SupportedStandardsCoverageDetector().Analyze(ctx).Should().BeEmpty();
    }

    [Fact]
    public void SupportedStandardsCoverage_FlagsAbiOnlyNepVariants()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-24","nep26","NEP_27"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };

        var findings = new SupportedStandardsCoverageDetector().Analyze(ctx).ToList();

        findings.Should().HaveCount(3);
        findings.Should().OnlyContain(f =>
            f.Severity == Severity.Info
            && f.Tags.Contains("standard-coverage")
            && f.Tags.Contains("abi-only"));
        findings.Should().Contain(f => f.Title.Contains("NEP-24"));
        findings.Should().Contain(f => f.Title.Contains("nep26"));
        findings.Should().Contain(f => f.Title.Contains("NEP_27"));
    }

    [Fact]
    public void CallbackReentry_FlagsTransferBeforePostWriteState()
    {
        // After audit C# #10 fix, the detector requires a concrete 20-byte target hash
        // (any external Hash160). Userland helper methods named "transfer" without a
        // concrete external target no longer fire.
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "transfer",
            TargetHash = SymbolicValue.Bytes(new byte[20]),
            HasReturnValue = true,
        });
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));
        var f = new CallbackReentryDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Tags.Should().Contain("callback-reentry");
    }

    [Fact]
    public void CallbackReentry_DoesNotFireOnUserlandTransferHelper_AuditFinding10()
    {
        // No concrete TargetHash → looks like an internal helper, not a NEP-17 transfer.
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "transfer",
            TargetHashDynamic = true,
            HasReturnValue = true,
        });
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));
        new CallbackReentryDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void CryptoBypass_FlagsUnusedSigCheck()
    {
        var s = NewState();
        s.Telemetry.SignatureChecks.Add(0x20);
        // No path condition mentions sig_ok_<offset>.
        var f = new CryptoVerificationBypassDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Tags.Should().Contain("crypto-bypass");
    }

    [Fact]
    public void CryptoBypass_SkipsSigCheckUsedInBranch()
    {
        var s = NewState();
        s.Telemetry.SignatureChecks.Add(0x20);
        s.PathConditions = s.PathConditions.Add(Expr.Sym(Sort.Bool, "sig_ok_32"));
        new CryptoVerificationBypassDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void StorageCollision_NamespacedKeysAreNotFlagged()
    {
        // Audit fix: "balance:" is a prefix of "balance:total" but the separator ':' makes it
        // a legitimate namespace, not a collision.
        var s = NewState();
        s.Telemetry.StorageOps.Add(new StorageOp(0x10, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("balance:")), SymbolicValue.Int(0), false, false));
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("balance:total")), SymbolicValue.Int(0), false, false));
        new StorageCollisionDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void StorageCollision_TrueOverlapIsFlagged()
    {
        var s = NewState();
        s.Telemetry.StorageOps.Add(new StorageOp(0x10, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1, 2 }), SymbolicValue.Int(0), false, false));
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1, 2, 3 }), SymbolicValue.Int(0), false, false));
        new StorageCollisionDetector().Analyze(Ctx(s)).Should().ContainSingle();
    }

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

    [Fact]
    public void PublicPrivilegedMethod_MatchesMethodWhenDispatcherOffsetIsInPath()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Dapp","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[{"name":"setOracle","parameters":[],"returntype":"Void","offset":256,"safe":false}],
                    "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var s = NewState();
        s.Path.Add(0x000);
        s.Path.Add(0x100);
        s.Telemetry.StorageOps.Add(new StorageOp(0x120, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("oracle")), SymbolicValue.Int(1), false, false));

        new PublicPrivilegedMethodDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
            .Should().ContainSingle();
    }

    [Fact]
    public void PublicPrivilegedMethod_AttributesEntryWhenItDispatchesToHigherOffsetMethod()
    {
        // Per-method analysis: state.Path[0] is the entry method's body offset. If a
        // privileged entry method (`burn` at 0x100) CALLs a non-privileged manifest method
        // at a higher offset (`getBalance` at 0x300, safe=true), MethodForState should
        // attribute to the entry, not the highest-offset visited method. Otherwise the
        // privileged-method finding gets silently re-categorized to the safe view method.
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Dapp","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[
               {"name":"burn","parameters":[],"returntype":"Void","offset":256,"safe":false},
               {"name":"getBalance","parameters":[],"returntype":"Integer","offset":768,"safe":true}
             ],"events":[]},
             "permissions":[],"trusts":[]}
        """);
        var s = NewState();
        s.Path.Add(0x100);  // entry: burn (privileged, unsafe)
        s.Path.Add(0x101);
        s.Path.Add(0x300);  // calls getBalance (safe view) - higher offset
        s.Path.Add(0x301);
        s.Telemetry.StorageOps.Add(new StorageOp(0x110, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("supply")), SymbolicValue.Int(1), false, false));

        new PublicPrivilegedMethodDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
            .Should().ContainSingle("the entry method `burn` is the privileged one regardless of dispatch into other manifest methods");
    }

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

    [Fact]
    public void DefiSlippageOracle_DoesNotTreatCommentsOrStringsAsSafetySignals()
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
        var sourceHints = SourceHints.FromText("""
            public bool swap()
            {
                // TODO: add amountOutMin, deadline, and oracle freshness checks.
                var note = "amountOutMin deadline oracle";
                storage.Put("pool:reserve0", amountIn);
                return true;
            }
        """);

        new DefiSlippageOracleDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest, SourceHints = sourceHints })
            .Should().ContainSingle()
            .Which.Tags.Should().Contain("defi-state");
    }

    [Fact]
    public void DefiSlippageOracle_SourceSafetyHintsRespectManifestParameterCount()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Pool","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[{"name":"swap","parameters":[{"name":"amountIn","type":"Integer"}],"returntype":"Boolean","offset":512,"safe":false}],
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
        var sourceHints = SourceHints.FromText("""
            public bool swap(BigInteger amountIn)
            {
                storage.Put("pool:reserve0", amountIn);
                return true;
            }

            public bool swap()
            {
                var amountOutMin = 1;
                var deadlineHeight = Runtime.Time;
                return amountOutMin > 0 && deadlineHeight > 0;
            }
        """);

        new DefiSlippageOracleDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest, SourceHints = sourceHints })
            .Should().ContainSingle()
            .Which.Tags.Should().Contain("defi-state");
    }

    [Fact]
    public void DefiSlippageOracle_SourceSafetyHintsResolveDisplayNameAlias()
    {
        // End-to-end: the ABI manifest exposes the method under "swap", but the C# source
        // method is named DoSwap and aliased via [DisplayName("swap")]. The body contains
        // amountOutMin + deadline, so the detector must locate the body by ABI name and
        // suppress the finding. Without the alias resolution shipped in 1718ba4 the lookup
        // would miss the body and a false-positive defi-slippage finding would surface.
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Pool","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[{"name":"swap","parameters":[{"name":"amountIn","type":"Integer"}],"returntype":"Boolean","offset":512,"safe":false}],
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
        var sourceHints = SourceHints.FromText("""
            using System.ComponentModel;

            public class Pool
            {
                [DisplayName("swap")]
                public bool DoSwap(BigInteger amountIn)
                {
                    var amountOutMin = 1;
                    var deadlineHeight = Runtime.Time;
                    storage.Put("pool:reserve0", amountIn);
                    return amountOutMin > 0 && deadlineHeight > 0;
                }
            }
        """);

        new DefiSlippageOracleDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest, SourceHints = sourceHints })
            .Should().BeEmpty("the safe DoSwap body must resolve via the [DisplayName] alias");
    }

    [Fact]
    public void DefiSlippageOracle_FlagsUnusuallyNamedReserveMutation()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Pool","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[{"name":"execute","parameters":[],"returntype":"Boolean","offset":512,"safe":false}],
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
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("reserve:token0")), SymbolicValue.Int(100), false, false));

        new DefiSlippageOracleDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
            .Should().ContainSingle()
            .Which.Tags.Should().Contain("defi-state");
    }

    [Fact]
    public void DefiSlippageOracle_FlagsSwapWithDynamicStateKey()
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
            SymbolicValue.Symbol(Sort.Bytes, "pool_key"), SymbolicValue.Int(100), false, false));

        new DefiSlippageOracleDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
            .Should().ContainSingle()
            .Which.Tags.Should().Contain("dynamic-storage-key");
    }

    [Fact]
    public void DefiSlippageOracle_UsesMethodLocalSourceHintsForOpaquePoolLogic()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Pool","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[{"name":"execute","parameters":[],"returntype":"Boolean","offset":512,"safe":false}],
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
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("opaque")), SymbolicValue.Int(100), false, false));
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                var reserveAfter = pool.Reserve0 + amountIn;
                storage.Put("opaque", reserveAfter);
                return true;
            }
        """);

        new DefiSlippageOracleDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest, SourceHints = sourceHints })
            .Should().ContainSingle()
            .Which.Tags.Should().Contain("source-hint");
    }

    [Fact]
    public void DefiSlippageOracle_SourceHintsDoNotBleedAcrossMethods()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Pool","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[{"name":"execute","parameters":[],"returntype":"Boolean","offset":512,"safe":false}],
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
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("opaque")), SymbolicValue.Int(100), false, false));
        var sourceHints = SourceHints.FromText("""
            public bool other()
            {
                var reserveAfter = pool.Reserve0 + amountIn;
                return true;
            }

            public bool execute()
            {
                storage.Put("opaque", amountIn);
                return true;
            }
        """);

        new DefiSlippageOracleDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest, SourceHints = sourceHints })
            .Should().BeEmpty();
    }

    [Fact]
    public void DefiSlippageOracle_ArityMatchesAbiMethod_OverloadCannotExonerateUnsafe()
    {
        // Production-readiness regression: under per-method analysis, the manifest entry method
        // is the unsafe arity-1 swap(amountIn). Source has TWO overloads — the safe arity-2
        // swap(amountIn, amountOutMin) DOES contain slippage hints, but those must not bleed to
        // the arity-1 entry. Without arity-aware MethodContainsAny, the detector would scan
        // both bodies and silently exonerate the unsafe overload by file order.
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"Pool","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[{"name":"swap",
                                "parameters":[{"name":"amountIn","type":"Integer"}],
                                "returntype":"Boolean","offset":256,"safe":false}],
                    "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var s = NewState();
        // Per-method analysis seeds Path[0] with the entry method's offset.
        s.Path.Add(256);
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x270,
            Method = "transfer",
            TargetHash = SymbolicValue.Bytes(new byte[20]),
            HasReturnValue = true,
        });
        s.Telemetry.StorageOps.Add(new StorageOp(0x280, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("reserve")),
            SymbolicValue.Int(100), false, false));
        // Source: the SAFE overload has BOTH slippage AND freshness/oracle hints; the UNSAFE one
        // (matching the ABI arity) has neither. Without arity disambiguation the detector would
        // see both signals satisfied (`hasSlippageSignal && hasFreshnessSignal`) and skip the
        // finding entirely — exonerating the unsafe path. With arity disambiguation, only the
        // arity-1 body is searched and both signals come up false.
        var sourceHints = SourceHints.FromText("""
            public bool swap(BigInteger amountIn, BigInteger amountOutMin, BigInteger deadline)
            {
                require(amountOut >= amountOutMin, "slippage");
                require(timestamp <= deadline, "deadline");
                require(oracle.fresh, "stale price");
                return true;
            }

            public bool swap(BigInteger amountIn)
            {
                storage.Put("reserve", amountIn);
                return true;
            }
        """);

        var findings = new DefiSlippageOracleDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest, SourceHints = sourceHints })
            .ToList();

        findings.Should().NotBeEmpty(
            "the unsafe arity-1 swap entry must still trigger — the safe arity-2 overload's slippage hint must not exonerate it");
        findings[0].Tags.Should().Contain("slippage");
    }

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

    [Fact]
    public void NftOwnershipAuthorization_FlagsDynamicOwnershipKeyInNep11Transfer()
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
            SymbolicValue.Symbol(Sort.Bytes, "owner_key"), SymbolicValue.Bytes(new byte[20]), false, false));

        new NftOwnershipAuthorizationDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
            .Should().ContainSingle()
            .Which.Tags.Should().Contain("dynamic-storage-key");
    }

    [Fact]
    public void NftOwnershipAuthorization_FlagsUnusuallyNamedNep11OwnershipMethod()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"NFT","groups":[],"features":{},"supportedstandards":["NEP-11"],
             "abi":{"methods":[{"name":"moveToken","parameters":[],"returntype":"Boolean","offset":768,"safe":false}],
                    "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var s = NewState();
        s.Path.Add(0x300);
        s.Telemetry.StorageOps.Add(new StorageOp(0x330, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("owner:token42")), SymbolicValue.Bytes(new byte[20]), false, false));

        new NftOwnershipAuthorizationDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest })
            .Should().ContainSingle();
    }

    [Fact]
    public void NftOwnershipAuthorization_UsesMethodLocalSourceHintsForOpaqueOwnershipLogic()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"NFT","groups":[],"features":{},"supportedstandards":["NEP-11"],
             "abi":{"methods":[{"name":"doIt","parameters":[{"name":"tokenId","type":"Hash256"},{"name":"to","type":"Hash160"}],"returntype":"Boolean","offset":768,"safe":false}],
                    "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var s = NewState();
        s.Path.Add(0x300);
        s.Telemetry.StorageOps.Add(new StorageOp(0x330, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("opaque")), SymbolicValue.Bytes(new byte[20]), false, false));
        var sourceHints = SourceHints.FromText("""
            public bool doIt(UInt256 tokenId, UInt160 to)
            {
                owners[tokenId] = to;
                approvals.Remove(tokenId);
                return true;
            }
        """);

        new NftOwnershipAuthorizationDetector()
            .Analyze(new AnalysisContext { States = new[] { s }, Manifest = manifest, SourceHints = sourceHints })
            .Should().ContainSingle()
            .Which.Tags.Should().Contain("source-hint")
            .And.NotContain("dynamic-storage-key");
    }

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

    [Fact]
    public void DefaultDetectorSet_HasAllAuditDrivenDetectors()
    {
        var detectors = DefaultDetectorSet.All();
        var names = detectors.Select(d => d.Name).ToHashSet();
        names.Should().Contain(new[]
        {
            "reentrancy", "access_control", "overflow", "unchecked_return", "dynamic_call_target",
            "dangerous_call_flags", "dos", "gas_exhaustion", "randomness", "timestamp",
            "storage_collision", "upgradeability", "permissions", "admin_centralization",
            "nep17_compliance", "supported_standards_coverage", "unknown_instructions",
            // audit-derived standard/runtime detectors
            "nep11_compliance", "nep24_compliance", "nep27_compliance", "nep26_compliance",
            "callback_reentry", "crypto_verification_bypass",
            "replay_attack", "taint_flow_upgrade",
            // Neo DApp / DeFi / NFT protocol-risk detectors
            "public_privileged_method", "defi_slippage_oracle", "nft_ownership_authorization",
        });
        detectors.Should().HaveCountGreaterThanOrEqualTo(24);
    }
}

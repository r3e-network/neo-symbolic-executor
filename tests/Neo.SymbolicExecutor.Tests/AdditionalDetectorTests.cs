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
        s.PathConditions = s.PathConditions.Add(Expr.Eq(Expr.Sym(Sort.Int, "timestamp"), Expr.Int(123)));
        var f = new RandomnessDetector().Analyze(Ctx(s)).ToList();
        f.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("weak-randomness"));
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
            "nep17_compliance", "unknown_instructions",
            // 5 audit-derived new detectors
            "nep11_compliance", "callback_reentry", "crypto_verification_bypass",
            "replay_attack", "taint_flow_upgrade",
            // Neo DApp / DeFi / NFT protocol-risk detectors
            "public_privileged_method", "defi_slippage_oracle", "nft_ownership_authorization",
        });
        detectors.Should().HaveCountGreaterThanOrEqualTo(24);
    }
}

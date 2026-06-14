using System.Collections.Immutable;
using System.Reflection;
using System.Text;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;
using Neo.SymbolicExecutor.Fuzzer.Coverage;
using Neo.SymbolicExecutor.Nef;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

public class SecurityHardeningTests
{
    [Fact]
    public void ScriptDecoder_RejectsPushDataLengthOverflowAsVmFault()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHDATA4,
            0xFF, 0xFF, 0xFF, 0x7F,
        };

        var act = () => ScriptDecoder.Decode(script);

        act.Should().Throw<VmFaultException>()
            .WithMessage("*Truncated operand*");
    }

    [Fact]
    public void CliLoadProgram_RejectsOversizedRawScriptBeforeDecoding()
    {
        string dir = CreateTempDirectory();
        try
        {
            string path = Path.Combine(dir, "oversized.bin");
            File.WriteAllBytes(path, Enumerable.Repeat((byte)NeoVm.OpCode.RET, NefFile.MaxScriptSize + 1).ToArray());
            var cliProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
                .GetType("Neo.SymbolicExecutor.Cli.Program", throwOnError: true)!;
            var loadProgram = cliProgram.GetMethod("LoadProgram", BindingFlags.NonPublic | BindingFlags.Static)!;

            var act = () => loadProgram.Invoke(null, new object[] { path });

            act.Should().Throw<TargetInvocationException>()
                .WithInnerException<ArgumentException>()
                .WithMessage("*exceeds*");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SourceHints_RejectsOversizedSourceFileBeforeRoslynParse()
    {
        string dir = CreateTempDirectory();
        try
        {
            string path = Path.Combine(dir, "Huge.cs");
            File.WriteAllText(path, "class C { void M() { } }\n" + new string(' ', 1_048_577), Encoding.UTF8);

            var act = () => SourceHints.FromPaths(new[] { path });

            act.Should().Throw<ArgumentException>()
                .WithMessage("*source file*exceeds*");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void AccessControl_SafeManifestMethodDowngradesInsteadOfSuppressingSensitiveOps()
    {
        var state = new ExecutionState();
        state.Path.Add(0x10);
        state.Telemetry.StorageOps.Add(new StorageOp(
            Offset: 0x20,
            Kind: StorageOpKind.Put,
            Key: SymbolicValue.Bytes(Encoding.ASCII.GetBytes("admin")),
            Value: SymbolicValue.Int(1),
            ContextDynamic: false,
            ContextReadOnly: false));
        var manifest = ContractManifest.FromJson("""
            {
              "name":"SafeButMutating",
              "groups":[],
              "features":{},
              "supportedstandards":[],
              "abi":{
                "methods":[
                  {"name":"mint","parameters":[],"returntype":"Void","offset":16,"safe":true}
                ],
                "events":[]
              },
              "permissions":[],
              "trusts":[]
            }
            """);
        var ctx = new AnalysisContext
        {
            States = ImmutableArray.Create(state),
            Manifest = manifest,
        };

        var findings = new AccessControlDetector().Analyze(ctx).ToList();

        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Info);
        findings[0].Tags.Should().Contain("manifest-safe-assertion");
    }

    [Fact]
    public void ContractManifest_RejectsUnboundedAbiMethodLists()
    {
        string methods = string.Join(
            ",",
            Enumerable.Range(0, 1025)
                .Select(i => $$"""{"name":"m{{i}}","parameters":[],"returntype":"Void","offset":0,"safe":false}"""));
        string json = $$"""
            {
              "name":"HugeManifest",
              "groups":[],
              "features":{},
              "supportedstandards":[],
              "abi":{"methods":[{{methods}}],"events":[]},
              "permissions":[],
              "trusts":[]
            }
            """;

        var act = () => ContractManifest.FromJson(json);

        act.Should().Throw<FormatException>()
            .WithMessage("*methods*exceeds*");
    }

    [Fact]
    public void ExpressionFactory_ModPowRejectsOversizedConcreteExponent()
    {
        var act = () => Expr.ModPow(Expr.Int(2), Expr.Int(257), Expr.Int(1009));

        act.Should().Throw<VmFaultException>()
            .WithMessage("*exponent*exceeds*");
    }

    [Fact]
    public void Engine_MarksCoverageIncompleteWhenStateStopsOnModelingLimit()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.REMOVE,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        var map = state.Heap.NewMap(new[]
        {
            (SymbolicValue.Bytes("key"u8.ToArray()), SymbolicValue.Int(1)),
        });
        state.Push(SymbolicValue.HeapRef(Sort.Map, map.Id));
        state.Push(SymbolicValue.Symbol(Sort.Bytes, "k"));

        var result = new SymbolicEngine(program).Run(state);

        result.FinalStates.Should().Contain(s => s.Status == TerminalStatus.Stopped);
        result.CoverageIncomplete.Should().BeTrue();
        result.CoverageReason.Should().Contain("symbolic execution stopped");
        result.CoverageReason.Should().Contain("REMOVE map with symbolic key");
    }

    [Fact]
    public void ReportGenerator_EscapesUntrustedMarkdownFields()
    {
        var finding = new Finding(
            Detector: "evil|detector",
            Severity: Severity.High,
            Title: "Injected\n# Forged heading",
            Description: "Description with\n| forged | table | <script>alert(1)</script>",
            Offset: 0x10,
            Confidence: 0.9,
            ConfidenceReason: "reason\n- forged bullet",
            Tags: ImmutableHashSet.Create("tag`x", "tag|y"),
            Witness: new Dictionary<string, object> { ["sym|x"] = "value\nrow" });
        var report = new AnalysisReport(
            ImmutableArray.Create(finding),
            RiskProfile.FromFindings(new[] { finding }),
            new GatePolicy().Evaluate(new[] { finding }, RiskProfile.FromFindings(new[] { finding })),
            new AnalysisMeta());

        string markdown = ReportGenerator.ToMarkdown(report);

        markdown.Should().NotContain("\n# Forged heading");
        markdown.Should().NotContain("| forged | table |");
        markdown.Should().NotContain("<script>");
        markdown.Should().Contain("&lt;script&gt;");
    }

    [Fact]
    public void DetectorEngine_DedupePreservesSatWitnessOverUnsatDuplicate()
    {
        var unsat = new Finding(
            "det",
            Severity.High,
            "same",
            "unsat",
            0x10,
            0.5,
            "unsat",
            ImmutableHashSet<string>.Empty,
            PathSatisfiable: false);
        var sat = unsat with
        {
            Confidence = 0.4,
            ConfidenceReason = "sat",
            PathSatisfiable = true,
            Witness = new Dictionary<string, object> { ["amount"] = 7 },
        };

        var deduped = DetectorEngine.Dedupe(new[] { unsat, sat });

        deduped.Should().ContainSingle();
        deduped[0].PathSatisfiable.Should().BeTrue();
        deduped[0].Witness.Should().ContainKey("amount");
    }

    [Fact]
    public void InterestingCorpus_SkipsOversizedPersistedInputsOnStartup()
    {
        string dir = CreateTempDirectory();
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "oversized.bin"), new byte[NefFile.MaxScriptSize + 1]);

            var corpus = new InterestingCorpus(capacity: 8, persistDir: dir);

            corpus.Count.Should().Be(0);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task FuzzerReproduce_RejectsOversizedInputBeforeReplay()
    {
        string dir = CreateTempDirectory();
        try
        {
            string path = Path.Combine(dir, "oversized.bin");
            File.WriteAllBytes(path, new byte[NefFile.MaxScriptSize + 1]);
            var fuzzerProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym-fuzz.dll"))
                .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
            var main = fuzzerProgram.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;

            var task = (Task<int>)main.Invoke(null, new object[]
            {
                new[] { "--target", "decoder", "--reproduce", path }
            })!;

            (await task).Should().Be(2);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void FuzzerParseArgs_RejectsAbsurdWorkerCount()
    {
        var fuzzerProgram = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym-fuzz.dll"))
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var parseArgs = fuzzerProgram.GetMethod("ParseArgs", BindingFlags.NonPublic | BindingFlags.Static)!;

        var act = () => parseArgs.Invoke(null, new object[] { new[] { "--workers", "1000000" } });

        act.Should().Throw<TargetInvocationException>()
            .WithInnerException<ArgumentException>()
            .WithMessage("*--workers*");
    }

    private static string CreateTempDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), "neo-sym-security-hardening", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}

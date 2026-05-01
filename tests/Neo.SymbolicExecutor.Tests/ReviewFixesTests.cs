using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Threading.Tasks;
using System.Text.Json.Nodes;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;
using Neo.SymbolicExecutor.Smt;
using Neo.SymbolicExecutor.Nef;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

public class ReviewFixesTests
{
    [Fact]
    public void SymbolicAssert_ConsumesExternalReturnOnBothBranches()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 16,
            Method = "transfer",
            HasReturnValue = true,
        });
        state.Push(SymbolicValue.Symbol(Sort.Bool, "ext_ret_16"));

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run(state);

        result.FinalStates.Should().HaveCount(2);
        result.FinalStates.SelectMany(s => s.Telemetry.ExternalCalls)
            .Should().OnlyContain(call => call.ReturnChecked);
        new UncheckedReturnDetector()
            .Analyze(new AnalysisContext { States = result.FinalStates })
            .Should().BeEmpty();
    }

    [Fact]
    public void Assert_PrunesUnsatisfiableFailureBranchWithSmt()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.RET,
        };

        var state = NewState(pc: 0);
        state.Push(SymbolicValue.Symbol(Sort.Bool, "ok"));
        var backend = new StubSmtBackend(expr => IsNotSymbol(expr, "ok") ? SmtOutcome.Unsat : SmtOutcome.Sat);

        var result = new SymbolicEngine(
            ScriptDecoder.Decode(script),
            new ExecutionOptions { SmtBackend = backend }).Run(state);

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Halted);
        result.FinalStates[0].PathConditions.Should().ContainSingle()
            .Which.Should().Be(Expr.Sym(Sort.Bool, "ok"));
    }

    [Theory]
    [InlineData("System.Runtime.CheckWitness")]
    [InlineData("System.Runtime.Notify")]
    [InlineData("System.Runtime.Log")]
    [InlineData("System.Runtime.GetNotifications")]
    [InlineData("System.Runtime.BurnGas")]
    [InlineData("System.Iterator.Next")]
    [InlineData("System.Iterator.Value")]
    [InlineData("System.Crypto.CheckSig")]
    [InlineData("System.Crypto.CheckMultisig")]
    [InlineData("System.Storage.AsReadOnly")]
    [InlineData("System.Contract.CallNative")]
    public void ModeledSyscall_StackUnderflowFaults(string syscallName)
    {
        uint hash = SyscallRegistry.ComputeHash(syscallName);
        byte[] hashBytes = System.BitConverter.GetBytes(hash);
        byte[] script =
        {
            (byte)NeoVm.OpCode.SYSCALL,
            hashBytes[0],
            hashBytes[1],
            hashBytes[2],
            hashBytes[3],
            (byte)NeoVm.OpCode.RET,
        };

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
        result.FinalStates[0].TerminationReason.Should().Contain("Stack underflow");
    }

    [Fact]
    public void DetectorEngine_ValidatesFindingsAgainstTheirSourcePathConditions()
    {
        var unsatState = NewState(pc: 0x10);
        unsatState.Path.Add(0x10);
        unsatState.PathConditions = ImmutableList.Create<Expression>(Expr.Sym(Sort.Bool, "impossible"));

        var satState = NewState(pc: 0x10);
        satState.Path.Add(0x10);
        satState.PathConditions = ImmutableList.Create<Expression>(Expr.Sym(Sort.Bool, "reachable"));

        var backend = new StubSmtBackend(
            expr => expr is Symbol { Name: "impossible" } ? SmtOutcome.Unsat : SmtOutcome.Sat,
            conditions => conditions.Any(c => c is Symbol { Name: "impossible" })
                ? SmtOutcome.Unsat
                : SmtOutcome.Sat);

        var findings = new DetectorEngine(new[] { new PathEchoDetector() }).Run(new AnalysisContext
        {
            States = new[] { unsatState, satState },
            SmtBackend = backend,
            DropUnsatFindings = true,
        });

        findings.Should().ContainSingle();
        findings[0].PathSatisfiable.Should().BeTrue();
    }

    [Fact]
    public void FuzzerWrapper_CapturesNonZeroWaitStatus()
    {
        string script = ReadRepoFile("scripts/run-fuzzer-forever.sh");

        script.Should().NotContain("wait $FUZZ_PID || true");
        script.Should().Contain("if wait \"$FUZZ_PID\"; then");
    }

    [Fact]
    public void DevPackTargets_MessageUsesNeoSymItemMetadata()
    {
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        targets.Should().NotContain("%(NefFile.");
        targets.Should().Contain("%(_NeoSymNefFile.Filename)");
    }

    [Fact]
    public void DevPackOutputDirDefaultIsDeferredUntilTargetsRun()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        props.Should().NotContain("$(OutputPath)neo-sym/");
        targets.Should().Contain("<_NeoSymOutputDirRaw Condition=\"'$(NeoSymOutputDir)' == ''\">$(OutputPath)neo-sym/</_NeoSymOutputDirRaw>");
        targets.Should().Contain("<_NeoSymOutputDirRaw Condition=\"'$(NeoSymOutputDir)' != ''\">$(NeoSymOutputDir)</_NeoSymOutputDirRaw>");
        targets.Should().Contain("<_NeoSymOutputDir>$([MSBuild]::EnsureTrailingSlash('$(_NeoSymOutputDirRaw)'))</_NeoSymOutputDir>");
        targets.Should().Contain("&quot;$(_NeoSymOutputDir)%(_NeoSymNefFile.Filename)$(_NeoSymExtension)&quot;");
    }

    [Fact]
    public void DevPackTargets_PassesProjectSourceHintsByDefault()
    {
        string props = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.props");
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        props.Should().Contain("<NeoSymSourceDir Condition=\"'$(NeoSymSourceDir)' == ''\">$(MSBuildProjectDirectory)</NeoSymSourceDir>");
        targets.Should().Contain("<_NeoSymSourceFlag Condition=\"'$(NeoSymSourceDir)' != ''\"> --source &quot;$(NeoSymSourceDir)&quot;</_NeoSymSourceFlag>");
        targets.Should().Contain("$(_NeoSymSourceFlag)$(_NeoSymSmtFlag)$(_NeoSymGateFlag)");
    }

    [Fact]
    public void ReportJson_EscapesHtmlSensitiveFindingText()
    {
        var finding = new Finding(
            "xss_probe",
            Severity.High,
            "<script>alert(1)</script>",
            "desc",
            0x10,
            0.8,
            "test",
            ImmutableHashSet<string>.Empty);
        var findings = ImmutableArray.Create(finding);
        var risk = RiskProfile.FromFindings(findings);
        var gate = new GatePolicy().Evaluate(findings, risk);

        string json = ReportGenerator.ToJson(new AnalysisReport(findings, risk, gate, new AnalysisMeta()));

        json.Should().NotContain("<script>");
        json.Should().Contain("\\u003Cscript\\u003E");
        JsonNode.Parse(json)!["findings"]![0]!["title"]!.GetValue<string>()
            .Should().Be("<script>alert(1)</script>");
    }

    [Fact]
    public void NefParser_TruncatedVarBytesThrowsFormatException()
    {
        byte[] data = new byte[4 + 64 + 1];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), NefFile.MagicValue);
        data[^1] = 4; // Source varbytes claims four bytes, but none follow.

        var act = () => NefFile.Parse(data, verifyChecksum: false);

        act.Should().Throw<FormatException>().WithMessage("*VarBytes*truncated*");
    }

    [Fact]
    public async Task FuzzerCli_InvalidNumericOptionReturnsBadArguments()
    {
        var program = typeof(Neo.SymbolicExecutor.Fuzzer.FuzzCampaign)
            .Assembly
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var main = program.GetMethod("Main", BindingFlags.Public | BindingFlags.Static)!;

        var task = (Task<int>)main.Invoke(null, new object[] { new[] { "--seconds", "not-an-int" } })!;
        int exitCode = await task;

        exitCode.Should().Be(2);
    }

    [Theory]
    [InlineData("--smt-timeout", "0")]
    [InlineData("--smt-timeout", "-1")]
    [InlineData("--smt-bytes-bound", "0")]
    [InlineData("--fail-on-total-findings", "-1")]
    [InlineData("--fail-on-weighted-score", "-1")]
    [InlineData("--fail-on-confidence-weighted-score", "-1")]
    [InlineData("--fail-on-severity-count", "high=-1")]
    public void CliAnalyze_RejectsInvalidNumericRanges(string option, string value)
    {
        var analyzeOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.AnalyzeOptions", throwOnError: true)!;
        var parse = analyzeOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;

        var act = () => parse.Invoke(null, new object[] { new[] { "contract.nef", option, value } });

        act.Should().Throw<TargetInvocationException>()
            .Which.InnerException.Should().BeOfType<ArgumentException>();
    }

    [Fact]
    public void CliAnalyze_RejectsInvalidFormatBeforeLoadingContract()
    {
        var analyzeOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.AnalyzeOptions", throwOnError: true)!;
        var parse = analyzeOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;

        var act = () => parse.Invoke(null, new object[] { new[] { "missing.nef", "--format", "xml" } });

        act.Should().Throw<TargetInvocationException>()
            .Which.InnerException.Should().BeOfType<ArgumentException>()
            .Which.Message.Should().Contain("unknown --format");
    }

    [Fact]
    public void CliAnalyze_ParsesSourceHintPaths()
    {
        var analyzeOptions = Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory, "neo-sym.dll"))
            .GetType("Neo.SymbolicExecutor.Cli.AnalyzeOptions", throwOnError: true)!;
        var parse = analyzeOptions.GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)!;

        var opts = parse.Invoke(null, new object[] { new[] { "contract.nef", "--source", "Contract.cs", "--source", "src" } })!;
        var sourcePaths = (System.Collections.IEnumerable)opts.GetType()
            .GetProperty("SourcePaths")!
            .GetValue(opts)!;

        sourcePaths.Cast<string>().Should().Equal("Contract.cs", "src");
    }

    [Fact]
    public void SourceHints_LoadsProjectSourceFiles()
    {
        string dir = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Contract.cs"), """
                public bool execute()
                {
                    var amountOutMin = 1;
                    return amountOutMin > 0;
                }
            """);

            SourceHints.FromPaths(new[] { dir })
                .MethodContainsAny("execute", new[] { "amountOutMin" })
                .Should().BeTrue();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SourceHints_SkipsGeneratedAndDependencyDirectories()
    {
        string dir = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Contract.cs"), """
                public bool execute()
                {
                    storage.Put("opaque", amountIn);
                    return true;
                }
            """);
            string objDir = Path.Combine(dir, "obj");
            Directory.CreateDirectory(objDir);
            File.WriteAllText(Path.Combine(objDir, "Generated.cs"), """
                public bool execute()
                {
                    var reserveAfter = pool.Reserve0 + amountIn;
                    return reserveAfter > 0;
                }
            """);

            SourceHints.FromPaths(new[] { dir })
                .MethodContainsAny("execute", new[] { "reserve" })
                .Should().BeFalse();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SourceHints_IgnoresCommentsWhenMatchingHints()
    {
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                // TODO: add reserve accounting and amountOutMin checks.
                storage.Put("opaque", amountIn);
                return true;
            }
        """);

        sourceHints.MethodContainsAny("execute", new[] { "reserve", "amountOutMin" })
            .Should().BeFalse();
    }

    [Fact]
    public void SourceHints_PreservesStringLiteralsForStateHintsWhenAllowed()
    {
        var sourceHints = SourceHints.FromText("""
            public bool doIt(UInt256 tokenId, UInt160 to)
            {
                storage.Put("owner:" + tokenId, to);
                return true;
            }
        """);

        sourceHints.MethodContainsAny("doIt", new[] { "owner" })
            .Should().BeTrue();
        sourceHints.MethodContainsAny("doIt", new[] { "owner" }, includeStringLiterals: false)
            .Should().BeFalse();
    }

    [Fact]
    public void SourceHints_StringAndCommentBracesDoNotEndMethodBody()
    {
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                var text = "{ not a block }";
                /* } */
                var reserveAfter = pool.Reserve0 + amountIn;
                return reserveAfter > 0;
            }
        """);

        sourceHints.MethodContainsAny("execute", new[] { "reserveAfter" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_SearchesAllBodiesForDuplicateMethodNames()
    {
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                var reserveAfter = pool.Reserve0 + amountIn;
                return reserveAfter > 0;
            }

            public bool execute(BigInteger amountIn)
            {
                storage.Put("opaque", amountIn);
                return true;
            }
        """);

        sourceHints.MethodContainsAny("execute", new[] { "reserveAfter" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_CanRestrictDuplicateMethodNamesByParameterCount()
    {
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                var reserveAfter = pool.Reserve0 + amountIn;
                return reserveAfter > 0;
            }

            public bool execute(BigInteger amountIn)
            {
                storage.Put("opaque", amountIn);
                return true;
            }
        """);

        sourceHints.MethodContainsAny("execute", parameterCount: 0, hints: new[] { "reserveAfter" })
            .Should().BeTrue();
        sourceHints.MethodContainsAny("execute", parameterCount: 1, hints: new[] { "reserveAfter" })
            .Should().BeFalse();
    }

    [Theory]
    [InlineData("--seconds", "0")]
    [InlineData("--minutes", "-1")]
    [InlineData("--hours", "0")]
    [InlineData("--workers", "0")]
    [InlineData("--status-seconds", "0")]
    [InlineData("--max-memory-mb", "0")]
    public void FuzzerCli_RejectsInvalidNumericRanges(string option, string value)
    {
        var program = typeof(Neo.SymbolicExecutor.Fuzzer.FuzzCampaign)
            .Assembly
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var parse = program.GetMethod("ParseArgs", BindingFlags.NonPublic | BindingFlags.Static)!;

        var act = () => parse.Invoke(null, new object[] { new[] { option, value } });

        act.Should().Throw<TargetInvocationException>()
            .Which.InnerException.Should().BeOfType<ArgumentException>();
    }

    [Fact]
    public void FuzzerCli_HelpListsEveryAvailableTarget()
    {
        var program = typeof(Neo.SymbolicExecutor.Fuzzer.FuzzCampaign)
            .Assembly
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var printHelp = program.GetMethod("PrintHelp", BindingFlags.NonPublic | BindingFlags.Static)!;
        var targetNames = FuzzerTargetNames();

        using var output = new StringWriter();
        var originalOut = Console.Out;
        try
        {
            Console.SetOut(output);
            printHelp.Invoke(null, null);
        }
        finally
        {
            Console.SetOut(originalOut);
        }

        string help = output.ToString();
        targetNames.Should().HaveCount(21);
        foreach (string targetName in targetNames)
            help.Should().Contain(targetName);
    }

    [Fact]
    public void FuzzerReadme_DocumentsEveryAvailableTarget()
    {
        string readme = ReadRepoFile("src/Neo.SymbolicExecutor.Fuzzer/README.md");

        foreach (string targetName in FuzzerTargetNames())
            readme.Should().Contain($"`{targetName}`");
    }

    private static ExecutionState NewState(int pc)
    {
        var state = new ExecutionState { Pc = pc };
        state.CallStack.Add(new CallFrame(returnPc: -1));
        return state;
    }

    private static bool IsNotSymbol(Expression expr, string name) =>
        expr is UnaryExpr { Op: "not", Operand: Symbol s } && s.Name == name;

    private static string ReadRepoFile(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Neo.SymbolicExecutor.sln")))
            dir = dir.Parent;
        dir.Should().NotBeNull("the test assembly should run under the repository tree");
        return File.ReadAllText(Path.Combine(dir!.FullName, relativePath));
    }

    private static string CreateTempDirectory()
    {
        string dir = Path.Combine(Path.GetTempPath(), "neo-sym-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string[] FuzzerTargetNames()
    {
        var program = typeof(Neo.SymbolicExecutor.Fuzzer.FuzzCampaign)
            .Assembly
            .GetType("Neo.SymbolicExecutor.Fuzzer.Program", throwOnError: true)!;
        var parse = program.GetMethod("ParseArgs", BindingFlags.NonPublic | BindingFlags.Static)!;
        var opts = parse.Invoke(null, new object[] { System.Array.Empty<string>() })!;
        var targets = (System.Collections.IEnumerable)opts.GetType()
            .GetProperty("Targets")!
            .GetValue(opts)!;
        return targets.Cast<object>()
            .Select(target => (string)target.GetType().GetProperty("Name")!.GetValue(target)!)
            .ToArray();
    }

    private sealed class PathEchoDetector : BaseDetector
    {
        public override string Name => "path_echo";

        public override IEnumerable<Finding> Analyze(AnalysisContext context)
        {
            foreach (var state in context.States)
            {
                yield return MakeFinding(
                    title: "Path-sensitive finding",
                    description: "Finding used to verify SMT validation keeps source path conditions.",
                    offset: 0x10,
                    severity: Severity.Medium,
                    state: state);
            }
        }
    }

    private sealed class StubSmtBackend : ISmtBackend
    {
        private readonly Func<Expression, SmtOutcome> _extraOutcome;
        private readonly Func<IReadOnlyList<Expression>, SmtOutcome> _conditionsOutcome;

        public StubSmtBackend(
            Func<Expression, SmtOutcome> extraOutcome,
            Func<IReadOnlyList<Expression>, SmtOutcome>? conditionsOutcome = null)
        {
            _extraOutcome = extraOutcome;
            _conditionsOutcome = conditionsOutcome ?? (_ => SmtOutcome.Sat);
        }

        public bool IsAvailable => true;
        public string Version => "stub";
        public int TimeoutMs => 1;

        public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions, Expression extra) =>
            _extraOutcome(extra);

        public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions) =>
            _conditionsOutcome(conditions);

        public IReadOnlyDictionary<string, object>? BuildWitness(IReadOnlyList<Expression> conditions) =>
            new Dictionary<string, object>();

        public BigInteger? ConcretizeInt(
            IReadOnlyList<Expression> conditions,
            Expression target,
            BigInteger? lo = null,
            BigInteger? hi = null) => null;

        public SmtStats GetStats() => new(0, 0, 0, 0, 0, 0);
    }
}

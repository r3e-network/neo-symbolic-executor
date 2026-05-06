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
        // The Exec command must keep --source first, then --smt, then engine budgets, then the
        // gate flag last. Ordering matters because gate-failure exit codes only fire after the
        // analysis itself succeeded.
        targets.Should().Contain("$(_NeoSymSourceFlag)$(_NeoSymSmtFlag)$(_NeoSymBudgetFlags)$(_NeoSymGateFlag)");
    }

    [Fact]
    public void DevPackTargets_WiresFailOnBudgetExceededIntoGateFlag()
    {
        // The CLI exposes --fail-on-budget-exceeded; the .targets file must surface it as an
        // MSBuild property so DevPack contracts can opt CI builds into incomplete-coverage
        // failures without wrapping the tool invocation by hand.
        string targets = ReadRepoFile("devpack-integration/Neo.SymbolicExecutor.targets");

        targets.Should().Contain(
            "<_NeoSymGateBudgetFlag Condition=\"'$(NeoSymFailOnBudgetExceeded)' == 'true'\"> --fail-on-budget-exceeded</_NeoSymGateBudgetFlag>");
        targets.Should().Contain(
            "<_NeoSymGateFlag>$(_NeoSymGateSeverityFlag)$(_NeoSymGateBudgetFlag)</_NeoSymGateFlag>");
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
    public void SourceHints_CharLiteralBraceDoesNotEndMethodBody()
    {
        // FindCharLiteralEnd handles 'X' literals so an embedded } in a char literal
        // doesn't prematurely close the method body. Without this guard, the regex would
        // see the brace at the } in '}' and stop the body extraction early, missing
        // everything after.
        var sourceHints = SourceHints.FromText("""
            public bool execute()
            {
                char close = '}';
                var reserveAfter = pool.Reserve0;
                return close == '}' && reserveAfter > 0;
            }
        """);

        sourceHints.MethodContainsAny("execute", new[] { "reserveAfter" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_RawStringBraceDoesNotEndMethodBody()
    {
        // C# 11 raw string literals: """..."""  — the parser must recognize these and treat
        // any embedded braces as opaque text. FindRawStringEnd handles this.
        var sourceHints = SourceHints.FromText("\n"
            + "public bool execute()\n"
            + "{\n"
            + "    var template = \"\"\"\n"
            + "        { embedded brace } in raw string\n"
            + "        { another } here\n"
            + "    \"\"\";\n"
            + "    var reserveAfter = pool.Reserve0;\n"
            + "    return reserveAfter > 0;\n"
            + "}\n");

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

    [Fact]
    public void SourceHints_DisplayNameAttribute_AliasesMethodToAbiName()
    {
        // Real Neo DevPack pattern: the C# method is named DoTransfer but exposed in the
        // manifest under a different ABI name via [DisplayName("transfer")]. Without alias
        // resolution, our protocol-risk detectors would look up "transfer" and miss the body.
        var hints = SourceHints.FromText("""
            using System.ComponentModel;

            public class FooContract
            {
                [DisplayName("transfer")]
                public static bool DoTransfer(byte[] from, byte[] to, int amount)
                {
                    int amountOutMin = 0;
                    return amountOutMin >= 0;
                }
            }
        """);

        // ABI name resolves via the alias.
        hints.MethodContainsAny("transfer", parameterCount: 3, hints: new[] { "amountOutMin" })
            .Should().BeTrue();
        // C# identifier still resolves directly.
        hints.MethodContainsAny("DoTransfer", parameterCount: 3, hints: new[] { "amountOutMin" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_DisplayNameOnClass_DoesNotAliasFollowingMethod()
    {
        // A [DisplayName("X")] on a class declaration must not alias the next method to "X" —
        // the attribute targets the class itself. Without the blocking-declaration check
        // we would silently mis-bind. This regression-tests the precision of alias scoping.
        var hints = SourceHints.FromText("""
            using System.ComponentModel;

            [DisplayName("ClassAlias")]
            public class FooContract
            {
                public static bool TransferImpl(byte[] from, byte[] to, int amount)
                {
                    int amountOutMin = 0;
                    return amountOutMin >= 0;
                }
            }
        """);

        hints.MethodContainsAny("ClassAlias", parameterCount: 3, hints: new[] { "amountOutMin" })
            .Should().BeFalse();
        hints.MethodContainsAny("TransferImpl", parameterCount: 3, hints: new[] { "amountOutMin" })
            .Should().BeTrue();
    }

    [Fact]
    public void SourceHints_DisplayNameAttribute_DoesNotLeakAcrossFiles()
    {
        // Per-file scoping: a [DisplayName] in file A must not bind to the first method in
        // file B even though SourceHints.FromPaths processes them together. Concatenating
        // files before scanning would silently mis-bind. We use a stray-attribute layout in
        // FileA (which a careless paste could leave), and FileB starts with a method that
        // would have absorbed the alias under naive concatenation.
        string dir = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(dir, "A.cs"), """
                using System.ComponentModel;

                public class A
                {
                    public static void Done() { }
                }

                [DisplayName("zombie")]
            """);
            File.WriteAllText(Path.Combine(dir, "B.cs"), """
                using System.ComponentModel;

                public class B
                {
                    public static void Other(int marker) { var leakedMarker = marker; }
                }
            """);

            var hints = SourceHints.FromPaths(new[] { dir });
            // The stray FileA attribute should NOT alias FileB's Other method.
            hints.MethodContainsAny("zombie", parameterCount: 1, hints: new[] { "leakedMarker" })
                .Should().BeFalse();
            // Sanity: Other resolves under its own name and the marker is found.
            hints.MethodContainsAny("Other", parameterCount: 1, hints: new[] { "leakedMarker" })
                .Should().BeTrue();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SourceHints_DisplayNameAttribute_DoesNotLeakToSubsequentMethod()
    {
        // The alias must bind to exactly one method (the first one after the attribute) and
        // never leak to later methods that have no DisplayName of their own. Walk-with-cursor
        // semantics guarantee at-most-one consumption per attribute.
        var hints = SourceHints.FromText("""
            using System.ComponentModel;

            public class FooContract
            {
                [DisplayName("aliased")]
                public static void First(int x) { int firstMarker = x; }

                public static void Second(int x) { int secondMarker = x; }
            }
        """);

        hints.MethodContainsAny("aliased", parameterCount: 1, hints: new[] { "firstMarker" })
            .Should().BeTrue();
        hints.MethodContainsAny("aliased", parameterCount: 1, hints: new[] { "secondMarker" })
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
        targetNames.Should().HaveCount(22);
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

    [Fact]
    public void Engine_CreateMethodEntryState_SeedsArgsAtMethodOffset()
    {
        // Realistic DevPack-shaped bytecode: a dispatcher prelude that reads stack arg 0 then
        // jumps, plus a method body that takes 2 parameters via INITSLOT and adds them. Without
        // method-entry seeding the engine starts at offset 0, faults at LDARG0 with no args, and
        // never reaches the method body — exactly the production gap this regression locks down.
        byte[] script =
        {
            // 0..2: dispatcher prelude (1 arg = method-name string)
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x01,
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.DROP,
            (byte)NeoVm.OpCode.RET,
            // 6..end: method "add"(a, b) => a + b
            (byte)NeoVm.OpCode.INITSLOT, 0x00, 0x02, // 0 locals, 2 args
            (byte)NeoVm.OpCode.LDARG0,
            (byte)NeoVm.OpCode.LDARG1,
            (byte)NeoVm.OpCode.ADD,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program);
        var add = new ContractMethodDescriptor
        {
            Name = "add",
            Offset = 6,
            Parameters = new[]
            {
                new ContractParameterDefinition("a", "Integer"),
                new ContractParameterDefinition("b", "Integer"),
            },
        };

        var state = engine.CreateMethodEntryState(add.Offset, add.Parameters);
        var result = engine.Run(state);

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Should().ContainSingle();
        halted.EvaluationStack.Single().Expression.Should()
            .BeOfType<BinaryExpr>().Which.Op.Should().Be("+");
        // Both symbolic args reach the body in declared order.
        halted.EvaluationStack.Single().Expression.FreeSymbols().Should()
            .BeEquivalentTo(new[] { "arg_a", "arg_b" });
    }

    [Fact]
    public void Engine_CreateMethodEntryState_HandlesZeroAndManyParameters()
    {
        // Bare RET method: no INITSLOT, no params. Seeded with 0 args should HALT immediately.
        byte[] retScript = { (byte)NeoVm.OpCode.RET };
        var program = ScriptDecoder.Decode(retScript);
        var engine = new SymbolicEngine(program);

        var noArgs = engine.CreateMethodEntryState(offset: 0, parameters: Array.Empty<ContractParameterDefinition>());
        noArgs.EvaluationStack.Should().BeEmpty("no parameters means no seeded symbolic values");
        engine.Run(noArgs).FinalStates.Single().Status.Should().Be(TerminalStatus.Halted);

        // Null parameters should behave like an empty list (degenerate but defined input).
        var nullParams = new SymbolicEngine(program).CreateMethodEntryState(offset: 0, parameters: null);
        nullParams.EvaluationStack.Should().BeEmpty();

        // Many params + unfamiliar Type strings should not throw and should land within the
        // engine's stack budget. 64 is well under the 2048 default MaxStackSize.
        var manyParams = new List<ContractParameterDefinition>();
        for (int i = 0; i < 64; i++)
            manyParams.Add(new ContractParameterDefinition($"p{i}",
                Type: i % 2 == 0 ? "Integer" : "ExoticUnseenType"));
        var seededWithMany = new SymbolicEngine(program).CreateMethodEntryState(offset: 0, parameters: manyParams);
        seededWithMany.EvaluationStack.Should().HaveCount(64);
        // Param index 63 has Type "ExoticUnseenType" -> unmapped -> Sort.Bytes; pushed first
        // (reverse order), so it sits at the bottom of the stack.
        seededWithMany.EvaluationStack[0].Expression.Sort.Should().Be(Sort.Bytes);
        // Param index 0 ("p0", "Integer") pushed last -> top of stack -> Sort.Int.
        seededWithMany.EvaluationStack[^1].Expression.Sort.Should().Be(Sort.Int);
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

using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Reports unknown opcodes and unmodeled syscalls reached during exploration. INFO severity:
/// not necessarily a vulnerability but always worth surfacing — analysis ran on incomplete coverage.
/// </summary>
public sealed class UnknownInstructionsDetector : BaseDetector
{
    public override string Name => "unknown_instructions";
    public override Severity DefaultSeverity => Severity.Info;
    public override double DefaultConfidence => 1.0;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var emitted = new HashSet<(string, int)>();
        foreach (var state in context.States)
        {
            foreach (var off in state.Telemetry.UnknownOpcodes)
            {
                if (!emitted.Add(("op", off))) continue;
                yield return MakeFinding(
                    title: "Unsupported opcode reached",
                    description: $"Engine halted at 0x{off:X4} on an opcode without a symbolic handler.",
                    offset: off,
                    severity: Severity.Info,
                    state: state,
                    tags: new[] { "coverage-gap" });
            }
            foreach (var off in state.Telemetry.UnknownSyscalls)
            {
                if (!emitted.Add(("syscall", off))) continue;
                yield return MakeFinding(
                    title: "Unmodeled syscall invoked",
                    description: $"Syscall at 0x{off:X4} is not in the registry; argument vector and " +
                                 "side effects were approximated.",
                    offset: off,
                    severity: Severity.Info,
                    state: state,
                    tags: new[] { "coverage-gap", "syscall" });
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using Neo.SymbolicExecutor;

namespace Neo.SymbolicExecutor.Smt.Z3;

/// <summary>
/// SMT implementation that emits SMT-LIB and invokes the platform z3 executable when available,
/// then falls back to a conservative in-process solver for simple integer constraints.
///
/// Sort mapping:
///   Sort.Int   -> BitVec(256), signed comparisons via bvslt/bvsle/bvsgt/bvsge
///   Sort.Bool  -> Bool
/// Unsupported expressions are wrapped in fresh symbols of the right sort. That degrades query
/// precision but keeps UNSAT answers sound; callers treat UNKNOWN as "could be SAT".
/// </summary>
public sealed class Z3Backend : ISmtBackend, IDisposable
{
    public const int IntegerBits = 256;
    public const int BytesIndexBits = 32;

    private static readonly BigInteger SignedHalfRange = BigInteger.One << (IntegerBits - 1);
    private static readonly BigInteger UnsignedRange = BigInteger.One << IntegerBits;
    private static readonly Regex SmtValueRegex = new(
        @"(?<value>#x[0-9A-Fa-f]+|#b[01]+|true|false|\(_\s+bv[0-9]+\s+[0-9]+\))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private readonly string _z3Path;
    private readonly bool _useExternalZ3;
    private readonly int _timeoutMs;
    private readonly int _bytesBound;
    private readonly PortableSmtSolver _portableSolver = new();
    private long _queries, _cacheHits, _unknowns, _timeouts, _sat, _unsat, _opaqueTranslations;
    private readonly Dictionary<string, SmtOutcome> _queryCache = new(StringComparer.Ordinal);

    public bool IsAvailable { get; }
    public string Version { get; }
    public int TimeoutMs => _timeoutMs;
    public int BytesBound => _bytesBound;

    public Z3Backend(int timeoutMs = 5000, int bytesBound = 64)
    {
        _timeoutMs = timeoutMs;
        _bytesBound = bytesBound;
        _z3Path = Environment.GetEnvironmentVariable("NEO_SYMBOLIC_EXECUTOR_Z3") ?? "z3";

        var detected = DetectZ3(_z3Path);
        _useExternalZ3 = detected.available;
        IsAvailable = true;
        Version = _useExternalZ3
            ? detected.version
            : $"portable fallback ({detected.version})";
    }

    public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions, Expression extra)
    {
        var all = new List<Expression>(conditions.Count + 1);
        all.AddRange(conditions);
        all.Add(extra);
        return IsSatisfiable(all);
    }

    public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions)
    {
        if (conditions.Count == 0) return SmtOutcome.Sat;

        string key = ConstraintSetKey(conditions);
        if (_queryCache.TryGetValue(key, out var cached))
        {
            _cacheHits++;
            return cached;
        }

        var outcome = _useExternalZ3
            ? RunExternalSatisfiabilityQuery(conditions)
            : RunPortableSatisfiabilityQuery(conditions);
        _queryCache[key] = outcome;
        return outcome;
    }

    public BigInteger? ConcretizeInt(
        IReadOnlyList<Expression> conditions,
        Expression target,
        BigInteger? lo = null,
        BigInteger? hi = null)
    {
        if (!_useExternalZ3)
        {
            var portable = _portableSolver.ConcretizeInt(conditions, target, lo, hi);
            RecordOutcome(portable.Outcome, timedOut: false);
            return portable.Value;
        }

        var translator = new SmtLibTranslator();
        var assertions = conditions.Select(translator.TranslateBool).ToList();
        var targetValue = translator.TranslateInt(target);
        var targetAtom = translator.NewAuxInt("__target", out var targetName);
        assertions.Add($"(= {targetAtom} {targetValue})");
        if (lo.HasValue) assertions.Add($"(bvsge {targetAtom} {SmtLibTranslator.Bv(lo.Value)})");
        if (hi.HasValue) assertions.Add($"(bvsle {targetAtom} {SmtLibTranslator.Bv(hi.Value)})");

        var run = RunQuery(BuildScript(translator, assertions, _timeoutMs, new[] { targetName }));
        _opaqueTranslations += translator.OpaqueTranslations;
        if (run.Outcome != SmtOutcome.Sat) return null;
        return TryReadValueForName(run.Output, targetName, out var raw) && TryParseBitVec(raw, out var value)
            ? value
            : null;
    }

    public IReadOnlyDictionary<string, object>? BuildWitness(IReadOnlyList<Expression> conditions)
    {
        if (conditions.Count == 0) return new Dictionary<string, object>();

        if (!_useExternalZ3)
        {
            var portable = _portableSolver.BuildWitness(conditions);
            RecordOutcome(portable.Outcome, timedOut: false);
            return portable.Witness;
        }

        var translator = new SmtLibTranslator();
        var assertions = conditions.Select(translator.TranslateBool).ToArray();
        var names = translator.UserSymbols.Keys.ToArray();
        var run = RunQuery(BuildScript(translator, assertions, _timeoutMs, names));
        _opaqueTranslations += translator.OpaqueTranslations;
        if (run.Outcome != SmtOutcome.Sat) return null;

        var witness = new Dictionary<string, object>();
        foreach (var (name, sort) in translator.UserSymbols)
        {
            if (!TryReadValueForName(run.Output, name, out var raw)) continue;
            if (sort == Sort.Int && TryParseBitVec(raw, out var integer))
                witness[name] = integer;
            else if (sort == Sort.Bool && bool.TryParse(raw, out var boolean))
                witness[name] = boolean;
        }
        return witness;
    }

    public SmtStats GetStats() =>
        new(_queries, _cacheHits, _unknowns, _timeouts, _sat, _unsat, _opaqueTranslations);

    private SmtOutcome RunExternalSatisfiabilityQuery(IReadOnlyList<Expression> conditions)
    {
        var translator = new SmtLibTranslator();
        var assertions = conditions.Select(translator.TranslateBool).ToArray();
        var outcome = RunQuery(BuildScript(translator, assertions, _timeoutMs)).Outcome;
        _opaqueTranslations += translator.OpaqueTranslations;
        return outcome;
    }

    private SmtOutcome RunPortableSatisfiabilityQuery(IReadOnlyList<Expression> conditions)
    {
        var portable = _portableSolver.IsSatisfiable(conditions);
        RecordOutcome(portable.Outcome, timedOut: false);
        return portable.Outcome;
    }

    private SolverRun RunQuery(string script)
    {
        var run = RunSolver(script);
        RecordOutcome(run.Outcome, run.TimedOut);
        return run;
    }

    private void RecordOutcome(SmtOutcome outcome, bool timedOut)
    {
        _queries++;
        switch (outcome)
        {
            case SmtOutcome.Sat:
                _sat++;
                break;
            case SmtOutcome.Unsat:
                _unsat++;
                break;
            case SmtOutcome.Unknown:
                _unknowns++;
                if (timedOut) _timeouts++;
                break;
        }
    }

    private SolverRun RunSolver(string script)
    {
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = _z3Path,
                Arguments = "-in -smt2",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            process.Start();
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            process.StandardInput.Write(script);
            process.StandardInput.Close();

            if (!process.WaitForExit(_timeoutMs + 250))
            {
                KillProcess(process);
                return new SolverRun(SmtOutcome.Unknown, string.Empty, TimedOut: true);
            }

            var output = outputTask.GetAwaiter().GetResult();
            var error = errorTask.GetAwaiter().GetResult();
            if (process.ExitCode != 0 && string.IsNullOrWhiteSpace(output))
                return new SolverRun(SmtOutcome.Unknown, error, TimedOut: false);

            return new SolverRun(ClassifyOutput(output), output, TimedOut: false);
        }
        catch (Exception ex)
        {
            return new SolverRun(SmtOutcome.Unknown, ex.Message, TimedOut: false);
        }
    }

    private static string BuildScript(
        SmtLibTranslator translator,
        IReadOnlyList<string> assertions,
        int timeoutMs,
        IReadOnlyList<string>? getValueNames = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("(set-logic QF_BV)");
        sb.AppendLine(CultureInfo.InvariantCulture, $"(set-option :timeout {timeoutMs})");
        foreach (var declaration in translator.Declarations())
            sb.AppendLine(declaration);
        foreach (var assertion in assertions)
            sb.AppendLine(CultureInfo.InvariantCulture, $"(assert {assertion})");
        sb.AppendLine("(check-sat)");

        if (getValueNames is { Count: > 0 })
        {
            sb.Append("(get-value (");
            for (int i = 0; i < getValueNames.Count; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(SmtLibTranslator.Atom(getValueNames[i]));
            }
            sb.AppendLine("))");
        }

        return sb.ToString();
    }

    private static SmtOutcome ClassifyOutput(string output)
    {
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;
            return trimmed switch
            {
                "sat" => SmtOutcome.Sat,
                "unsat" => SmtOutcome.Unsat,
                _ => SmtOutcome.Unknown,
            };
        }
        return SmtOutcome.Unknown;
    }

    private static bool TryReadValueForName(string output, string name, out string value)
    {
        var pattern = @"\(\s*" + Regex.Escape(SmtLibTranslator.Atom(name)) + @"\s+" + SmtValueRegex + @"\s*\)";
        var match = Regex.Match(output, pattern, RegexOptions.CultureInvariant | RegexOptions.Singleline);
        value = match.Success ? match.Groups["value"].Value : string.Empty;
        return match.Success;
    }

    private static bool TryParseBitVec(string raw, out BigInteger value)
    {
        value = BigInteger.Zero;
        try
        {
            BigInteger unsigned;
            if (raw.StartsWith("#x", StringComparison.OrdinalIgnoreCase))
            {
                unsigned = ParseUnsigned(raw.AsSpan(2), 16);
            }
            else if (raw.StartsWith("#b", StringComparison.OrdinalIgnoreCase))
            {
                unsigned = ParseUnsigned(raw.AsSpan(2), 2);
            }
            else
            {
                var match = Regex.Match(raw, @"^\(_\s+bv(?<value>[0-9]+)\s+[0-9]+\)$", RegexOptions.CultureInvariant);
                if (!match.Success) return false;
                unsigned = BigInteger.Parse(match.Groups["value"].Value, CultureInfo.InvariantCulture);
            }

            value = unsigned >= SignedHalfRange ? unsigned - UnsignedRange : unsigned;
            return true;
        }
        catch
        {
            value = BigInteger.Zero;
            return false;
        }
    }

    private static BigInteger ParseUnsigned(ReadOnlySpan<char> digits, int radix)
    {
        var value = BigInteger.Zero;
        foreach (var digit in digits)
        {
            int current = digit switch
            {
                >= '0' and <= '9' => digit - '0',
                >= 'a' and <= 'f' => digit - 'a' + 10,
                >= 'A' and <= 'F' => digit - 'A' + 10,
                _ => throw new FormatException($"Invalid base-{radix} digit '{digit}'"),
            };
            if (current >= radix)
                throw new FormatException($"Invalid base-{radix} digit '{digit}'");
            value = value * radix + current;
        }
        return value;
    }

    private static (bool available, string version) DetectZ3(string z3Path)
    {
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = z3Path,
                Arguments = "-version",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            process.Start();
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(1000))
            {
                KillProcess(process);
                return (false, "unavailable (z3 -version timed out)");
            }

            var output = outputTask.GetAwaiter().GetResult();
            var error = errorTask.GetAwaiter().GetResult();
            var version = string.IsNullOrWhiteSpace(output) ? error.Trim() : output.Trim();
            return process.ExitCode == 0
                ? (true, version)
                : (false, $"unavailable ({version})");
        }
        catch (Exception ex)
        {
            return (false, $"unavailable ({ex.GetType().Name}: {ex.Message})");
        }
    }

    private static string ConstraintSetKey(IReadOnlyList<Expression> conditions)
    {
        return string.Join(
            "\n",
            conditions.Select(ExpressionKey)
                .Order(StringComparer.Ordinal)
                .Select(key => $"{key.Length}:{key}"));
    }

    private static string ExpressionKey(Expression expression) => expression switch
    {
        IntConst i => FormattableString.Invariant($"int:{i.Value}"),
        BoolConst b => b.Value ? "bool:true" : "bool:false",
        BytesConst bytes => $"bytes:{Convert.ToHexString(bytes.Value)}",
        NullConst => "null",
        HeapRef heap => FormattableString.Invariant($"heap:{heap.RefSort}:{heap.ObjectId}"),
        Symbol symbol => $"symbol:{symbol.Sort}:{StringKey(symbol.Name)}",
        UnaryExpr unary => $"unary:{unary.Sort}:{StringKey(unary.Op)}:{ExpressionKey(unary.Operand)}",
        BinaryExpr binary => $"binary:{binary.Sort}:{StringKey(binary.Op)}:{ExpressionKey(binary.Left)}:{ExpressionKey(binary.Right)}",
        TernaryExpr ternary => $"ternary:{ternary.Sort}:{StringKey(ternary.Op)}:{ExpressionKey(ternary.A)}:{ExpressionKey(ternary.B)}:{ExpressionKey(ternary.C)}",
        _ => $"{expression.Sort}:{StringKey(expression.ToString() ?? string.Empty)}",
    };

    private static string StringKey(string value) => $"{value.Length}:{value}";

    private static void KillProcess(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Best effort cleanup after a solver timeout.
        }
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }

    private readonly record struct SolverRun(SmtOutcome Outcome, string Output, bool TimedOut);
}

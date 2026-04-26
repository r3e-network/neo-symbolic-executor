namespace Neo.SymbolicExecutor;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public static class SeverityExtensions
{
    public static string ToLowerString(this Severity severity) => severity switch
    {
        Severity.Info => "info",
        Severity.Low => "low",
        Severity.Medium => "medium",
        Severity.High => "high",
        Severity.Critical => "critical",
        _ => severity.ToString().ToLowerInvariant(),
    };

    public static int Weight(this Severity severity) => severity switch
    {
        Severity.Info => 1,
        Severity.Low => 3,
        Severity.Medium => 7,
        Severity.High => 15,
        Severity.Critical => 31,
        _ => 0,
    };
}

using FluentAssertions;
using FluentAssertions.Extensibility;
using Xunit;

[assembly: AssertionEngineInitializer(
    typeof(Neo.SymbolicExecutor.Tests.FluentAssertionsConfig),
    nameof(Neo.SymbolicExecutor.Tests.FluentAssertionsConfig.Initialize))]
// Several SMT tests intentionally mutate NEO_SYMBOLIC_EXECUTOR_Z3 to force external/fallback
// solver modes. That environment variable is process-global, so the suite must be serialized.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Neo.SymbolicExecutor.Tests;

public static class FluentAssertionsConfig
{
    public static void Initialize()
    {
        License.Accepted = true;
    }
}

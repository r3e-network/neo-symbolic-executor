using System.Collections.Generic;
using Neo.SymbolicExecutor.Detectors.Detectors;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Built-in detector list. Subsequent commits add the remaining audit-driven detectors
/// (NEP-11, callback-reentry, replay, crypto-bypass, taint-flow upgrade, etc.).
/// </summary>
public static class DefaultDetectorSet
{
    public static IReadOnlyList<IDetector> All() => new IDetector[]
    {
        new ReentrancyDetector(),
        new AccessControlDetector(),
        new OverflowDetector(),
        new UncheckedReturnDetector(),
        new DynamicCallTargetDetector(),
        new UnknownInstructionsDetector(),
    };
}

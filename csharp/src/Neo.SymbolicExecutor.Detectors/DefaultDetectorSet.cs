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
        // Original 16 (16 of which are audit-driven; storage_collision, dos, gas_exhaustion below).
        new ReentrancyDetector(),
        new AccessControlDetector(),
        new OverflowDetector(),
        new UncheckedReturnDetector(),
        new DynamicCallTargetDetector(),
        new DangerousCallFlagsDetector(),
        new DosDetector(),
        new GasExhaustionDetector(),
        new RandomnessDetector(),
        new TimestampDetector(),
        new StorageCollisionDetector(),
        new UpgradeabilityDetector(),
        new PermissionsDetector(),
        new AdminCentralizationDetector(),
        new Nep17ComplianceDetector(),
        new UnknownInstructionsDetector(),
        // 5 new detectors per audit coverage gaps.
        new Nep11ComplianceDetector(),
        new CallbackReentryDetector(),
        new CryptoVerificationBypassDetector(),
        new ReplayAttackDetector(),
        new TaintFlowUpgradeDetector(),
    };
}

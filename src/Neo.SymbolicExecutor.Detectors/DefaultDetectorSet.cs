using System.Collections.Generic;
using Neo.SymbolicExecutor.Detectors.Detectors;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Built-in detector list. Detectors are stateless — we cache a single shared instance list
/// to avoid per-call allocations. Audit C# perf finding (iter 12): the prior `All()` returned
/// a fresh array of detector instances on every call; with the fuzzer invoking it
/// from multiple targets per iteration, this drove sustained allocation pressure that
/// contributed to multi-GB managed-heap growth on 1B+-iteration runs.
/// </summary>
public static class DefaultDetectorSet
{
    private static readonly IReadOnlyList<IDetector> _instances = new IDetector[]
    {
        // Original 16 (audit-driven).
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
        // Neo DApp / DeFi / NFT protocol-risk detectors.
        new PublicPrivilegedMethodDetector(),
        new DefiSlippageOracleDetector(),
        new NftOwnershipAuthorizationDetector(),
        // Cross-cutting Neo VM / contract-runtime issue classes (audit Iter-3 coverage pass).
        new EntryScriptAuthDetector(),
        new UnsafeDeserializationDetector(),
        new UnprotectedDeployDetector(),
        new Nep17AmountValidationDetector(),
    };

    public static IReadOnlyList<IDetector> All() => _instances;
}

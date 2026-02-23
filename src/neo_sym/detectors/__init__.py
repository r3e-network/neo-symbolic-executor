"""Security detectors module."""

from __future__ import annotations

from .access_control import AccessControlDetector
from .admin_centralization import AdminCentralizationDetector
from .base import SEVERITY_RANK, BaseDetector, Finding, Severity
from .dangerous_call_flags import DangerousCallFlagsDetector
from .dos import DoSDetector
from .dynamic_call_target import DynamicCallTargetDetector
from .gas_exhaustion import GasExhaustionDetector
from .nep17 import NEP17Detector
from .overflow import OverflowDetector
from .permissions import ManifestPermissionDetector
from .randomness import RandomnessDetector
from .reentrancy import ReentrancyDetector
from .storage import StorageCollisionDetector
from .timestamp import TimestampDetector
from .unchecked_return import UncheckedReturnDetector
from .unknown_instructions import UnknownInstructionsDetector
from .upgradeability import UpgradeabilityDetector

ALL_DETECTORS: dict[str, type[BaseDetector]] = {
    "access_control": AccessControlDetector,
    "admin_centralization": AdminCentralizationDetector,
    "dangerous_call_flags": DangerousCallFlagsDetector,
    "dos": DoSDetector,
    "dynamic_call_target": DynamicCallTargetDetector,
    "gas_exhaustion": GasExhaustionDetector,
    "manifest_permissions": ManifestPermissionDetector,
    "nep17": NEP17Detector,
    "overflow": OverflowDetector,
    "randomness": RandomnessDetector,
    "reentrancy": ReentrancyDetector,
    "storage_collision": StorageCollisionDetector,
    "timestamp": TimestampDetector,
    "unchecked_return": UncheckedReturnDetector,
    "unknown_instructions": UnknownInstructionsDetector,
    "upgradeability": UpgradeabilityDetector,
}

__all__ = [
    "ALL_DETECTORS",
    "SEVERITY_RANK",
    "AccessControlDetector",
    "AdminCentralizationDetector",
    "BaseDetector",
    "DangerousCallFlagsDetector",
    "DoSDetector",
    "DynamicCallTargetDetector",
    "Finding",
    "GasExhaustionDetector",
    "ManifestPermissionDetector",
    "NEP17Detector",
    "OverflowDetector",
    "RandomnessDetector",
    "ReentrancyDetector",
    "Severity",
    "StorageCollisionDetector",
    "TimestampDetector",
    "UncheckedReturnDetector",
    "UnknownInstructionsDetector",
    "UpgradeabilityDetector",
]

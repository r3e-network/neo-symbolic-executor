"""Security detectors module."""
from .base import BaseDetector, Finding, Severity
from .reentrancy import ReentrancyDetector
from .overflow import OverflowDetector
from .access_control import AccessControlDetector
from .unchecked_return import UncheckedReturnDetector
from .dos import DoSDetector
from .storage import StorageCollisionDetector
from .timestamp import TimestampDetector
from .randomness import RandomnessDetector
from .gas_exhaustion import GasExhaustionDetector
from .nep17 import NEP17Detector
from .admin_centralization import AdminCentralizationDetector
from .upgradeability import UpgradeabilityDetector
from .permissions import ManifestPermissionDetector
from .dynamic_call_target import DynamicCallTargetDetector
from .dangerous_call_flags import DangerousCallFlagsDetector

ALL_DETECTORS: dict[str, type[BaseDetector]] = {
    "reentrancy": ReentrancyDetector,
    "overflow": OverflowDetector,
    "access_control": AccessControlDetector,
    "unchecked_return": UncheckedReturnDetector,
    "dos": DoSDetector,
    "storage_collision": StorageCollisionDetector,
    "timestamp": TimestampDetector,
    "randomness": RandomnessDetector,
    "gas_exhaustion": GasExhaustionDetector,
    "nep17": NEP17Detector,
    "admin_centralization": AdminCentralizationDetector,
    "upgradeability": UpgradeabilityDetector,
    "manifest_permissions": ManifestPermissionDetector,
    "dynamic_call_target": DynamicCallTargetDetector,
    "dangerous_call_flags": DangerousCallFlagsDetector,
}

__all__ = ["ALL_DETECTORS", "BaseDetector", "Finding", "Severity"]

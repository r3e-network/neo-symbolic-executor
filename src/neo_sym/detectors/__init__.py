"""Security detectors module."""

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
    "unknown_instructions": UnknownInstructionsDetector,
}

__all__ = ["ALL_DETECTORS", "SEVERITY_RANK", "BaseDetector", "Finding", "Severity"]

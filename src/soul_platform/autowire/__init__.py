"""Production local-model discovery for SOUL Platform.

AutoWire keeps discovery separate from activation.  Discovery is read-only and
never sends SOUL context.  Activating a brain remains an explicit owner action.
"""

from soul_platform.autowire.manager import AutoWireManager
from soul_platform.autowire.types import ProviderCandidate, ProviderState

__all__ = ["AutoWireManager", "ProviderCandidate", "ProviderState"]

"""Normalizer registry: the single place vendor adapters are wired up."""

from __future__ import annotations

from app.normalize.adapters.cisco import CiscoIOSNormalizer, CiscoNXOSNormalizer
from app.normalize.adapters.fortinet import FortinetFortiOSNormalizer
from app.normalize.adapters.juniper import JuniperJunosNormalizer
from app.normalize.adapters.paloalto import PaloAltoPANOSNormalizer
from app.normalize.base import NormalizerRegistry

_registry: NormalizerRegistry | None = None

#: Declaration order is irrelevant -- ``priority()`` decides routing.
ALL_NORMALIZERS = (
    PaloAltoPANOSNormalizer,
    CiscoNXOSNormalizer,
    CiscoIOSNormalizer,
    FortinetFortiOSNormalizer,
    JuniperJunosNormalizer,
)


def get_registry() -> NormalizerRegistry:
    global _registry
    if _registry is None:
        _registry = NormalizerRegistry([cls() for cls in ALL_NORMALIZERS])
    return _registry

"""Shared fixtures: one normalized config per vendor, built once per session."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from app.normalize.models import NormalizedConfig, Vendor
from app.normalize.registry import get_registry

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "configs"

#: Every vendor the project claims to support. Adding a vendor means adding it
#: here too -- the parametrized suites below then fail loudly rather than
#: leaving the new adapter silently untested.
VENDOR_SAMPLES: dict[Vendor, str] = {
    Vendor.CISCO_IOS: "cisco_ios_core_switch.cfg",
    Vendor.FORTINET_FORTIOS: "fortinet_fortigate.cfg",
    Vendor.JUNIPER_JUNOS: "juniper_junos.txt",
    Vendor.PALOALTO_PANOS: "paloalto_panos.xml",
}


@pytest.fixture(scope="session")
def registry():
    return get_registry()


@pytest.fixture(scope="session")
def raw_samples() -> dict[Vendor, str]:
    return {vendor: (SAMPLES / name).read_text(encoding="utf-8") for vendor, name in VENDOR_SAMPLES.items()}


@pytest.fixture(scope="session")
def configs(registry, raw_samples) -> dict[Vendor, NormalizedConfig]:
    """Normalized configs, keyed by vendor. Session-scoped: parsing is slow."""
    out: dict[Vendor, NormalizedConfig] = {}
    for vendor, raw in raw_samples.items():
        adapter, confidence, _ = registry.detect(raw)
        assert adapter.vendor is vendor, f"{vendor} sample misdetected as {adapter.vendor}"
        out[vendor] = adapter.run(raw, device_id=f"dev-{vendor.value}")
    return out


@pytest.fixture
def cisco(configs) -> NormalizedConfig:
    return configs[Vendor.CISCO_IOS]


@pytest.fixture
def juniper(configs) -> NormalizedConfig:
    return configs[Vendor.JUNIPER_JUNOS]


@pytest.fixture
def panos(configs) -> NormalizedConfig:
    return configs[Vendor.PALOALTO_PANOS]


@pytest.fixture
def fortinet(configs) -> NormalizedConfig:
    return configs[Vendor.FORTINET_FORTIOS]


@pytest.fixture(params=list(VENDOR_SAMPLES), ids=lambda v: v.value)
def any_config(request, configs) -> NormalizedConfig:
    return configs[request.param]


@pytest.fixture
def engine():
    from app.analysis.rule_packs import get_engine

    return get_engine()


@pytest.fixture
def scorer():
    from app.analysis.compliance import ComplianceScorer

    return ComplianceScorer()


@pytest.fixture
def run_rules(engine):
    """``cfg -> (findings, outcomes)`` helper."""
    from itertools import count

    ids = count()

    def _run(cfg: NormalizedConfig):
        return engine.execute(cfg, analysis_id=f"an-test-{next(ids)}")

    return _run


@pytest.fixture
def failed_by_rule():
    def _index(findings) -> dict[str, object]:
        return {f.rule_id: f for f in findings}

    return _index


@pytest.fixture
def iter_all_configs(configs) -> Iterator[NormalizedConfig]:
    yield from configs.values()

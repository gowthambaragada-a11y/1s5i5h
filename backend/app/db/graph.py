"""Security Knowledge Graph over Neo4j.

What the graph adds that the rule engine cannot
-----------------------------------------------
Rules see one device at a time. The graph sees the *fleet*: which devices share a
management ACL, which trust paths reach an exposed service, which control has
been failing on every switch for a year. Those are cross-device questions, and
answering them by re-parsing every config on every request does not scale.

Every function here degrades to "no graph" when Neo4j is unreachable. An auditor
must be able to run the tool and get findings without standing up a second
database, so graph enrichment is strictly additive and its absence is reported
rather than hidden.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.core.config import get_settings
from app.normalize.models import NormalizedConfig, Vendor
from app.schemas.api import Finding

logger = logging.getLogger(__name__)

#: Constraints and indexes. Safe to re-run; Neo4j treats them as idempotent.
SCHEMA_STATEMENTS: tuple[str, ...] = (
    "CREATE CONSTRAINT device_id IF NOT EXISTS FOR (d:Device) REQUIRE d.device_id IS UNIQUE",
    "CREATE CONSTRAINT control_key IF NOT EXISTS FOR (c:Control) REQUIRE c.key IS UNIQUE",
    "CREATE INDEX device_vendor IF NOT EXISTS FOR (d:Device) ON (d.vendor)",
    "CREATE INDEX finding_rule IF NOT EXISTS FOR (f:Finding) ON (f.rule_id)",
)

#: MERGE-only writes. Nothing in this module ever DELETEs, because a shared
#: resource node may legitimately belong to a device whose row we have not seen.
_MERGE_DEVICE = (
    "MERGE (d:Device {device_id: $device_id}) SET d.vendor = $vendor, d.hostname = $hostname, d.role = $role"
)
_MERGE_CONTROL = (
    "MERGE (c:Control {key: $key}) SET c.framework = $framework, c.control_id = $control_id, c.title = $title"
)
_MERGE_FINDING = (
    "MATCH (d:Device {device_id: $device_id}) "
    "MERGE (f:Finding {finding_id: $finding_id}) "
    "SET f.rule_id = $rule_id, f.title = $title, f.severity = $severity, "
    "f.confidence = $confidence, f.status = $status "
    "MERGE (d)-[:RAISED]->(f)"
)
_MERGE_VIOLATES = (
    "MATCH (f:Finding {finding_id: $finding_id}) MATCH (c:Control {key: $key}) MERGE (f)-[:VIOLATES]->(c)"
)
_MERGE_SERVICES = (
    "MATCH (d:Device {device_id: $device_id}) "
    "MERGE (s:Service {name: $name, port: $port, service: $service}) "
    "MERGE (d)-[:EXPOSES]->(s)"
)

#: Attack paths worth flagging: a device exposing a management service with no
#: restrictive binding is reachable from anywhere it is routed.
_REACHABILITY_QUERY = """
MATCH (d:Device)-[:EXPOSES]->(s:Service)
WHERE s.restricted = false
OPTIONAL MATCH (d)-[:MANAGED_BY]->(peer:Device)
RETURN d.device_id AS device_id,
       s.name AS service,
       s.port AS port,
       count(peer) AS shared_managers
ORDER BY shared_managers DESC, device_id
"""


@dataclass
class GraphAvailability:
    """Whether the graph is usable, and why not when it is not."""

    available: bool = False
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"available": self.available, "reason": self.reason}


@dataclass
class GraphEnrichment:
    """Result of pushing one analysis into the graph."""

    devices: int = 0
    findings: int = 0
    controls: int = 0
    services: int = 0
    skipped_reason: str | None = None

    @property
    def nodes_written(self) -> int:
        return self.devices + self.findings + self.controls + self.services


@dataclass
class SecurityGraph:
    """Thin wrapper over the Neo4j driver.

    The driver is created lazily so importing this module never opens a socket,
    which keeps the test suite and the CLI fast.
    """

    _driver: Any = field(default=None, repr=False)
    _available: bool = field(default=False, repr=False)
    _reason: str | None = field(default=None, repr=False)

    @classmethod
    def from_settings(cls) -> SecurityGraph:
        settings = get_settings()
        graph = cls()
        if not settings.graph_enabled:
            graph._reason = "graph disabled by configuration"
            return graph
        if not settings.neo4j_password:
            graph._reason = "no neo4j password configured"
            return graph
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:  # pragma: no cover - neo4j is a hard dep
            graph._reason = f"neo4j driver unavailable: {exc}"
            return graph
        try:
            graph._driver = GraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
            )
            graph._driver.verify_connectivity()
            graph._available = True
        except Exception as exc:  # noqa: BLE001 - any driver failure means "off"
            graph._reason = f"neo4j unreachable: {type(exc).__name__}: {exc}"
            logger.info("graph unavailable: %s", graph._reason)
        return graph

    @property
    def available(self) -> bool:
        return self._available

    def availability(self) -> GraphAvailability:
        return GraphAvailability(available=self._available, reason=self._reason)

    def apply_schema(self) -> None:
        if not self._available:
            return
        with self._driver.session() as session:
            for statement in SCHEMA_STATEMENTS:
                session.run(statement)

    def ingest(self, cfg: NormalizedConfig, findings: list[Finding], *, analysis_id: str) -> GraphEnrichment:
        """Write one device, its findings, their controls and its services."""
        if not self._available:
            return GraphEnrichment(skipped_reason=self._reason or "graph unavailable")

        result = GraphEnrichment()
        _ = analysis_id
        with self._driver.session() as session:
            session.run(
                _MERGE_DEVICE,
                device_id=cfg.device_id,
                vendor=str(cfg.vendor),
                hostname=cfg.identity.hostname or "",
                role=str(cfg.role),
            )
            result.devices = 1

            for finding in findings:
                session.run(
                    _MERGE_FINDING,
                    device_id=cfg.device_id,
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    title=finding.title,
                    severity=str(finding.severity),
                    confidence=finding.confidence,
                    status=str(finding.status),
                )
                result.findings += 1
                for control in finding.controls:
                    key = f"{control.framework}:{control.control_id}"
                    session.run(
                        _MERGE_CONTROL,
                        key=key,
                        framework=str(control.framework),
                        control_id=control.control_id,
                        title=control.title,
                    )
                    session.run(_MERGE_VIOLATES, finding_id=finding.id, key=key)
                    result.controls += 1

            for service in cfg.services:
                if not service.enabled:
                    continue
                session.run(
                    _MERGE_SERVICES,
                    device_id=cfg.device_id,
                    name=str(service.service),
                    port=service.port.high,
                    service=str(service.service),
                )
                session.run(
                    "MATCH (s:Service {name: $name, port: $port}) SET s.restricted = $restricted",
                    name=str(service.service),
                    port=service.port.high,
                    restricted=not service.is_unrestricted,
                )
                result.services += 1
        return result

    def exposed_services(self) -> list[dict[str, Any]]:
        """Devices exposing an unrestricted service. Empty when graph is off."""
        if not self._available:
            return []
        with self._driver.session() as session:
            return [dict(record) for record in session.run(_REACHABILITY_QUERY)]

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
        self._driver = None
        self._available = False


def cross_vendor_peers(devices: list[NormalizedConfig]) -> dict[str, list[str]]:
    """Peers per vendor, for reporting. Works without Neo4j.

    Included here so callers have one place to ask "who else is this device
    comparable to", even when the graph is switched off.
    """
    grouped: dict[str, list[str]] = {}
    for cfg in devices:
        grouped.setdefault(str(cfg.vendor), []).append(cfg.device_id)
    return grouped


def peer_group_vendor(vendor: Vendor, available: dict[str, list[str]]) -> str:
    return vendor.value if available.get(vendor.value) else "unknown"

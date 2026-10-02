"""Normalizer abstraction -- DELIVERABLE 4.

Every vendor adapter implements :class:`VendorNormalizer` and returns a
:class:`NormalizedConfig`. The pipeline never sees vendor syntax past this
boundary.

Contract
--------
``supports``    cheap vendor sniff, used to route a file to the right adapter.
``parse``       text -> vendor-native AST (dict). Free to use any library.
``normalize``   AST -> ``NormalizedConfig``. Pure mapping, no regex guessing.

Splitting parse from normalize matters: ``parse`` can be slow (pyATS,
hier_config) and vendor-fiddly, while ``normalize`` is a pure function that is
easy to unit test with a fixture dict and impossible to get silently wrong.
It also lets us cache the vendor AST in Postgres and re-normalize without
re-reading the file.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Literal

from app.normalize.models import NormalizedConfig, SourceRef, SourceRefs, Vendor


class NormalizationError(RuntimeError):
    """Raised when a config cannot be mapped to the unified model."""

    def __init__(self, message: str, *, vendor: Vendor | None = None, line_no: int | None = None):
        super().__init__(message)
        self.vendor = vendor
        self.line_no = line_no


class VendorNormalizer(ABC):
    """Base class for a vendor-specific normalizer."""

    #: Vendor this adapter handles.
    vendor: ClassVar[Vendor]
    #: Prefix used for evidence logging and rule-pack selection.
    rule_pack: ClassVar[str]
    #: Whether this adapter can cite an exact config line for every finding.
    #: Line-oriented formats say "line"; brace/XML tree walkers say "block".
    evidence_precision: ClassVar[Literal["line", "block"]] = "line"

    # -- routing ----------------------------------------------------------
    @classmethod
    @abstractmethod
    def supports(cls, raw_text: str) -> float:
        """Return confidence in [0, 1] that ``raw_text`` is this vendor's config.

        Implementations should weight *distinctive* markers (e.g. PAN-OS
        ``set address`` / ``<entry name=``) far above generic ones (``hostname``).
        """

    @classmethod
    def priority(cls) -> int:
        """Higher wins ties. Fortinet/PAN-OS XML-ish forms beat generic regex."""
        return 50

    # -- the two required phases -----------------------------------------
    @abstractmethod
    def parse(self, raw_text: str) -> dict[str, Any]:
        """Vendor syntax -> vendor-native AST. May be lossless or lossy."""

    @abstractmethod
    def normalize(self, ast: dict[str, Any]) -> NormalizedConfig:
        """Vendor AST -> unified model. Must not perform I/O."""

    # -- shared helpers ---------------------------------------------------
    def run(self, raw_text: str, *, device_id: str) -> NormalizedConfig:
        """Convenience: parse then normalize, tagging warnings on the way out."""
        ast = self.parse(raw_text)
        cfg = self.normalize(ast)
        cfg.device_id = device_id
        cfg.vendor = self.vendor
        cfg.parse_warnings.extend(ast.get("_warnings", []))
        cfg.evidence_precision = type(self).evidence_precision
        # Coverage is measured *after* normalization because that is the only
        # point where we know which source lines actually became entities.
        cfg.unparsed_line_ratio = self.coverage_gap(raw_text, cfg)
        # Fingerprint the exact bytes that produced this config. Computed here
        # because this is the only place both the raw upload and the finished
        # config are in scope; an auditor needs it to prove which file a finding
        # came from, and the pipeline uses it to skip re-analysing a re-upload.
        cfg.raw_config_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        return cfg

    @staticmethod
    def coverage_gap(raw_text: str, cfg: NormalizedConfig) -> float:
        """Fraction of meaningful config lines that produced no normalized entity.

        This is the honest confidence signal: a parser that silently ignores a
        whole config section will show a high gap, and the dashboard lowers its
        trust in the score rather than reporting a clean bill of health we did
        not earn.
        """
        meaningful = [
            ln for ln in raw_text.splitlines() if ln.strip() and not ln.strip().startswith(("!", "#", "/*"))
        ]
        if not meaningful:
            return 0.0

        covered: set[int] = set()
        for refs in _iter_source_refs(cfg):
            covered.update(ref.line_no for ref in refs.refs if ref.line_no > 0)
        return round(max(0.0, 1.0 - (len(covered) / len(meaningful))), 4)

    @staticmethod
    def count_unparsed(raw_text: str, recognised: set[str]) -> float:
        """Fraction of non-blank lines missing from ``recognised``.

        Kept for adapters that track handled lines explicitly; prefer
        :meth:`coverage_gap` where entity provenance is available.
        """
        lines = [ln for ln in raw_text.splitlines() if ln.strip() and not ln.strip().startswith(("!", "#"))]
        if not lines:
            return 0.0
        covered = sum(1 for ln in lines if ln.strip() in recognised)
        return round(1.0 - (covered / len(lines)), 4)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} vendor={self.vendor}>"


def _iter_source_refs(cfg: NormalizedConfig) -> list[SourceRefs]:
    """Every SourceRefs bundle in a NormalizedConfig, flattened."""
    out: list[SourceRefs] = [cfg.logging.source_refs, cfg.routing.source_refs, cfg.crypto.source_refs]
    out.extend(i.source for i in cfg.interfaces)
    out.extend(c.source_refs for c in cfg.credentials)
    out.extend(s.source_refs for s in cfg.services)
    for acl in cfg.access_lists:
        out.append(acl.source_refs)
        out.extend(r.source_refs for r in acl.rules)
    return out


def all_source_refs(cfg: NormalizedConfig) -> list[SourceRef]:
    """Every individual :class:`SourceRef` held by ``cfg``.

    Public so the invariant tests can assert the property the whole product
    rests on: every fact NETGUARD reports is traceable to a real line.
    """
    return [ref for bundle in _iter_source_refs(cfg) for ref in bundle.refs]


class NormalizerRegistry:
    """Chooses an adapter for a given blob of config text."""

    def __init__(self, normalizers: list[VendorNormalizer] | None = None) -> None:
        self._normalizers: list[VendorNormalizer] = sorted(
            normalizers or [], key=lambda n: type(n).priority(), reverse=True
        )

    def register(self, normalizer: VendorNormalizer) -> None:
        self._normalizers.append(normalizer)
        self._normalizers.sort(key=lambda n: type(n).priority(), reverse=True)

    @property
    def normalizers(self) -> list[VendorNormalizer]:
        return list(self._normalizers)

    def detect(
        self, raw_text: str, *, threshold: float = 0.30
    ) -> tuple[VendorNormalizer | None, float, list[tuple[str, float]]]:
        """Return (best_adapter, confidence, full_score_table).

        The score table is returned so the API can show *why* a vendor was
        chosen -- important when a user uploads a mixed config.
        """
        scores: list[tuple[str, float]] = [
            (type(n).__name__, round(float(n.supports(raw_text)), 4)) for n in self._normalizers
        ]
        scores.sort(key=lambda pair: pair[1], reverse=True)
        if not scores or scores[0][1] < threshold:
            return None, (scores[0][1] if scores else 0.0), scores
        by_name = {type(n).__name__: n for n in self._normalizers}
        best = by_name[scores[0][0]]
        return best, scores[0][1], scores

    def get(self, vendor: Vendor) -> VendorNormalizer | None:
        return next((n for n in self._normalizers if n.vendor is vendor), None)

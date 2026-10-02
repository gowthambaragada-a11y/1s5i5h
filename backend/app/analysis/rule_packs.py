"""Rule pack assembly.

A "pack" is the set of rules enabled for a vendor. Keeping the mapping here
(rather than inside the engine) means adding a vendor is a one-line change and
the rule classes stay vendor-agnostic.
"""

from __future__ import annotations

from app.analysis.rules import firewall as fw
from app.analysis.rules import management as mgmt
from app.analysis.rules.base import RuleEngine, SecurityRule
from app.normalize.models import Vendor

#: Every rule the engine knows about. Order drives execution order only.
ALL_RULES: tuple[type[SecurityRule], ...] = (
    # Management plane
    mgmt.TelnetEnabled,
    mgmt.SSHVersion1,
    mgmt.UnrestrictedManagementService,
    mgmt.NoExecTimeout,
    mgmt.WeakPasswordStorage,
    mgmt.SharedPrivilege15Account,
    mgmt.SNMPWeakCommunity,
    mgmt.PasswordEncryptionDisabled,
    # Logging / audit
    mgmt.RemoteSyslogAbsent,
    mgmt.LogLevelTooVerbose,
    mgmt.ConfigChangeLoggingMissing,
    # Traffic policy
    fw.AnyAnyAllow,
    fw.UnrestrictedInterfaceExposure,
    fw.WidePortRange,
    fw.RemoteAdminServicesExposed,
    fw.DenyAllMissing,
    fw.DeadRule,
    fw.LoggingDisabledOnPermit,
    fw.DisabledRuleWithAllowAction,
    # Infrastructure
    fw.UnusedInterfaceAddressing,
    mgmt.DefaultRoutePresent,
    mgmt.WeakIKECrypto,
)

_BY_ID: dict[str, type[SecurityRule]] = {r.rule_id: r for r in ALL_RULES}


def get_engine(*, vendor: Vendor | None = None) -> RuleEngine:
    """Build a :class:`RuleEngine`.

    ``vendor`` is accepted for symmetry with the pack registry and future
    per-vendor rule tuning. Today every rule self-gates on ``applies_to``, so
    passing all of them is correct and keeps cross-vendor comparisons honest.
    """
    return RuleEngine([cls() for cls in ALL_RULES])


def rules_for_vendor(vendor: Vendor) -> list[SecurityRule]:
    """Instantiated rules that apply to ``vendor``."""
    out: list[SecurityRule] = []
    for cls in ALL_RULES:
        rule = cls()
        if vendor is Vendor.UNKNOWN:
            if rule.run_on_unknown_vendor:
                out.append(rule)
        elif vendor in rule.applies_to:
            out.append(rule)
    return out


def control_index() -> dict[str, str]:
    """``control_id -> rule_id`` for coverage reporting."""
    index: dict[str, str] = {}
    for cls in ALL_RULES:
        for cid in cls.control_ids:
            index.setdefault(cid, cls.rule_id)
    return index

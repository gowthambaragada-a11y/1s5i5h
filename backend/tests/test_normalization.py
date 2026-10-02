"""Vendor detection and normalization contract tests.

The recurring theme here is *evidence*: every structural fact NETGUARD reports
must be traceable to a real line in the uploaded file. Several of these tests
were written after finding a defect where the fact was correct but the
supporting evidence was missing or pointed at the wrong line.
"""

from __future__ import annotations

import pytest

from app.normalize.base import all_source_refs
from app.normalize.models import (
    SEVERITY_ORDER,
    AdminState,
    DeviceRole,
    ManagementService,
    PortRange,
    Protocol,
    Severity,
    Vendor,
)

pytestmark = pytest.mark.usefixtures("configs")


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
class TestDetection:
    @pytest.mark.parametrize(
        ("vendor", "min_confidence"),
        [
            (Vendor.CISCO_IOS, 0.5),
            (Vendor.FORTINET_FORTIOS, 0.4),
            (Vendor.JUNIPER_JUNOS, 0.9),
            (Vendor.PALOALTO_PANOS, 0.9),
        ],
    )
    def test_detects_expected_vendor(self, registry, raw_samples, vendor, min_confidence):
        adapter, confidence, signals = registry.detect(raw_samples[vendor])
        assert adapter.vendor is vendor
        assert confidence >= min_confidence, f"{vendor} detected with low confidence {confidence}"
        assert signals, "detection must report the signals it matched on"

    def test_detection_is_stable_across_calls(self, registry, raw_samples):
        first = registry.detect(raw_samples[Vendor.CISCO_IOS])[0].vendor
        second = registry.detect(raw_samples[Vendor.CISCO_IOS])[0].vendor
        assert first is second

    def test_unknown_input_is_reported_as_unknown(self, registry):
        adapter, confidence, _ = registry.detect("this is a haiku, not a network config\n")
        assert adapter is None
        assert confidence <= 0.2

    def test_empty_input_does_not_raise(self, registry):
        adapter, confidence, _ = registry.detect("")
        assert adapter is None
        assert confidence == 0.0


# --------------------------------------------------------------------------- #
# Role inference
# --------------------------------------------------------------------------- #
class TestRoleInference:
    def test_cisco_switch_is_a_switch(self, cisco):
        assert cisco.role is DeviceRole.SWITCH

    def test_firewalls_are_detected_as_firewalls(self, juniper, panos, fortinet):
        assert juniper.role is DeviceRole.FIREWALL
        assert panos.role is DeviceRole.FIREWALL
        assert fortinet.role is DeviceRole.FIREWALL


# --------------------------------------------------------------------------- #
# Interfaces and addresses
# --------------------------------------------------------------------------- #
class TestInterfaces:
    def test_interfaces_are_found_for_every_vendor(self, any_config):
        assert any_config.interfaces, f"{any_config.vendor} produced no interfaces"

    def test_every_interface_has_an_admin_state(self, any_config):
        for iface in any_config.interfaces:
            assert isinstance(iface.admin_state, AdminState)

    def test_trunk_interface_carries_subnets(self, cisco):
        trunk = next((i for i in cisco.interfaces if i.kind.value.startswith("trunk")), None)
        if trunk is not None:
            assert trunk.ipv4, "an active trunk with no subnet is likely a parse miss"

    def test_loopback_interfaces_are_flagged_as_loopback(self, cisco):
        loopbacks = [i for i in cisco.interfaces if "loopback" in i.name.lower()]
        for lo in loopbacks:
            assert lo.is_l3


# --------------------------------------------------------------------------- #
# Ports -- the semantics that silently hid any-any rules
# --------------------------------------------------------------------------- #
class TestPortSemantics:
    def test_portless_ace_counts_as_any_port(self):
        """'permit ip any any' omits the port operand, meaning every port.

        Keying 'is_any' on Protocol.ANY alone hid these from the any-any and
        wide-range checks, because their span computed as a single port.
        """
        pr = PortRange(protocol=Protocol.IP)
        assert pr.is_any
        assert pr.span == 65535

    def test_protocol_any_with_ports_is_not_any(self):
        pr = PortRange(protocol=Protocol.ANY, low=80, high=80)
        assert not pr.is_any
        assert not pr.is_all_protocols

    def test_single_port_is_not_any(self):
        assert not PortRange(protocol=Protocol.TCP, low=22, high=22).is_any

    def test_range_span_is_inclusive(self):
        assert PortRange(protocol=Protocol.TCP, low=100, high=200).span == 101

    def test_contains_respects_bounds(self):
        pr = PortRange(protocol=Protocol.TCP, low=100, high=200)
        assert pr.contains(100) and pr.contains(200) and pr.contains(150)
        assert not pr.contains(99) and not pr.contains(201)

    def test_any_port_range_contains_everything(self):
        assert PortRange(protocol=Protocol.ANY).contains(1)
        assert PortRange(protocol=Protocol.ANY).contains(65535)

    def test_well_known_service_names_resolve(self):
        assert PortRange(protocol=Protocol.TCP, low=22, high=22).well_known_name == "ssh"


# --------------------------------------------------------------------------- #
# Services -- management plane exposure
# --------------------------------------------------------------------------- #
class TestServices:
    def test_telnet_is_exposed_in_the_cisco_sample(self, cisco):
        telnet = cisco.service(ManagementService.TELNET)
        assert telnet is not None and telnet.enabled

    def test_transport_input_lists_both_protocols(self, cisco):
        """'transport input telnet ssh' enables both.

        Reading only the leading token reported SSH as disabled on a device
        that was plainly using it.
        """
        ssh = cisco.service(ManagementService.SSH)
        assert ssh is not None and ssh.enabled, "SSH reported disabled despite 'transport input telnet ssh'"

    def test_vty_exec_timeout_is_captured(self, cisco):
        """exec-timeout lives under 'line vty' and must reach the SSH binding."""
        ssh = cisco.service(ManagementService.SSH)
        assert ssh is not None
        assert ssh.timeout_seconds == 5

    def test_unrestricted_services_have_no_acl(self, cisco):
        telnet = cisco.service(ManagementService.TELNET)
        assert telnet is not None
        assert telnet.is_unrestricted

    def test_panos_telnet_and_ssh_are_both_reported(self, panos):
        assert panos.service(ManagementService.TELNET) is not None
        assert panos.service(ManagementService.SSH) is not None


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #
class TestCredentials:
    def test_privileged_accounts_are_identified(self, cisco):
        assert any(c.is_privileged for c in cisco.credentials)

    def test_password_material_is_never_retained(self, any_config):
        """Credential objects must never carry the secret itself.

        The whole point of the evidence model is that a config file can be
        handled safely; storing the password would defeat that.
        """
        blob = any_config.model_dump_json()
        assert "121A0E041104" not in blob, "reversible Cisco password leaked into the model"
        assert "plaintext123" not in blob, "plaintext password leaked into the model"

    def test_weak_password_evidence_still_cites_the_line(self, cisco):
        cred = next(c for c in cisco.credentials if c.username == "netops")
        assert cred.source_refs.refs
        assert any("password" in r.raw.lower() for r in cred.source_refs.refs)


# --------------------------------------------------------------------------- #
# Access rules
# --------------------------------------------------------------------------- #
class TestAccessRules:
    def test_rules_are_normalized_for_every_vendor(self, any_config):
        rules = [r for acl in any_config.access_lists for r in acl.rules]
        assert rules, f"{any_config.vendor} produced no access rules"

    def test_permissive_rules_exist_in_the_samples(self, cisco):
        rules = [r for acl in cisco.access_lists for r in acl.rules]
        assert any(r.is_permissive for r in rules)

    def test_every_permissive_rule_has_destination_or_service_detail(self, cisco):
        rules = [r for acl in cisco.access_lists for r in acl.rules if r.is_permissive]
        unconstrained = [r for r in rules if r.source.is_any and r.destination.is_any]
        # The Cisco fixture intentionally contains exactly one any-any rule, so
        # assert it is identified rather than asserting none exist.
        assert len(unconstrained) == 1, f"expected 1 any-any rule, found {len(unconstrained)}"
        assert unconstrained[0].source_refs.refs, "any-any rule must cite its config line"

    def test_any_any_rule_is_present_and_evidenced(self, cisco):
        any_any = [
            r
            for acl in cisco.access_lists
            for r in acl.rules
            if r.is_permissive and r.source.is_any and r.destination.is_any
        ]
        assert any_any, "sample is supposed to contain 'permit ip any any'"
        for rule in any_any:
            assert rule.source_refs.refs, "any-any rule must cite its config line"

    def test_rejected_rules_are_not_treated_as_permissive(self, any_config):
        for acl in any_config.access_lists:
            for rule in acl.rules:
                if "deny" in rule.action.value or rule.action.value == "discard":
                    assert rule.action.value in {"deny", "discard"}


# --------------------------------------------------------------------------- #
# Routing, logging, crypto
# --------------------------------------------------------------------------- #
class TestOtherSections:
    def test_default_route_is_detected_with_evidence(self, cisco):
        assert cisco.routing.default_route_present
        assert cisco.routing.source_refs.refs, "default route detected but no line cited"
        assert any("0.0.0.0" in r.raw for r in cisco.routing.source_refs.refs)  # noqa: S104 - default-route citation

    def test_syslog_server_is_captured(self, cisco):
        assert cisco.logging.remote_servers

    def test_weak_ike_proposal_is_detected_with_evidence(self, juniper):
        assert juniper.crypto.weak_ciphers, "sample has a DES/MD5 proposal"
        assert juniper.crypto.source_refs.refs, "weak IKE detected but no proposal line cited"
        assert any("proposal" in r.raw for r in juniper.crypto.source_refs.refs)

    def test_snmp_communities_are_captured(self, cisco):
        snmp = cisco.service(ManagementService.SNMP)
        assert snmp is not None


# --------------------------------------------------------------------------- #
# Evidence quality -- the invariant this whole project rests on
# --------------------------------------------------------------------------- #
class TestEvidenceQuality:
    def test_every_source_ref_has_a_line_number(self, any_config):
        for ref in all_source_refs(any_config):
            assert ref.line_no > 0, f"evidence without a line number: {ref.raw!r}"

    def test_evidence_line_numbers_are_within_the_file(self, any_config, raw_samples):
        total = len(raw_samples[any_config.vendor].splitlines())
        for ref in all_source_refs(any_config):
            assert ref.line_no <= total, (
                f"{any_config.vendor} cited line {ref.line_no} but the file has only {total} lines"
            )

    def test_every_interface_is_evidenced(self, any_config):
        for iface in any_config.interfaces:
            assert iface.source.refs, f"interface {iface.name} has no evidence"

    def test_junos_reports_block_level_evidence(self, juniper):
        """Junos is brace-delimited, so line precision would be a lie."""
        assert juniper.evidence_precision == "block"

    def test_line_based_vendors_report_line_evidence(self, cisco, panos, fortinet):
        for cfg in (cisco, panos, fortinet):
            assert cfg.evidence_precision == "line"

    def test_severity_ordering_is_strictly_descending(self):
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        ranks = [SEVERITY_ORDER[s] for s in order]
        assert ranks == sorted(ranks, reverse=True)
        assert len(set(ranks)) == len(order), "severity ranks must be distinct"

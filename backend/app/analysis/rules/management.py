"""Vendor-agnostic rules: management plane, credentials, logging, crypto.

These run against every device because they are expressed purely in terms of
the unified model -- an ``ssh`` service with no source restriction means the
same thing on IOS, Junos, FortiOS and PAN-OS.
"""

from __future__ import annotations

from app.analysis.rules.base import (
    RuleOutcome,
    SecurityRule,
    fail,
    passed,
)
from app.normalize.models import (
    ManagementService,
    NormalizedConfig,
    Severity,
    SourceRefs,
    Vendor,
)


class TelnetEnabled(SecurityRule):
    rule_id = "NG-REMOTE-TELNET-ENABLED"
    title = "Telnet management service is enabled"
    description = (
        "Telnet transmits credentials in clear text. CIS benchmarks and DISA STIGs require it to be "
        "disabled and replaced with SSH."
    )
    severity = Severity.CRITICAL
    confidence = 0.97
    cvss_score = 9.1
    control_ids = ("CIS-CISCO-1.2.1", "STIG-NET-1", "CIS-FGT-2", "CIS-PAN-2", "NIST-AC-3", "ISO-A.5.15")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        telnet = cfg.service(ManagementService.TELNET)
        if telnet is None or not telnet.enabled:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        scope = " from any source address" if telnet.is_unrestricted else ""
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                cvss_score=self.cvss_score,
                evidence=telnet.source_refs,
                affected=[f"service:{ManagementService.TELNET.value}"],
                control_ids=self.control_ids,
                port=telnet.port.low,
                restricted=bool(telnet.restricted_to),
                explanation=_telnet_explanation(scope),
            )
        ]


def _telnet_explanation(scope: str) -> str:
    reachability = (
        f". Right now it is reachable{scope}, which widens that risk considerably. " if scope else ". "
    )
    return (
        "Telnet sends your login and password in clear text over the network, so anyone on the same "
        "segment or any router in between can capture them and take over this device"
        + reachability
        + "Switching to SSH encrypts the session so credentials cannot be read or replayed."
    )


class SSHVersion1(SecurityRule):
    rule_id = "NG-REMOTE-SSH-V1"
    title = "SSH version 1 is in use or not explicitly disabled"
    description = "SSHv1 has broken key exchange; CIS requires 'ip ssh version 2'."
    severity = Severity.HIGH
    confidence = 0.88
    cvss_score = 7.4
    control_ids = ("CIS-CISCO-1.1.1", "NIST-SC-13", "ISO-A.8.24")
    #: Declared as data rather than an ``if`` inside evaluate(), so the engine
    #: records an explicit NOT_APPLICABLE for every other vendor. A rule that
    #: quietly returns None leaves no trace, and a missing trace is
    #: indistinguishable from "we checked and it was fine".
    applies_to = frozenset({Vendor.CISCO_IOS, Vendor.CISCO_NXOS})

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        # Only Cisco IOS/NX-OS expose a configurable protocol version
        # ('ip ssh version 1|2'). On FortiOS, PAN-OS and Junos there is no such
        # statement to inspect, so an absent version is not a finding -- treating
        # "unspecified" as "vulnerable" there produced a critical false positive
        # on every PAN-OS device, which would destroy trust in the whole report.
        if cfg.vendor not in {Vendor.CISCO_IOS, Vendor.CISCO_NXOS}:
            return None

        ssh = cfg.service(ManagementService.SSH)
        if ssh is None or not ssh.enabled:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        version = (ssh.version or "").strip().lower().lstrip("v")
        if version in {"2", "2.0"}:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        if version == "1":
            return [
                fail(
                    self.rule_id,
                    self.title,
                    description=self.description,
                    severity=self.severity,
                    confidence=self.confidence,
                    cvss_score=self.cvss_score,
                    evidence=ssh.source_refs,
                    affected=["service:ssh"],
                    control_ids=self.control_ids,
                    ssh_version="1",
                )
            ]

        # No 'ip ssh version' statement at all: IOS defaults to v1, so this is a
        # real failure but with slightly lower confidence because it is inferred
        # from an absence rather than read from an explicit insecure setting.
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=0.7,
                cvss_score=self.cvss_score,
                evidence=ssh.source_refs,
                affected=["service:ssh"],
                control_ids=self.control_ids,
                ssh_version="unspecified (device default is 1)",
            )
        ]


class UnrestrictedManagementService(SecurityRule):
    rule_id = "NG-REMOTE-MGMT-UNRESTRICTED"
    title = "Administrative service reachable from any source address"
    description = (
        "Management services must be restricted to a management/jump-host network via an ACL, "
        "access-class or vendor management profile."
    )
    severity = Severity.HIGH
    confidence = 0.85
    cvss_score = 7.5
    control_ids = (
        "CIS-CISCO-1.2.1",
        "CIS-FGT-1",
        "CIS-FGT-4",
        "CIS-PAN-4",
        "NIST-AC-17",
        "NIST-SC-7",
        "ISO-A.5.15",
    )

    #: Services where world-reachability is an outright finding.
    MONITORED = (
        ManagementService.SSH,
        ManagementService.TELNET,
        ManagementService.HTTP,
        ManagementService.SNMP,
    )

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome]:
        out: list[RuleOutcome] = []
        for svc in cfg.services:
            if svc.service not in self.MONITORED or not svc.enabled:
                continue
            if not svc.is_unrestricted:
                continue
            # HTTP next to HTTPS is a downgrade risk but not an exposed admin plane
            # on its own; it gets its own lower-severity rule.
            severity = self.severity
            if svc.service is ManagementService.HTTP or (
                cfg.vendor is Vendor.FORTINET_FORTIOS and svc.service is ManagementService.HTTPS
            ):
                severity = Severity.MEDIUM
            out.append(
                fail(
                    self.rule_id,
                    f"{svc.service.value.upper()} is reachable from any source address",
                    description=self.description,
                    severity=severity,
                    confidence=self.confidence if svc.service is not ManagementService.HTTP else 0.7,
                    evidence=svc.source_refs,
                    affected=[f"service:{svc.service.value}"],
                    control_ids=self.control_ids,
                    service=svc.service.value,
                    port=svc.port.low,
                )
            )
        return out


class WeakPasswordStorage(SecurityRule):
    rule_id = "NG-CRED-WEAK-PASSWORD-TYPE"
    title = "Local account uses reversible or plaintext password storage"
    description = (
        "Cisco 'password' (type 0/7) stores secrets reversibly; 'secret' (type 5/8/9) is hashed. "
        "STIG and CIS require hashed secrets exclusively."
    )
    severity = Severity.HIGH
    confidence = 0.8
    cvss_score = 6.8
    control_ids = ("NIST-IA-5", "CIS-CISCO-4.6.1", "STIG-SRX-2", "ISO-A.5.17")
    #: Reads Cisco's reversible 'password' vs hashed 'secret' keyword pair, which
    #: only exists on IOS/NX-OS.
    applies_to = frozenset({Vendor.CISCO_IOS, Vendor.CISCO_NXOS})

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:

        # Re-derive from the raw evidence: the normalizer deliberately does not
        # retain password material, so we inspect only the *storage type*
        # keyword (type 0 = plaintext, type 7 = weak Vigenere) and never the
        # secret itself.
        weak_users: list[str] = []
        refs = SourceRefs()

        for cred in cfg.credentials:
            for ref in cred.source_refs.refs:
                low = f" {ref.raw.lower()} "
                if " password " in low and " secret " not in low:
                    weak_users.append(cred.username)
                    refs.add(ref)
                    break

        if not weak_users:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=refs,
                affected=[f"user:{u}" for u in weak_users],
                control_ids=self.control_ids,
                usernames=weak_users,
            )
        ]


class SharedPrivilege15Account(SecurityRule):
    rule_id = "NG-CRED-PRIVILEGE-15-SHARED"
    title = "Administrative credentials are shared across operators"
    description = (
        "NIST AC-2 requires unique, attributable accounts. A single privileged login shared by "
        "several engineers defeats audit attribution and separation of duties."
    )
    severity = Severity.MEDIUM
    confidence = 0.6
    control_ids = ("NIST-AC-2", "ISO-A.8.2", "ISO-A.5.18")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        privileged = [c for c in cfg.credentials if c.is_privileged]
        others = [c for c in cfg.credentials if not c.is_privileged]
        if len(privileged) != 1 or not others:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        admin = privileged[0]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=admin.source_refs,
                affected=[f"user:{admin.username}"],
                control_ids=self.control_ids,
                admin_username=admin.username,
                unprivileged_users=[c.username for c in others],
            )
        ]


class SNMPWeakCommunity(SecurityRule):
    rule_id = "NG-SNMP-WEAK-COMMUNITY"
    title = "SNMP uses a guessable community string over v1/v2c"
    description = (
        "SNMPv1/v2c community strings travel in clear text and are frequently left at defaults. "
        "CIS requires SNMPv3 with authentication and privacy."
    )
    severity = Severity.CRITICAL
    confidence = 0.92
    cvss_score = 8.8
    control_ids = ("CIS-CISCO-1.3.1", "CIS-FGT-6", "NIST-SC-8", "NIST-AC-3", "ISO-A.8.15")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        snmp = cfg.service(ManagementService.SNMP)
        if snmp is None or not snmp.enabled:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        version = (snmp.version or "").lower()
        # SNMPv3 with an auth+priv suffix means v1/v2c communities are not the
        # live auth path even if legacy entries linger in the config.
        if version.startswith("3") and "-" in version:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        # The normalizer classified each community rather than storing it, so
        # this check can never leak the value it is complaining about.
        defaults = [c for c in snmp.credentials if c.is_well_known_default]
        weak = [c for c in snmp.credentials if c.is_weak]
        if not weak:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity if defaults else Severity.HIGH,
                confidence=self.confidence if defaults else 0.75,
                evidence=snmp.source_refs,
                affected=["service:snmp"],
                control_ids=self.control_ids,
                weak_community_count=len(weak),
                default_community_count=len(defaults),
                snmp_version=version or "v2c",
            )
        ]


class RemoteSyslogAbsent(SecurityRule):
    rule_id = "NG-LOG-REMOTE-SYSLOG-ABSENT"
    title = "Logs are not forwarded to a remote syslog server"
    description = "Audit evidence must survive device compromise; NIST AU-9 requires log protection."
    severity = Severity.MEDIUM
    confidence = 0.92
    control_ids = ("CIS-CISCO-4.1.1", "CIS-FGT-3", "CIS-PAN-3", "NIST-AU-9", "ISO-A.8.15")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        logging = cfg.logging
        if logging.enabled and logging.remote_servers:
            return [passed(self.rule_id, control_ids=self.control_ids)]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=logging.source_refs,
                affected=["logging"],
                control_ids=self.control_ids,
            )
        ]


class LogLevelTooVerbose(SecurityRule):
    rule_id = "NG-LOG-LEVEL-EXCESSIVE"
    title = "Syslog trap level is set too low (debug/informational)"
    description = (
        "'logging trap informational' and below floods the log with noise, which is how real "
        "incidents get missed. CIS requires 'notifications' or higher for forwarding."
    )
    severity = Severity.LOW
    confidence = 0.85
    control_ids = ("CIS-CISCO-4.1.2", "NIST-AU-2")

    #: Ordered most to least verbose.
    VERBOSE = {"debugging", "debug", "informational", "info", "logging", "log"}

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        level = (cfg.logging.severity_level or "").strip().lower()
        if not level or level not in self.VERBOSE:
            return None
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=cfg.logging.source_refs,
                affected=["logging"],
                control_ids=self.control_ids,
                severity_level=level,
            )
        ]


class ConfigChangeLoggingMissing(SecurityRule):
    rule_id = "NG-LOG-CONFIG-CHANGE-MISSING"
    title = "Configuration changes are not logged"
    description = "NIST AU-2 / CIS require that every configuration change is recorded for forensics."
    severity = Severity.MEDIUM
    confidence = 0.7
    control_ids = ("CIS-CISCO-4.2.1", "CIS-FGT-3", "CIS-PAN-3", "NIST-AU-2", "NIST-CM-6")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        if cfg.logging.logs_config_changes:
            return [passed(self.rule_id, control_ids=self.control_ids)]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=cfg.logging.source_refs,
                affected=["logging"],
                control_ids=self.control_ids,
            )
        ]


class PasswordEncryptionDisabled(SecurityRule):
    rule_id = "NG-CRYPTO-PASSWORD-ENCRYPTION"
    title = "Service password encryption is not enabled"
    description = "Cisco 'service password-encryption' obfuscates type-7 secrets on the device."
    severity = Severity.LOW
    confidence = 0.9
    control_ids = ("CIS-CISCO-4.6.1", "NIST-IA-5")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        if cfg.vendor not in {Vendor.CISCO_IOS, Vendor.CISCO_NXOS}:
            return None
        # Present only if the parser saw the global command.
        marker = cfg.service(ManagementService.OTHER)
        if marker and marker.version == "service password-encryption":
            return [passed(self.rule_id, control_ids=self.control_ids)]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                affected=["service:password-encryption"],
                control_ids=self.control_ids,
            )
        ]


class NoExecTimeout(SecurityRule):
    rule_id = "NG-REMOTE-NO-EXEC-TIMEOUT"
    title = "Administrative sessions have no inactivity timeout"
    description = (
        "Without 'exec-timeout' an abandoned vty session stays privileged indefinitely. CIS "
        "requires a 5-minute default; NIST AC-12 requires automatic session termination."
    )
    severity = Severity.MEDIUM
    confidence = 0.75
    control_ids = ("CIS-CISCO-1.2.10", "NIST-AC-12", "ISO-A.5.15")
    #: 'exec-timeout' is an IOS/NX-OS vty concept; FortiOS, PAN-OS and Junos
    #: express session timeouts differently, so declaring it here keeps the
    #: engine honest about NOT_APPLICABLE instead of silently skipping.
    applies_to = frozenset({Vendor.CISCO_IOS, Vendor.CISCO_NXOS})

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        mgmt = [s for s in cfg.services if s.service in {ManagementService.SSH, ManagementService.TELNET}]
        if not mgmt:
            return None
        lacking = [s for s in mgmt if s.timeout_seconds in (None, 0)]
        if not lacking:
            return [passed(self.rule_id, control_ids=self.control_ids)]
        evidence = SourceRefs()
        for s in lacking:
            evidence.extend(s.source_refs)
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=evidence,
                affected=[f"service:{s.service.value}" for s in lacking],
                control_ids=self.control_ids,
            )
        ]


class DefaultRoutePresent(SecurityRule):
    rule_id = "NG-INFRA-DEFAULT-ROUTE"
    title = "A default route is configured on the device"
    description = (
        "CIS recommends edge devices not hold a default route, so traffic cannot be silently "
        "black-holed and the device is not a pivot for unintended transit."
    )
    severity = Severity.LOW
    confidence = 0.9
    control_ids = ("CIS-CISCO-5.2.1", "NIST-SC-7")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        if not cfg.routing.default_route_present:
            return None
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=cfg.routing.source_refs,
                affected=["routing"],
                control_ids=self.control_ids,
            )
        ]


class WeakIKECrypto(SecurityRule):
    rule_id = "NG-CRYPTO-WEAK-IKE"
    title = "IPsec proposal uses deprecated cryptography"
    description = (
        "DES/3DES, MD5/SHA-1 and DH groups 1-2 are broken or impractical. NIST SC-13 requires "
        "AES-256 with SHA-256 and DH group 14 or higher."
    )
    severity = Severity.HIGH
    confidence = 0.85
    cvss_score = 7.1
    control_ids = ("NIST-SC-13", "NIST-SC-8", "ISO-A.8.24")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        if not cfg.crypto.weak_ciphers:
            return [passed(self.rule_id, control_ids=self.control_ids)]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=cfg.crypto.source_refs,
                affected=[f"proposal:{p}" for p in cfg.crypto.weak_ciphers],
                control_ids=self.control_ids,
                proposals=cfg.crypto.weak_ciphers,
            )
        ]

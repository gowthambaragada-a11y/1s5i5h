import type {
  CommandMode,
  Detector,
  EvidencePrecision,
  FindingStatus,
  Framework,
  RemediationGenerator,
  RemediationStatus,
  RiskLevel,
  Severity,
  Vendor,
} from "../types/api";

/** Shared display vocabulary so vendor/framework names read the same everywhere. */

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ff4d5e",
  high: "#ff8a3d",
  medium: "#ffd23d",
  low: "#3ddc97",
  info: "#5aa9e6",
};

export const VENDOR_LABELS: Record<Vendor, string> = {
  cisco_ios: "Cisco IOS",
  cisco_nxos: "Cisco NX-OS",
  juniper_junos: "Juniper Junos",
  fortinet_fortios: "Fortinet FortiOS",
  paloalto_panos: "Palo Alto PAN-OS",
  unknown: "Unknown vendor",
};

export const FRAMEWORK_LABELS: Record<Framework, string> = {
  CIS_CISCO_IOS: "CIS Cisco IOS",
  CIS_NXOS: "CIS NX-OS",
  CIS_FORTINET: "CIS FortiOS",
  CIS_PANOS: "CIS PAN-OS",
  CIS_JUNOS: "CIS Junos",
  NIST_800_53: "NIST 800-53",
  NIST_CSF: "NIST CSF",
  DISA_STIG: "DISA STIG",
  ISO_27001: "ISO 27001",
  ISO_27002: "ISO 27002",
};

/** Framework groups shown as tabs on the dashboard, in reporting priority order. */
export const FRAMEWORK_TABS: { id: string; label: string; matches: Framework[] }[] = [
  {
    id: "cis",
    label: "CIS",
    matches: ["CIS_CISCO_IOS", "CIS_NXOS", "CIS_FORTINET", "CIS_PANOS", "CIS_JUNOS"],
  },
  { id: "nist", label: "NIST 800-53", matches: ["NIST_800_53", "NIST_CSF"] },
  { id: "stig", label: "DISA STIG", matches: ["DISA_STIG"] },
  { id: "iso", label: "ISO 27001", matches: ["ISO_27001", "ISO_27002"] },
];

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False positive",
  suppressed: "Suppressed",
};

export const REMEDIATION_STATUS_LABELS: Record<RemediationStatus, string> = {
  pending_review: "Pending review",
  approved: "Approved",
  rejected: "Rejected",
  applied: "Applied",
  failed: "Failed",
};

export const DETECTOR_LABELS: Record<Detector, string> = {
  rule: "Rule pack",
  ml: "ML anomaly",
  graph: "Knowledge graph",
  llm: "LLM review",
};

export const GENERATOR_LABELS: Record<RemediationGenerator, string> = {
  hier_config: "Hier config diff",
  template: "Template",
  llm: "LLM",
  hybrid: "Hybrid",
};

export const RISK_LABELS: Record<RiskLevel, string> = {
  low: "Low risk",
  medium: "Medium risk",
  high: "High risk",
};

/** Select-box option lists, derived from the label maps so they cannot drift apart. */
export const VENDORS = Object.keys(VENDOR_LABELS) as Vendor[];

export const FRAMEWORKS = Object.keys(FRAMEWORK_LABELS) as Framework[];

export const FINDING_STATUSES = Object.keys(FINDING_STATUS_LABELS) as FindingStatus[];

export const REMEDIATION_STATUSES = Object.keys(REMEDIATION_STATUS_LABELS) as RemediationStatus[];

/** Prompt shown when the parser could only anchor evidence to a config block. */
export const PRECISION_NOTES: Record<EvidencePrecision, string> = {
  line: "Evidence precision: line - each cited line is quoted verbatim from the uploaded configuration.",
  block: "Evidence precision: block - the parser anchored to a top-level block, so the quoted lines are indicative context, not an exact match. Treat this finding as needing manual confirmation.",
};

export const COMMAND_MODE_LABELS: Record<CommandMode, string> = {
  exec: "EXEC",
  configure: "CONFIGURE",
  edit: "EDIT",
  set: "SET",
  exit: "EXIT",
};

/** Ordered CLI snippet: mode headers interleaved so it can be pasted as a session. */
export function renderCommandScript(
  commands: { mode: CommandMode; command: string }[],
): string {
  const lines: string[] = [];
  for (const item of commands) {
    if (item.mode === "exit") {
      lines.push("exit");
      continue;
    }
    if (item.mode === "exec") {
      if (lines.length > 0) lines.push("exit");
      lines.push(item.command);
      continue;
    }
    if (item.mode === "configure") {
      if (lines.length > 0) lines.push("exit");
      lines.push(item.command);
      continue;
    }
    if (item.mode === "edit") {
      if (lines.length > 0) lines.push("exit");
      lines.push(item.command);
      continue;
    }
    lines.push(item.command);
  }
  return lines.join("\n");
}

export function formatScore(score: number | null | undefined): string {
  if (score === null || score === undefined || Number.isNaN(score)) return "--";
  return `${Math.round(score)}%`;
}

export function formatPercent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "--";
  return `${(value * 100).toFixed(digits)}%`;
}

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "never";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

/** Traffic-light colouring for a 0..100 compliance score. */
export function scoreColor(score: number | null | undefined): string {
  if (score === null || score === undefined) return "var(--text-dim)";
  if (score >= 90) return "var(--ok)";
  if (score >= 75) return "var(--warn)";
  if (score >= 50) return "var(--high)";
  return "var(--critical)";
}

/** Same thresholds as {@link scoreColor}, expressed as a StatCard tone token. */
export function scoreTone(score: number | null | undefined): "ok" | "warn" | "high" | "critical" {
  if (score === null || score === undefined) return "critical";
  if (score >= 90) return "ok";
  if (score >= 75) return "warn";
  if (score >= 50) return "high";
  return "critical";
}
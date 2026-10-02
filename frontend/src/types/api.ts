/**
 * Wire types for the NETGUARD-AI backend (`/api/v1`).
 *
 * Field names mirror the FastAPI/Pydantic models one-for-one (snake_case,
 * `null` for absent values) so that responses can be consumed without any
 * translation layer. Enum-like unions are closed: an unrecognised value from
 * the API is a contract break and should be loud in development, not silently
 * coerced.
 */

export type Vendor =
  | "cisco_ios"
  | "cisco_nxos"
  | "juniper_junos"
  | "fortinet_fortios"
  | "paloalto_panos"
  | "unknown";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Framework =
  | "CIS_CISCO_IOS"
  | "CIS_NXOS"
  | "CIS_FORTINET"
  | "CIS_PANOS"
  | "CIS_JUNOS"
  | "NIST_800_53"
  | "NIST_CSF"
  | "DISA_STIG"
  | "ISO_27001"
  | "ISO_27002";

export type FindingStatus =
  | "open"
  | "acknowledged"
  | "resolved"
  | "false_positive"
  | "suppressed";

export type RemediationStatus =
  | "pending_review"
  | "approved"
  | "rejected"
  | "applied"
  | "failed";

/**
 * How precisely the parser could point back at the source configuration.
 * `block` means the parser anchored to a top-level block rather than to an
 * exact line, so evidence is indicative rather than quotable.
 */
export type EvidencePrecision = "line" | "block";

export type Detector = "rule" | "ml" | "graph" | "llm";

export type RiskLevel = "low" | "medium" | "high";

export type RemediationGenerator = "hier_config" | "template" | "llm" | "hybrid";

/** Interactive mode the command belongs to for the target vendor's CLI. */
export type CommandMode = "exec" | "configure" | "edit" | "set" | "exit";

export type AnalysisState = "queued" | "running" | "completed" | "failed";

export interface VendorDetection {
  vendor: Vendor;
  confidence: number;
  rule_pack: string | null;
  candidates: { adapter: string; score: number }[];
  evidence_precision: EvidencePrecision;
}

export interface ControlRef {
  framework: Framework;
  control_id: string;
  title: string;
  description?: string | null;
}

export interface EvidenceLine {
  line_no: number;
  raw: string;
}

export interface Finding {
  id: string;
  analysis_id: string;
  device_id: string;
  rule_id: string;
  title: string;
  description: string;
  /** Plain-language explanation of the risk, written for a non-expert. */
  explanation: string;
  severity: Severity;
  /** Detector confidence, 0..1. */
  confidence: number;
  status: FindingStatus;
  category: string;
  controls: ControlRef[];
  evidence: EvidenceLine[];
  evidence_precision: EvidencePrecision;
  affected_objects: string[];
  remediation_id: string | null;
  detector: Detector;
  /** ISO 8601 timestamp. */
  created_at: string;
}

export interface RemediationCommand {
  order: number;
  mode: CommandMode;
  command: string;
  config_before: string | null;
  config_after: string | null;
  description: string;
  reversible: boolean;
  requires_confirmation: boolean;
}

export interface Remediation {
  id: string;
  finding_id: string;
  device_id: string;
  vendor: Vendor;
  status: RemediationStatus;
  title: string;
  rationale: string;
  risk: RiskLevel;
  generator: RemediationGenerator;
  commands: RemediationCommand[];
  diff_summary: string | null;
  created_at: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_note: string | null;
}

export interface FrameworkScore {
  framework: Framework;
  /** Compliance score, 0..100. */
  score: number;
  passed: number;
  failed: number;
  not_applicable: number;
  total_controls: number;
  /**
   * False when too few controls were actually assessed for this framework, so the
   * score is reported but must not be read as a real compliance rate.
   */
  sufficient_evidence: boolean;
}

export interface DeviceCompliance {
  device_id: string;
  hostname: string | null;
  vendor: Vendor;
  role: string;
  /** Compliance score, 0..100. */
  overall_score: number;
  severity_counts: Record<Severity, number>;
  framework_scores: FrameworkScore[];
  total_findings: number;
  open_findings: number;
  last_analyzed_at: string | null;
  evidence_precision: EvidencePrecision;
  /** 1 - unparsed_line_ratio; how much of the config we actually understood. */
  parser_coverage: number;
}

export interface AnalysisSummary {
  analysis_id: string;
  device_id: string;
  status: AnalysisState;
  vendor: Vendor;
  vendor_confidence: number;
  started_at: string;
  completed_at: string | null;
  overall_score: number | null;
  framework_scores: FrameworkScore[];
  findings: Finding[];
  remediations: Remediation[];
  total_findings: number;
  duration_ms: number | null;
  parse_warnings: string[];
  evidence_precision: EvidencePrecision;
  parser_coverage: number;
}

export interface TopRiskyRule {
  rule_id: string;
  title: string;
  count: number;
  severity: Severity;
}

export interface DashboardSummary {
  generated_at: string;
  total_devices: number;
  total_findings: number;
  overall_score: number;
  severity_counts: Record<Severity, number>;
  framework_scores: FrameworkScore[];
  devices: DeviceCompliance[];
  pending_remediations: number;
  /** Change in critical findings versus the previous period. */
  critical_delta: number;
  top_risky_rules: TopRiskyRule[];
}

export interface Paged<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

/* -------------------------------------------------------------------------- */
/* Request payloads                                                            */
/* -------------------------------------------------------------------------- */

export interface AnalysisRequest {
  device_id: string;
  text: string;
  frameworks: Framework[];
  run_ml: boolean;
  persist_graph: boolean;
}

export interface AnalysisAccepted {
  analysis_id: string;
  status: "queued" | "running";
  poll_url: string;
}

export interface VendorDetectRequest {
  text: string;
}

export interface RejectRequest {
  reason: string;
}

/** Query parameters accepted by `GET /api/v1/findings` (all optional). */
export interface FindingQuery {
  severity?: Severity;
  framework?: Framework;
  device_id?: string;
  status?: FindingStatus;
  limit?: number;
  offset?: number;
}

/** Query parameters accepted by `GET /api/v1/remediations`. */
export interface RemediationQuery {
  status?: RemediationStatus;
  finding_id?: string;
}
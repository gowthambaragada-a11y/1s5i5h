import type { Severity } from "../types/api";
import { SEVERITY_COLORS } from "../lib/labels";

interface SeverityBadgeProps {
  severity: Severity;
  /** Optional trailing count, e.g. "12". */
  count?: number;
  title?: string;
}

/** Colour-coded severity chip. Colour alone never carries the meaning: the word is always shown. */
export function SeverityBadge({ severity, count, title }: SeverityBadgeProps) {
  return (
    <span
      className={`sev-chip sev-${severity}`}
      style={{ color: SEVERITY_COLORS[severity] }}
      title={title ?? `Severity: ${severity}`}
    >
      <span className="sev-dot" aria-hidden="true" />
      {severity}
      {count !== undefined && <span className="num"> {count}</span>}
    </span>
  );
}

export default SeverityBadge;
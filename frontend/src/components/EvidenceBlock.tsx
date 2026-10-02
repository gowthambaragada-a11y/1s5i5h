import { useMemo, useState } from "react";
import type { EvidenceLine, EvidencePrecision } from "../types/api";
import { PRECISION_NOTES } from "../lib/labels";

interface EvidenceBlockProps {
  evidence: EvidenceLine[];
  precision: EvidencePrecision;
  /** Line numbers are only trustworthy when the parser preserved them. */
  showLineNumbers?: boolean;
  maxLines?: number;
}

function buildPlainText(evidence: EvidenceLine[]): string {
  return evidence.map((line) => `L${line.line_no}: ${line.raw}`).join("\n");
}

async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  // Fallback for non-secure origins, where the async clipboard API is unavailable.
  const area = document.createElement("textarea");
  area.value = text;
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  document.body.removeChild(area);
}

/** Quoted configuration lines backing a finding, plus a provenance caveat when imprecise. */
export function EvidenceBlock({
  evidence,
  precision,
  showLineNumbers = true,
  maxLines = 40,
}: EvidenceBlockProps) {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const visible = useMemo(
    () => (expanded ? evidence : evidence.slice(0, maxLines)),
    [evidence, expanded, maxLines],
  );
  const hidden = evidence.length - visible.length;

  if (evidence.length === 0) {
    return (
      <div className="evidence">
        <div className="evidence-head">Config evidence</div>
        <div className="empty">
          No source lines were captured for this finding. The rule fired on the absence of a
          setting rather than on a line that exists.
        </div>
      </div>
    );
  }

  const handleCopy = async () => {
    try {
      await copyText(buildPlainText(evidence));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="stack sm">
      <div className="evidence">
        <div className="evidence-head">
          <span>Config evidence ({evidence.length} line{evidence.length === 1 ? "" : "s"})</span>
          <button type="button" className="btn sm ghost" onClick={handleCopy}>
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <div className="evidence-lines">
          {visible.map((line) => (
            <div className="evidence-line" key={`${line.line_no}-${line.raw}`}>
              <span className="line-no">{showLineNumbers ? `L${line.line_no}:` : ""}</span>
              <span className="line-raw">{line.raw}</span>
            </div>
          ))}
        </div>
        {hidden > 0 && (
          <div className="evidence-head" style={{ borderTop: "1px solid var(--border)", borderBottom: "none" }}>
            <button type="button" className="btn sm ghost" onClick={() => setExpanded(true)}>
              Show {hidden} more line{hidden === 1 ? "" : "s"}
            </button>
          </div>
        )}
      </div>
      <p className={`precision-note ${precision === "block" ? "block" : "ok"}`}>
        {PRECISION_NOTES[precision]}
      </p>
    </div>
  );
}

export default EvidenceBlock;
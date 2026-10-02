import { useState } from "react";
import type { Remediation, RemediationCommand } from "../types/api";
import {
  COMMAND_MODE_LABELS,
  GENERATOR_LABELS,
  REMEDIATION_STATUS_LABELS,
  RISK_LABELS,
  VENDOR_LABELS,
  formatTimestamp,
  renderCommandScript,
} from "../lib/labels";

interface RemediationCardProps {
  remediation: Remediation;
  /** Omit to render the card read-only (e.g. inside an already-reviewed queue item). */
  onApprove?: (id: string) => void;
  onReject?: (id: string, reason: string) => void;
  /** Id currently being reviewed, for per-row button state. */
  busyId?: string | null;
}

async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  document.body.removeChild(area);
}

function CommandRow({ command }: { command: RemediationCommand }) {
  return (
    <div className={`cmd${command.requires_confirmation ? " confirm" : ""}`}>
      <div className="cmd-meta">
        <span className="cmd-mode">{COMMAND_MODE_LABELS[command.mode]}</span>
        <span className="dim small">#{command.order}</span>
        {command.reversible && <span className="chip ok">reversible</span>}
        {command.requires_confirmation && <span className="chip high">confirm before apply</span>}
      </div>
      <div className="cmd-code">{command.command}</div>
      {command.description && <div className="cmd-desc">{command.description}</div>}
      {(command.config_before !== null || command.config_after !== null) && (
        <div className="diff">
          {command.config_before !== null && (
            <div className="diff-line before">- {command.config_before}</div>
          )}
          {command.config_after !== null && <div className="diff-line after">+ {command.config_after}</div>}
        </div>
      )}
    </div>
  );
}

export function RemediationCard({
  remediation,
  onApprove,
  onReject,
  busyId = null,
}: RemediationCardProps) {
  const [copied, setCopied] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState("");

  const isPending = remediation.status === "pending_review";
  const isBusy = busyId === remediation.id;
  const riskTone = remediation.risk === "high" ? "critical" : remediation.risk === "medium" ? "warn" : "ok";
  const canReview = isPending && Boolean(onApprove || onReject);

  const handleCopyAll = async () => {
    try {
      await copyText(renderCommandScript(remediation.commands));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  const handleCopyOne = async (command: RemediationCommand) => {
    try {
      await copyText(command.command);
    } catch {
      /* clipboard blocked by policy: the text stays selectable on screen */
    }
  };

  const submitReject = () => {
    const trimmed = reason.trim();
    if (!trimmed || !onReject) return;
    onReject(remediation.id, trimmed);
    setRejecting(false);
    setReason("");
  };

  return (
    <div className="remediation">
      <div className="remediation-head">
        <div className="stack sm">
          <strong>{remediation.title}</strong>
          <div className="meta-row">
            <span className="chip accent">{VENDOR_LABELS[remediation.vendor]}</span>
            <span className={`chip ${riskTone}`}>{RISK_LABELS[remediation.risk]}</span>
            <span className="chip">{GENERATOR_LABELS[remediation.generator]}</span>
            <span className="chip dim">{REMEDIATION_STATUS_LABELS[remediation.status]}</span>
          </div>
        </div>
        <button type="button" className="btn sm" onClick={handleCopyAll}>
          {copied ? "Script copied" : "Copy script"}
        </button>
      </div>

      <p className="muted small">{remediation.rationale}</p>

      {remediation.diff_summary && (
        <div className="alert info">
          <span>{remediation.diff_summary}</span>
        </div>
      )}

      <div className="cmd-list">
        {remediation.commands.length === 0 && (
          <div className="empty">No CLI commands were generated for this remediation.</div>
        )}
        {remediation.commands.map((command) => (
          <div key={`${command.order}-${command.command}`} className="stack sm">
            <CommandRow command={command} />
            <div className="row">
              <button type="button" className="btn sm ghost" onClick={() => handleCopyOne(command)}>
                Copy command
              </button>
            </div>
          </div>
        ))}
      </div>

      {remediation.reviewed_at && (
        <div className="small dim">
          Reviewed by {remediation.reviewed_by ?? "unknown"} on {formatTimestamp(remediation.reviewed_at)}
          {remediation.review_note ? ` - ${remediation.review_note}` : ""}
        </div>
      )}

      {canReview && (
        <div className="stack sm">
          <div className="btn-row">
            <button
              type="button"
              className="btn approve"
              disabled={isBusy}
              onClick={() => onApprove?.(remediation.id)}
            >
              Approve
            </button>
            <button
              type="button"
              className="btn reject"
              disabled={isBusy}
              onClick={() => setRejecting((open) => !open)}
            >
              Reject
            </button>
            {isBusy && <span className="small dim">Submitting review...</span>}
          </div>
          {rejecting && (
            <div className="stack sm">
              <textarea
                rows={2}
                value={reason}
                placeholder="Why is this remediation rejected? e.g. ACL change would drop branch VPN traffic."
                onChange={(event) => setReason(event.target.value)}
              />
              <div className="btn-row">
                <button
                  type="button"
                  className="btn primary"
                  disabled={reason.trim().length === 0}
                  onClick={submitReject}
                >
                  Confirm rejection
                </button>
                <button type="button" className="btn ghost" onClick={() => setRejecting(false)}>
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default RemediationCard;
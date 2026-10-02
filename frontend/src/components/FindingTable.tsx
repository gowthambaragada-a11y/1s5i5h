import { Fragment, useMemo, useState } from "react";
import type { Finding, Paged } from "../types/api";
import { useApproveRemediation, useRemediationForFinding, useRejectRemediation } from "../hooks/useAnalysis";
import {
  DETECTOR_LABELS,
  FINDING_STATUS_LABELS,
  FRAMEWORK_LABELS,
  formatPercent,
  formatRelative,
} from "../lib/labels";
import { EvidenceBlock } from "./EvidenceBlock";
import { RemediationCard } from "./RemediationCard";
import { SeverityBadge } from "./SeverityBadge";

interface FindingTableProps {
  page: Paged<Finding> | null;
  loading: boolean;
  error: string | null;
  onPageChange?: (offset: number) => void;
  onPageSizeChange?: (limit: number) => void;
  emptyHint?: string;
}

type SortKey = "severity" | "title" | "device_id" | "confidence" | "status" | "created_at";
type SortDirection = "asc" | "desc";

const SEVERITY_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function SortHeader({
  label,
  sortKey,
  active,
  direction,
  onSort,
  numeric,
}: {
  label: string;
  sortKey: SortKey;
  active: SortKey | null;
  direction: SortDirection;
  onSort: (key: SortKey) => void;
  numeric?: boolean;
}) {
  const isActive = active === sortKey;
  return (
    <th className={numeric ? "num" : undefined}>
      <button
        type="button"
        className="sort-btn"
        onClick={() => onSort(sortKey)}
        aria-sort={isActive ? (direction === "asc" ? "ascending" : "descending") : "none"}
      >
        {label}
        <span className="sort-caret" aria-hidden="true">
          {isActive ? (direction === "asc" ? "▲" : "▼") : "▾"}
        </span>
      </button>
    </th>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  const remediation = useRemediationForFinding(finding.id, finding.remediation_id);
  const approve = useApproveRemediation();
  const reject = useRejectRemediation();
  const mutationError = approve.error ?? reject.error;

  return (
    <div className="detail-panel">
      <div className="stack">
        <div className="stack sm">
          <h3>Why this matters</h3>
          <p className="explanation">{finding.explanation || finding.description}</p>
          <p className="muted small">{finding.description}</p>
        </div>

        <div className="stack sm">
          <h3>Framework controls</h3>
          {finding.controls.length === 0 ? (
            <span className="small dim">This finding is not mapped to a control yet.</span>
          ) : (
            <div className="control-list">
              {finding.controls.map((control) => (
                <div className="control-item" key={`${control.framework}-${control.control_id}`}>
                  <span className="chip accent">{FRAMEWORK_LABELS[control.framework]}</span>
                  <span className="control-id">{control.control_id}</span>
                  <span className="muted">{control.title}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {finding.affected_objects.length > 0 && (
          <div className="stack sm">
            <h3>Affected objects</h3>
            <div className="meta-row">
              {finding.affected_objects.map((object) => (
                <span className="chip dim mono" key={object}>
                  {object}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="meta-row">
          <span className="chip">{DETECTOR_LABELS[finding.detector]}</span>
          <span className="chip">confidence {formatPercent(finding.confidence)}</span>
          <span className="chip dim">{finding.rule_id}</span>
          <span className="chip dim">analysis {finding.analysis_id}</span>
        </div>
      </div>

      <div className="stack">
        <EvidenceBlock evidence={finding.evidence} precision={finding.evidence_precision} />

        <div className="card" style={{ padding: 12 }}>
          {remediation.loading && <div className="small dim">Loading remediation...</div>}
          {remediation.error && <div className="alert">{remediation.error}</div>}
          {!remediation.loading && remediation.data && (
            <RemediationCard
              remediation={remediation.data}
              onApprove={(id) => {
                // Re-read the record so the card reflects the server's new status.
                void approve.approve(id).then((updated) => {
                  if (updated) remediation.reload();
                });
              }}
              onReject={(id, reason) => {
                void reject.reject(id, reason).then((updated) => {
                  if (updated) remediation.reload();
                });
              }}
              busyId={approve.activeId ?? reject.activeId}
            />
          )}
          {!remediation.loading && !remediation.data && !remediation.error && (
            <div className="empty">
              No remediation is attached to this finding
              {finding.remediation_id ? " yet" : ""}.
            </div>
          )}
          {mutationError && <div className="alert">{mutationError}</div>}
        </div>
      </div>
    </div>
  );
}

export function FindingTable({
  page,
  loading,
  error,
  onPageChange,
  onPageSizeChange,
  emptyHint,
}: FindingTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [direction, setDirection] = useState<SortDirection>("desc");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const findings = page?.items ?? [];

  const sorted = useMemo(() => {
    const factor = direction === "asc" ? 1 : -1;
    return [...findings].sort((a, b) => {
      switch (sortKey) {
        case "severity":
          return (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) * factor;
        case "confidence":
          return (a.confidence - b.confidence) * factor;
        case "created_at":
          return (new Date(a.created_at).getTime() - new Date(b.created_at).getTime()) * factor;
        case "status":
          return a.status.localeCompare(b.status) * factor;
        case "device_id":
          return a.device_id.localeCompare(b.device_id) * factor;
        case "title":
        default:
          return a.title.localeCompare(b.title) * factor;
      }
    });
  }, [findings, sortKey, direction]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) {
      setDirection((current) => (current === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setDirection(key === "title" || key === "device_id" ? "asc" : "desc");
    }
  };

  const total = page?.total ?? 0;
  const offset = page?.offset ?? 0;
  const limit = page?.limit ?? findings.length;
  const pageIndex = limit > 0 ? Math.floor(offset / limit) + 1 : 1;
  const pageCount = limit > 0 ? Math.ceil(total / limit) : 1;

  if (error) return <div className="alert">{error}</div>;

  return (
    <div className="card">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th style={{ width: 34 }} aria-label="Expand" />
              <SortHeader
                label="Severity"
                sortKey="severity"
                active={sortKey}
                direction={direction}
                onSort={toggleSort}
              />
              <SortHeader label="Finding" sortKey="title" active={sortKey} direction={direction} onSort={toggleSort} />
              <SortHeader label="Device" sortKey="device_id" active={sortKey} direction={direction} onSort={toggleSort} />
              <SortHeader label="Status" sortKey="status" active={sortKey} direction={direction} onSort={toggleSort} />
              <SortHeader
                label="Conf."
                sortKey="confidence"
                active={sortKey}
                direction={direction}
                onSort={toggleSort}
                numeric
              />
              <th>Controls</th>
              <SortHeader
                label="Detected"
                sortKey="created_at"
                active={sortKey}
                direction={direction}
                onSort={toggleSort}
              />
            </tr>
          </thead>
          <tbody>
            {loading && findings.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <div className="stack sm">
                    <div className="skeleton" />
                    <div className="skeleton" />
                    <div className="skeleton" />
                  </div>
                </td>
              </tr>
            )}

            {!loading && sorted.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <div className="empty">
                    {emptyHint ?? "No findings match the current filters."}
                  </div>
                </td>
              </tr>
            )}

            {sorted.map((finding) => {
              const isOpen = expandedId === finding.id;
              return (
                <Fragment key={finding.id}>
                  <tr className={isOpen ? "row-expanded" : undefined}>
                    <td>
                      <button
                        type="button"
                        className="row-toggle"
                        onClick={() => setExpandedId(isOpen ? null : finding.id)}
                        aria-expanded={isOpen}
                        title={isOpen ? "Hide evidence and remediation" : "Show evidence and remediation"}
                      >
                        {isOpen ? "-" : "+"}
                      </button>
                    </td>
                    <td>
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td>
                      <div className="finding-title">{finding.title}</div>
                      <div className="finding-sub">
                        {finding.rule_id} - {finding.category}
                      </div>
                    </td>
                    <td className="mono small">{finding.device_id}</td>
                    <td>
                      <span className="chip dim">{FINDING_STATUS_LABELS[finding.status]}</span>
                    </td>
                    <td className="num">{formatPercent(finding.confidence)}</td>
                    <td>
                      <div className="meta-row">
                        {finding.controls.slice(0, 2).map((control) => (
                          <span className="chip accent" key={`${control.framework}-${control.control_id}`}>
                            {control.control_id}
                          </span>
                        ))}
                        {finding.controls.length > 2 && (
                          <span className="chip dim">+{finding.controls.length - 2}</span>
                        )}
                      </div>
                    </td>
                    <td className="small dim nowrap">{formatRelative(finding.created_at)}</td>
                  </tr>
                  {isOpen && (
                    <tr>
                      <td className="detail-cell" colSpan={8}>
                        <FindingDetail finding={finding} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="pagination">
        <span>
          {total === 0
            ? "No findings"
            : `${offset + 1}-${Math.min(offset + findings.length, total)} of ${total}`}
          {total > 0 && ` - page ${pageIndex} of ${pageCount}`}
        </span>
        <div className="btn-row">
          {onPageSizeChange && (
            <select
              value={limit}
              onChange={(event) => onPageSizeChange(Number(event.target.value))}
              aria-label="Rows per page"
            >
              {[25, 50, 100, 200].map((size) => (
                <option key={size} value={size}>
                  {size} / page
                </option>
              ))}
            </select>
          )}
          {onPageChange && (
            <>
              <button
                type="button"
                className="btn sm"
                disabled={offset === 0 || loading}
                onClick={() => onPageChange(Math.max(0, offset - limit))}
              >
                Previous
              </button>
              <button
                type="button"
                className="btn sm"
                disabled={offset + limit >= total || loading}
                onClick={() => onPageChange(offset + limit)}
              >
                Next
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default FindingTable;
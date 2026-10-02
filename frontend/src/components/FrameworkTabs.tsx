import { useMemo, useState } from "react";
import type { Framework, FrameworkScore } from "../types/api";
import { FRAMEWORK_LABELS, FRAMEWORK_TABS, scoreColor } from "../lib/labels";

interface FrameworkTabsProps {
  scores: FrameworkScore[];
  onSelectFramework?: (framework: Framework) => void;
}

interface Aggregate {
  score: number;
  passed: number;
  failed: number;
  not_applicable: number;
  total_controls: number;
  sufficient_evidence: boolean;
}

/**
 * Rolls the per-framework scores into one number for a tab. Score is weighted by
 * control count so a 12-control STIG baseline does not drown out a 300-control
 * CIS benchmark; frameworks that report zero controls fall back to a plain mean.
 *
 * Frameworks the backend flagged as evidence-poor are excluded from the rollup --
 * averaging a real 0% into a headline number overstates what we actually checked.
 */
function aggregate(scores: FrameworkScore[]): Aggregate {
  const usable = scores.filter((item) => item.sufficient_evidence && item.total_controls > 0);
  const weightedBase = usable.reduce((sum, item) => sum + item.total_controls, 0);

  const score =
    weightedBase > 0
      ? usable.reduce((sum, item) => sum + item.score * item.total_controls, 0) / weightedBase
      : 0;

  return {
    score,
    passed: scores.reduce((sum, item) => sum + item.passed, 0),
    failed: scores.reduce((sum, item) => sum + item.failed, 0),
    not_applicable: scores.reduce((sum, item) => sum + item.not_applicable, 0),
    total_controls: scores.reduce((sum, item) => sum + item.total_controls, 0),
    sufficient_evidence: scores.length > 0 && scores.every((item) => item.sufficient_evidence),
  };
}

export function FrameworkTabs({ scores, onSelectFramework }: FrameworkTabsProps) {
  const groups = useMemo(
    () =>
      FRAMEWORK_TABS.map((tab) => {
        const matches = scores.filter((score) => tab.matches.includes(score.framework));
        return { ...tab, scores: matches, totals: aggregate(matches) };
      }).filter((tab) => tab.scores.length > 0),
    [scores],
  );

  const [activeId, setActiveId] = useState<string | null>(null);

  if (groups.length === 0) {
    return (
      <div className="card">
        <div className="card-head">
          <span className="card-title">Compliance frameworks</span>
        </div>
        <div className="empty">
          No framework scores yet. Run an analysis to populate CIS, NIST 800-53, DISA STIG and ISO
          control results.
        </div>
      </div>
    );
  }

  const active = groups.find((group) => group.id === activeId) ?? groups[0];

  return (
    <div className="card">
      <div className="card-head">
        <span className="card-title">Compliance frameworks</span>
        <span className="chip accent">
            {active.totals.sufficient_evidence
              ? `${Math.round(active.totals.score)}% weighted`
              : "insufficient evidence"}
          </span>
      </div>
      <div className="tabs" role="tablist">
        {groups.map((group) => (
          <button
            key={group.id}
            type="button"
            role="tab"
            aria-selected={group.id === active.id}
            className={`tab${group.id === active.id ? " active" : ""}`}
            onClick={() => setActiveId(group.id)}
          >
            {group.label}
            <span className="chip dim" style={{ marginLeft: 6 }}>
              {group.totals.sufficient_evidence ? `${Math.round(group.totals.score)}%` : "--"}
            </span>
          </button>
        ))}
      </div>
      <div className="framework-body">
        <div className="framework-list">
          {active.scores.map((score) => (
            <div className="framework-row" key={score.framework}>
              <button
                type="button"
                className="label framework-link"
                onClick={() => onSelectFramework?.(score.framework)}
                title={onSelectFramework ? "View findings for this framework" : undefined}
              >
                {FRAMEWORK_LABELS[score.framework]}
              </button>
              <div className="progress-track">
                <div
                  className="progress-fill"
                  style={{ width: `${Math.max(0, Math.min(100, score.score))}%`, background: scoreColor(score.score) }}
                />
              </div>
              <div className="counts">
                {score.sufficient_evidence ? (
                  <>
                    <strong style={{ color: scoreColor(score.score) }}>
                      {Math.round(score.score)}%
                    </strong>{" "}
                    - {score.passed} passed / {score.failed} failed
                    {score.not_applicable > 0 ? ` / ${score.not_applicable} n/a` : ""} of{" "}
                    {score.total_controls}
                  </>
                ) : (
                  <>
                    <strong className="muted">{Math.round(score.score)}%</strong> - only{" "}
                    {score.total_controls} control{score.total_controls === 1 ? "" : "s"} mapped;
                    treat as indicative only
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default FrameworkTabs;
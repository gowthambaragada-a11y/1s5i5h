import type { ReactNode } from "react";

export type StatTone = "neutral" | "ok" | "warn" | "high" | "critical";

interface StatCardProps {
  label: string;
  value: ReactNode;
  /** Signed change versus the previous period. */
  trend?: number | null;
  trendLabel?: string;
  /**
   * Security counts read "up = bad", but scores read "up = good". Set this when the
   * value is a score so the arrow colour matches intuition.
   */
  trendUpIsGood?: boolean;
  hint?: string;
  tone?: StatTone;
  onClick?: () => void;
}

function trendClass(delta: number, upIsGood: boolean): string {
  if (delta === 0) return "flat";
  const up = delta > 0;
  if (up === upIsGood) return "up-good";
  return up ? "up-bad" : "down-bad";
}

export function StatCard({
  label,
  value,
  trend,
  trendLabel,
  trendUpIsGood = false,
  hint,
  tone = "neutral",
  onClick,
}: StatCardProps) {
  const hasTrend = typeof trend === "number" && Number.isFinite(trend);

  return (
    <div
      className={`stat-card${onClick ? " clickable" : ""}`}
      onClick={onClick}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={
        onClick
          ? (event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onClick();
              }
            }
          : undefined
      }
    >
      <span className="stat-label">{label}</span>
      <span className={`stat-value ${tone}`}>{value}</span>
      {hasTrend && (
        <span className={`stat-trend ${trendClass(trend as number, trendUpIsGood)}`}>
          <span aria-hidden="true">{(trend as number) > 0 ? "▲" : (trend as number) < 0 ? "▼" : "■"}</span>
          {Math.abs(trend as number)}
          {trendLabel ? ` ${trendLabel}` : " vs previous period"}
        </span>
      )}
      {hint && <span className="stat-hint">{hint}</span>}
    </div>
  );
}

export default StatCard;
import { PolarAngleAxis, RadialBar, RadialBarChart, ResponsiveContainer } from "recharts";
import { formatScore, scoreColor } from "../lib/labels";

interface ComplianceGaugeProps {
  /** 0..100, or null while a score is not yet available. */
  score: number | null;
  label?: string;
  caption?: string;
  size?: number;
}

/** Circular compliance score, 0..100, drawn as a single Recharts radial bar. */
export function ComplianceGauge({
  score,
  label = "Overall compliance",
  caption,
  size = 220,
}: ComplianceGaugeProps) {
  const value = score === null || Number.isNaN(score) ? 0 : Math.max(0, Math.min(100, score));
  const hasScore = score !== null && !Number.isNaN(score);

  return (
    <div className="gauge-wrap" style={{ position: "relative", height: size, width: "100%" }}>
      <ResponsiveContainer width="100%" height={size}>
        <RadialBarChart
          data={[{ name: label, value }]}
          startAngle={90}
          endAngle={-270}
          innerRadius="72%"
          outerRadius="100%"
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar
            dataKey="value"
            angleAxisId={0}
            cornerRadius={6}
            fill={scoreColor(score)}
            background={{ fill: "#1c2839" }}
            isAnimationActive={false}
          />
        </RadialBarChart>
      </ResponsiveContainer>
      <div
        className="gauge-center"
        style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", justifyContent: "center" }}
      >
        <div className="stat-value" style={{ fontSize: 34, color: scoreColor(score) }}>
          {hasScore ? formatScore(score) : "--"}
        </div>
        <div className="gauge-caption">{label}</div>
        {caption && <div className="small dim">{caption}</div>}
      </div>
    </div>
  );
}

export default ComplianceGauge;
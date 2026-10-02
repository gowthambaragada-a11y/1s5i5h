import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Severity } from "../types/api";
import { SEVERITIES, SEVERITY_COLORS } from "../lib/labels";

interface SeverityChartProps {
  counts: Partial<Record<Severity, number>>;
  height?: number;
  onSelect?: (severity: Severity) => void;
  activeSeverity?: Severity | null;
}

/** Findings-per-severity bar chart; clicking a bar can drill into the findings list. */
export function SeverityChart({ counts, height = 240, onSelect, activeSeverity = null }: SeverityChartProps) {
  const data = SEVERITIES.map((severity) => ({
    severity,
    name: severity.charAt(0).toUpperCase() + severity.slice(1),
    count: counts[severity] ?? 0,
    fill: SEVERITY_COLORS[severity],
  }));

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }} barCategoryGap="28%">
        <CartesianGrid strokeDasharray="3 3" stroke="#22304a" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: "#9fb0c9", fontSize: 11 }} axisLine={{ stroke: "#22304a" }} tickLine={false} />
        <YAxis
          allowDecimals={false}
          tick={{ fill: "#6c809e", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: "rgba(53,194,255,0.06)" }}
          formatter={(value: unknown) => [
            `${String(value)} finding${Number(value) === 1 ? "" : "s"}`,
            "Findings",
          ]}
        />
        <Bar
          dataKey="count"
          name="Findings"
          radius={[4, 4, 0, 0]}
          isAnimationActive={false}
          onClick={(entry: unknown) => {
            const severity = (entry as { payload?: { severity?: Severity } })?.payload?.severity;
            if (severity && onSelect) onSelect(severity);
          }}
          cursor={onSelect ? "pointer" : undefined}
        >
          {data.map((row) => (
            <Cell
              key={row.severity}
              fill={row.fill}
              fillOpacity={activeSeverity === null || activeSeverity === row.severity ? 1 : 0.35}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export default SeverityChart;
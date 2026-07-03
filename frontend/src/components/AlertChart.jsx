import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

// Colour palette — one per attack class
const COLORS = {
  DoS:   "#ef4444",
  Probe: "#f97316",
  R2L:   "#eab308",
  U2R:   "#a855f7",
};

export default function AlertChart({ counts }) {
  // Transform the {attackType: count} map into the array format
  // that Recharts expects: [{name, value}, ...]
  const data = Object.entries(counts)
    .filter(([name]) => name !== "Normal") // only show attacks
    .map(([name, value]) => ({ name, value }));

  if (data.length === 0) {
    return <p className="empty">No attack data yet.</p>;
  }

  return (
    // ResponsiveContainer makes the chart fill its parent div.
    // width="100%" height={300} means: full width, fixed 300px height.
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          outerRadius={100}
          label={({ name, percent }) =>
            `${name} ${(percent * 100).toFixed(0)}%`
          }
        >
          {data.map((entry) => (
            <Cell
              key={entry.name}
              fill={COLORS[entry.name] || "#6b7280"}
            />
          ))}
        </Pie>
        <Tooltip formatter={(value) => [`${value} alerts`, ""]} />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  );
}
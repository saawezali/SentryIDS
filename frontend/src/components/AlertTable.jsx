// Severity → CSS class mapping for row colour coding
const SEVERITY_CLASS = {
  critical: "row--critical",
  high:     "row--high",
  medium:   "row--medium",
};

export default function AlertTable({ alerts }) {
  if (alerts.length === 0) {
    return <p className="empty">No alerts yet. Start capture to begin monitoring.</p>;
  }

  return (
    <div className="table-wrap">
      <table className="alert-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Src IP</th>
            <th>Dst IP</th>
            <th>Proto</th>
            <th>Attack</th>
            <th>Confidence</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.ID} className={SEVERITY_CLASS[a.Severity] || ""}>
              <td>{new Date(a.Timestamp).toLocaleTimeString()}</td>
              <td className="mono">{a.SrcIP}:{a.SrcPort}</td>
              <td className="mono">{a.DstIP}:{a.DstPort}</td>
              <td>{a.Protocol.toUpperCase()}</td>
              <td>{a.AttackType}</td>
              <td>{(a.Confidence * 100).toFixed(1)}%</td>
              <td>
                <span className={`badge badge--${a.Severity}`}>
                  {a.Severity}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export default function ControlBar({
  interfaces, selected, onSelect,
  running, onStart, onStop, error
}) {
  return (
    <div className="control-bar">
      <select
        value={selected}
        onChange={(e) => onSelect(e.target.value)}
        disabled={running}
        className="iface-select"
      >
        <option value="">Select interface…</option>
        {interfaces.map((i) => (
          <option key={i} value={i}>{i}</option>
        ))}
      </select>

      {running ? (
        <button className="btn btn--stop" onClick={onStop}>
          Stop Capture
        </button>
      ) : (
        <button
          className="btn btn--start"
          onClick={onStart}
          disabled={!selected}
        >
          Start Capture
        </button>
      )}

      {error && <span className="error">{error}</span>}
    </div>
  );
}
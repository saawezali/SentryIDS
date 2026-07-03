import { useState, useEffect } from "react";
import {
  StartCapture,
  StopCapture,
  GetRecentAlerts,
  GetAlertCounts,
  ListInterfaces,
  IsRunning,
} from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";
import ControlBar from "./components/ControlBar";
import AlertTable from "./components/AlertTable";
import AlertChart from "./components/AlertChart";

export default function App() {
  const [running, setRunning]       = useState(false);
  const [iface, setIface]           = useState("");
  const [interfaces, setInterfaces] = useState([]);
  const [alerts, setAlerts]         = useState([]);
  const [counts, setCounts]         = useState({});
  const [error, setError]           = useState("");

  useEffect(() => {
    ListInterfaces().then(setInterfaces).catch(console.error);
    IsRunning().then(setRunning);
    GetRecentAlerts(100).then(setAlerts).catch(console.error);
    GetAlertCounts().then(setCounts).catch(console.error);
  }, []);

  useEffect(() => {
    const unsubAlert = EventsOn("alert:new", (alert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, 200));
      setCounts((prev) => ({
        ...prev,
        [alert.AttackType]: (prev[alert.AttackType] || 0) + 1,
      }));
    });

    const unsubStarted = EventsOn("capture:started", () => setRunning(true));
    const unsubStopped = EventsOn("capture:stopped", () => setRunning(false));

    return () => {
      unsubAlert();
      unsubStarted();
      unsubStopped();
    };
  }, []);

  const handleStart = async () => {
    setError("");
    const err = await StartCapture(iface);
    if (err) setError(err);
  };

  const handleStop = () => StopCapture();

  return (
    <div className="app">
      <header className="header">
        <h1>SentryIDS</h1>
        <span className={`status ${running ? "status--live" : "status--idle"}`}>
          {running ? "● LIVE" : "○ IDLE"}
        </span>
      </header>

      <main className="main">
        <ControlBar
          interfaces={interfaces}
          selected={iface}
          onSelect={setIface}
          running={running}
          onStart={handleStart}
          onStop={handleStop}
          error={error}
        />

        <div className="panels">
          <section className="panel panel--table">
            <h2>Recent Alerts</h2>
            <AlertTable alerts={alerts} />
          </section>

          <section className="panel panel--chart">
            <h2>Alerts by Type</h2>
            <AlertChart counts={counts} />
          </section>
        </div>
      </main>
    </div>
  );
}
import { useState, useEffect } from "react";
import {
  StartCapture,
  StopCapture,
  GetRecentAlerts,
  GetAlertCounts,
  ListInterfaces,
  IsRunning,
  GetConfig,
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
  const [maxAlerts, setMaxAlerts]   = useState(200);

  useEffect(() => {
    const reportError = (err) => setError(String(err));
    Promise.all([ListInterfaces(), GetConfig()]).then(([available, cfg]) => {
      setInterfaces(available);
      const preferred = available.includes(cfg.default_interface)
        ? cfg.default_interface
        : (available[0] || "");
      setIface(preferred);
      setMaxAlerts(cfg.max_alerts_in_memory || 200);
      document.documentElement.dataset.theme = cfg.theme || "dark";
    }).catch(reportError);
    IsRunning().then(setRunning).catch(reportError);
    GetRecentAlerts(100).then(setAlerts).catch(reportError);
    GetAlertCounts().then(setCounts).catch(reportError);
  }, []);

  useEffect(() => {
    const unsubAlert = EventsOn("alert:new", (alert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, maxAlerts));
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
  }, [maxAlerts]);

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

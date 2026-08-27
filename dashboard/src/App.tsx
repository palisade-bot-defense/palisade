import { FormEvent, ReactNode, useCallback, useEffect, useState } from "react";

type Health = "checking" | "ready" | "offline";
type LoadState = "locked" | "loading" | "ready" | "unauthorized" | "error";
type ActionCounts = { allow: number; observe: number; throttle: number; challenge: number; block: number };
type Recommendation = { code: string; priority: string; message: string };
type Analysis = {
  source: { first_at: string; last_at: string; decisions: number; outcomes: number };
  readiness: { state: string; operator_action: string; automatic_enforcement: boolean; reason_codes: string[] };
  decisions: { total: number; computed_challenge_rate: number };
  outcomes: { total: number; coverage: number; human_confirmed: number; operator_confirmed_abuse: number; challenge_failure_rate: number };
  recommendations: Recommendation[];
};
type Summary = {
  schema_version: string;
  generated_at: string;
  uptime_seconds: number;
  runtime: { mode: string; rollout_id?: string; policy_version: string; model_version: string };
  capabilities: { shadow_log: boolean; event_shadow: boolean; analysis_report: boolean };
  traffic: { accepted_event_batches: number; accepted_events: number; decisions: number; origin_checks: number; enforced: ActionCounts; computed: ActionCounts };
  recording: { decisions: number; outcomes: number; dropped: number; event_shadow_dropped: number };
  analysis: Analysis | null;
};

const actionNames: (keyof ActionCounts)[] = ["allow", "observe", "throttle", "challenge", "block"];
const formatNumber = (value: number) => new Intl.NumberFormat().format(value);
const formatPercent = (value: number) => new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 1 }).format(value);
const formatDuration = (seconds: number) => seconds < 60 ? `${seconds}s` : seconds < 3600 ? `${Math.floor(seconds / 60)}m` : `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;

function StatusPill({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  return <span className={`status-pill ${enabled ? "on" : "off"}`}><i />{children}</span>;
}

export function App() {
  const [health, setHealth] = useState<Health>("checking");
  const [loadState, setLoadState] = useState<LoadState>("locked");
  const [adminKey, setAdminKey] = useState("");
  const [summary, setSummary] = useState<Summary | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/health/ready", { signal: controller.signal })
      .then((response) => setHealth(response.ok ? "ready" : "offline"))
      .catch(() => setHealth("offline"));
    return () => controller.abort();
  }, []);

  const refresh = useCallback(async (key: string) => {
    if (!key) return;
    setLoadState((current) => current === "ready" ? current : "loading");
    try {
      const response = await fetch("/v1/admin/summary", {
        headers: { Authorization: `Bearer ${key}` }, cache: "no-store", credentials: "omit",
      });
      if (response.status === 401) {
        setSummary(null);
        setLoadState("unauthorized");
        return;
      }
      if (!response.ok) throw new Error("summary unavailable");
      setSummary(await response.json() as Summary);
      setLoadState("ready");
    } catch {
      setLoadState("error");
    }
  }, []);

  useEffect(() => {
    if (loadState !== "ready" || !adminKey) return;
    const timer = window.setInterval(() => void refresh(adminKey), 10_000);
    return () => window.clearInterval(timer);
  }, [adminKey, loadState, refresh]);

  function connect(event: FormEvent) {
    event.preventDefault();
    void refresh(adminKey);
  }

  function lock() {
    setAdminKey("");
    setSummary(null);
    setLoadState("locked");
  }

  return (
    <main>
      <header>
        <img src="/palisade-horizontal.svg" alt="PALISADE" />
        <nav>
          <span className={`health ${health}`}><i /> runtime {health}</span>
          {loadState === "ready" && <button className="text-button" onClick={lock}>Lock console</button>}
        </nav>
      </header>

      {loadState !== "ready" || !summary ? (
        <section className="login-shell">
          <div className="login-copy">
            <p className="eyebrow">LOCAL OPERATOR CONSOLE</p>
            <h1>Observe the system.<br /><em>Keep control local.</em></h1>
            <p className="lede">Live counters and validated aggregate analysis only. No session rows, request bodies, tokens, raw identifiers or shadow-log contents cross this interface.</p>
          </div>
          <form className="login-card" onSubmit={connect}>
            <div className="lock-mark" aria-hidden="true">◆</div>
            <h2>Operator access</h2>
            <p>The key stays in this tab&apos;s memory and is never written to browser storage.</p>
            <label htmlFor="admin-key">PALISADE_ADMIN_KEY</label>
            <input id="admin-key" type="password" autoComplete="off" value={adminKey} onChange={(event) => setAdminKey(event.target.value)} required />
            <button type="submit" disabled={loadState === "loading"}>{loadState === "loading" ? "Connecting…" : "Open console"}</button>
            {loadState === "unauthorized" && <p className="form-error" role="alert">The operator key was rejected.</p>}
            {loadState === "error" && <p className="form-error" role="alert">The local admin endpoint is unavailable.</p>}
          </form>
        </section>
      ) : (
        <>
          <section className="console-heading">
            <div><p className="eyebrow">OPERATOR OVERVIEW</p><h1>Shadow evidence,<br /><em>without raw traffic.</em></h1></div>
            <div className="runtime-badges">
              <StatusPill enabled={summary.runtime.mode === "shadow"}>{summary.runtime.mode} mode</StatusPill>
              <StatusPill enabled={summary.capabilities.shadow_log}>encrypted log</StatusPill>
              <StatusPill enabled={summary.capabilities.event_shadow}>event analysis</StatusPill>
            </div>
          </section>

          <section className="metric-grid" aria-label="Live runtime counters">
            <article><span>Evaluated decisions</span><strong>{formatNumber(summary.traffic.decisions)}</strong><small>{formatNumber(summary.traffic.origin_checks)} origin checks</small></article>
            <article><span>Accepted browser events</span><strong>{formatNumber(summary.traffic.accepted_events)}</strong><small>{formatNumber(summary.traffic.accepted_event_batches)} bounded batches</small></article>
            <article><span>Encrypted records</span><strong>{formatNumber(summary.recording.decisions + summary.recording.outcomes)}</strong><small>{formatNumber(summary.recording.outcomes)} outcomes</small></article>
            <article className={summary.recording.dropped + summary.recording.event_shadow_dropped > 0 ? "alert" : ""}><span>Dropped records</span><strong>{formatNumber(summary.recording.dropped + summary.recording.event_shadow_dropped)}</strong><small>measurement loss, never hidden</small></article>
          </section>

          <section className="two-column">
            <article className="panel action-panel">
              <div className="panel-title"><div><p className="eyebrow">LIVE PROCESS</p><h2>Computed vs enforced</h2></div><span>uptime {formatDuration(summary.uptime_seconds)}</span></div>
              <div className="action-table">
                <div className="table-head"><span>Action</span><span>Computed</span><span>Enforced</span></div>
                {actionNames.map((action) => <div className="action-row" key={action}><b className={action}>{action}</b><strong>{formatNumber(summary.traffic.computed[action])}</strong><strong>{formatNumber(summary.traffic.enforced[action])}</strong></div>)}
              </div>
              <footer className="panel-footer"><span>{summary.runtime.policy_version}</span><span>{summary.runtime.model_version}</span></footer>
            </article>

            <article className="panel analysis-panel">
              <div className="panel-title"><div><p className="eyebrow">LOCAL ANALYSIS</p><h2>Readiness</h2></div>{summary.analysis && <span className={`readiness ${summary.analysis.readiness.state}`}>{summary.analysis.readiness.state.replaceAll("_", " ")}</span>}</div>
              {summary.analysis ? (
                <>
                  <div className="analysis-stats">
                    <div><strong>{formatNumber(summary.analysis.decisions.total)}</strong><span>analyzed decisions</span></div>
                    <div><strong>{formatPercent(summary.analysis.outcomes.coverage)}</strong><span>outcome coverage</span></div>
                    <div><strong>{formatPercent(summary.analysis.decisions.computed_challenge_rate)}</strong><span>challenge candidate rate</span></div>
                  </div>
                  <div className="recommendations"><h3>Next recommended work</h3>{summary.analysis.recommendations.slice(0, 4).map((item) => <div className="recommendation" key={item.code}><span className={item.priority}>{item.priority}</span><div><code>{item.code}</code><p>{item.message}</p></div></div>)}</div>
                  <p className="safety-note">Automatic enforcement: <b>{summary.analysis.readiness.automatic_enforcement ? "enabled" : "disabled"}</b> · Operator action: <code>{summary.analysis.readiness.operator_action}</code></p>
                </>
              ) : (
                <div className="empty-state"><div aria-hidden="true">◎</div><h3>No aggregate report loaded</h3><p>Live counters are available, but PALISADE will not invent readiness or false-positive claims. Generate a private report and restart with <code>--admin-analysis-report</code>.</p></div>
              )}
            </article>
          </section>

          <footer className="page-footer"><span>Updated {new Date(summary.generated_at).toLocaleTimeString()}</span><span>No raw records exposed · refreshes every 10 seconds</span></footer>
        </>
      )}
    </main>
  );
}

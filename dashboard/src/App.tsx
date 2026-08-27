import { FormEvent, ReactNode, useCallback, useEffect, useState } from "react";

type Health = "checking" | "ready" | "offline";
type LoadState = "locked" | "loading" | "ready" | "unauthorized" | "error";
type ActionCounts = { allow: number; observe: number; throttle: number; challenge: number; block: number };
type Recommendation = { code: string; priority: string; message: string };
type Proportion = { count: number; total: number; rate: number; lower_95: number; upper_95: number };
type LinkedEvaluation = {
  decisions: number; confirmed_labels: number; ambiguous_ground_truth: number;
  confusion: { true_positive: number; false_positive: number; true_negative: number; false_negative: number };
  false_positive_rate: Proportion; abuse_recall: Proportion; abuse_precision: Proportion;
  mature_challenges: number; challenge_passed: number; challenge_failed: number; challenge_abandoned: number; fallback_used: number;
  unresolved_mature_challenges: number; ambiguous_challenge_outcomes: number;
  challenge_pass_rate: Proportion; challenge_failure_rate: Proportion; challenge_abandonment_rate: Proportion; fallback_rate: Proportion;
};
type EndpointEvidence = {
  endpoint_class: string; decisions: number; outcomes: number; human_confirmed: number; operator_confirmed_abuse: number;
  evaluation: { computed_risky_rate: Proportion; challenge_failure_rate: Proportion; challenge_abandonment_rate: Proportion; fallback_outcome_share: Proportion; unknown_outcome_share: Proportion; confirmed_labels: number; abuse_label_share: Proportion };
  linked_evaluation: LinkedEvaluation;
};
type Analysis = {
  source: { first_at: string; last_at: string; decisions: number; outcomes: number };
  readiness: { state: string; operator_action: string; automatic_enforcement: boolean; reason_codes: string[] };
  decisions: { total: number; computed_challenge_rate: number };
  outcomes: { total: number; coverage: number; human_confirmed: number; operator_confirmed_abuse: number; challenge_failure_rate: number };
  linkage: { confirmed_decision_labels: number; confirmed_label_coverage: Proportion; ambiguous_ground_truth_decisions: number; ambiguous_challenge_decisions: number };
  evaluation_slices: { endpoint_class: string; evaluation_cohort: string; evaluation: LinkedEvaluation }[];
  endpoints: EndpointEvidence[];
  canary_comparisons: { rollout_id: string; endpoint_class: string; comparable: boolean; canary_decisions: number; computed_risk_difference: { estimate: number; lower_95: number; upper_95: number } }[];
  recommendations: Recommendation[];
};
type Summary = {
  schema_version: string;
  generated_at: string;
  uptime_seconds: number;
  runtime: { mode: string; rollout_id?: string; policy_version: string; model_version: string };
  capabilities: { shadow_log: boolean; event_shadow: boolean; analysis_report: boolean };
  traffic: { accepted_event_batches: number; accepted_events: number; decisions: number; origin_checks: number; enforced: ActionCounts; computed: ActionCounts; reasons: { code: string; count: number }[] };
  recording: { decisions: number; outcomes: number; dropped: number; event_shadow_dropped: number };
  analysis_status: { state: "not_configured" | "ready" | "invalid_update"; loaded_at: string | null; last_attempt_at: string | null };
  analysis: Analysis | null;
};

const actionNames: (keyof ActionCounts)[] = ["allow", "observe", "throttle", "challenge", "block"];
const formatNumber = (value: number) => new Intl.NumberFormat().format(value);
const formatPercent = (value: number) => new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 1 }).format(value);
export const formatInterval = (value: Proportion) => value.total === 0 ? "no sample" : `${formatPercent(value.rate)} · 95% ${formatPercent(value.lower_95)}–${formatPercent(value.upper_95)}`;
export const countComparableCanaries = (values: { comparable: boolean }[]) => values.filter((value) => value.comparable).length;
const formatDuration = (seconds: number) => seconds < 60 ? `${seconds}s` : seconds < 3600 ? `${Math.floor(seconds / 60)}m` : `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
const reasonCopy: Record<string, string> = {
  BASELINE_LOW_RISK: "No configured risk threshold matched.",
  STEP_UP_REQUIRED: "Policy recommends a reversible verification step.",
  ELEVATED_RISK: "Signals crossed the observation threshold.",
  HIGH_RISK: "Multiple or high-confidence signals crossed the high-risk threshold.",
  PUBLIC_CONTENT_HIGH_RISK: "Public-content policy limited the response to progressive friction.",
  MULTI_SOURCE_ABUSE: "Independent policy and decoy signals agreed.",
  SHADOW_ACTION_OVERRIDDEN: "A risky computed action was safely reduced in shadow mode.",
  NAVIGATION_SURFACE_SWEEP: "A session crossed many closed endpoint classes unusually quickly.",
  HONEYPOT_INTERACTION: "A trusted origin adapter reported interaction with a decoy surface.",
  COMPARE_NOINDEX_CAMPAIGN_SURFACE: "The request reached a public comparison surface associated with the configured campaign pattern.",
  POLICY_ALERT: "A trusted deployment policy adapter reported elevated abuse intent.",
  EXTERNAL_RISK: "A trusted external adapter contributed a normalized risk signal.",
  CHALLENGE_VERDICT_SUSPICIOUS: "A trusted challenge adapter reported a suspicious outcome.",
  VERIFIED_BOT_IDENTITY: "A trusted origin adapter verified the declared automation identity.",
  VERIFIED_AUTOMATION_ALLOWED: "Verified automation remained below the intent and continuity risk thresholds.",
  SERVER_SESSION_VERIFIED: "The server observed a valid first-party session continuity signal.",
  BROWSER_PROTOCOL_CONTRADICTION: "Browser claims conflicted with the protocol behavior observed by the trusted origin.",
  BROWSER_SEQUENCE_PRESENT: "Bounded browser-event sequencing was present for the session.",
  SEQUENCE_GAP_HIGH: "The server observed unusually large gaps in the bounded event sequence.",
  SESSION_SEQUENCE_STABLE: "The bounded session sequence progressed without suspicious gaps.",
  SESSION_BURST: "The session produced a short request burst above the conservative baseline.",
  SESSION_BURST_FAST: "A session produced a high request volume in a short window.",
  SESSION_VOLUME_HIGH: "A session crossed the conservative volume threshold.",
  UA_MISSING: "The trusted origin observed no User-Agent header.",
};
export const explainReason = (code: string) => reasonCopy[code] ?? "Stable detector or policy reason; inspect the matching versioned rule before changing enforcement.";

function StatusPill({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  return <span className={`status-pill ${enabled ? "on" : "off"}`}><i />{children}</span>;
}

export function App() {
  const [health, setHealth] = useState<Health>("checking");
  const [loadState, setLoadState] = useState<LoadState>("locked");
  const [adminKey, setAdminKey] = useState("");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [refreshSeconds, setRefreshSeconds] = useState(10);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshWarning, setRefreshWarning] = useState(false);

  const comparableCanaries = countComparableCanaries(summary?.analysis?.canary_comparisons ?? []);

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
      setRefreshWarning(false);
      setLoadState("ready");
    } catch {
      setSummary((current) => {
        if (current) {
          setRefreshWarning(true);
          setLoadState("ready");
        } else {
          setLoadState("error");
        }
        return current;
      });
    }
  }, []);

  useEffect(() => {
    if (loadState !== "ready" || !adminKey || !autoRefresh) return;
    const timer = window.setInterval(() => void refresh(adminKey), refreshSeconds * 1_000);
    return () => window.clearInterval(timer);
  }, [adminKey, autoRefresh, loadState, refresh, refreshSeconds]);

  function connect(event: FormEvent) {
    event.preventDefault();
    void refresh(adminKey);
  }

  function lock() {
    setAdminKey("");
    setSummary(null);
    setLoadState("locked");
  }

  const generatedAt = summary ? new Date(summary.generated_at) : null;
  const stale = generatedAt ? Date.now() - generatedAt.getTime() > Math.max(30_000, refreshSeconds * 3_000) : false;

  return (
    <main>
      <header>
        <img src="/palisade-horizontal.svg" alt="PALISADE" />
        <nav>
          <span className={`health ${health}`}><i /> runtime {health}</span>
          {loadState === "ready" && <><button className="text-button" onClick={() => void refresh(adminKey)}>Refresh now</button><button className="text-button" onClick={lock}>Lock console</button></>}
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
          <div className={`connection-banner ${refreshWarning || stale ? "warning" : "ok"}`} role="status" aria-live="polite">
            <span>{refreshWarning ? "Refresh failed — showing the last valid summary." : stale ? "Summary is stale — verify the local service." : "Live aggregate telemetry connected."}</span>
            <b>{generatedAt ? generatedAt.toLocaleString() : "No timestamp"}</b>
          </div>
          <section className="console-heading">
            <div><p className="eyebrow">OPERATOR OVERVIEW</p><h1>Shadow evidence,<br /><em>without raw traffic.</em></h1></div>
            <div className="runtime-badges">
              <StatusPill enabled={summary.runtime.mode === "shadow"}>{summary.runtime.mode} mode</StatusPill>
              <StatusPill enabled={summary.capabilities.shadow_log}>encrypted log</StatusPill>
              <StatusPill enabled={summary.capabilities.event_shadow}>event analysis</StatusPill>
              <StatusPill enabled={summary.capabilities.analysis_report}>aggregate report</StatusPill>
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
              <div className="reason-list">
                <div className="subsection-title"><div><p className="eyebrow">DECISION EXPLANATIONS</p><h3>Why PALISADE decided</h3></div><span>aggregate · no request rows</span></div>
                {(summary.traffic.reasons ?? []).length > 0 ? (summary.traffic.reasons ?? []).slice(0, 8).map((reason) => (
                  <details className="reason-item" key={reason.code}>
                    <summary><code>{reason.code}</code><strong>{formatNumber(reason.count)}</strong></summary>
                    <p>{explainReason(reason.code)}</p>
                  </details>
                )) : <p className="inline-empty">No decision reasons recorded in this process yet.</p>}
              </div>
              <footer className="panel-footer"><span>{summary.runtime.policy_version}</span><span>{summary.runtime.model_version}</span></footer>
            </article>

            <article className="panel analysis-panel">
              <div className="panel-title"><div><p className="eyebrow">LOCAL ANALYSIS</p><h2>Readiness</h2></div>{summary.analysis && <span className={`readiness ${summary.analysis.readiness.state}`}>{summary.analysis.readiness.state.replaceAll("_", " ")}</span>}</div>
              {summary.analysis ? (
                <>
                  {summary.analysis_status.state === "invalid_update" && <p className="feed-warning" role="status">A report update was rejected. Showing the last valid aggregate report.</p>}
                  <div className="analysis-stats">
                    <div><strong>{formatNumber(summary.analysis.decisions.total)}</strong><span>analyzed decisions</span></div>
                    <div><strong>{formatPercent(summary.analysis.linkage.confirmed_label_coverage.rate)}</strong><span>linked label coverage</span></div>
                    <div><strong>{formatPercent(summary.analysis.decisions.computed_challenge_rate)}</strong><span>challenge candidate rate</span></div>
                  </div>
                  <div className="endpoint-evidence">
                    <h3>Endpoint evidence <span>Wilson 95% intervals</span></h3>
                    {summary.analysis.endpoints.filter((endpoint) => endpoint.decisions > 0).slice(0, 4).map((endpoint) => (
                      <div className="endpoint-row" key={endpoint.endpoint_class}>
                        <div><code>{endpoint.endpoint_class}</code><small>{formatNumber(endpoint.decisions)} decisions · {formatNumber(endpoint.outcomes)} outcome events</small></div>
                        <div><span>computed risky</span><b>{formatInterval(endpoint.evaluation.computed_risky_rate)}</b></div>
                        <div><span>false-positive rate</span><b>{formatInterval(endpoint.linked_evaluation.false_positive_rate)}</b></div>
                        <div><span>linked labels</span><b>{formatNumber(endpoint.linked_evaluation.confirmed_labels)}</b></div>
                      </div>
                    ))}
                    {summary.analysis.evaluation_slices.filter((slice) => slice.evaluation.mature_challenges > 0 || slice.evaluation.confirmed_labels > 0).slice(0, 4).map((slice) => (
                      <p className="comparison-note" key={`${slice.endpoint_class}:${slice.evaluation_cohort}`}><code>{slice.endpoint_class}</code> · {slice.evaluation_cohort.replaceAll("_", " ")} · false positives {formatInterval(slice.evaluation.false_positive_rate)} · challenge pass {formatInterval(slice.evaluation.challenge_pass_rate)}</p>
                    ))}
                    {summary.analysis.canary_comparisons.length > 0 && <p className="comparison-note">{formatNumber(summary.analysis.canary_comparisons.length)} canary endpoint group{summary.analysis.canary_comparisons.length === 1 ? "" : "s"} recorded; {formatNumber(comparableCanaries)} have a same-window shadow baseline. Intervals describe aggregate uncertainty, not causality.</p>}
                  </div>
                  <div className="recommendations"><h3>Next recommended work</h3>{summary.analysis.recommendations.slice(0, 4).map((item) => <div className="recommendation" key={item.code}><span className={item.priority}>{item.priority}</span><div><code>{item.code}</code><p>{item.message}</p></div></div>)}</div>
                  <p className="safety-note">Source through: <b>{summary.analysis.source.last_at || "no records yet"}</b><br />Ambiguous labels: <b>{formatNumber(summary.analysis.linkage.ambiguous_ground_truth_decisions)}</b> · ambiguous challenge outcomes: <b>{formatNumber(summary.analysis.linkage.ambiguous_challenge_decisions)}</b><br />Automatic enforcement: <b>{summary.analysis.readiness.automatic_enforcement ? "enabled" : "disabled"}</b> · Operator action: <code>{summary.analysis.readiness.operator_action}</code></p>
                </>
              ) : (
                <div className="empty-state"><div aria-hidden="true">◎</div><h3>No aggregate report loaded</h3><p>Live counters are available, but PALISADE will not invent readiness or false-positive claims. Generate a private report and restart with <code>--admin-analysis-report</code>.</p></div>
              )}
            </article>
          </section>

          <section className="control-panel" aria-labelledby="control-title">
            <div className="control-copy"><p className="eyebrow">CONTROL CENTER</p><h2 id="control-title">Operational controls, without unsafe shortcuts.</h2><p>These settings affect only this browser tab. Policy, canary and enforcement changes still require validated local reports and signed rollout artifacts.</p></div>
            <div className="control-grid">
              <label><span>Automatic refresh</span><select value={refreshSeconds} onChange={(event) => setRefreshSeconds(Number(event.target.value))} disabled={!autoRefresh}><option value={5}>Every 5 seconds</option><option value={10}>Every 10 seconds</option><option value={30}>Every 30 seconds</option><option value={60}>Every minute</option></select></label>
              <div className="control-action"><span>Polling state</span><button type="button" className="secondary-button" onClick={() => setAutoRefresh((current) => !current)}>{autoRefresh ? "Pause auto-refresh" : "Resume auto-refresh"}</button></div>
              <div className="control-action"><span>Latest aggregate</span><button type="button" className="primary-button" onClick={() => void refresh(adminKey)}>Refresh now</button></div>
              <div className="control-action danger-zone"><span>Console credential</span><button type="button" className="secondary-button" onClick={lock}>Lock console</button></div>
            </div>
            <dl className="runtime-contract"><div><dt>Runtime mode</dt><dd>{summary.runtime.mode}</dd></div><div><dt>Rollout</dt><dd>{summary.runtime.rollout_id || "none loaded"}</dd></div><div><dt>Activation authority</dt><dd>signed rollout only</dd></div><div><dt>Automatic enforcement</dt><dd>{summary.analysis?.readiness.automatic_enforcement ? "reported enabled" : "disabled"}</dd></div></dl>
          </section>

          <footer className="page-footer"><span>Updated {generatedAt?.toLocaleTimeString()}</span><span>No raw records exposed · {autoRefresh ? `refreshes every ${refreshSeconds} seconds` : "auto-refresh paused"}</span></footer>
        </>
      )}
    </main>
  );
}

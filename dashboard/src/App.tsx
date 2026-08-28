import { FormEvent, ReactNode, useCallback, useEffect, useState } from "react";

type Health = "checking" | "ready" | "offline";
type LoadState = "locked" | "loading" | "ready" | "unauthorized" | "error";
type ActionCounts = { allow: number; observe: number; delay: number; throttle: number; challenge: number; block: number };
type Recommendation = { code: string; priority: string; message: string };
type Proportion = { count: number; total: number; rate: number; lower_95: number; upper_95: number };
type ScoreSummary = { minimum: number; maximum: number; mean: number };
export type Collection = {
  state: "disabled" | "no_samples" | "collecting" | "degraded";
  traffic_denominator: "external_total_unavailable";
  context_proofs_issued: number;
  accepted_event_batches: number;
  recorded_shadow_decisions: number;
  rejected_before_ingest: number;
  dropped_after_ingest: number;
  batch_recording_rate: number;
  endpoint_context_proofs: { endpoint_class: string; count: number }[];
};
export type OriginCoverage = {
  state: "unavailable" | "no_samples" | "collecting" | "degraded";
  scope: "protected_handler_requests";
  traffic_denominator: "authenticated_origin_reports";
  sources: number;
  observed_since: string | null;
  last_reported_at: string | null;
  protected_requests: number;
  evaluated_requests: number;
  bypassed_requests: number;
  rejected_requests: number;
  granted_retries: number;
  decision_coverage_rate: number;
  endpoints: { endpoint_class: string; protected_requests: number; evaluated_requests: number; bypassed_requests: number; rejected_requests: number; granted_retries: number }[];
};
export type OutcomeFlow = { state: "disabled" | "no_samples" | "collecting" | "degraded"; accepted: number; rejected: number; dropped: number };
export type TransportPosture = {
  state: "no_samples" | "collecting" | "attention";
  scope: "evaluated_decisions";
  samples: number;
  protocol: { http1: number; http2: number; http3: number; unknown: number };
  security: { direct_tls: number; trusted_proxy_tls: number; plaintext: number; unknown: number };
  address_source: { direct: number; trusted_proxy: number; invalid_trusted_proxy: number; unknown: number };
};
export type CrawlerIdentity = {
  state: "no_samples" | "collecting" | "attention";
  scope: "evaluated_identity_observations";
  observations: number;
  qualified_public: number;
  unqualified: number;
  classes: { search_indexer: number; answer_engine: number; training_crawler: number; user_triggered_agent: number; preview: number; monitoring: number; other: number; unknown: number };
  verification: { ip_ua_registry: number; fcrdns_ua: number; http_signature: number; unknown: number };
};
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
  scores: { automation_risk: ScoreSummary; abuse_intent_risk: ScoreSummary; account_continuity: ScoreSummary };
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
  capabilities: { shadow_log: boolean; event_shadow: boolean; event_shadow_proof_contexts: boolean; analysis_report: boolean };
  traffic: { accepted_event_batches: number; accepted_events: number; decisions: number; origin_checks: number; enforced: ActionCounts; computed: ActionCounts; reasons: { code: string; count: number }[] };
  recording: { decisions: number; outcomes: number; dropped: number; event_shadow_dropped: number };
  collection: Collection;
  origin_coverage: OriginCoverage;
  outcome_flow: OutcomeFlow;
  transport_posture: TransportPosture;
  crawler_identity: CrawlerIdentity;
  analysis_status: { state: "not_configured" | "ready" | "invalid_update"; loaded_at: string | null; last_attempt_at: string | null };
  analysis: Analysis | null;
};

const actionNames: (keyof ActionCounts)[] = ["allow", "observe", "delay", "throttle", "challenge", "block"];
const formatNumber = (value: number) => new Intl.NumberFormat().format(value);
const formatPercent = (value: number) => new Intl.NumberFormat(undefined, { style: "percent", maximumFractionDigits: 1 }).format(value);
export const formatInterval = (value: Proportion) => value.total === 0 ? "no sample" : `${formatPercent(value.rate)} · 95% ${formatPercent(value.lower_95)}–${formatPercent(value.upper_95)}`;
export const countComparableCanaries = (values: { comparable: boolean }[]) => values.filter((value) => value.comparable).length;
export const scoreEvidenceState = (value: ScoreSummary) => value.minimum === 0.5 && value.maximum === 0.5 && value.mean === 0.5
  ? "No evidence observed · neutral prior"
  : value.minimum === value.maximum
    ? "No variation observed"
    : `Observed range ${formatPercent(value.minimum)}–${formatPercent(value.maximum)}`;
export const collectionRateLabel = (collection: Collection) => collection.accepted_event_batches === 0
  ? "no accepted batch sample"
  : `${formatPercent(collection.batch_recording_rate)} of accepted batches recorded`;
export const collectionStateCopy = (collection: Collection) => {
  if (collection.state === "disabled") return "Event-shadow collection is disabled.";
  if (collection.state === "no_samples") return "Collection is enabled, but no accepted event batch has been observed.";
  if (collection.state === "degraded") return "Collection loss or a pre-ingest rejection was observed; investigate before interpreting results.";
  return "The internal PALISADE collection funnel is active. This is not a site-traffic coverage claim.";
};
export const originCoverageCopy = (coverage: OriginCoverage) => {
  if (coverage.state === "unavailable") return "No authenticated reference-adapter report has arrived.";
  if (coverage.state === "no_samples") return "A source is registered, but its process-local measurement window has no completed request sample.";
  if (coverage.state === "degraded") return "A protected request bypassed evaluation or was rejected by the adapter; investigate before rollout.";
  return "Authenticated coverage for requests that completed inside the configured protected handler.";
};
export const outcomeFlowCopy = (flow: OutcomeFlow) => {
  if (flow.state === "disabled") return "Encrypted outcome recording is disabled.";
  if (flow.state === "no_samples") return "Outcome recording is enabled, but no normalized outcome event has arrived.";
  if (flow.state === "degraded") return "An authorized outcome was rejected or could not be written; linkage evidence is incomplete.";
  return "Normalized outcome events are reaching the encrypted local sink.";
};
export const transportPostureCopy = (posture: TransportPosture) => {
  if (posture.state === "no_samples") return "No successfully evaluated decision has supplied transport context in this process.";
  if (posture.state === "attention") return "Plaintext, unknown or invalid trusted-proxy context was observed; verify the deployment boundary before rollout.";
  return "Evaluated decisions contain complete closed transport provenance without address values.";
};
export const crawlerIdentityCopy = (identity: CrawlerIdentity) => {
  if (identity.state === "no_samples") return "No crawler identity observation has reached this process.";
  if (identity.state === "attention") return "At least one crawler claim lacked eligible proof, purpose or public endpoint scope; it was not allowlisted.";
  return "All observed crawler identities in this process qualified for their narrow public scope.";
};
const formatDuration = (seconds: number) => seconds < 60 ? `${seconds}s` : seconds < 3600 ? `${Math.floor(seconds / 60)}m` : `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
const reasonCopy: Record<string, string> = {
  BASELINE_LOW_RISK: "No configured risk threshold matched.",
  STEP_UP_REQUIRED: "Policy recommends a reversible verification step.",
  ELEVATED_RISK: "Signals crossed the bounded progressive-response threshold.",
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
  VERIFIED_PUBLIC_CRAWLER: "A trusted origin adapter verified a declared crawler class for an indexable public endpoint.",
  VERIFIED_PUBLIC_CRAWLER_ALLOWED: "A verified beneficial crawler remained below intent and continuity risk thresholds on a public endpoint.",
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
              <StatusPill enabled={summary.capabilities.event_shadow_proof_contexts}>route proof contexts</StatusPill>
              <StatusPill enabled={summary.capabilities.analysis_report}>aggregate report</StatusPill>
            </div>
          </section>

          <section className="metric-grid" aria-label="Live runtime counters">
            <article><span>Evaluated decisions</span><strong>{formatNumber(summary.traffic.decisions)}</strong><small>{formatNumber(summary.traffic.origin_checks)} origin checks</small></article>
            <article><span>Accepted browser events</span><strong>{formatNumber(summary.traffic.accepted_events)}</strong><small>{formatNumber(summary.traffic.accepted_event_batches)} bounded batches</small></article>
            <article><span>Encrypted records</span><strong>{formatNumber(summary.recording.decisions + summary.recording.outcomes)}</strong><small>{formatNumber(summary.recording.outcomes)} outcomes</small></article>
            <article className={summary.recording.dropped + summary.recording.event_shadow_dropped > 0 ? "alert" : ""}><span>Dropped records</span><strong>{formatNumber(summary.recording.dropped + summary.recording.event_shadow_dropped)}</strong><small>measurement loss, never hidden</small></article>
          </section>

          <section className={`collection-panel ${summary.collection.state}`} aria-labelledby="collection-title">
            <div className="collection-heading">
              <div><p className="eyebrow">MEASUREMENT COMPLETENESS</p><h2 id="collection-title">Collection funnel</h2></div>
              <span>{summary.collection.state.replaceAll("_", " ")}</span>
            </div>
            <div className="collection-flow" aria-label="Event shadow collection funnel">
              <div><strong>{formatNumber(summary.collection.context_proofs_issued)}</strong><span>route-classified proofs</span></div>
              <i aria-hidden="true">→</i>
              <div><strong>{formatNumber(summary.collection.accepted_event_batches)}</strong><span>accepted batches</span></div>
              <i aria-hidden="true">→</i>
              <div><strong>{formatNumber(summary.collection.recorded_shadow_decisions)}</strong><span>recorded decisions</span></div>
            </div>
            <div className="collection-copy">
              <p><strong>{collectionRateLabel(summary.collection)}</strong><br />{collectionStateCopy(summary.collection)}</p>
              <p className="denominator-warning"><strong>Total site traffic: unavailable.</strong><br />PALISADE has no authenticated external request denominator, so this console does not claim what share of website traffic was evaluated.</p>
            </div>
            <div className="collection-detail">
              <span>{formatNumber(summary.collection.rejected_before_ingest)} rejected before ingestion</span>
              <span>{formatNumber(summary.collection.dropped_after_ingest)} dropped after ingestion</span>
              {summary.collection.endpoint_context_proofs.map((endpoint) => <span key={endpoint.endpoint_class}><code>{endpoint.endpoint_class}</code> {formatNumber(endpoint.count)} proofs</span>)}
              {summary.collection.endpoint_context_proofs.length === 0 && <span>No route-classified proof sample yet.</span>}
            </div>
          </section>

          <section className="operational-funnels" aria-label="Origin coverage, outcome ingestion, transport posture and crawler identity">
            <article className={`funnel-card ${summary.origin_coverage.state}`}>
              <div className="collection-heading"><div><p className="eyebrow">PROTECTED HANDLER</p><h2>Origin coverage</h2></div><span>{summary.origin_coverage.state.replaceAll("_", " ")}</span></div>
              <strong className="funnel-primary">{summary.origin_coverage.protected_requests === 0 ? "no sample" : formatPercent(summary.origin_coverage.decision_coverage_rate)}</strong>
              <p>{originCoverageCopy(summary.origin_coverage)}</p>
              <div className="funnel-metrics">
                <span><b>{formatNumber(summary.origin_coverage.protected_requests)}</b> completed protected requests</span>
                <span><b>{formatNumber(summary.origin_coverage.evaluated_requests)}</b> fresh evaluations</span>
                <span><b>{formatNumber(summary.origin_coverage.granted_retries)}</b> bound challenge retries</span>
                <span className={summary.origin_coverage.bypassed_requests > 0 ? "loss" : ""}><b>{formatNumber(summary.origin_coverage.bypassed_requests)}</b> availability bypasses</span>
                <span className={summary.origin_coverage.rejected_requests > 0 ? "loss" : ""}><b>{formatNumber(summary.origin_coverage.rejected_requests)}</b> adapter rejections</span>
              </div>
              <div className="collection-detail">
                {summary.origin_coverage.endpoints.map((endpoint) => <span key={endpoint.endpoint_class}><code>{endpoint.endpoint_class}</code> {formatNumber(endpoint.protected_requests)} completed</span>)}
                {summary.origin_coverage.endpoints.length === 0 && <span>No closed endpoint sample in this window.</span>}
              </div>
              <p className="scope-warning"><strong>Scope boundary:</strong> only requests routed through configured PALISADE middleware. This is not total website traffic.</p>
            </article>

            <article className={`funnel-card ${summary.outcome_flow.state}`}>
              <div className="collection-heading"><div><p className="eyebrow">GROUND-TRUTH PIPELINE</p><h2>Outcome ingestion</h2></div><span>{summary.outcome_flow.state.replaceAll("_", " ")}</span></div>
              <strong className="funnel-primary">{formatNumber(summary.outcome_flow.accepted)}</strong>
              <p>{outcomeFlowCopy(summary.outcome_flow)}</p>
              <div className="outcome-flow">
                <div><strong>{formatNumber(summary.outcome_flow.accepted)}</strong><span>accepted events</span></div>
                <div className={summary.outcome_flow.rejected > 0 ? "loss" : ""}><strong>{formatNumber(summary.outcome_flow.rejected)}</strong><span>rejected events</span></div>
                <div className={summary.outcome_flow.dropped > 0 ? "loss" : ""}><strong>{formatNumber(summary.outcome_flow.dropped)}</strong><span>write failures</span></div>
              </div>
              <p className="scope-warning"><strong>Evidence boundary:</strong> outcome events are not automatically human or abuse labels. Only the linked aggregate analysis determines usable ground truth.</p>
            </article>

            <article className={`funnel-card transport-card ${summary.transport_posture.state}`}>
              <div className="collection-heading"><div><p className="eyebrow">TRUST BOUNDARY</p><h2>Transport posture</h2></div><span>{summary.transport_posture.state.replaceAll("_", " ")}</span></div>
              <strong className="funnel-primary">{summary.transport_posture.samples === 0 ? "no sample" : formatNumber(summary.transport_posture.samples)}</strong>
              <p>{transportPostureCopy(summary.transport_posture)}</p>
              <div className="transport-groups">
                <div><h3>Protocol</h3><span>HTTP/1 <b>{formatNumber(summary.transport_posture.protocol.http1)}</b></span><span>HTTP/2 <b>{formatNumber(summary.transport_posture.protocol.http2)}</b></span><span>HTTP/3 <b>{formatNumber(summary.transport_posture.protocol.http3)}</b></span><span className={summary.transport_posture.protocol.unknown > 0 ? "loss" : ""}>unknown <b>{formatNumber(summary.transport_posture.protocol.unknown)}</b></span></div>
                <div><h3>Security</h3><span>direct TLS <b>{formatNumber(summary.transport_posture.security.direct_tls)}</b></span><span>proxy edge TLS <b>{formatNumber(summary.transport_posture.security.trusted_proxy_tls)}</b></span><span className={summary.transport_posture.security.plaintext > 0 ? "loss" : ""}>plaintext <b>{formatNumber(summary.transport_posture.security.plaintext)}</b></span><span className={summary.transport_posture.security.unknown > 0 ? "loss" : ""}>unknown <b>{formatNumber(summary.transport_posture.security.unknown)}</b></span></div>
                <div><h3>Address provenance</h3><span>direct peer <b>{formatNumber(summary.transport_posture.address_source.direct)}</b></span><span>trusted proxy <b>{formatNumber(summary.transport_posture.address_source.trusted_proxy)}</b></span><span className={summary.transport_posture.address_source.invalid_trusted_proxy > 0 ? "loss" : ""}>invalid proxy value <b>{formatNumber(summary.transport_posture.address_source.invalid_trusted_proxy)}</b></span><span className={summary.transport_posture.address_source.unknown > 0 ? "loss" : ""}>unknown <b>{formatNumber(summary.transport_posture.address_source.unknown)}</b></span></div>
              </div>
              <p className="scope-warning"><strong>Privacy boundary:</strong> aggregate classes from evaluated decisions only. No IP address or forwarding-header value is retained.</p>
            </article>

            <article className={`funnel-card transport-card ${summary.crawler_identity.state}`}>
              <div className="collection-heading"><div><p className="eyebrow">SEO / GEO IDENTITY</p><h2>Crawler verification</h2></div><span>{summary.crawler_identity.state.replaceAll("_", " ")}</span></div>
              <strong className="funnel-primary">{summary.crawler_identity.observations === 0 ? "no sample" : formatNumber(summary.crawler_identity.qualified_public)}</strong>
              <p>{crawlerIdentityCopy(summary.crawler_identity)}</p>
              <div className="transport-groups crawler-groups">
                <div><h3>Purpose</h3><span>search indexer <b>{formatNumber(summary.crawler_identity.classes.search_indexer)}</b></span><span>answer engine <b>{formatNumber(summary.crawler_identity.classes.answer_engine)}</b></span><span>user-triggered <b>{formatNumber(summary.crawler_identity.classes.user_triggered_agent)}</b></span><span className={summary.crawler_identity.classes.training_crawler > 0 ? "loss" : ""}>training crawler <b>{formatNumber(summary.crawler_identity.classes.training_crawler)}</b></span></div>
                <div><h3>Proof</h3><span>IP + UA registry <b>{formatNumber(summary.crawler_identity.verification.ip_ua_registry)}</b></span><span>FCrDNS + UA <b>{formatNumber(summary.crawler_identity.verification.fcrdns_ua)}</b></span><span>HTTP signature <b>{formatNumber(summary.crawler_identity.verification.http_signature)}</b></span><span className={summary.crawler_identity.verification.unknown > 0 ? "loss" : ""}>unknown <b>{formatNumber(summary.crawler_identity.verification.unknown)}</b></span></div>
                <div><h3>Qualification</h3><span>eligible public <b>{formatNumber(summary.crawler_identity.qualified_public)}</b></span><span className={summary.crawler_identity.unqualified > 0 ? "loss" : ""}>not allowlisted <b>{formatNumber(summary.crawler_identity.unqualified)}</b></span></div>
              </div>
              <p className="scope-warning"><strong>Identity boundary:</strong> aggregate closed classes only. No IP, user-agent, DNS name or vendor label is retained.</p>
            </article>
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
                  <div className="score-evidence">
                    <div className="subsection-title"><div><p className="eyebrow">SIGNAL DIMENSIONS</p><h3>What moved the scores</h3></div><span>aggregate evidence</span></div>
                    {([
                      ["Automation risk", summary.analysis.scores.automation_risk],
                      ["Abuse intent", summary.analysis.scores.abuse_intent_risk],
                      ["Account continuity risk", summary.analysis.scores.account_continuity],
                    ] as [string, ScoreSummary][]).map(([label, score]) => (
                      <div className={`score-row ${scoreEvidenceState(score).startsWith("No evidence") ? "neutral" : "observed"}`} key={label}>
                        <span>{label}</span><strong>{formatPercent(score.mean)}</strong><small>{scoreEvidenceState(score)}</small>
                      </div>
                    ))}
                    <p>A neutral 50% prior is an absence of directional evidence, not a measured 50% probability of abuse.</p>
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

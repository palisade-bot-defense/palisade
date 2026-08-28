import { useState } from "react";
import logoUrl from "../../brand/logo/palisade-horizontal.svg";

const githubUrl = "https://github.com/palisade-bot-defense/palisade";

const repositoryParts = [
  {
    name: "Decision service",
    status: "Go",
    summary: "Fuse bounded evidence into separate automation, abuse-intent and continuity scores.",
    items: ["Stable reason codes and policy versions", "Fail-safe shadow mode", "Signed and reversible rollout plans"],
  },
  {
    name: "Origin integration",
    status: "Go + HTTP",
    summary: "Classify protected routes on the trusted server side and apply bounded results at the origin.",
    items: ["Closed endpoint classes", "One-time proof and challenge binding", "Explicit availability policy"],
  },
  {
    name: "Local evaluation",
    status: "Encrypted",
    summary: "Measure decisions and linked outcomes inside the deployment boundary before enforcement.",
    items: ["Append-only rotated shadow logs", "Aggregate confidence intervals", "Deterministic replay and recommendations"],
  },
] as const;

const stages = [
  { number: "01", name: "Connect", copy: "Add the same-origin sensor or trusted origin adapter. Palisade accepts bounded signals, not raw vendor payloads." },
  { number: "02", name: "Measure", copy: "Run in shadow mode and keep encrypted decision and outcome records inside the deployment boundary." },
  { number: "03", name: "Understand", copy: "Separate automation, abuse intent and continuity. Review aggregate recommendations and stable reason codes." },
  { number: "04", name: "Respond", copy: "Promote only a reviewed, signed and expiring canary with a defined rollback." },
] as const;

const scenarios = {
  observe: {
    tab: "Shadow", eyebrow: "ILLUSTRATIVE TRAFFIC", action: "OBSERVE", computed: "CHALLENGE",
    copy: "The risky recommendation is recorded, while the live response remains unchanged.",
    scores: [["Automation", 76], ["Abuse intent", 58], ["Continuity", 34]] as const,
  },
  canary: {
    tab: "Canary", eyebrow: "ILLUSTRATIVE 1% COHORT", action: "THROTTLE", computed: "THROTTLE",
    copy: "Only the signed endpoint and stable cohort receive the bounded response.",
    scores: [["Automation", 89], ["Abuse intent", 81], ["Continuity", 21]] as const,
  },
} as const;

type Scenario = keyof typeof scenarios;

function Score({ label, value }: { label: string; value: number }) {
  return (
    <div className="score-row">
      <span>{label}</span>
      <div className="score-track" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={value}>
        <i style={{ width: `${value}%` }} />
      </div>
      <strong>{value}</strong>
    </div>
  );
}

export function App() {
  const [scenario, setScenario] = useState<Scenario>("observe");
  const sample = scenarios[scenario];

  return (
    <div className="site-shell">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="Palisade home"><img src={logoUrl} alt="PALISADE" /></a>
        <nav aria-label="Primary navigation">
          <a href="#how-it-works">How it works</a>
          <a href="#repository">Repository</a>
          <a href="#trust">Trust</a>
          <a className="nav-cta" href={githubUrl}>View on GitHub</a>
        </nav>
      </header>

      <main id="top">
        <section className="hero-section">
          <div className="hero-copy">
            <p className="eyebrow"><span /> OPEN-SOURCE SIGNAL FUSION FOR BOT DEFENSE</p>
            <h1>Turn bot signals into <em>decisions you can explain.</em></h1>
            <p className="hero-lede">Palisade is a self-hosted decision layer for normalized edge, reputation, policy and behavioral evidence. It starts in shadow mode and does not pretend that one signal can prove who is human.</p>
            <div className="hero-actions">
              <a className="button primary" href="#repository">Explore the repository</a>
              <a className="button secondary" href={githubUrl}>View source <span aria-hidden="true">↗</span></a>
            </div>
            <ul className="trust-list" aria-label="Core guarantees">
              <li>Open source</li><li>Self-hosted</li><li>Shadow-first</li><li>No cross-site identity graph</li>
            </ul>
          </div>

          <div className="decision-demo" aria-label="Illustrative Palisade decision">
            <div className="demo-head">
              <div><p>Decision preview</p><span>Illustrative, not customer data or measured efficacy</span></div>
              <div className="scenario-tabs" role="group" aria-label="Decision stage">
                {(Object.keys(scenarios) as Scenario[]).map((key) => (
                  <button key={key} className={scenario === key ? "active" : ""} aria-pressed={scenario === key} onClick={() => setScenario(key)}>{scenarios[key].tab}</button>
                ))}
              </div>
            </div>
            <div className="demo-body">
              <p className="demo-eyebrow">{sample.eyebrow}</p>
              <div className="verdict-line"><strong>{sample.action}</strong><span>computed {sample.computed}</span></div>
              <p className="demo-copy">{sample.copy}</p>
              <div className="score-list">{sample.scores.map(([label, value]) => <Score key={label} label={label} value={value} />)}</div>
            </div>
            <div className="demo-foot"><span className="live-dot" /> versioned policy · bounded evidence · stable reasons</div>
          </div>
        </section>

        <section className="principles" aria-label="Project scope">
          <p>Built to fuse</p><div><span>Edge signals</span><span>Reputation</span><span>Policy alerts</span><span>Behavior</span><span>Outcomes</span></div>
        </section>

        <section className="section platform-section" id="how-it-works">
          <div className="section-heading">
            <p className="eyebrow">ONE AUDITABLE CONTROL LOOP</p>
            <h2>Enforcement has to earn its evidence.</h2>
            <p>Palisade does not turn a user agent, browser trait or reputation flag into an automatic block. It fuses bounded evidence, preserves uncertainty and requires a measured promotion path.</p>
          </div>
          <div className="stage-grid">{stages.map((stage) => <article key={stage.number}><span>{stage.number}</span><h3>{stage.name}</h3><p>{stage.copy}</p></article>)}</div>
        </section>

        <section className="section dimension-section">
          <div className="dimension-copy">
            <p className="eyebrow light">THREE QUESTIONS, KEPT SEPARATE</p>
            <h2>Automation is not the same as abuse.</h2>
            <p>Useful crawlers, assistive technology and scripted clients exist. Palisade evaluates activity in context instead of treating automation as a verdict.</p>
          </div>
          <div className="dimension-grid">
            <article><b>A</b><div><h3>Automation risk</h3><p>Is this client likely automated?</p></div></article>
            <article><b>I</b><div><h3>Abuse intent</h3><p>Is this action likely harmful?</p></div></article>
            <article><b>C</b><div><h3>Continuity</h3><p>Does this session match its established behavior?</p></div></article>
          </div>
        </section>

        <section className="section deployment-section" id="repository">
          <div className="section-heading compact">
            <p className="eyebrow">ONE OPEN-SOURCE PROJECT</p>
            <h2>Run the entire decision loop on your infrastructure.</h2>
            <p>The repository contains the data path, reference integration and local evaluation workflow. There is no managed-service tier or central telemetry requirement.</p>
          </div>
          <div className="product-grid">
            {repositoryParts.map((part) => (
              <article key={part.name}>
                <div className="product-top"><h3>{part.name}</h3><span>{part.status}</span></div>
                <p>{part.summary}</p>
                <ul>{part.items.map((item) => <li key={item}>{item}</li>)}</ul>
                <a href={githubUrl}>Inspect the source <span aria-hidden="true">→</span></a>
              </article>
            ))}
          </div>
          <p className="availability-note"><strong>Current maturity:</strong> PALISADE is an early prototype with runnable components, not a production-supported release. Detection efficacy and false-positive rate still require representative labeled shadow outcomes.</p>
        </section>

        <section className="section trust-section" id="trust">
          <div className="section-heading compact"><p className="eyebrow">SECURITY BY BOUNDARY</p><h2>Your defense layer should not become another data leak.</h2></div>
          <div className="trust-grid">
            <article><span>01</span><h3>Local measurement</h3><p>Encrypted append-only shadow records stay inside the deployment boundary with explicit rotation and retention.</p></article>
            <article><span>02</span><h3>Closed inputs</h3><p>The decision API accepts normalized bounded signals, not URLs, bodies, cookies or arbitrary upstream payloads.</p></article>
            <article><span>03</span><h3>Controlled rollout</h3><p>Risky live actions require an expiring signed plan, endpoint scope, stable cohort and documented rollback.</p></article>
            <article><span>04</span><h3>Auditable reasons</h3><p>Every decision carries stable reason codes plus policy and model versions for deterministic replay.</p></article>
          </div>
        </section>

        <section className="section proof-section">
          <div><p className="eyebrow light">WHAT YOU CAN TEST</p><h2>A decision you can inspect—including the decision not to block.</h2></div>
          <ul>
            <li><span>Replay</span><strong>Deterministic synthetic decisions with separate computed and enforced actions</strong></li>
            <li><span>Evidence</span><strong>Three score dimensions, stable reasons and closed signal contracts</strong></li>
            <li><span>Analysis</span><strong>Local aggregate outcomes, uncertainty and non-enforcing recommendations</strong></li>
            <li><span>Operations</span><strong>Signed rollout scope, expiry, coverage counters and rollback</strong></li>
          </ul>
        </section>

        <section className="section faq-section">
          <div className="section-heading compact"><p className="eyebrow">STRAIGHT ANSWERS</p><h2>Before you put Palisade in a request path.</h2></div>
          <div className="faq-grid">
            <details><summary>Is Palisade a validated universal bot detector?</summary><p>No. Its current confirmed-human cohort is not representative enough to support that claim. Palisade is an explainable fusion and policy layer whose thresholds must be measured on each protected surface.</p></details>
            <details><summary>Which signals can it use?</summary><p>Trusted adapters can submit normalized protocol, transport, reputation, crawler, policy and server-continuity evidence. The browser sensor adds bounded behavior counts. Raw vendor payloads are not accepted by the public decision API.</p></details>
            <details><summary>Do I need to upload traffic logs?</summary><p>No. Normal operation uses closed signals, and optional encrypted measurement remains local. Historical imports are local-only and raw deployment data must never enter the repository or CI.</p></details>
            <details><summary>Can I self-host the complete project?</summary><p>Yes. The core is AGPL-3.0-only and the browser sensor is Apache-2.0. The project currently focuses exclusively on the open-source, self-hosted path.</p></details>
          </div>
        </section>

        <section className="contact-section" id="run-locally">
          <div><p className="eyebrow light">BUILD IN THE OPEN</p><h2>Inspect the limits, run the tests, improve the evidence.</h2><p>Start with the repository quick start, synthetic replay and Operator Console. Contributions are accepted under the license covering the affected path.</p></div>
          <div className="contact-action"><a className="button contact-button" href={githubUrl}>Open the repository <span aria-hidden="true">↗</span></a><small>No analytics, form submissions or private contact funnel.</small></div>
        </section>
      </main>

      <footer className="site-footer">
        <div><img src={logoUrl} alt="PALISADE" /><p>Open-source signal fusion for bot defense.</p></div>
        <div className="footer-links"><a href={githubUrl}>GitHub</a><a href={`${githubUrl}/blob/main/SECURITY.md`}>Security</a><a href={`${githubUrl}/blob/main/LICENSING.md`}>Licensing</a></div>
        <p className="legal">Core AGPL-3.0-only · Sensor Apache-2.0 · No tracking on this site</p>
      </footer>
    </div>
  );
}

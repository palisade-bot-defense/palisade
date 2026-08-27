import { useState } from "react";
import logoUrl from "../../brand/logo/palisade-horizontal.svg";

const githubUrl = "https://github.com/palisade-bot-defense/palisade";

const productPaths = [
  {
    name: "Palisade Core",
    status: "Available now",
    summary: "The open-source control plane for teams that operate everything themselves.",
    items: ["Go decision service and origin adapter", "Encrypted local measurement", "Explainable policy and reversible rollout"],
    action: "Explore Core",
    href: githubUrl,
    featured: false,
  },
  {
    name: "Palisade Pilot",
    status: "Design partner",
    summary: "A guided engagement that turns your traffic into an evidence-backed protection policy.",
    items: ["Integration and signal-boundary review", "Shadow baseline and aggregate report", "Reviewed canary with rollback plan"],
    action: "Plan a pilot",
    href: "#contact",
    featured: true,
  },
  {
    name: "Palisade Managed",
    status: "Early access",
    summary: "A dedicated, single-tenant deployment operated for your environment.",
    items: ["Isolated runtime and customer-specific keys", "Managed upgrades and policy review", "Operational support for canary and rollback"],
    action: "Join early access",
    href: "#contact",
    featured: false,
  },
] as const;

const stages = [
  {
    number: "01",
    name: "Connect",
    copy: "Add the same-origin sensor or trusted origin adapter. Palisade accepts bounded signals, not raw vendor payloads.",
  },
  {
    number: "02",
    name: "Measure",
    copy: "Run in shadow mode and keep encrypted decision and outcome records inside the deployment boundary.",
  },
  {
    number: "03",
    name: "Understand",
    copy: "Separate automation, abuse intent and continuity. Review aggregate recommendations and stable reason codes.",
  },
  {
    number: "04",
    name: "Respond",
    copy: "Promote a signed, expiring canary. Delay, throttle, challenge or temporarily block with a defined rollback.",
  },
] as const;

const scenarios = {
  observe: {
    tab: "Shadow",
    eyebrow: "CURRENT TRAFFIC",
    action: "OBSERVE",
    computed: "CHALLENGE",
    copy: "The risky recommendation is recorded, while the live response remains unchanged.",
    scores: [
      ["Automation", 76],
      ["Abuse intent", 58],
      ["Continuity", 34],
    ] as const,
  },
  canary: {
    tab: "Canary",
    eyebrow: "1% REVIEWED COHORT",
    action: "THROTTLE",
    computed: "THROTTLE",
    copy: "Only the signed endpoint and stable cohort receive the bounded response.",
    scores: [
      ["Automation", 89],
      ["Abuse intent", 81],
      ["Continuity", 21],
    ] as const,
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
  const configuredContact = import.meta.env.VITE_CONTACT_URL?.trim();
  const contactUrl = configuredContact || githubUrl;

  return (
    <div className="site-shell">
      <header className="site-header">
        <a className="brand" href="#top" aria-label="Palisade home">
          <img src={logoUrl} alt="PALISADE" />
        </a>
        <nav aria-label="Primary navigation">
          <a href="#platform">Platform</a>
          <a href="#deployment">Deployment</a>
          <a href="#trust">Trust</a>
          <a className="nav-cta" href="#contact">Private pilot</a>
        </nav>
      </header>

      <main id="top">
        <section className="hero-section">
          <div className="hero-copy">
            <p className="eyebrow"><span /> ADAPTIVE BOT DEFENSE, UNDER YOUR CONTROL</p>
            <h1>Stop abusive automation <em>without guessing who is human.</em></h1>
            <p className="hero-lede">
              Palisade gives security and platform teams an explainable path from private shadow measurement to reviewed, reversible protection.
            </p>
            <div className="hero-actions">
              <a className="button primary" href="#deployment">Choose a deployment</a>
              <a className="button secondary" href={githubUrl}>View open source <span aria-hidden="true">↗</span></a>
            </div>
            <ul className="trust-list" aria-label="Core guarantees">
              <li>Shadow-first</li>
              <li>Explainable decisions</li>
              <li>No cross-site identity graph</li>
            </ul>
          </div>

          <div className="decision-demo" aria-label="Illustrative Palisade decision">
            <div className="demo-head">
              <div>
                <p>Decision preview</p>
                <span>Illustrative, not customer data</span>
              </div>
              <div className="scenario-tabs" role="group" aria-label="Decision stage">
                {(Object.keys(scenarios) as Scenario[]).map((key) => (
                  <button key={key} className={scenario === key ? "active" : ""} aria-pressed={scenario === key} onClick={() => setScenario(key)}>
                    {scenarios[key].tab}
                  </button>
                ))}
              </div>
            </div>
            <div className="demo-body">
              <p className="demo-eyebrow">{sample.eyebrow}</p>
              <div className="verdict-line">
                <strong>{sample.action}</strong>
                <span>computed {sample.computed}</span>
              </div>
              <p className="demo-copy">{sample.copy}</p>
              <div className="score-list">
                {sample.scores.map(([label, value]) => <Score key={label} label={label} value={value} />)}
              </div>
            </div>
            <div className="demo-foot"><span className="live-dot" /> reviewed policy · versioned model · bounded evidence</div>
          </div>
        </section>

        <section className="principles" aria-label="Product principles">
          <p>Built for teams protecting</p>
          <div><span>Public content</span><span>APIs</span><span>Sign-up flows</span><span>High-value actions</span></div>
        </section>

        <section className="section platform-section" id="platform">
          <div className="section-heading">
            <p className="eyebrow">ONE CONTROL LOOP</p>
            <h2>Protection that earns the right to enforce.</h2>
            <p>Palisade does not turn a single browser trait into a block. It combines bounded evidence, preserves uncertainty and requires an operator-reviewed promotion path.</p>
          </div>
          <div className="stage-grid">
            {stages.map((stage) => (
              <article key={stage.number}>
                <span>{stage.number}</span>
                <h3>{stage.name}</h3>
                <p>{stage.copy}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="section dimension-section">
          <div className="dimension-copy">
            <p className="eyebrow light">THREE QUESTIONS, KEPT SEPARATE</p>
            <h2>Automation is not the same as abuse.</h2>
            <p>Useful bots, assistive technology and scripted clients exist. Palisade evaluates behavior in context instead of treating automation as a verdict.</p>
          </div>
          <div className="dimension-grid">
            <article><b>A</b><div><h3>Automation risk</h3><p>Is this client likely automated?</p></div></article>
            <article><b>I</b><div><h3>Abuse intent</h3><p>Is this action likely harmful?</p></div></article>
            <article><b>C</b><div><h3>Continuity</h3><p>Does this session match its established behavior?</p></div></article>
          </div>
        </section>

        <section className="section deployment-section" id="deployment">
          <div className="section-heading compact">
            <p className="eyebrow">DEPLOYMENT PATHS</p>
            <h2>Own the stack, share the work, or let us operate it.</h2>
            <p>Every path uses the same transparent core. Services and hosting add operations, integration and review — they do not remove the open-source rights already granted.</p>
          </div>
          <div className="product-grid">
            {productPaths.map((product) => (
              <article key={product.name} className={product.featured ? "featured" : ""}>
                <div className="product-top">
                  <h3>{product.name}</h3>
                  <span>{product.status}</span>
                </div>
                <p>{product.summary}</p>
                <ul>{product.items.map((item) => <li key={item}>{item}</li>)}</ul>
                <a href={product.href}>{product.action} <span aria-hidden="true">→</span></a>
              </article>
            ))}
          </div>
          <p className="availability-note"><strong>Current product boundary:</strong> Core is runnable today. Pilot and Managed are limited design-partner offers; production SLAs, multi-region shared state, SSO and billing are not represented as generally available.</p>
        </section>

        <section className="section trust-section" id="trust">
          <div className="section-heading compact">
            <p className="eyebrow">SECURITY BY BOUNDARY</p>
            <h2>Your protection system should not become another data leak.</h2>
          </div>
          <div className="trust-grid">
            <article><span>01</span><h3>Private measurement</h3><p>Encrypted, append-only shadow records stay in the deployment boundary with explicit rotation and retention.</p></article>
            <article><span>02</span><h3>Closed inputs</h3><p>The decision API accepts normalized bounded signals, not URLs, bodies, cookies or arbitrary upstream payloads.</p></article>
            <article><span>03</span><h3>Controlled rollout</h3><p>Risky live actions require an expiring signed plan, endpoint scope, stable cohort and a documented rollback.</p></article>
            <article><span>04</span><h3>Auditable reasons</h3><p>Every decision carries stable reason codes plus policy and model versions for deterministic replay.</p></article>
          </div>
        </section>

        <section className="section proof-section">
          <div>
            <p className="eyebrow light">WHAT THE PILOT DELIVERS</p>
            <h2>A decision you can defend — including the decision not to block.</h2>
          </div>
          <ul>
            <li><span>Baseline</span><strong>Endpoint-level shadow coverage and unknown-label rate</strong></li>
            <li><span>Evidence</span><strong>Aggregate score, outcome and reason-code analysis</strong></li>
            <li><span>Recommendation</span><strong>Hold, instrument further, or nominate a bounded canary</strong></li>
            <li><span>Operations</span><strong>Signed rollout scope, expiry, support path and rollback command</strong></li>
          </ul>
        </section>

        <section className="section faq-section">
          <div className="section-heading compact">
            <p className="eyebrow">STRAIGHT ANSWERS</p>
            <h2>Before you put Palisade in the request path.</h2>
          </div>
          <div className="faq-grid">
            <details><summary>Does Palisade promise perfect bot detection?</summary><p>No. Adaptive attackers and real browser automation make perfect separation an unsafe claim. Palisade measures uncertainty and stages enforcement.</p></details>
            <details><summary>Do you need our raw traffic logs?</summary><p>No for normal operation. Palisade consumes normalized signals and keeps optional encrypted measurement inside the deployment boundary. Historical imports are local-only.</p></details>
            <details><summary>Is managed hosting multi-tenant?</summary><p>Not in the initial offer. Managed deployments are dedicated and single-tenant so runtime, keys and retention remain isolated while the shared-state architecture matures.</p></details>
            <details><summary>Can we self-host without buying a service?</summary><p>Yes. The core is AGPL-3.0-only and the browser sensor is Apache-2.0. Commercial support, managed hosting and alternative licensing are separate offers.</p></details>
          </div>
        </section>

        <section className="contact-section" id="contact">
          <div>
            <p className="eyebrow light">PRIVATE DESIGN-PARTNER PILOT</p>
            <h2>Start with evidence, not a blocklist.</h2>
            <p>We will map one protected flow, define the signal boundary and establish a shadow baseline before discussing enforcement.</p>
          </div>
          <div className="contact-action">
            <a className="button contact-button" href={contactUrl}>{configuredContact ? "Request a private pilot" : "Follow the project"} <span aria-hidden="true">↗</span></a>
            <small>{configuredContact ? "Private contact channel" : "A private contact URL will be added before public launch."}</small>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <div><img src={logoUrl} alt="PALISADE" /><p>Adaptive bot defense, built together.</p></div>
        <div className="footer-links"><a href={githubUrl}>GitHub</a><a href={`${githubUrl}/blob/main/SECURITY.md`}>Security</a><a href={`${githubUrl}/blob/main/LICENSING.md`}>Licensing</a></div>
        <p className="legal">Core AGPL-3.0-only · Sensor Apache-2.0 · No tracking on this site</p>
      </footer>
    </div>
  );
}

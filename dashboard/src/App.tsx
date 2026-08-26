import { useEffect, useMemo, useState } from "react";

type Health = "checking" | "ready" | "offline";
type Mode = "traffic" | "attack";

const samples = {
  traffic: {
    action: "ALLOW",
    automation: 18,
    intent: 9,
    continuity: 91,
    reasons: ["browser_events_consistent", "sequence_stable", "no_external_alert"],
  },
  attack: {
    action: "BLOCK",
    automation: 97,
    intent: 94,
    continuity: 22,
    reasons: ["browser_claim_contradiction", "honeypot_hit", "anubis_bot", "crowdsec_alert"],
  },
} as const;

function ScoreCard({ label, value, inverse = false }: { label: string; value: number; inverse?: boolean }) {
  const risk = inverse ? 100 - value : value;
  const tone = risk >= 75 ? "danger" : risk >= 45 ? "warn" : "safe";
  return (
    <article className={`score-card ${tone}`}>
      <div className="score-heading"><span>{label}</span><strong>{value}</strong></div>
      <div className="meter" aria-label={`${label}: ${value} percent`}><i style={{ width: `${value}%` }} /></div>
      <small>{tone === "safe" ? "within baseline" : tone === "warn" ? "review signal" : "strong signal"}</small>
    </article>
  );
}

export function App() {
  const [health, setHealth] = useState<Health>("checking");
  const [mode, setMode] = useState<Mode>("attack");
  const sample = samples[mode];
  const now = useMemo(() => new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date()), [mode]);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/health/ready", { signal: controller.signal })
      .then((response) => setHealth(response.ok ? "ready" : "offline"))
      .catch(() => setHealth("offline"));
    return () => controller.abort();
  }, []);

  return (
    <main>
      <header>
        <img src="/palisade-horizontal.svg" alt="PALISADE" />
        <nav>
          <span className={`health ${health}`}><i /> {health}</span>
          <a href="https://github.com/palisade-bot-defense/palisade">GitHub</a>
        </nav>
      </header>

      <section className="hero">
        <div>
          <p className="eyebrow">BEHAVIOR-FIRST BOT DEFENSE</p>
          <h1>Decide from behavior.<br /><em>In minutes, not weeks.</em></h1>
          <p className="lede">A privacy-limited control plane that combines automation, intent and continuity — with deterministic evidence behind every action.</p>
        </div>
        <div className="mode-switch" role="group" aria-label="Demo traffic">
          <button className={mode === "traffic" ? "active" : ""} onClick={() => setMode("traffic")}>Human path</button>
          <button className={mode === "attack" ? "active" : ""} onClick={() => setMode("attack")}>Scraper attack</button>
        </div>
      </section>

      <section className="score-grid" aria-label="Decision scores">
        <ScoreCard label="Automation risk" value={sample.automation} />
        <ScoreCard label="Abuse intent" value={sample.intent} />
        <ScoreCard label="Account continuity" value={sample.continuity} inverse />
      </section>

      <section className="decision-panel">
        <div className="verdict">
          <p>Latest decision</p>
          <strong className={sample.action.toLowerCase()}>{sample.action}</strong>
          <span>{now} · shadow policy v0.1</span>
        </div>
        <div className="evidence">
          <div className="panel-title"><h2>Evidence trail</h2><span>{sample.reasons.length} signals</span></div>
          <ol>{sample.reasons.map((reason, index) => <li key={reason}><b>{String(index + 1).padStart(2, "0")}</b><code>{reason}</code></li>)}</ol>
        </div>
      </section>

      <footer><span>PALISADE v0.1.0</span><span>No raw pointer coordinates. No keystrokes. No DOM text.</span></footer>
    </main>
  );
}

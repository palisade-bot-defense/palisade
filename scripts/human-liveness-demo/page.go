package main

// demoPage is the operator-facing walkthrough. It is deliberately plain: every
// option is a real button, reachable by keyboard, announced by a screen reader,
// with no pointer movement, timing capture or animation required to answer.
const demoPage = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PALISADE liveness demo</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.6 system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  .note { border-left: 3px solid #888; padding-left: .8rem; color: #666; font-size: .9rem; }
  button { font: inherit; padding: .6rem 1rem; margin: .25rem .25rem .25rem 0; cursor: pointer; }
  button.option { font-family: ui-monospace, monospace; }
  pre { background: #8881; padding: .8rem; overflow-x: auto; font-size: .82rem; }
  .verdict { font-weight: 600; padding: .6rem .8rem; margin: 1rem 0; border-left: 4px solid #888; }
  .ok { border-color: #178a4c; }
  .withheld { border-color: #b8860b; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .8rem; }
  dt { font-weight: 600; }
  dd { margin: 0; font-family: ui-monospace, monospace; font-size: .9rem; }
</style>

<h1>PALISADE liveness demo</h1>

<p class="note">
  Loopback only, synthetic keys. This shows the path works with a real person in
  it. It is <strong>not</strong> a measurement: one person is not a cohort, and
  no false-positive interval comes out of this.
</p>

<h2>1. Assertion without liveness</h2>
<button id="plain">Request an assertion</button>
<div id="plain-out"></div>

<h2>2. Complete the liveness challenge</h2>
<p>Pick the option the prompt names. Answer at your own pace — there is a floor
of 120&nbsp;ms and a window of 20&nbsp;s per round; both are deliberate.</p>
<button id="start">Start the challenge</button>
<div id="challenge"></div>

<h2>3. Assertion with liveness</h2>
<div id="live-out"></div>

<script type="module">
const SESSION = "demo-session-" + Math.random().toString(36).slice(2, 10);
const body = { session_id: SESSION, action: "login", endpoint_class: "login", sequence: 1, observations: {} };
let attestation = null, challengeId = null, round = 0;

const key = await (await fetch("/public-key")).json();

async function assertion(headers) {
  const response = await fetch("/v1/assurance", {
    method: "POST",
    headers: { "content-type": "application/json", "X-Palisade-Assurance-Audience": key.audience, ...headers },
    body: JSON.stringify(body),
  });
  return response.json();
}

function render(target, document_, label) {
  const payload = document_.payload;
  const withheld = payload.reason_codes.includes("level_withheld_pending_measurement");
  const live = payload.reason_codes.includes("interactive_liveness_completed");
  target.innerHTML =
    '<div class="verdict ' + (withheld ? "withheld" : "ok") + '">' +
      "Level " + payload.assurance_level +
      (withheld ? " — computed higher, withheld pending measurement" : "") +
    "</div>" +
    "<dl>" +
      "<dt>evidence</dt><dd>" + (payload.assurance_sources.join(", ") || "(none)") + "</dd>" +
      "<dt>liveness</dt><dd>" + (live ? "completed" : "not completed") + "</dd>" +
      "<dt>profile</dt><dd>" + payload.binding.profile + "</dd>" +
      "<dt>audience</dt><dd>" + payload.binding.audience + "</dd>" +
      "<dt>session commitment</dt><dd>" + payload.binding.session_binding.slice(0, 16) + "…</dd>" +
    "</dl>" +
    "<p>reason codes: <code>" + payload.reason_codes.join("</code>, <code>") + "</code></p>" +
    "<details><summary>" + label + " — full document</summary><pre>" +
      JSON.stringify(document_, null, 2).replace(/</g, "&lt;") + "</pre></details>";
}

document.getElementById("plain").onclick = async () => {
  render(document.getElementById("plain-out"), await assertion({}), "without liveness");
};

function showPrompt(prompt) {
  const host = document.getElementById("challenge");
  host.innerHTML = "<p><strong>Round " + (prompt.round + 1) + ".</strong> " + prompt.instruction + "</p>";
  for (const option of prompt.options) {
    const button = document.createElement("button");
    button.className = "option";
    button.textContent = option;
    button.onclick = () => answer(option);
    host.appendChild(button);
  }
  const hint = document.createElement("p");
  hint.className = "note";
  hint.textContent = "The instruction names the option. A script reading this page answers as well as you do — " +
    "what the challenge shows is that someone stayed attached and answered each round in order, inside its window.";
  host.appendChild(hint);
}

document.getElementById("start").onclick = async () => {
  round = 0;
  const response = await fetch("/v1/assurance/liveness", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_id: SESSION, action: "login", endpoint_class: "login" }),
  });
  const begun = await response.json();
  challengeId = begun.challenge_id;
  showPrompt(begun.prompt);
};

async function answer(option) {
  const response = await fetch("/v1/assurance/liveness/answer", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ challenge_id: challengeId, session_id: SESSION, round, answer: option }),
  });
  if (!response.ok) {
    document.getElementById("challenge").innerHTML =
      '<p class="verdict">The attempt ended. The server does not say why — a wrong answer, one faster than the ' +
      "reaction floor and one past the deadline all look the same, so an attacker cannot learn which " +
      "constraint to tune. Start again.</p>";
    return;
  }
  const progress = await response.json();
  if (progress.completed) {
    attestation = progress.attestation;
    document.getElementById("challenge").innerHTML = '<p class="verdict ok">Challenge completed.</p>';
    render(document.getElementById("live-out"),
      await assertion({ "X-Palisade-Device-Attestation": "", "X-Palisade-Liveness-Attestation": attestation }),
      "with liveness");
    return;
  }
  round = progress.next.round;
  showPrompt(progress.next);
}
</script>
`

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
  table { border-collapse: collapse; width: 100%; font-size: .88rem; margin-top: .5rem; }
  th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #8883; }
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

<h2>4. Device credential (real WebAuthn)</h2>
<p>Registers a passkey with your platform authenticator — Touch ID on a Mac —
then answers a PALISADE challenge with it. The registration is the deployment's
job, not PALISADE's; this page does it so there is something to verify against.</p>
<button id="register">Register a passkey</button>
<button id="ceremony" disabled>Answer a device challenge</button>
<div id="device-out"></div>

<h2>5. All three surfaces</h2>
<p>The same evidence, bound three different ways.</p>
<button id="surfaces">Mint a request, a message and a call assertion</button>
<div id="surfaces-out"></div>

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

// --- helpers shared by the surface demos -------------------------------
const b64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));

async function post(path, body, headers) {
  const response = await fetch(path, {
    method: "POST", headers: { "content-type": "application/json", ...(headers || {}) },
    body: JSON.stringify(body),
  });
  return { ok: response.ok, status: response.status, json: await response.json().catch(() => null) };
}

let credentialId = null, deviceAttestation = null;

document.getElementById("register").onclick = async () => {
  const out = document.getElementById("device-out");
  try {
    const created = await navigator.credentials.create({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "PALISADE demo", id: "localhost" },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "demo", displayName: "demo" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { userVerification: "preferred" },
      attestation: "none",
      timeout: 60000,
    }});
    // The public key as a raw uncompressed P-256 point, which is what the
    // verifier expects. getPublicKey() gives SPKI; the last 65 bytes are the point.
    const spki = new Uint8Array(created.response.getPublicKey());
    credentialId = b64(created.rawId);
    const registered = await post("/demo/register", {
      credential_id: credentialId, public_key: b64(spki.slice(-65)), algorithm: "es256",
    });
    out.innerHTML = registered.ok
      ? '<p class="verdict ok">Passkey registered. PALISADE did not create it — your deployment would.</p>'
      : '<p class="verdict">Registration failed: ' + JSON.stringify(registered.json) + "</p>";
    document.getElementById("ceremony").disabled = !registered.ok;
  } catch (error) {
    out.innerHTML = '<p class="verdict">WebAuthn refused: ' + error.message +
      ". A platform authenticator and a secure context are needed; this page must be on http://localhost:8099.</p>";
  }
};

document.getElementById("ceremony").onclick = async () => {
  const out = document.getElementById("device-out");
  const issued = await post("/v1/assurance/device/challenge",
    { session_id: SESSION, action: "login", endpoint_class: "login" });
  if (!issued.ok) { out.innerHTML = "<p>challenge failed</p>"; return; }
  try {
    const got = await navigator.credentials.get({ publicKey: {
      challenge: unb64(issued.json.challenge),
      rpId: issued.json.relying_party_id,
      allowCredentials: [{ type: "public-key", id: unb64(credentialId) }],
      userVerification: "preferred",
      timeout: 60000,
    }});
    const completed = await post("/v1/assurance/device/complete", {
      challenge_id: issued.json.challenge_id, session_id: SESSION, credential_id: credentialId,
      authenticator_data: b64(got.response.authenticatorData),
      client_data_json: b64(got.response.clientDataJSON),
      signature: b64(got.response.signature),
    });
    if (!completed.ok) {
      out.innerHTML = '<p class="verdict">The ceremony failed. The server does not say which constraint — ' +
        "unknown credential, wrong signature, untouched authenticator and a stale counter all look the same.</p>";
      return;
    }
    deviceAttestation = completed.json.attestation;
    const headers = { "X-Palisade-Device-Attestation": deviceAttestation };
    if (attestation) headers["X-Palisade-Liveness-Attestation"] = attestation;
    out.innerHTML = '<p class="verdict ok">Device ceremony completed.</p>';
    const withDevice = await assertion(headers);
    const holder = document.createElement("div");
    out.appendChild(holder);
    render(holder, withDevice, attestation ? "with liveness and device" : "with device only");
    if (!attestation) {
      const note = document.createElement("p");
      note.className = "note";
      note.textContent = "A device credential alone carries no level: possession of hardware is not presence of a " +
        "person. Complete the liveness challenge above, then run this again to see the level computed and withheld.";
      out.appendChild(note);
    }
  } catch (error) {
    out.innerHTML = '<p class="verdict">WebAuthn refused: ' + error.message + "</p>";
  }
};

document.getElementById("surfaces").onclick = async () => {
  const out = document.getElementById("surfaces-out");
  const message = new TextEncoder().encode("the message that was actually sent");
  const commitment = b64(await crypto.subtle.digest("SHA-256", message));
  const headers = { "X-Palisade-Assurance-Audience": key.audience };
  if (attestation) headers["X-Palisade-Liveness-Attestation"] = attestation;

  const request = await post("/v1/assurance", body, headers);
  const content = await post("/v1/assurance/content", { ...body, content_commitment: commitment }, headers);
  const channel = await post("/v1/assurance/channel", { ...body, channel_id: "demo-call-0001" }, headers);

  const row = (label, result, extra) => {
    const b = result.json.payload.binding;
    return "<tr><td>" + label + "</td><td><code>" + b.profile + "</code></td><td>" +
      (b.request_action ? "action " + b.request_action : "") +
      (b.content_commitment ? "commitment " + b.content_commitment.slice(0, 12) + "…" : "") +
      (b.channel_binding ? "channel " + b.channel_binding.slice(0, 10) + "… interval " + b.interval_index : "") +
      "</td><td>" + result.json.payload.expires_at + "</td><td>" + (extra || "") + "</td></tr>";
  };
  out.innerHTML = "<table><tr><th>surface</th><th>profile</th><th>bound to</th><th>expires</th><th></th></tr>" +
    row("transaction", request) +
    row("message", content, "PALISADE never saw the message") +
    row("call", channel, "one per interval") +
    "</table><p class=\"note\">Same evidence, three bindings. The message assertion is valid for a day; the " +
    "call assertion for two minutes, because presence must be re-established rather than assumed.</p>";
};

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

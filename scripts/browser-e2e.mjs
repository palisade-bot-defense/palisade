#!/usr/bin/env node

import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import os from "node:os";
import path from "node:path";

const timeoutMs = 20_000;
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function assert(condition, message) {
	if (!condition) throw new Error(message);
}

async function executable(file) {
	try {
		await access(file, fsConstants.X_OK);
		return true;
	} catch {
		return false;
	}
}

async function browserBinary() {
	const candidates = [
		process.env.PALISADE_BROWSER_BIN,
		process.platform === "darwin" ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "",
		process.platform === "linux" ? "/usr/bin/google-chrome" : "",
		process.platform === "linux" ? "/usr/bin/chromium" : "",
	].filter(Boolean);
	for (const candidate of candidates) {
		if (await executable(candidate)) return candidate;
	}
	throw new Error("Chrome/Chromium not found; set PALISADE_BROWSER_BIN to an executable browser path");
}

function waitForLine(child, label) {
	return new Promise((resolve, reject) => {
		const stream = child.stdout;
		let buffer = "";
		const finish = (callback, value) => {
			clearTimeout(timer);
			child.off("error", failed);
			child.off("exit", exited);
			stream.off("error", failed);
			stream.off("data", received);
			callback(value);
		};
		const failed = (error) => finish(reject, new Error(`${label} failed to start: ${error.message}`));
		const exited = (code, signal) => finish(reject, new Error(`${label} exited before becoming ready (${code ?? signal})`));
		const received = (chunk) => {
			buffer += chunk;
			const newline = buffer.indexOf("\n");
			if (newline !== -1) finish(resolve, buffer.slice(0, newline));
		};
		const timer = setTimeout(() => finish(reject, new Error(`${label} did not become ready`)), timeoutMs);
		stream.setEncoding("utf8");
		child.once("error", failed);
		child.once("exit", exited);
		stream.once("error", failed);
		stream.on("data", received);
	});
}

async function waitForFile(file) {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		try {
			return await readFile(file, "utf8");
		} catch {
			await sleep(50);
		}
	}
	throw new Error(`timed out waiting for ${file}`);
}

async function stopChild(child) {
	if (!child || child.exitCode !== null || child.signalCode !== null) return;
	const exited = new Promise((resolve) => child.once("exit", resolve));
	child.kill("SIGTERM");
	await Promise.race([exited, sleep(2_000)]);
	if (child.exitCode === null && child.signalCode === null) {
		child.kill("SIGKILL");
		await Promise.race([exited, sleep(2_000)]);
	}
}

class CDP {
	constructor(url) {
		this.url = url;
		this.nextID = 1;
		this.pending = new Map();
		this.listeners = new Map();
	}

	async connect() {
		this.socket = new WebSocket(this.url);
		await new Promise((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("DevTools WebSocket did not open")), timeoutMs);
			this.socket.addEventListener("open", () => {
				clearTimeout(timer);
				resolve();
			}, { once: true });
			this.socket.addEventListener("error", reject, { once: true });
		});
		this.socket.addEventListener("message", (event) => {
			const message = JSON.parse(event.data);
			if (message.id) {
				const pending = this.pending.get(message.id);
				if (!pending) return;
				this.pending.delete(message.id);
				clearTimeout(pending.timer);
				if (message.error) pending.reject(new Error(`${pending.method}: ${message.error.message}`));
				else pending.resolve(message.result ?? {});
				return;
			}
			for (const listener of this.listeners.get(message.method) ?? []) listener(message.params ?? {});
		});
		this.socket.addEventListener("close", () => {
			for (const pending of this.pending.values()) {
				clearTimeout(pending.timer);
				pending.reject(new Error(`DevTools connection closed during ${pending.method}`));
			}
			this.pending.clear();
		});
	}

	on(method, listener) {
		const listeners = this.listeners.get(method) ?? [];
		listeners.push(listener);
		this.listeners.set(method, listeners);
	}

	send(method, params = {}) {
		const id = this.nextID++;
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(new Error(`DevTools command timed out: ${method}`));
			}, timeoutMs);
			this.pending.set(id, { method, resolve, reject, timer });
			try {
				this.socket.send(JSON.stringify({ id, method, params }));
			} catch (error) {
				clearTimeout(timer);
				this.pending.delete(id);
				reject(error);
			}
		});
	}

	close() {
		this.socket?.close();
	}
}

async function evaluate(cdp, expression) {
	const result = await cdp.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
	if (result.exceptionDetails) throw new Error(`browser evaluation failed: ${result.exceptionDetails.text}`);
	return result.result?.value;
}

async function waitForExpression(cdp, expression, description) {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (await evaluate(cdp, `Boolean(${expression})`)) return;
		await sleep(50);
	}
	throw new Error(`timed out waiting for ${description}`);
}

async function navigate(cdp, url, expression, description) {
	await cdp.send("Page.navigate", { url });
	await waitForExpression(cdp, expression, description);
}

function lowerHeaders(headers) {
	return Object.fromEntries(Object.entries(headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]));
}

async function main() {
	assert(Number(process.versions.node.split(".")[0]) >= 24, "browser E2E requires Node.js 24 or newer");
	const chromePath = await browserBinary();
	const profile = await mkdtemp(path.join(os.tmpdir(), "palisade-browser-e2e-"));
	let fixture;
	let chrome;
	let cdp;
	let fixtureError = "";
	let chromeError = "";
	try {
		const fixtureCommand = process.env.PALISADE_FIXTURE_BIN || "go";
		const fixtureArguments = process.env.PALISADE_FIXTURE_BIN ? [] : ["run", "./scripts/browser-e2e-fixture"];
		fixture = spawn(fixtureCommand, fixtureArguments, { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
		fixture.stderr.on("data", (chunk) => { fixtureError = (fixtureError + chunk).slice(-8192); });
		const startup = JSON.parse(await waitForLine(fixture, "browser fixture"));
		const origin = new URL(startup.origin);
		assert(origin.protocol === "http:" && origin.hostname === "localhost" && origin.username === "" && origin.password === "", "fixture must bind only to loopback localhost");

		chrome = spawn(chromePath, [
			"--headless=new",
			"--remote-debugging-address=127.0.0.1",
			"--remote-debugging-port=0",
			`--user-data-dir=${profile}`,
			`--unsafely-treat-insecure-origin-as-secure=${origin.origin}`,
			"--disable-background-networking",
			"--disable-component-extensions-with-background-pages",
			"--disable-component-update",
			"--disable-default-apps",
			"--disable-features=AutofillServerCommunication,CertificateTransparencyComponentUpdater,MediaRouter,OptimizationHints",
			"--disable-sync",
			"--metrics-recording-only",
			"--no-default-browser-check",
			"--no-first-run",
			"--password-store=basic",
			`--proxy-server=http://127.0.0.1:9`,
			"--proxy-bypass-list=localhost;127.0.0.1",
			"--use-mock-keychain",
			"about:blank",
		], { stdio: ["ignore", "ignore", "pipe"] });
		chrome.stderr.on("data", (chunk) => { chromeError = (chromeError + chunk).slice(-8192); });
		const chromeFailure = new Promise((_, reject) => {
			chrome.once("error", (error) => reject(new Error(`Chrome failed to start: ${error.message}`)));
			chrome.once("exit", (code, signal) => reject(new Error(`Chrome exited before DevTools became ready (${code ?? signal})`)));
		});
		const devtoolsContents = await Promise.race([waitForFile(path.join(profile, "DevToolsActivePort")), chromeFailure]);
		const devtools = devtoolsContents.trim().split("\n");
		assert(devtools.length >= 2 && /^\d+$/.test(devtools[0]), "invalid DevToolsActivePort contract");
		const targetResponse = await fetch(`http://127.0.0.1:${devtools[0]}/json/new?${encodeURIComponent("about:blank")}`, { method: "PUT" });
		assert(targetResponse.ok, `create DevTools target failed with HTTP ${targetResponse.status}`);
		const target = await targetResponse.json();
		cdp = new CDP(target.webSocketDebuggerUrl);
		await cdp.connect();
		await Promise.all([cdp.send("Page.enable"), cdp.send("Runtime.enable"), cdp.send("Network.enable")]);

		const requests = [];
		const responses = [];
		cdp.on("Network.requestWillBeSent", ({ request }) => requests.push(request.url));
		cdp.on("Network.responseReceived", ({ response }) => responses.push({ url: response.url, status: response.status, headers: lowerHeaders(response.headers) }));

		await navigate(cdp, `${origin.origin}/protected`, `document.title === "Request verification"`, "initial challenge page");
		await waitForExpression(cdp, `document.querySelector("#palisade-status")?.textContent === "Verification is ready."`, "ready challenge");
		const challengeDOM = await evaluate(cdp, `(() => {
			const root = document.querySelector("#palisade-challenge");
			const status = document.querySelector("#palisade-status");
			const proceed = document.querySelector("#palisade-continue");
			const fallback = document.querySelector("#palisade-fallback");
			return {
				language: document.documentElement.lang,
				labelledBy: root?.getAttribute("aria-labelledby"),
				describedBy: root?.getAttribute("aria-describedby"),
				statusRole: status?.getAttribute("role"),
				statusLive: status?.getAttribute("aria-live"),
				proceedEnabled: proceed?.disabled === false,
				fallbackVisible: Boolean(fallback && fallback.getClientRects().length),
				hiddenFields: [...document.querySelectorAll("input")].map((input) => [input.type, input.name]),
			};
		})()`);
		assert(challengeDOM.language === "en", "challenge document must declare its language");
		assert(challengeDOM.labelledBy === "palisade-title" && challengeDOM.describedBy === "palisade-description", "challenge accessible name/description binding is missing");
		assert(challengeDOM.statusRole === "status" && challengeDOM.statusLive === "polite", "challenge status must be announced politely");
		assert(challengeDOM.proceedEnabled && challengeDOM.fallbackVisible, "primary and fallback paths must both be available");
		assert(JSON.stringify(challengeDOM.hiddenFields) === JSON.stringify([["hidden", "challenge_id"]]), "challenge page exposed unexpected form fields");

		const initialResponse = responses.find((response) => response.url === `${origin.origin}/protected` && response.status === 403);
		assert(initialResponse, "browser did not receive the challenged origin response");
		assert(initialResponse.headers["content-security-policy"]?.includes("default-src 'none'"), "challenge CSP is missing or open");
		assert(initialResponse.headers["x-frame-options"] === "DENY", "challenge framing protection is missing");
		assert(initialResponse.headers["cache-control"] === "no-store", "challenge response must not be cached");

		const cookies = (await cdp.send("Network.getAllCookies")).cookies;
		for (const [name, sameSite] of [["__Host-palisade_session", "Lax"], ["__Host-palisade_pending", "Strict"]]) {
			const cookie = cookies.find((candidate) => candidate.name === name);
			assert(cookie?.secure && cookie?.httpOnly && cookie.path === "/" && cookie.sameSite === sameSite && !cookie.domain.startsWith("."), `${name} lost its host-only Secure/HttpOnly/SameSite contract`);
		}

		await evaluate(cdp, `document.querySelector("#palisade-continue").click()`);
		await waitForExpression(cdp, `document.title === "Protected route" && document.body.textContent.includes("Protected content reached")`, "redeemed protected route");
		assert(responses.some((response) => response.url === `${origin.origin}/protected` && response.status === 200 && response.headers["x-palisade-adapter"] === "redeemed"), "one-time redeemed retry did not reach the protected route");
		const afterRedemption = (await cdp.send("Network.getAllCookies")).cookies;
		assert(!afterRedemption.some((cookie) => cookie.name === "__Host-palisade_redemption" || cookie.name === "__Host-palisade_pending"), "one-time or pending cookie remained after the redeemed retry");

		await navigate(cdp, `${origin.origin}/protected`, `document.title === "Request verification"`, "second challenge after one-time grant");
		await waitForExpression(cdp, `document.querySelector("#palisade-status")?.textContent === "Verification is ready."`, "second ready challenge");
		await evaluate(cdp, `document.querySelector("#palisade-fallback").click()`);
		await waitForExpression(cdp, `location.pathname === "/fallback" && document.body.textContent.includes("Alternative method available")`, "accessible fallback route");

		const stateURL = new URL("/__fixture/state", origin);
		assert(stateURL.hostname === "localhost", "state request escaped loopback");
		const stateResponse = await fetch(stateURL);
		assert(stateResponse.ok, "fixture state endpoint unavailable");
		const state = await stateResponse.json();
		assert(state.session_issues === 1, `session issuance count = ${state.session_issues}, want 1`);
		assert(state.token_issues === 2 && state.origin_checks === 2, `one-time grant counts token/origin = ${state.token_issues}/${state.origin_checks}, want 2/2`);
		assert(state.metadata_gets >= 2 && state.verifications === 1 && state.redemptions === 1, "challenge lifecycle counts are incomplete");
		assert(state.fallbacks === 1 && state.protected_hits === 1, "fallback or protected retry count is incorrect");

		const external = requests.filter((value) => {
			try {
				const url = new URL(value);
				return (url.protocol === "http:" || url.protocol === "https:") && url.hostname !== "localhost" && url.hostname !== "127.0.0.1";
			} catch {
				return false;
			}
		});
		assert(external.length === 0, `browser attempted external requests: ${external.join(", ")}`);
		console.log("browser-e2e: passed real Chrome challenge, one-time redemption, fallback, cookie, CSP and loopback-egress contracts");
	} catch (error) {
		if (fixtureError) console.error(`fixture stderr:\n${fixtureError}`);
		if (chromeError) console.error(`chrome stderr:\n${chromeError}`);
		throw error;
	} finally {
		cdp?.close();
		await stopChild(chrome);
		await stopChild(fixture);
		await rm(profile, { recursive: true, force: true });
	}
}

main().catch((error) => {
	console.error(`browser-e2e: ${error.message}`);
	process.exitCode = 1;
});

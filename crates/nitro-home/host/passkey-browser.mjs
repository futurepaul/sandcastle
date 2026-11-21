// A headless Chrome with a virtual passkey authenticator, for proving a
// home's sign-in end to end (docs/nitro-home.md, "Acceptance"): the real
// WebAuthn protocol against the real door, with a software key.
//
//   node passkey-browser.mjs <chrome> <cdp port> <control port> <profile dir>
//
// It starts Chrome (its own profile, headless, DevTools on loopback alone),
// opens one tab, gives it a CTAP2 authenticator with user verification
// (Chrome's CDP WebAuthn domain), and holds that session for its life, so
// the passkeys it makes live as long as it runs. Plans of steps are posted
// to its control port (loopback):
//
//   curl -s localhost:<control>/plan -d '[{"go":"https://…"},{"click":"button"}]'
//
// Steps: go (a URL), wait (a CSS selector), fill ([selector, text]), click
// (a selector), waitUrl (a regex), text (a selector: its text back), shot
// ([file, width, height]: a PNG of the page),
// eval (an expression: its value back), sleep (ms), credentials (each
// device's), addAuthenticator (another device), removeAuthenticator (the
// oldest device, lost with its passkeys). Each answers with what
// it saw; the first failure stops the plan. Another tool (agent-browser
// --cdp <port>) may drive the same Chrome meanwhile: its cookies are this
// profile's.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { writeFileSync } from "node:fs";

const [chrome, cdpPort, controlPort, profile] = process.argv.slice(2);
const proc = spawn(chrome, [
  "--headless=new", `--remote-debugging-port=${cdpPort}`, "--remote-debugging-address=127.0.0.1",
  `--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });
proc.on("exit", (code) => { console.log(JSON.stringify({ chrome: "exited", code })); process.exit(1); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function version() {
  for (let i = 0; i < 100; i++) {
    try { return await (await fetch(`http://127.0.0.1:${cdpPort}/json/version`)).json(); } catch { await sleep(100); }
  }
  throw new Error("Chrome's DevTools never answered");
}
const { webSocketDebuggerUrl } = await version();
const ws = new WebSocket(webSocketDebuggerUrl);
await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
let next = 1;
const waiting = new Map();
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiting.has(msg.id)) {
    const { resolve, reject } = waiting.get(msg.id);
    waiting.delete(msg.id);
    msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
  }
};
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = next++;
  waiting.set(id, { resolve, reject });
  ws.send(JSON.stringify({ id, method, params, sessionId }));
});

const { targetInfos } = await send("Target.getTargets");
const page = targetInfos.find((t) => t.type === "page");
const { sessionId } = await send("Target.attachToTarget", { targetId: page.targetId, flatten: true });
const s = (method, params) => send(method, params, sessionId);
await s("Page.enable");
await s("Runtime.enable");
await s("WebAuthn.enable", { enableUI: false });
// the first a platform authenticator, each later one a security key (Chrome
// holds one internal authenticator a tab)
const authenticator = async (transport) => (await s("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport, hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
})).authenticatorId;
// the authenticators this tab holds, oldest first (a device each)
const authenticators = [await authenticator("internal")];

async function evaluate(expression) {
  const r = await s("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  return r.result.value;
}
async function until(what, test, ms = 30000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { const v = await test(); if (v) return v; } catch {}
    await sleep(100);
  }
  throw new Error(`timed out: ${what}`);
}
const q = (sel) => JSON.stringify(sel);
async function step(st) {
  if (st.go) { await s("Page.navigate", { url: st.go }); await sleep(300); return { at: await evaluate("location.href") }; }
  if (st.wait) return { found: await until(st.wait, () => evaluate(`!!document.querySelector(${q(st.wait)})`)) };
  if (st.fill) {
    const [sel, text] = st.fill;
    await until(sel, () => evaluate(`!!document.querySelector(${q(sel)})`));
    await evaluate(`(() => { const e = document.querySelector(${q(sel)}); e.focus(); e.value = ${q(text)}; e.dispatchEvent(new Event("input", { bubbles: true })); return true })()`);
    return { filled: sel };
  }
  if (st.click) {
    await until(st.click, () => evaluate(`!!document.querySelector(${q(st.click)})`));
    await evaluate(`document.querySelector(${q(st.click)}).click()`);
    return { clicked: st.click };
  }
  if (st.waitUrl) return { at: await until(st.waitUrl, async () => { const u = await evaluate("location.href"); return new RegExp(st.waitUrl).test(u) && u; }, st.ms || 30000) };
  if (st.text) return { text: await until(st.text, () => evaluate(`document.querySelector(${q(st.text)})?.innerText`)) };
  if (st.eval !== undefined) return { value: await evaluate(st.eval) };
  if (st.sleep) { await sleep(st.sleep); return { slept: st.sleep }; }
  // a screenshot of the page to a file (PNG), at a width of its own
  if (st.shot) {
    const [path, width, height] = st.shot;
    await s("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: width < 600 });
    await sleep(500);
    const { data } = await s("Page.captureScreenshot", { format: "png" });
    writeFileSync(path, Buffer.from(data, "base64"));
    return { shot: path };
  }
  if (st.credentials) {
    const out = [];
    for (const authenticatorId of authenticators) {
      const { credentials } = await s("WebAuthn.getCredentials", { authenticatorId });
      out.push(credentials.map((c) => ({ rpId: c.rpId, signCount: c.signCount })));
    }
    return { credentials: out };
  }
  // another device; or the oldest one gone (its passkeys lost with it)
  if (st.addAuthenticator) { authenticators.push(await authenticator("usb")); return { authenticators: authenticators.length }; }
  if (st.removeAuthenticator) { await s("WebAuthn.removeVirtualAuthenticator", { authenticatorId: authenticators.shift() }); return { authenticators: authenticators.length }; }
  throw new Error(`no such step: ${JSON.stringify(st)}`);
}

createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) body += chunk;
  const out = [];
  try {
    for (const st of JSON.parse(body)) {
      const t0 = Date.now();
      out.push({ ...(await step(st)), ms: Date.now() - t0 });
    }
    res.end(JSON.stringify({ ok: true, steps: out }));
  } catch (e) {
    let at = "";
    try { at = await evaluate("location.href"); } catch {}
    res.end(JSON.stringify({ ok: false, error: e.message, at, steps: out }));
  }
}).listen(Number(controlPort), "127.0.0.1", () => console.log(JSON.stringify({ ready: true, cdp: Number(cdpPort), control: Number(controlPort) })));

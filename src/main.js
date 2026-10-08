/* apiwatch: the HTTP APIs this machine serves and calls, and a Slack
 * alert when one of them breaks.
 *
 *   --discover   watch live traffic for a while, then list every API seen
 *   --watch      keep watching; post to Slack when an API returns 5xx or
 *                its port stops listening (run it as a yeet service)
 *   --test-alert post one message, to prove the Slack path works
 *
 * Capture is lib/capture.js, the API registry lib/apis.js, the alert
 * rules lib/alerts.js. This file is arguments, output and the loop.
 */

import { startCapture, SELF_COMMS } from "./lib/capture.js";
import { Apis } from "./lib/apis.js";
import { Alerts } from "./lib/alerts.js";
import { describe, known } from "./lib/procs.js";
import { MODES as BODY_MODES, sampleMrkdwn, sampleOf } from "./lib/bodies.js";
import { decodeContentEncoding } from "yeet:compression";

const HELP = `apiwatch: the HTTP APIs this machine serves and calls, and a Slack alert when one breaks.

List the APIs (watches live traffic, then prints what it saw):
  yeet run github:yeet-src/apiwatch -- --discover [--seconds 30] [--json]

Alert when one breaks (run as a yeet service so it outlives your shell):
  yeet run github:yeet-src/apiwatch -- --watch --slack "#channel" [--name web-1]
      --window 60       seconds of history each check looks at
      --min-errors 1    5xx responses within the window that count as broken
      --client-errors baseline
                        4xx alerts: baseline (when an API's 4xx share jumps far above
                        its own normal, learned over its first 5 min), all, or off
      --client-codes 401,403,429
                        count only these 4xx statuses (default: every 4xx)
      --min-client-errors 5
                        4xx answers within the window before a jump can fire
      --bodies redacted the failing request and response in each alert: redacted
                        (secret fields, tokens and card numbers blanked), raw, or off
      --recover 120     seconds without a 5xx before an API counts as recovered
      --remind 1800     seconds between "still broken" reminders
      --down-after 5    seconds a served port must be gone before it counts as down
      --ignore a,b      APIs not to alert on, by name, host or port (e.g. httpbin.org,8082)
      --ports 80,8081   capture only these ports; watch them for going down from the start
      --dry-run         print alerts as JSON lines instead of posting them

Check that Slack delivery works:
  yeet run github:yeet-src/apiwatch -- --test-alert --slack "#channel" [--name web-1]

Posting needs this host signed in (yeet login) and a Slack workspace connected
at https://yeet.cx/settings. Reads plaintext HTTP/1.x and h2c on any port, and
HTTPS from programs using OpenSSL (dynamic libssl, node, deno, bun) or rustls.
Go's crypto/tls and other TLS stacks are named from the handshake but not read.`;

const argv = yeet.args ?? {};
const arg = (name, fallback) => argv[name] ?? argv[name.replace(/-/g, "_")] ?? fallback;
const num = (name, fallback) => {
  const v = Number(arg(name, fallback));
  return Number.isFinite(v) && v >= 0 ? v : fallback;
};
const portsArg = String(arg("ports", "") || "")
  .split(",")
  .map((p) => Number(p.trim()))
  .filter((p) => p > 0 && p < 65536);
const host = String(arg("name", "") || "this host");
const channel = arg("slack", null);
const json = Boolean(arg("json", false));
const bodies = String(arg("bodies", "redacted"));
const clientErrors = String(arg("client-errors", "baseline"));
const clientCodes = new Set(
  String(arg("client-codes", "") || "")
    .split(",")
    .map((c) => Number(c.trim()))
    .filter((c) => c >= 400 && c < 500),
);

const out = (line) => console.log(line);
const jlog = (obj) => console.log(JSON.stringify({ t: new Date().toISOString(), ...obj }));

const name = (pid) => known(pid)?.label ?? `pid ${pid}`;

async function postSlack(message) {
  return yeet.alert({ method: "slack", channel, text: message.text, blocks: message.blocks });
}

const describeError = (e) => (e && typeof e === "object" ? e.message ?? e.code ?? JSON.stringify(e) : String(e));

/* ---------------------------------------------------------------- */

async function testAlert() {
  if (!channel) throw new Error('--test-alert needs --slack "#channel"');
  const who = await yeet.whoami().catch(() => null);
  if (!who) throw new Error("this host is not signed in to yeet; run `yeet login` first, then connect Slack at https://yeet.cx/settings");
  const title = `apiwatch on ${host} can post here`;
  const body = `This channel will get a message when an API on *${host}* returns 5xx responses or stops listening, and another when it recovers.`;
  try {
    await postSlack({
      text: `${title}. ${body.replace(/\*/g, "")}`,
      blocks: [
        { type: "header", text: { type: "plain_text", text: title } },
        { type: "section", text: { type: "mrkdwn", text: body } },
      ],
    });
  } catch (e) {
    throw new Error(`Slack rejected the test message: ${describeError(e)}`);
  }
  out(`sent a test message to ${channel}`);
}

/* ---------------------------------------------------------------- */

async function boot() {
  const errors = [];
  let apis = null;
  const capture = await startCapture({
    base: import.meta.dirname,
    ports: portsArg,
    /* Enough of each body that a compressed one can be decoded whole; an
     * alert shows at most about 1000 characters of it. */
    bodyLimit: 16_384,
    onPid: (pid) => {
      if (!known(pid)) describe(pid);
    },
    onTransaction: (tx) => apis.observe(tx),
    onError: (e) => {
      if (errors.length < 50) errors.push(describeError(e));
    },
  });
  const callerOf = (addr, port) => {
    const row = capture.rows().find((r) => r.lport === port && r.laddr === addr && r.pid != null);
    if (row && !known(row.pid)) describe(row.pid);
    return row?.pid ?? null;
  };
  apis = new Apis({ name, info: known, isLocal: capture.isLocal, listeners: capture.listeners, callerOf, clientCodes });
  return { capture, apis, errors };
}

const isSelf = (pid) => SELF_COMMS.has(known(pid)?.comm);

/* ---------------------------------------------------------------- */

async function discover() {
  const seconds = num("seconds", 30);
  const { capture, apis, errors } = await boot();
  if (!json) out(`apiwatch: watching this machine's HTTP traffic for ${seconds}s…`);
  await new Promise((r) => setTimeout(r, seconds * 1000));

  const listeners = capture.listeners();
  const unreadable = capture.unreadableTls();
  await Promise.all([...apis.pids(), ...[...listeners.values()].map((l) => l.pid), ...unreadable.map((u) => u.pid)].map((p) => describe(p)));

  const rows = [...apis.byKey.values()].filter((a) => ![...a.procs].every(isSelf) || a.procs.size === 0).map((a) => apis.row(a));
  const served = rows.filter((r) => r.kind === "served").sort((a, b) => a.port - b.port);
  const called = rows.filter((r) => r.kind === "called").sort((a, b) => b.requests - a.requests);
  const localOnly = (addr) => /^(127\.|::1$|0:0:0:0:0:0:0:1$)/.test(addr ?? "");
  for (const r of served) {
    const l = listeners.get(r.port);
    r.address = l?.laddr ?? null;
    r.reachableFrom = l ? (localOnly(l.laddr) ? "this machine only" : "the network") : null;
  }
  const servedPorts = new Set(served.map((r) => r.port));
  const quiet = [...listeners.values()]
    .filter((l) => !servedPorts.has(l.port) && !isSelf(l.pid))
    .sort((a, b) => a.port - b.port)
    .map((l) => ({ port: l.port, address: l.laddr, process: name(l.pid), reachableFrom: localOnly(l.laddr) ? "this machine only" : "the network" }));
  const calledHosts = new Set(called.map((c) => c.host));
  const opaqueBy = new Map();
  for (const u of unreadable) {
    if (isSelf(u.pid) || calledHosts.has(u.sni)) continue;
    const k = `${u.sni}|${name(u.pid)}`;
    const o = opaqueBy.get(k) ?? { host: u.sni, process: name(u.pid), address: `${u.daddr}:${u.dport}`, connections: 0 };
    o.connections += u.flows;
    opaqueBy.set(k, o);
  }
  const opaque = [...opaqueBy.values()];
  const tls = capture.tlsStatus();

  await capture.stop();

  if (json) {
    out(JSON.stringify({ seconds, transactions: apis.transactions, served, called, unreadable: opaque, quiet, tls, errors: errors.slice(0, 5) }));
    return;
  }

  const codes = (s) =>
    Object.entries(s)
      .sort((a, b) => b[1] - a[1])
      .map(([c, n]) => `${c} ×${n}`)
      .join(", ") || "no responses";
  const eps = (r) =>
    r.endpoints
      .slice(0, 4)
      .map((e) => `${e.method} ${e.path} ×${e.n}`)
      .join(" · ");

  out(`\nSaw ${apis.transactions} HTTP exchanges in ${seconds}s: ${served.length} served API${served.length === 1 ? "" : "s"}, ${called.length} called.\n`);
  out("Served by this machine");
  if (!served.length) out("  (none seen)");
  for (const r of served) {
    out(`  ${r.name}  port ${r.port}${r.address ? ` on ${r.address} (${r.reachableFrom})` : ""}  ${r.requests} requests  ${codes(r.statuses)}`);
    if (r.endpoints.length) out(`      ${eps(r)}`);
    if (r.callers.length) out(`      called by ${r.callers.join(", ")}`);
  }
  out("\nCalled by this machine");
  if (!called.length) out("  (none seen)");
  for (const r of called) {
    out(`  ${r.name}  ${r.transport}  ${r.requests} calls  ${codes(r.statuses)}  from ${r.process}`);
    if (r.endpoints.length) out(`      ${eps(r)}`);
  }
  if (opaque.length) {
    out("\nCalled, named from the TLS handshake but not readable (status codes unknown)");
    for (const u of opaque) out(`  ${u.host}  from ${u.process}  ${u.connections} connection${u.connections === 1 ? "" : "s"}`);
  }
  if (quiet.length) {
    out("\nListening, but no HTTP seen in the window");
    for (const q of quiet) out(`  port ${q.port} on ${q.address} (${q.reachableFrom})  ${q.process}`);
  }
  out(`\nTLS read through: ${tls.filter((t) => t.state === "attached").map((t) => `${t.path} [${t.taps.join(",")}]`).join("; ") || "nothing"}`);
  if (errors.length) out(`Capture errors (${errors.length}): ${errors.slice(0, 3).join(" | ")}`);
}

/* ---------------------------------------------------------------- */

async function watch() {
  const dryRun = Boolean(arg("dry-run", false));
  if (!channel && !dryRun) throw new Error('--watch needs --slack "#channel" (or --dry-run)');
  if (!BODY_MODES.includes(bodies)) throw new Error(`--bodies must be one of ${BODY_MODES.join(", ")}, not "${bodies}"`);
  if (!["baseline", "all", "off"].includes(clientErrors)) throw new Error(`--client-errors must be baseline, all or off, not "${clientErrors}"`);
  const window = num("window", 60);
  const { capture, apis, errors } = await boot();

  /* Messages that land within BATCH_MS of each other go out as one: an
   * upstream that dies takes its proxy and its callers down with it, and
   * that is one incident, not four pings. */
  const BATCH_MS = 6000;
  const queue = [];
  let sending = false;
  const pump = async () => {
    if (sending) return;
    sending = true;
    while (queue.length) {
      await new Promise((r) => setTimeout(r, BATCH_MS));
      const batch = queue.splice(0, queue.length).map((q) => q.render());
      const m = batch.length === 1 ? batch[0] : combine(batch);
      if (dryRun) jlog({ event: "alert", dryRun: true, title: m.title, preview: preview(m) });
      else {
        try {
          await postSlack(m);
          jlog({ event: "sent", title: m.title, channel, messages: batch.length });
        } catch (e) {
          jlog({ event: "send_failed", title: m.title, channel, error: describeError(e) });
        }
      }
    }
    sending = false;
  };
  /* The message as Slack will show it, minus the formatting. */
  const preview = (m) =>
    m.blocks
      .map((b) => b.text?.text ?? b.elements?.map((e) => e.text).join(" ") ?? (b.type === "divider" ? "---" : ""))
      .filter(Boolean)
      .join("\n");
  const combine = (batch) => {
    const broken = batch.filter((m) => /^(failing|down|reminder)/.test(m.event)).length;
    const title = broken === batch.length
      ? `${batch.length} APIs broke on ${host}`
      : broken === 0 ? `${batch.length} APIs recovered on ${host}` : `${batch.length} API changes on ${host}`;
    const blocks = [{ type: "header", text: { type: "plain_text", text: title } }];
    for (const m of batch.slice(0, 12)) {
      blocks.push({ type: "section", text: { type: "mrkdwn", text: `*${m.title}*\n${m.blocks[1].text.text}` } });
      if (m.detail) blocks.push(m.blocks[2]);
      blocks.push({ type: "divider" });
    }
    blocks.pop();
    blocks.push(batch[0].blocks[2]);
    return { title, text: `${title}: ${batch.map((m) => m.title).join("; ")}`, blocks };
  };

  const alerts = new Alerts({
    apis,
    listeners: capture.listeners,
    host,
    window,
    minErrors: Math.max(1, num("min-errors", 1)),
    recover: Math.max(window, num("recover", 120)),
    remind: num("remind", 1800),
    downAfter: num("down-after", 5),
    ports: portsArg,
    ignore: String(arg("ignore", "") || "").split(",").map((x) => x.trim()).filter(Boolean),
    clientErrors,
    minClient: Math.max(1, num("min-client-errors", 5)),
    sample: (api, cls) => {
      const tx = api.lastTx?.[cls];
      if (!tx) return null;
      const label = bodies === "off" ? "Latest failing request (bodies off)" : `Latest failing request${bodies === "redacted" ? " (secrets redacted)" : ""}`;
      return sampleMrkdwn(sampleOf(tx, { mode: bodies, inflate: decodeContentEncoding }), label);
    },
    log: jlog,
    send: (m) => {
      if (queue.length < 50) queue.push(m);
      pump();
    },
  });

  const who = dryRun ? null : await yeet.whoami().catch(() => null);
  jlog({ event: "start", host, channel, dryRun, signedIn: dryRun ? null : Boolean(who), ports: portsArg, window });
  if (!dryRun && !who) jlog({ event: "warning", message: "this host is not signed in; alerts will fail until `yeet login` succeeds" });

  setInterval(() => {
    for (const pid of apis.pids()) if (!known(pid)) describe(pid);
    alerts.check();
  }, 1000);

  /* What is being watched, 20 s and 60 s after start and then every ten
   * minutes, so whoever attaches to the service log (which shows only
   * what is printed after they attach) sees that capture is alive and
   * whether alerts can be delivered. */
  const status = async () => {
    await Promise.all([...apis.pids()].map((p) => describe(p)));
    const list = apis.list().filter((r) => r.requests > 0);
    const signedIn = dryRun ? null : Boolean(await yeet.whoami().catch(() => null));
    jlog({
      event: "status",
      host,
      channel,
      dryRun,
      signedIn,
      bodies,
      clientErrors,
      transactions: apis.transactions,
      apis: list.map((r) => ({ kind: r.kind, name: r.name, port: r.port, requests: r.requests, errors5xx: r.errors5xx })),
      tls: capture.tlsStatus().filter((t) => t.state === "attached").map((t) => t.path),
      captureErrors: errors.length,
    });
  };
  setTimeout(status, 20_000);
  setTimeout(status, 60_000);
  setInterval(status, 600_000);
}

/* ---------------------------------------------------------------- */

let failure = null;
try {
  if (arg("help", false) || argv.h) out(HELP);
  else if (arg("test-alert", false)) await testAlert();
  else if (arg("watch", false)) await watch();
  else await discover();
} catch (e) {
  failure = e;
}
if (failure) {
  console.error(`apiwatch: ${describeError(failure)}`);
  /* An uncaught throw is what gives the shell a non-zero exit. */
  throw failure;
}
if (!arg("watch", false)) yeet.exit(0);

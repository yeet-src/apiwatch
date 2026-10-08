/* Transactions → the APIs this machine serves and calls.
 *
 *   served   an HTTP server on this box, keyed by its listening port. Its
 *            numbers come from the server's side of each exchange.
 *   called   an HTTP API somewhere else, keyed by the Host the caller
 *            asked for (or ip:port when there was none).
 *
 * A call from one process on the box to another (nginx → orders-api on
 * 127.0.0.1:8081) is seen twice, once from each end. It is counted once,
 * on the served API, and the client end only adds the caller's name — so
 * a 502 from orders-api is one error, not two.
 *
 * Pure apart from the injected `name(pid)` and `isLocal(addr)`.
 */

import { parseTarget, templateOf } from "./path.js";

const MAX_ENDPOINTS = 40;
const MAX_RECENT = 8;
const MAX_CALLERS = 256;
const RING = 4096; // 5xx timestamps kept per API for the sliding window

/* Request and 4xx counts in 10-second buckets, about 32 minutes of them:
 * enough to learn what share of an API's answers are normally 4xx, which
 * a ring of timestamps cannot hold for a busy API. */
export const BUCKET_MS = 10_000;
const BUCKETS = 192;

const hostOnly = (h) => {
  const s = String(h ?? "").trim().toLowerCase();
  if (s.startsWith("[")) return s.slice(1, s.indexOf("]"));
  return s.replace(/:\d+$/, "");
};
const unique = (xs) => [...new Set(xs)];

/* The port a called API listens on: written in the Host header, else the
 * socket's remote port for plaintext, else the scheme's default. A TLS
 * tap's 4-tuple comes from a correlation and is not trusted for this. */
const calledPort = (tx) => {
  const m = /:(\d+)$/.exec(String(tx.host ?? "").replace(/^\[[^\]]*\]/, ""));
  if (m) return Number(m[1]);
  if (tx.transport === 0 && tx.flow?.dport) return tx.flow.dport;
  return tx.transport === 1 ? 443 : 80;
};
const addCaller = (api, c) => {
  if (api.callers.has(c)) return;
  if (api.callers.size >= MAX_CALLERS) api.callers.delete(api.callers.values().next().value);
  api.callers.add(c);
};
const isIpLiteral = (h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(":");

export class Apis {
  constructor({ name = (pid) => `pid ${pid}`, info = null, isLocal = () => false, listeners = () => new Map(), callerOf = null, clientCodes = null } = {}) {
    this.name = name;
    /* Which 4xx statuses count as client errors; null means all of them. */
    this.clientCodes = clientCodes && clientCodes.size ? clientCodes : null;
    this.info = info;
    this.callerOf = callerOf;
    this.isLocal = isLocal;
    this.listeners = listeners;
    this.byKey = new Map();
    this.startedAt = Date.now();
    this.transactions = 0;
  }

  get(key) {
    return this.byKey.get(key) ?? null;
  }

  ensure(key, init) {
    let api = this.byKey.get(key);
    if (!api) {
      api = {
        key,
        n: 0,
        statuses: {},
        noResponse: 0,
        endpoints: new Map(),
        procs: new Set(),
        callers: new Set(),
        hosts: new Set(),
        firstAt: Date.now(),
        lastAt: 0,
        errorTimes: [],
        reqTimes: [],
        recentErrors: [],
        recent4xx: [],
        buckets: [],
        lastTx: {},
        ...init,
      };
      this.byKey.set(key, api);
    }
    return api;
  }

  /** One decoded transaction. Returns `{ api, error }` when it was counted, else null. */
  observe(tx) {
    if (!tx.method && tx.status == null) return null;
    const flow = tx.flow ?? null;
    let api;

    if (tx.role === "server") {
      const port = flow?.sport ?? null;
      const key = `served:${port ?? tx.pid}`;
      api = this.ensure(key, { kind: "served", port, transport: tx.transport });
      api.procs.add(tx.pid);
      if (tx.host) api.hosts.add(tx.host);
      if (flow && this.isLocal(flow.daddr)) {
        const caller = this.callerAt(flow.daddr, flow.dport);
        if (caller != null) addCaller(api, caller);
      } else if (flow?.daddr) addCaller(api, "remote clients");
    } else if (tx.role === "client") {
      const dport = flow?.dport ?? null;
      if (flow && this.isLocal(flow.daddr) && this.listeners().has(dport)) {
        /* A hop to an API on this box: the server's side counts it. */
        const served = this.ensure(`served:${dport}`, { kind: "served", port: dport, transport: tx.transport });
        addCaller(served, tx.pid);
        return null;
      }
      const host = hostOnly(tx.host) || (flow ? `${flow.daddr}:${flow.dport}` : `pid ${tx.pid}`);
      api = this.ensure(`called:${host}`, { kind: "called", host, port: calledPort(tx), transport: tx.transport });
      api.procs.add(tx.pid);
      if (flow?.daddr && !isIpLiteral(host)) api.hosts.add(flow.daddr);
    } else return null;

    this.transactions++;
    api.n++;
    api.lastAt = Date.now();
    api.reqTimes.push(api.lastAt);
    if (api.reqTimes.length > RING) api.reqTimes.splice(0, api.reqTimes.length - RING);
    const status = tx.status;
    if (status == null) api.noResponse++;
    else api.statuses[status] = (api.statuses[status] ?? 0) + 1;

    const path = tx.target ? templateOf(parseTarget(tx.target).segments) : "?";
    const epKey = api.endpoints.size >= MAX_ENDPOINTS && !api.endpoints.has(`${tx.method} ${path}`) ? "(other endpoints)" : `${tx.method} ${path}`;
    const ep = api.endpoints.get(epKey) ?? { method: tx.method, path, n: 0, statuses: {} };
    if (epKey === "(other endpoints)") Object.assign(ep, { method: "*", path: "(other endpoints)" });
    ep.n++;
    if (status != null) ep.statuses[status] = (ep.statuses[status] ?? 0) + 1;
    api.endpoints.set(epKey, ep);

    const error = status != null && status >= 500;
    const clientError = status != null && status >= 400 && status < 500 && (!this.clientCodes || this.clientCodes.has(status));
    this.bucket(api, api.lastAt, clientError);
    if (error || clientError) {
      const cls = error ? "5xx" : "4xx";
      if (error) {
        api.errorTimes.push(api.lastAt);
        if (api.errorTimes.length > RING) api.errorTimes.splice(0, api.errorTimes.length - RING);
      }
      const recent = error ? api.recentErrors : api.recent4xx;
      recent.push({ at: api.lastAt, cls, method: tx.method, path, status, reason: tx.reason ?? null, pid: tx.pid });
      if (recent.length > MAX_RECENT) recent.shift();
      /* The whole exchange of the latest failure of each class, kept so an
       * alert can show its bodies. One per class, so at most two bodies
       * per API stay in memory. */
      api.lastTx[cls] = tx;
    }
    return { api, error, clientError };
  }

  bucket(api, at, clientError) {
    const t = at - (at % BUCKET_MS);
    let b = api.buckets[api.buckets.length - 1];
    if (!b || b.t !== t) {
      api.buckets.push((b = { t, req: 0, c4: 0 }));
      if (api.buckets.length > BUCKETS) api.buckets.shift();
    }
    b.req++;
    if (clientError) b.c4++;
  }

  /** Requests and 4xx answers in [from, to). */
  counts(api, from, to) {
    let req = 0;
    let c4 = 0;
    for (const b of api.buckets) {
      if (b.t < from || b.t >= to) continue;
      req += b.req;
      c4 += b.c4;
    }
    return { req, c4 };
  }

  /* The pid holding the client end of a loopback connection, from the
   * socket inventory (injected as `callerOf`). */
  callerAt(addr, port) {
    return this.callerOf?.(addr, port) ?? null;
  }

  /** Every pid this registry mentions, so a caller can name them all first. */
  pids() {
    const out = new Set();
    for (const a of this.byKey.values()) {
      for (const p of a.procs) out.add(p);
      for (const c of a.callers) if (typeof c === "number") out.add(c);
    }
    return out;
  }

  /** 5xx responses within the last `ms`. */
  errorsWithin(api, ms, now = Date.now()) {
    const cut = now - ms;
    let n = 0;
    for (let i = api.errorTimes.length - 1; i >= 0 && api.errorTimes[i] >= cut; i--) n++;
    return n;
  }

  /** Plain rows, for printing and JSON. */
  list() {
    return [...this.byKey.values()].map((a) => this.row(a));
  }

  row(a) {
    const errors = Object.entries(a.statuses).reduce((s, [code, n]) => s + (Number(code) >= 500 ? n : 0), 0);
    return {
      kind: a.kind,
      name: this.label(a),
      port: a.port ?? null,
      host: a.host ?? null,
      process: unique([...a.procs].map(this.name)).join(", ") || null,
      callers: this.callerNames(a),
      hosts: [...a.hosts].slice(0, 6),
      transport: a.transport === 1 ? "https" : "http",
      requests: a.n,
      statuses: a.statuses,
      errors5xx: errors,
      noResponse: a.noResponse,
      endpoints: [...a.endpoints.values()].sort((x, y) => y.n - x.n),
      recentErrors: a.recentErrors.map((e) => ({ ...e, process: this.name(e.pid) })),
      firstSeen: a.firstAt,
      lastSeen: a.lastAt,
    };
  }

  /* Callers by name. Processes that exited before they could be named
   * (a curl in a loop) are counted, not listed. */
  callerNames(a) {
    /* Fold every pid that has a name into the name set, so the bounded
     * pid set only ever holds the ones still unresolved. */
    a.callerNamed ??= new Set();
    a.callerGone ??= 0;
    let unnamed = 0;
    for (const c of [...a.callers]) {
      if (typeof c !== "number") {
        a.callerNamed.add(c);
        a.callers.delete(c);
        continue;
      }
      const info = this.info?.(c);
      if (info && !info.gone) {
        a.callerNamed.add(info.label);
        a.callers.delete(c);
      } else if (info?.gone) {
        a.callerGone++;
        a.callers.delete(c);
      } else unnamed++;
    }
    const out = [...a.callerNamed];
    const n = a.callerGone + unnamed;
    if (n) out.push(`${n} short-lived process${n === 1 ? "" : "es"} that exited before they could be named`);
    return out;
  }

  /** What a person calls this API. */
  label(a) {
    if (a.kind === "called") return a.host;
    const owner = [...a.procs][0];
    if (owner != null) return this.name(owner);
    const l = this.listeners().get(a.port);
    return l ? `${l.comm} :${a.port}` : `port ${a.port}`;
  }
}

/* Captured windows → HTTP/1 transactions.
 *
 * Every tap delivers the same dataRecord (app/lib/probes/records.js):
 * pid, an opaque connection id, a direction and some bytes. This module
 * keeps one entry per connection, works out which side the process is
 * on, runs a request parser on one direction and a response parser on
 * the other, and pairs them in order — HTTP/1 answers requests in the
 * order they were sent, pipelined or not. A finished pair is a
 * transaction, handed to `onTransaction`.
 *
 * What a connection turns out to carry is decided on its first bytes:
 * HTTP/1 in either direction, the HTTP/2 preface (then h2.js follows
 * the frames and streams), a TLS record (the socket tap seeing
 * ciphertext — the TLS tap carries the plaintext under another id), or
 * something else. The labels are kept so the layers above can say why a
 * connection shows no transactions.
 *
 * Records do not arrive in the order they were made: the loader hands
 * over a ring's records with the head of a response sometimes behind
 * its body, tens of microseconds apart. So each record waits in a
 * window sorted by kernel timestamp and is fed to the parsers only once
 * `reorderMs` of later timestamps have been seen — or, when the flow
 * stops, once `tick()` finds it has waited that long on the wall clock.
 *
 * Capture is lossy in a known way: a record says how long its call was
 * and how much of it was copied. The difference is a hole, and the
 * parser is told its size. A hole inside a body costs the bytes; a hole
 * across a head loses the framing, and the parser is restarted at the
 * next record boundary — the next call a client makes begins a request.
 *
 * Pure. The clock and the records are injected, so tests replay fixtures.
 */

import { DIR_READ, DIR_WRITE, TRANSPORT_TCP } from "../probes/records.js";
import { H1Parser, REQUEST, RESPONSE, header, looksLike } from "./h1.js";
import { H2Connection } from "./h2.js";
import { latin1 } from "./bytes.js";

const H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/* emit_data's segment size (CAP_MASK in bpf/include/events.h). A record
 * shorter than the segment it should fill is the last of its call: the
 * copy failed part-way and the program gave up on the rest. */
const SEG = 4095;

/* recvmsg flags on a TCP read record. A peek hands the same bytes out
 * again on the next read; a truncating read copies nothing. */
const MSG_PEEK = 0x02;
const MSG_TRUNC = 0x20;

/* How many record boundaries a connection gets to look like HTTP
 * before it is written off as something else. A keep-alive connection
 * we joined mid-response needs one or two. */
const SNIFF_TRIES = 8;

export const connKey = (r) => `${r.pid}:${r.transport}:${r.conn}`;

/* What a first window is. `dir` matters for HTTP/1: a request the
 * process wrote makes it the client. */
export function sniff(bytes, dir) {
  if (bytes.length === 0) return null;
  const head = latin1(bytes, 0, Math.min(bytes.length, H2_PREFACE.length));
  if (H2_PREFACE.startsWith(head)) return head.length === H2_PREFACE.length ? { proto: "h2", role: dir === DIR_WRITE ? "client" : "server" } : null;
  /* A TLS record: type 20–23 (change-cipher-spec, alert, handshake,
   * application data), then version 3.x. A flow joined mid-stream
   * shows application data, not a ClientHello. */
  if (bytes[0] >= 0x14 && bytes[0] <= 0x17 && bytes[1] === 0x03 && bytes[2] <= 0x04) return { proto: "tls" };
  const req = looksLike(REQUEST, bytes);
  if (req) return { proto: "http/1", role: dir === DIR_WRITE ? "client" : "server", kind: REQUEST };
  const res = looksLike(RESPONSE, bytes);
  if (res) return { proto: "http/1", role: dir === DIR_WRITE ? "server" : "client", kind: RESPONSE };
  if (req === null || res === null) return null;
  return { proto: "other" };
}

export class Decoder {
  /**
   *   onTransaction(tx)          a request and its response, or what
   *                              was seen of them when the connection
   *                              went away (`tx.complete` is false)
   *   onConnection(conn, event)  "open" | "label" | "close", for the
   *                              connection table
   *   bodyLimit                  bytes of body kept per message; the
   *                              rest is counted. 1 MiB: the model keeps
   *                              a schema and a short example, not the
   *                              body, so this is transient memory
   *   reorderMs                  how long a record waits for earlier
   *                              ones; 0 feeds records as they come
   *   now()                      wall clock, ms
   */
  constructor({ onTransaction, onConnection, bodyLimit = 1 << 20, reorderMs = 20, now = Date.now } = {}) {
    this.onTransaction = onTransaction;
    this.onConnection = onConnection;
    this.bodyLimit = bodyLimit;
    this.reorderMs = reorderMs;
    this.reorderNs = BigInt(Math.round(reorderMs * 1e6));
    this.now = now;
    this.conns = new Map();
    this.nextId = 1;
    this.hold = [];
    this.maxTs = 0n;
  }

  /** One dataRecord from any tap. */
  push(r) {
    if (r.transport === TRANSPORT_TCP && r.flags & (MSG_PEEK | MSG_TRUNC)) return;
    if (this.reorderNs === 0n) {
      this.ingest(r);
      return;
    }
    const hold = this.hold;
    let i = hold.length;
    while (i > 0 && hold[i - 1].r.ts > r.ts) i--;
    hold.splice(i, 0, { r, at: this.now() });
    if (r.ts > this.maxTs) this.maxTs = r.ts;
    this.release();
  }

  /** Call every `reorderMs` or so: feeds what has waited long enough. */
  tick() {
    const cutoff = this.now() - this.reorderMs;
    if (this.hold.some((e) => e.at <= cutoff)) this.drain();
    else this.release();
  }

  /* Records whose timestamp is `reorderMs` behind the newest seen. */
  release() {
    const cut = this.maxTs - this.reorderNs;
    while (this.hold.length && this.hold[0].r.ts <= cut) this.ingest(this.hold.shift().r);
  }

  /* Everything held, in timestamp order. */
  drain() {
    const held = this.hold;
    this.hold = [];
    for (const e of held) this.ingest(e.r);
  }

  /** A TLS connection's socket, from a peer_event. */
  peer(p) {
    const c = this.conns.get(`${p.pid}:1:${p.conn}`) ?? this.open({ pid: p.pid, transport: 1, conn: p.conn, ts: p.ts, family: 0 });
    c.flow = { family: p.family, saddr: p.saddr, sport: p.sport, daddr: p.daddr, dport: p.dport };
    c.sk = p.sk;
    this.onConnection?.(c, "label");
  }

  ingest(r) {
    const key = connKey(r);
    let c = this.conns.get(key);

    const flow = r.family ? { family: r.family, saddr: r.saddr, sport: r.sport, daddr: r.daddr, dport: r.dport } : null;
    /* A `struct sock` address comes back for a new socket once the old
     * one is freed; the 4-tuple says which this is. */
    if (c && flow && c.flow && !sameFlow(c.flow, flow)) {
      this.closeConn(c, "reused");
      c = null;
    }
    if (!c) {
      c = this.open(r);
      if (flow) c.flow = flow;
    } else if (flow && !c.flow) c.flow = flow;

    c.lastTs = r.ts;
    c.lastAt = this.now();
    c.bytes[r.dir] += r.capLen;
    c.records++;

    const d = c.dirs[r.dir];

    /* Segment accounting: a call arrives as up to MAX_SEGS records with
     * `off` and `len`; what was not copied is a hole. A new call (off 0)
     * closes out the previous one. */
    if (r.off === 0 || r.off < d.seen) {
      if (d.callLen > d.seen) this.gap(c, r.dir, d.callLen - d.seen);
      d.callLen = r.len;
      d.seen = 0;
      d.boundary = true;
    } else d.boundary = false;
    if (r.off > d.seen) this.gap(c, r.dir, r.off - d.seen);
    d.seen = r.off + r.capLen;

    this.feed(c, r.dir, r.data, r.ts, d.boundary);

    /* A short segment ends the call: what is left is a hole, known now
     * rather than when the next call shows up. A full call is closed
     * out the same way. */
    const wanted = Math.min(SEG, r.len - r.off);
    if (r.capLen < wanted && d.callLen > d.seen) {
      this.gap(c, r.dir, d.callLen - d.seen);
      d.seen = d.callLen;
    }
    if (d.seen >= d.callLen) {
      d.callLen = 0;
      d.seen = 0;
    }
  }

  open(r) {
    const c = {
      key: connKey(r),
      id: this.nextId++,
      pid: r.pid,
      transport: r.transport,
      conn: r.conn,
      flow: null,
      sk: null,
      proto: null, // "http/1" | "h2" | "tls" | "other"
      h2: null,
      role: null, // "client" | "server"
      note: null,
      firstTs: r.ts,
      lastTs: r.ts,
      openedAt: this.now(),
      lastAt: this.now(),
      bytes: { [DIR_READ]: 0, [DIR_WRITE]: 0 },
      records: 0,
      transactions: 0,
      sniffTries: 0,
      desyncing: false,
      dirs: {
        [DIR_READ]: { callLen: 0, seen: 0, boundary: true, parser: null, pending: [] },
        [DIR_WRITE]: { callLen: 0, seen: 0, boundary: true, parser: null, pending: [] },
      },
      /* Requests whose response has not finished, in order. */
      inflight: [],
    };
    this.conns.set(c.key, c);
    this.onConnection?.(c, "open");
    return c;
  }

  gap(c, dir, n) {
    if (c.h2) return c.h2.gap(dir, n);
    const p = c.dirs[dir].parser;
    if (p) p.gap(n);
  }

  feed(c, dir, bytes, ts, boundary) {
    const d = c.dirs[dir];
    if (c.proto === "http/1" && d.parser) {
      if (d.parser.state === "desync") {
        /* Waiting for a boundary to start over. Only a record that
         * begins a call can be a message start. */
        if (!boundary) return;
        d.parser.reset();
      }
      c.ts = ts;
      d.parser.push(bytes);
      return;
    }
    if (c.proto === "h2") {
      c.h2?.push(dir, bytes, ts);
      return;
    }
    if (c.proto === "tls" || c.proto === "other") return;

    /* Unlabelled: sniff at call boundaries. Bytes from a call whose
     * start we did not see cannot begin a message — unless the start
     * is waiting in `pending` for more of the same call. */
    if (!boundary && !d.pending.length) return;
    if (d.pending.length) {
      const joined = new Uint8Array(d.pending.reduce((n, b) => n + b.length, 0) + bytes.length);
      let o = 0;
      for (const b of d.pending) {
        joined.set(b, o);
        o += b.length;
      }
      joined.set(bytes, o);
      bytes = joined;
    }
    const verdict = sniff(bytes, dir);
    if (verdict === null) {
      /* Not enough bytes to say (a 1-byte send). Keep them for the
       * next segment of this call. */
      d.pending = [bytes];
      return;
    }
    d.pending = [];
    if (verdict.proto === "h2") {
      c.proto = "h2";
      c.role = verdict.role;
      c.h2 = new H2Connection({
        clientDir: verdict.role === "client" ? DIR_WRITE : DIR_READ,
        bodyLimit: this.bodyLimit,
        now: this.now,
        onTransaction: (t) => this.emit(c, { id: this.nextId++, req: t.req, res: t.res, interim: t.interim, stream: t.stream }, t.cut),
        onOpaque: (reason) => {
          c.proto = "other";
          c.note = `h2 lost: ${reason}`;
          this.onConnection?.(c, "label");
        },
      });
      this.onConnection?.(c, "label");
      c.h2.push(dir, bytes, ts);
      return;
    }
    if (verdict.proto !== "http/1") {
      c.sniffTries++;
      if (verdict.proto !== "other" || c.sniffTries >= SNIFF_TRIES) {
        c.proto = verdict.proto;
        c.role = verdict.role ?? null;
        this.onConnection?.(c, "label");
      }
      return;
    }
    this.label(c, verdict.role);
    c.ts = ts;
    c.dirs[dir].parser.push(bytes);
  }

  /* The process is `role` on this connection: build both parsers. */
  label(c, role) {
    c.proto = "http/1";
    c.role = role;
    const reqDir = role === "client" ? DIR_WRITE : DIR_READ;
    const resDir = role === "client" ? DIR_READ : DIR_WRITE;
    c.dirs[reqDir].parser = new H1Parser(REQUEST, {
      bodyLimit: this.bodyLimit,
      onHead: (msg) => this.onRequestHead(c, msg),
      onEnd: (msg) => this.onRequestEnd(c, msg),
      onDesync: (why) => this.onDesync(c, "request", why),
    });
    c.dirs[resDir].parser = new H1Parser(RESPONSE, {
      bodyLimit: this.bodyLimit,
      methodOf: () => c.inflight.find((t) => !t.res)?.req.method ?? null,
      onHead: (msg) => this.onResponseHead(c, msg),
      onEnd: (msg) => this.onResponseEnd(c, msg),
      onDesync: (why) => this.onDesync(c, "response", why),
      onOpaque: (msg) => this.onOpaque(c, msg),
    });
    this.onConnection?.(c, "label");
  }

  onRequestHead(c, msg) {
    msg.ts = c.ts;
    msg.at = this.now();
    const tx = { id: this.nextId++, req: msg, res: null, interim: [] };
    c.inflight.push(tx);
  }

  onRequestEnd(c, msg) {
    msg.tsEnd = c.ts;
    /* If the response already finished (a server that answers before the
     * body is in), the transaction was emitted with `req.complete`
     * provisional; nothing to redo. */
  }

  onResponseHead(c, msg) {
    msg.ts = c.ts;
    msg.at = this.now();
    let tx = c.inflight.find((t) => !t.res);
    if (!tx) {
      /* A response to a request we never saw (attached mid-exchange). */
      tx = { id: this.nextId++, req: null, res: null, interim: [], orphan: true };
      c.inflight.push(tx);
    }
    if (msg.status >= 100 && msg.status < 200 && msg.status !== 101) {
      tx.interim.push(msg.status);
      return;
    }
    tx.res = msg;
  }

  onResponseEnd(c, msg) {
    msg.tsEnd = c.ts;
    if (msg.status >= 100 && msg.status < 200 && msg.status !== 101) return;
    const i = c.inflight.findIndex((t) => t.res === msg);
    if (i < 0) return;
    const [tx] = c.inflight.splice(i, 1);
    this.emit(c, tx);
  }

  onDesync(c, side, why) {
    if (c.desyncing) return;
    c.desyncing = true;
    c.note = `${side} desync: ${why}`;
    /* Pairing is lost with the framing: flush what was in flight, then
     * stop the other side too — its message has no pair any more. Both
     * restart at their next call boundary. */
    for (const tx of c.inflight.splice(0)) this.emit(c, tx, "desync");
    for (const dir of [DIR_READ, DIR_WRITE]) {
      const p = c.dirs[dir].parser;
      if (p && p.state !== "desync") p.desync(`${side} side lost sync`);
    }
    c.desyncing = false;
  }

  onOpaque(c, msg) {
    c.proto = "other";
    c.note = msg ? `upgraded (${header(msg.headers, "upgrade") ?? msg.status})` : "tunnel";
    for (const dir of [DIR_READ, DIR_WRITE]) {
      const p = c.dirs[dir].parser;
      if (p && p.state !== "opaque") p.opaque();
    }
    this.onConnection?.(c, "label");
  }

  emit(c, tx, cut = null) {
    c.transactions++;
    const req = tx.req;
    const res = tx.res;
    const complete = Boolean(req?.complete && res?.complete && !cut);
    const out = {
      id: tx.id,
      key: c.key,
      pid: c.pid,
      transport: c.transport,
      conn: c.conn,
      flow: c.flow,
      role: c.role,
      proto: `HTTP/${(res ?? req)?.version ?? "1.1"}`,
      stream: tx.stream ?? null,
      method: req?.method ?? null,
      target: req?.target ?? null,
      host: req ? hostOf(req) : null,
      reqHeaders: req?.headers ?? [],
      reqBody: bodyOf(req),
      status: res?.status ?? null,
      reason: res?.reason ?? null,
      resHeaders: res?.headers ?? [],
      resBody: bodyOf(res),
      interim: tx.interim,
      ts: req?.ts ?? res?.ts ?? null,
      tsRes: res?.ts ?? null,
      tsEnd: res?.tsEnd ?? req?.tsEnd ?? null,
      at: req?.at ?? res?.at ?? this.now(),
      complete,
      cut: cut ?? res?.cut ?? req?.cut ?? (req && !res ? "no response" : null) ?? (res && !req ? "no request" : null),
    };
    out.durationNs = out.ts != null && out.tsEnd != null ? out.tsEnd - out.ts : null;
    this.onTransaction?.(out, c);
  }

  /** The connection went away (the inventory no longer lists it, or it idled out). */
  close(key, why = "closed") {
    this.drain();
    const c = this.conns.get(key);
    if (c) this.closeConn(c, why);
  }

  /* The connection is over. Called from ingest() too, so it must not
   * drain the window: the records held there would be fed out from
   * under the one being processed. */
  closeConn(c, why) {
    this.conns.delete(c.key);
    c.h2?.close(why);
    /* A response that runs to the close completes now and emits its
     * transaction; anything else in flight was cut. */
    for (const dir of [DIR_READ, DIR_WRITE]) c.dirs[dir].parser?.close();
    for (const tx of c.inflight.splice(0)) this.emit(c, tx, why);
    this.onConnection?.(c, "close");
  }

  /** Drop connections silent for `idleMs`. Returns how many. */
  sweep(idleMs = 120_000) {
    this.drain();
    const cutoff = this.now() - idleMs;
    let n = 0;
    for (const c of [...this.conns.values()]) {
      if (c.lastAt < cutoff) {
        this.closeConn(c, "idle");
        n++;
      }
    }
    return n;
  }

  /** A row per live connection, for the connection table. */
  connections() {
    return [...this.conns.values()].map((c) => ({
      key: c.key,
      pid: c.pid,
      transport: c.transport,
      conn: c.conn,
      flow: c.flow,
      proto: c.proto,
      role: c.role,
      note: c.note,
      bytesIn: c.bytes[DIR_READ],
      bytesOut: c.bytes[DIR_WRITE],
      transactions: c.transactions,
      inflight: c.inflight.length,
      openedAt: c.openedAt,
      lastAt: c.lastAt,
    }));
  }
}

const sameFlow = (a, b) => a.sport === b.sport && a.dport === b.dport && a.saddr === b.saddr && a.daddr === b.daddr;

/* The service a request names: the Host header, or the authority of an
 * absolute-form target (a proxy request). Port kept as written. */
export function hostOf(req) {
  const h = header(req.headers, "host");
  if (h) return h;
  const m = /^https?:\/\/([^/?#]+)/i.exec(req.target ?? "");
  if (m) return m[1];
  if (req.method === "CONNECT") return req.target;
  return null;
}

const bodyOf = (msg) =>
  msg?.body
    ? { len: msg.body.len, holes: msg.body.holes, truncated: msg.body.truncated, data: msg.body.data(), complete: msg.complete }
    : { len: 0, holes: 0, truncated: false, data: new Uint8Array(0), complete: Boolean(msg) };

export { TRANSPORT_TCP };

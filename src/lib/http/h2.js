/* HTTP/2 (RFC 7540) on one connection: frames → streams → transactions.
 *
 * Both directions are frame streams once the client's preface has gone
 * by. Each direction has its own HPACK decoder, fed every HEADERS,
 * CONTINUATION and PUSH_PROMISE block in order; SETTINGS from one side
 * size the decoder for blocks the other side sends. A stream's request
 * comes from the client direction, its response from the server's;
 * END_STREAM on both, or RST_STREAM, closes it and the transaction goes
 * out in the same shape the HTTP/1 decoder produces — `:method`,
 * `:path`, `:authority` and `:status` become method, target, a `host`
 * header and status, the rest of the pseudo-headers are dropped.
 *
 * Holes: a hole inside a DATA frame's payload costs the body those
 * bytes and nothing else. A hole anywhere else loses the frame boundary
 * and, worse, the HPACK state — after that nothing on the connection
 * can be trusted, so it is declared opaque and its open streams are
 * reported cut.
 *
 * Pure.
 */

import { BodyCapture, ByteQueue } from "./bytes.js";
import { HpackDecoder, HpackError } from "./hpack.js";

export const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const PREFACE_LEN = 24;

const DATA = 0;
const HEADERS = 1;
const PRIORITY = 2;
const RST_STREAM = 3;
const SETTINGS = 4;
const PUSH_PROMISE = 5;
const PING = 6;
const GOAWAY = 7;
const WINDOW_UPDATE = 8;
const CONTINUATION = 9;

const END_STREAM = 0x1;
const END_HEADERS = 0x4;
const PADDED = 0x8;
const HAS_PRIORITY = 0x20;

const SETTINGS_HEADER_TABLE_SIZE = 1;
const MAX_FRAME = 1 << 24;

const RST_NAMES = { 0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED" };

export class H2Connection {
  /**
   *   clientDir            the direction the client writes (its preface came on it)
   *   onTransaction(tx)    `{ req, res, interim, cut, stream }`, req/res message-like:
   *                        { method, target, version, headers, body, complete, ts, tsEnd, at }
   *   onOpaque(reason)     the connection can no longer be followed
   *   bodyLimit, now()
   */
  constructor({ clientDir, onTransaction, onOpaque, bodyLimit = 1 << 20, now = Date.now }) {
    this.clientDir = clientDir;
    this.serverDir = clientDir === 0 ? 1 : 0;
    this.onTransaction = onTransaction;
    this.onOpaque = onOpaque;
    this.bodyLimit = bodyLimit;
    this.now = now;
    this.dirs = {};
    for (const d of [0, 1]) {
      this.dirs[d] = {
        q: new ByteQueue(),
        preface: d === clientDir ? PREFACE_LEN : 0,
        frame: null, /* the header of the frame whose payload is being collected */
        skip: 0, /* payload bytes to drop after a hole */
        hpack: new HpackDecoder(4096),
        headerBlock: null, /* { stream, frameType, flags, promised, parts } while CONTINUATION is expected */
      };
    }
    this.streams = new Map();
    this.opaque = false;
    this.ts = 0n;
    this.frames = 0;
  }

  /** Bytes of direction `dir`, stamped `ts`. */
  push(dir, bytes, ts) {
    if (this.opaque) return;
    this.ts = ts;
    const d = this.dirs[dir];
    d.q.append(bytes);
    try {
      this.run(dir);
    } catch (e) {
      this.fail(e instanceof HpackError ? `hpack: ${e.message}` : `h2: ${e.message}`);
    }
  }

  /** `n` bytes of `dir` went by unseen. */
  gap(dir, n) {
    if (this.opaque || n <= 0) return;
    const d = this.dirs[dir];
    if (d.frame && d.frame.type === DATA) {
      /* Inside a DATA payload: what was buffered so far is body, the
       * hole is a hole, and the rest of the frame (if any) follows. */
      const have = d.q.length;
      const remaining = d.frame.length - have;
      if (n <= remaining) {
        const f = d.frame;
        this.dataPartial(dir, f, d.q.take(have), n);
        f.length = remaining - n; /* what is still to come of this frame */
        f.partial = true;
        if (f.length === 0) {
          /* The hole ran to the end of the frame: its flags still count. */
          d.frame = null;
          if (f.flags & END_STREAM) {
            const s = this.streams.get(f.stream);
            if (s) this.endStream(s, dir);
          }
        }
        return;
      }
    }
    this.fail(`hole of ${n} bytes across a frame boundary`);
  }

  /** The connection is over: open streams are cut. */
  close(why = "closed") {
    for (const s of [...this.streams.values()]) this.finish(s, why);
    this.streams.clear();
    this.opaque = true;
  }

  fail(reason) {
    if (this.opaque) return;
    for (const s of [...this.streams.values()]) this.finish(s, "desync");
    this.streams.clear();
    this.opaque = true;
    this.onOpaque?.(reason);
  }

  run(dir) {
    const d = this.dirs[dir];
    for (;;) {
      if (d.preface) {
        const k = d.q.skip(d.preface);
        d.preface -= k;
        if (d.preface) return;
      }
      if (!d.frame) {
        if (d.q.length < 9) return;
        const h = d.q.take(9);
        const length = (h[0] << 16) | (h[1] << 8) | h[2];
        if (length > MAX_FRAME) throw new Error(`frame of ${length} bytes`);
        d.frame = { type: h[3], flags: h[4], stream: ((h[5] & 0x7f) << 24) | (h[6] << 16) | (h[7] << 8) | h[8], length, partial: false };
        this.frames++;
      }
      const f = d.frame;
      if (d.q.length < f.length) return;
      const payload = d.q.take(f.length);
      d.frame = null;
      if (f.partial) {
        /* the tail of a DATA frame after a hole */
        this.dataPartial(dir, f, payload, 0, true);
        continue;
      }
      this.frame(dir, f, payload);
    }
  }

  frame(dir, f, payload) {
    const d = this.dirs[dir];
    if (d.headerBlock && f.type !== CONTINUATION) throw new Error("expected CONTINUATION");
    switch (f.type) {
      case DATA: {
        let data = payload;
        if (f.flags & PADDED) {
          const pad = data[0];
          data = data.subarray(1, data.length - pad);
        }
        const s = this.stream(f.stream, dir);
        const side = dir === this.clientDir ? s.req : s.res;
        side.body.add(data);
        if (f.flags & END_STREAM) this.endStream(s, dir);
        break;
      }
      case HEADERS: {
        let data = payload;
        let pad = 0;
        if (f.flags & PADDED) {
          pad = data[0];
          data = data.subarray(1);
        }
        if (f.flags & HAS_PRIORITY) data = data.subarray(5);
        if (pad) data = data.subarray(0, data.length - pad);
        this.headerFragment(dir, { stream: f.stream, endStream: (f.flags & END_STREAM) !== 0, promised: null }, data, (f.flags & END_HEADERS) !== 0);
        break;
      }
      case PUSH_PROMISE: {
        let data = payload;
        let pad = 0;
        if (f.flags & PADDED) {
          pad = data[0];
          data = data.subarray(1);
        }
        const promised = ((data[0] & 0x7f) << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        data = data.subarray(4, pad ? data.length - pad : data.length);
        this.headerFragment(dir, { stream: f.stream, endStream: false, promised }, data, (f.flags & END_HEADERS) !== 0);
        break;
      }
      case CONTINUATION: {
        if (!d.headerBlock) throw new Error("CONTINUATION without HEADERS");
        this.headerFragment(dir, d.headerBlock.meta, payload, (f.flags & END_HEADERS) !== 0);
        break;
      }
      case SETTINGS: {
        if (f.flags & 0x1) break; /* ACK */
        for (let i = 0; i + 6 <= payload.length; i += 6) {
          const id = (payload[i] << 8) | payload[i + 1];
          const value = ((payload[i + 2] << 24) | (payload[i + 3] << 16) | (payload[i + 4] << 8) | payload[i + 5]) >>> 0;
          /* The sender's table size ceiling binds the *other* side's encoder. */
          if (id === SETTINGS_HEADER_TABLE_SIZE) this.dirs[dir === 0 ? 1 : 0].hpack.setMaxSize(value);
        }
        break;
      }
      case RST_STREAM: {
        const s = this.streams.get(f.stream);
        const code = payload.length >= 4 ? ((payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]) >>> 0 : 0;
        if (s) {
          this.streams.delete(f.stream);
          this.finish(s, `rst ${RST_NAMES[code] ?? code}`);
        }
        break;
      }
      case GOAWAY:
      case PING:
      case WINDOW_UPDATE:
      case PRIORITY:
      default:
        break;
    }
  }

  /* Body bytes with a hole after them (from gap()), or the tail of a frame after one. */
  dataPartial(dir, f, data, hole, tail = false) {
    const s = this.stream(f.stream, dir);
    const side = dir === this.clientDir ? s.req : s.res;
    /* Padding is not tracked across a hole; the pad bytes count as body. */
    if (data.length) side.body.add(data);
    if (hole) side.body.gap(hole);
    if (tail && f.flags & END_STREAM) this.endStream(s, dir);
  }

  headerFragment(dir, meta, data, end) {
    const d = this.dirs[dir];
    if (!d.headerBlock) d.headerBlock = { meta, parts: [] };
    d.headerBlock.parts.push(data);
    if (!end) return;
    const block = concat(d.headerBlock.parts);
    d.headerBlock = null;
    const headers = d.hpack.decode(block);
    if (meta.promised != null) {
      /* A pushed request: the server describes what it will send. */
      const s = this.stream(meta.promised, this.clientDir);
      this.requestHeaders(s, headers, true);
      return;
    }
    const s = this.stream(meta.stream, dir);
    if (dir === this.clientDir) {
      if (s.req.headers.length && s.req.headersDone) s.req.trailers = headers.filter(([n]) => !n.startsWith(":"));
      else this.requestHeaders(s, headers, meta.endStream);
    } else {
      const status = headers.find(([n]) => n === ":status")?.[1];
      if (s.res.status != null && s.res.headersDone) s.res.trailers = headers.filter(([n]) => !n.startsWith(":"));
      else if (status != null && Number(status) >= 100 && Number(status) < 200) s.interim.push(Number(status));
      else {
        s.res.status = status != null ? Number(status) : null;
        s.res.headers = headers.filter(([n]) => !n.startsWith(":"));
        s.res.headersDone = true;
        s.res.ts = this.ts;
        s.res.at = this.now();
      }
    }
    if (meta.endStream) this.endStream(s, dir);
  }

  requestHeaders(s, headers, endStream) {
    const get = (n) => headers.find(([k]) => k === n)?.[1] ?? null;
    s.req.method = get(":method") ?? "GET";
    s.req.target = get(":path") ?? (s.req.method === "CONNECT" ? get(":authority") : "/");
    const authority = get(":authority");
    s.req.headers = headers.filter(([n]) => !n.startsWith(":"));
    if (authority && !s.req.headers.some(([n]) => n === "host")) s.req.headers.unshift(["host", authority]);
    s.req.scheme = get(":scheme");
    s.req.headersDone = true;
    s.req.ts = this.ts;
    s.req.at = this.now();
    void endStream;
  }

  stream(id, dir) {
    let s = this.streams.get(id);
    if (!s) {
      s = {
        id,
        req: { kind: "request", version: "2", method: null, target: null, headers: [], trailers: [], body: new BodyCapture(this.bodyLimit), headersDone: false, ended: false, complete: true, ts: this.ts, tsEnd: null, at: this.now() },
        res: { kind: "response", version: "2", status: null, reason: "", headers: [], trailers: [], body: new BodyCapture(this.bodyLimit), headersDone: false, ended: false, complete: true, ts: null, tsEnd: null, at: null },
        interim: [],
        openedBy: dir,
      };
      this.streams.set(id, s);
    }
    return s;
  }

  endStream(s, dir) {
    const side = dir === this.clientDir ? s.req : s.res;
    side.ended = true;
    side.tsEnd = this.ts;
    if (s.req.ended && s.res.ended) {
      this.streams.delete(s.id);
      this.finish(s, null);
    }
  }

  finish(s, cut) {
    const req = s.req.headersDone ? s.req : null;
    const res = s.res.headersDone ? s.res : null;
    if (req) req.complete = s.req.ended && !cut;
    if (res) res.complete = s.res.ended && !cut;
    if (req) req.tsEnd ??= this.ts;
    if (res) res.tsEnd ??= this.ts;
    this.onTransaction?.({ req, res, interim: s.interim, cut: cut ?? (req && !res ? "no response" : res && !req ? "no request" : null), stream: s.id });
  }
}

const concat = (parts) => {
  if (parts.length === 1) return parts[0];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

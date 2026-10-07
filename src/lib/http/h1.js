/* HTTP/1.x messages out of one direction's bytes.
 *
 * One `H1Parser` reads one direction of one connection — requests on the
 * direction the client writes, responses on the other — and reports
 * each message's head when it is complete, its body as it goes, and
 * its end. It knows how a message is framed (RFC 7230 §3.3.3) and
 * nothing about connections or pairing; decoder.js does that.
 *
 * The capture is lossy in a known way: a window can have a hole, whose
 * size is known. `gap(n)` tells the parser `n` bytes went by unseen.
 * Inside a body of known length that costs nothing but the bytes;
 * anywhere else the parser cannot know where the next message starts,
 * so it reports `desync` and the owner starts it again at the next
 * record boundary — a request always begins one.
 *
 * Pure. No `yeet:*` imports.
 */

import { BodyCapture, ByteQueue, CR, LF, latin1 } from "./bytes.js";

export const REQUEST = "request";
export const RESPONSE = "response";

const MAX_HEAD = 64 * 1024;

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const REQUEST_LINE = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+) (\S+) HTTP\/(\d)\.(\d)$/;
const STATUS_LINE = /^HTTP\/(\d)\.(\d) (\d{3})(?: (.*))?$/;

/* Does this window begin like a message of `kind`? Decided on the
 * first bytes, before a whole line is in, so the owner can label a
 * connection from its first record. Returns true, false, or null when
 * more bytes are needed to say.
 *
 * Stricter than the grammar on purpose: a method is upper-case words
 * (`GET`, `M-SEARCH`), a target starts with `/`, `*` or a letter, and
 * the version follows when the line is in. Body bytes we join
 * mid-stream must not pass — a token may legally contain `.`, so
 * `...tail of` would otherwise read as a request. */
const METHOD_PREFIX = /^[A-Z][A-Z-]{0,19}$/;
export function looksLike(kind, bytes) {
  const s = latin1(bytes, 0, Math.min(bytes.length, 64));
  const lf = s.indexOf("\n");
  const line = lf >= 0 ? s.slice(0, lf).replace(/\r$/, "") : null;
  if (kind === RESPONSE) {
    if (line !== null) return STATUS_LINE.test(line);
    const want = "HTTP/1.";
    if (s.length < want.length) return want.startsWith(s) ? null : false;
    return s.startsWith(want) && (s.length < 10 || /^HTTP\/1\.\d [1-5]\d?\d? ?/.test(s.slice(0, 13)));
  }
  if (line !== null) {
    const m = REQUEST_LINE.exec(line);
    return Boolean(m && METHOD_PREFIX.test(m[1]) && /^[/*A-Za-z]/.test(m[2]));
  }
  const sp = s.indexOf(" ");
  if (sp < 0) return s.length > 20 || !METHOD_PREFIX.test(s) ? false : null;
  if (!METHOD_PREFIX.test(s.slice(0, sp))) return false;
  const target = s.charAt(sp + 1);
  if (target === "") return null;
  return /^[/*A-Za-z]/.test(target);
}

/**
 * `kind` is REQUEST or RESPONSE. Events:
 *   onHead(msg)             start line and headers parsed; body follows
 *   onBody(msg, bytes)      a body window, de-chunked
 *   onEnd(msg)              the message is over; `msg.body` is final
 *   onDesync(reason)        lost the framing; feed a fresh boundary
 *   onOpaque(msg)           the connection stopped being HTTP after msg
 * `methodOf()` is asked, for a response, which request it answers — a
 * HEAD response has no body whatever its headers say.
 */
export class H1Parser {
  constructor(kind, { bodyLimit = 64 * 1024, methodOf = () => null, onHead, onBody, onEnd, onDesync, onOpaque } = {}) {
    this.kind = kind;
    this.bodyLimit = bodyLimit;
    this.methodOf = methodOf;
    this.onHead = onHead;
    this.onBody = onBody;
    this.onEnd = onEnd;
    this.onDesync = onDesync;
    this.onOpaque = onOpaque;
    this.q = new ByteQueue();
    this.state = "head";
    this.msg = null;
    this.remaining = 0;
  }

  /* True while the parser is between messages with nothing buffered:
   * the next byte starts a new head. */
  get idle() {
    return this.state === "head" && this.q.length === 0;
  }

  push(bytes) {
    if (this.state === "opaque" || this.state === "desync") return;
    this.q.append(bytes);
    this.run();
  }

  /* `n` bytes passed unseen. */
  gap(n) {
    if (n <= 0 || this.state === "opaque" || this.state === "desync") return;
    switch (this.state) {
      case "body-length":
      case "chunk-data": {
        const take = Math.min(n, this.remaining);
        this.msg.body.gap(take);
        this.remaining -= take;
        n -= take;
        if (this.remaining === 0) {
          if (this.state === "body-length") this.finish();
          else this.state = "chunk-crlf";
        }
        if (n > 0) this.desync("hole past the end of a body");
        else this.run();
        return;
      }
      case "body-close":
        this.msg.body.gap(n);
        return;
      default:
        this.desync(`hole while reading ${this.state}`);
    }
  }

  /* The connection is over. A body that ran to the close is complete
   * now; anything else in flight was cut. */
  close() {
    if (this.state === "body-close") {
      this.finish();
    } else if (this.msg) {
      this.msg.complete = false;
      this.msg.cut = this.state;
      this.onEnd?.(this.msg);
      this.msg = null;
    }
    this.state = "opaque";
    this.q.clear();
  }

  desync(reason) {
    if (this.msg) {
      this.msg.complete = false;
      this.msg.cut = reason;
      this.onEnd?.(this.msg);
      this.msg = null;
    }
    this.state = "desync";
    this.q.clear();
    this.onDesync?.(reason);
  }

  /* Ready for the next record boundary after a desync. */
  reset() {
    this.q.clear();
    this.msg = null;
    this.remaining = 0;
    this.state = "head";
  }

  run() {
    for (;;) {
      switch (this.state) {
        case "head":
          if (!this.readHead()) return;
          break;
        case "body-length": {
          if (this.q.length === 0) return;
          const chunk = this.q.take(this.remaining);
          this.remaining -= chunk.length;
          this.body(chunk);
          if (this.remaining === 0) this.finish();
          break;
        }
        case "body-close": {
          if (this.q.length === 0) return;
          this.body(this.q.take(this.q.length));
          break;
        }
        case "chunk-size": {
          const i = this.q.indexOfLF();
          if (i < 0) {
            if (this.q.length > 1024) this.desync("chunk-size line too long");
            return;
          }
          const line = latin1(this.q.take(i + 1)).replace(/\r?\n$/, "");
          const m = /^([0-9A-Fa-f]+)\s*(?:;.*)?$/.exec(line);
          if (!m) {
            this.desync(`bad chunk size ${JSON.stringify(line.slice(0, 32))}`);
            return;
          }
          const size = parseInt(m[1], 16);
          if (size === 0) this.state = "trailers";
          else {
            this.remaining = size;
            this.state = "chunk-data";
          }
          break;
        }
        case "chunk-data": {
          if (this.q.length === 0) return;
          const chunk = this.q.take(this.remaining);
          this.remaining -= chunk.length;
          this.body(chunk);
          if (this.remaining === 0) this.state = "chunk-crlf";
          break;
        }
        case "chunk-crlf": {
          /* The CRLF after chunk data. Tolerate a bare LF. */
          if (this.q.length === 0) return;
          if (this.q.at(0) === CR) {
            if (this.q.length < 2) return;
            if (this.q.at(1) !== LF) {
              this.desync("chunk not followed by CRLF");
              return;
            }
            this.q.skip(2);
          } else if (this.q.at(0) === LF) this.q.skip(1);
          else {
            this.desync("chunk not followed by CRLF");
            return;
          }
          this.state = "chunk-size";
          break;
        }
        case "trailers": {
          /* Header lines up to a blank line; the blank line alone is
           * the common case. */
          const i = this.q.indexOfLF();
          if (i < 0) {
            if (this.q.length > MAX_HEAD) this.desync("trailers too long");
            return;
          }
          const line = latin1(this.q.take(i + 1)).replace(/\r?\n$/, "");
          if (line === "") {
            this.finish();
            break;
          }
          const c = line.indexOf(":");
          if (c > 0) this.msg.trailers.push([line.slice(0, c).trim().toLowerCase(), line.slice(c + 1).trim()]);
          break;
        }
        default:
          return;
      }
    }
  }

  readHead() {
    const end = this.q.indexOfBlankLine();
    if (end < 0) {
      if (this.q.length > MAX_HEAD) this.desync("head longer than 64 KiB");
      return false;
    }
    const text = latin1(this.q.take(end + 1));
    const lines = text.split("\n").map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));
    /* Drop the blank line(s) that closed the block. */
    while (lines.length && lines[lines.length - 1] === "") lines.pop();
    /* A peer may send CRLF before a request (RFC 7230 §3.5). */
    while (lines.length && lines[0] === "") lines.shift();
    if (!lines.length) return true;

    const msg = this.startLine(lines[0]);
    if (!msg) {
      this.desync(`not a ${this.kind} line: ${JSON.stringify(lines[0].slice(0, 48))}`);
      return false;
    }

    for (let i = 1; i < lines.length; i++) {
      let line = lines[i];
      /* obs-fold: a continuation line starts with whitespace. */
      while (i + 1 < lines.length && /^[ \t]/.test(lines[i + 1])) line += " " + lines[++i].trim();
      const c = line.indexOf(":");
      if (c <= 0) continue;
      msg.headers.push([line.slice(0, c).trim().toLowerCase(), line.slice(c + 1).trim()]);
    }

    msg.body = new BodyCapture(this.bodyLimit);
    msg.trailers = [];
    msg.complete = true;
    this.msg = msg;

    const framing = this.framing(msg);
    if (framing.error) {
      this.desync(framing.error);
      return false;
    }
    msg.framing = framing.kind;
    this.onHead?.(msg);

    switch (framing.kind) {
      case "none":
        this.finish();
        break;
      case "length":
        this.remaining = framing.length;
        this.state = framing.length === 0 ? "head" : "body-length";
        if (framing.length === 0) this.finish();
        break;
      case "chunked":
        this.state = "chunk-size";
        break;
      case "close":
        this.state = "body-close";
        break;
      case "tunnel":
        this.finish();
        this.opaque();
        break;
    }
    return this.state !== "opaque";
  }

  startLine(line) {
    if (this.kind === REQUEST) {
      const m = REQUEST_LINE.exec(line);
      if (!m) return null;
      return { kind: REQUEST, method: m[1], target: m[2], version: `${m[3]}.${m[4]}`, headers: [] };
    }
    const m = STATUS_LINE.exec(line);
    if (!m) return null;
    return { kind: RESPONSE, version: `${m[1]}.${m[2]}`, status: Number(m[3]), reason: m[4] ?? "", headers: [] };
  }

  /* RFC 7230 §3.3.3, in order. */
  framing(msg) {
    const te = headerValues(msg.headers, "transfer-encoding");
    const cl = headerValues(msg.headers, "content-length");

    if (msg.kind === RESPONSE) {
      const method = this.methodOf() ?? null;
      if (msg.status >= 100 && msg.status < 200) return { kind: "none" };
      if (msg.status === 204 || msg.status === 304) return { kind: "none" };
      if (method === "HEAD") return { kind: "none" };
      if (method === "CONNECT" && msg.status >= 200 && msg.status < 300) return { kind: "tunnel" };
    }

    if (te.length) {
      const codings = te.join(",").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
      if (codings[codings.length - 1] === "chunked") return { kind: "chunked" };
      if (msg.kind === RESPONSE) return { kind: "close" };
      return { error: "request with transfer-encoding that is not chunked" };
    }
    if (cl.length) {
      const values = [...new Set(cl.join(",").split(",").map((s) => s.trim()))];
      if (values.length !== 1 || !/^\d+$/.test(values[0])) return { error: `bad content-length ${JSON.stringify(cl.join(","))}` };
      return { kind: "length", length: Number(values[0]) };
    }
    if (msg.kind === REQUEST) return { kind: "none" };
    return { kind: "close" };
  }

  body(bytes) {
    this.msg.body.add(bytes);
    this.onBody?.(this.msg, bytes);
  }

  finish() {
    const msg = this.msg;
    this.msg = null;
    this.remaining = 0;
    this.state = "head";
    this.onEnd?.(msg);
    /* 101 Switching Protocols: what follows is not HTTP/1. */
    if (msg.kind === RESPONSE && msg.status === 101) this.opaque(msg);
  }

  opaque(msg) {
    this.state = "opaque";
    this.q.clear();
    this.onOpaque?.(msg ?? null);
  }
}

/** Every value of header `name` (lower-case), in order. */
export const headerValues = (headers, name) => headers.filter(([n]) => n === name).map(([, v]) => v);

/** The first value of header `name`, or null. */
export const header = (headers, name) => headers.find(([n]) => n === name)?.[1] ?? null;

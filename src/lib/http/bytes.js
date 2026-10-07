/* Bytes, for a parser that eats from the front.
 *
 * The isolate has plain JavaScript and nothing else — no TextDecoder,
 * no Buffer — so the few byte routines HTTP/1 needs live here: a queue
 * that concatenates captured windows and hands out prefixes, a Latin-1
 * view for header text (HTTP header bytes are octets; treating them as
 * Latin-1 is lossless and is what the spec says to do), and a bounded
 * body accumulator.
 *
 * Pure. No `yeet:*` imports.
 */

export const CR = 13;
export const LF = 10;

/* A growable window. `append` copies, because a record's `data` is a
 * view into loader memory that may be reused; everything handed back
 * out is a view into this queue's own storage, which is never written
 * in place after the fact. */
export class ByteQueue {
  constructor() {
    this.buf = new Uint8Array(0);
    this.head = 0;
  }

  get length() {
    return this.buf.length - this.head;
  }

  append(bytes) {
    if (!bytes || bytes.length === 0) return;
    const live = this.length;
    if (live === 0) {
      this.buf = Uint8Array.from(bytes);
      this.head = 0;
      return;
    }
    const out = new Uint8Array(live + bytes.length);
    out.set(this.buf.subarray(this.head), 0);
    out.set(bytes, live);
    this.buf = out;
    this.head = 0;
  }

  at(i) {
    return this.buf[this.head + i];
  }

  /* Index (relative to the head) of the first LF at or after `from`,
   * or -1. Lines are cut on LF and a preceding CR is trimmed, so a
   * bare-LF peer still parses. */
  indexOfLF(from = 0) {
    const i = this.buf.indexOf(LF, this.head + from);
    return i < 0 ? -1 : i - this.head;
  }

  /* Relative index of the blank line ending a header block: the first
   * LF that is followed by an LF or by CR LF. Or -1. */
  indexOfBlankLine(from = 0) {
    let i = this.indexOfLF(from);
    while (i >= 0) {
      const a = this.at(i + 1);
      if (a === LF) return i + 1;
      if (a === CR && this.at(i + 2) === LF) return i + 2;
      i = this.indexOfLF(i + 1);
    }
    return -1;
  }

  peek(n) {
    return this.buf.subarray(this.head, this.head + Math.min(n, this.length));
  }

  take(n) {
    const out = this.peek(n);
    this.head += out.length;
    return out;
  }

  skip(n) {
    const k = Math.min(n, this.length);
    this.head += k;
    return k;
  }

  clear() {
    this.buf = new Uint8Array(0);
    this.head = 0;
  }
}

/* Bytes as the string with the same code points, one per byte. */
export function latin1(bytes, start = 0, end = bytes.length) {
  let out = "";
  for (let i = start; i < end; i += 8192) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, end)));
  }
  return out;
}

/* The reverse, for tests and for building probes. */
export function bytesOfString(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/* UTF-8, decoded by hand, with U+FFFD for anything malformed. Used on
 * bodies for display; headers stay Latin-1. */
export function utf8(bytes) {
  let out = "";
  const n = bytes.length;
  for (let i = 0; i < n; ) {
    const b = bytes[i];
    if (b < 0x80) {
      out += String.fromCharCode(b);
      i += 1;
      continue;
    }
    let need = 0;
    let cp = 0;
    if ((b & 0xe0) === 0xc0) (need = 1), (cp = b & 0x1f);
    else if ((b & 0xf0) === 0xe0) (need = 2), (cp = b & 0x0f);
    else if ((b & 0xf8) === 0xf0) (need = 3), (cp = b & 0x07);
    else {
      out += "�";
      i += 1;
      continue;
    }
    if (i + need >= n) {
      out += "�";
      break;
    }
    let ok = true;
    for (let k = 1; k <= need; k++) {
      const c = bytes[i + k];
      if ((c & 0xc0) !== 0x80) {
        ok = false;
        break;
      }
      cp = (cp << 6) | (c & 0x3f);
    }
    if (!ok || cp > 0x10ffff) {
      out += "�";
      i += 1;
      continue;
    }
    out += String.fromCodePoint(cp);
    i += need + 1;
  }
  return out;
}

/* Keeps the first `limit` bytes of a body and counts the rest. `holes`
 * are bytes the tap did not capture (a page not resident, a full ring),
 * which the framing still accounted for. */
export class BodyCapture {
  constructor(limit) {
    this.limit = limit;
    this.len = 0;
    this.holes = 0;
    this.parts = [];
    this.kept = 0;
  }

  add(bytes) {
    this.len += bytes.length;
    const room = this.limit - this.kept;
    if (room <= 0) return;
    const part = Uint8Array.from(bytes.length > room ? bytes.subarray(0, room) : bytes);
    this.parts.push(part);
    this.kept += part.length;
  }

  gap(n) {
    this.len += n;
    this.holes += n;
  }

  get truncated() {
    return this.len - this.holes > this.kept;
  }

  /* One Uint8Array of what was kept. */
  data() {
    if (this.parts.length === 1) return this.parts[0];
    const out = new Uint8Array(this.kept);
    let o = 0;
    for (const p of this.parts) {
      out.set(p, o);
      o += p.length;
    }
    this.parts = [out];
    return out;
  }
}

/* Ring-buffer records, made into plain JavaScript.
 *
 * What the loader hands a subscriber is the C struct decoded field by
 * field through BTF, wrapped under the struct's name: 64-bit fields are
 * BigInt, byte arrays come back as arrays (or, from a data section, as
 * objects keyed by index), and nothing is trimmed to the length that
 * was actually written. Everything downstream wants numbers, strings
 * and a Uint8Array cut to `cap_len` — so it is done here, once, and
 * the rest of the app never sees a raw record.
 *
 * Pure: no `yeet:*` imports, so this loads in a test as easily as in
 * the isolate.
 */

export const DIR_READ = 0;
export const DIR_WRITE = 1;
export const TRANSPORT_TCP = 0;
export const TRANSPORT_TLS = 1;
export const TRANSPORT_WIRE = 2;

export const TCPF_FIN = 0x01;
export const TCPF_SYN = 0x02;
export const TCPF_RST = 0x04;
export const TCPF_PSH = 0x08;
export const TCPF_ACK = 0x10;

const AF_INET6 = 10;

/* A fixed C byte array, whichever shape it arrived in, as a Uint8Array
 * of at most `len` bytes. Strings are the isolate's Latin-1 spelling of
 * the same bytes. */
export function bytesOf(data, len) {
  if (data == null) return new Uint8Array(0);
  if (data instanceof Uint8Array) return len == null ? data : data.subarray(0, len);
  if (typeof data === "string") {
    const n = len == null ? data.length : Math.min(len, data.length);
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = data.charCodeAt(i) & 0xff;
    return out;
  }
  const values = Array.isArray(data) ? data : Object.values(data);
  const n = len == null ? values.length : Math.min(len, values.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = Number(values[i]) & 0xff;
  return out;
}

/* A NUL-terminated `char[16]`. */
export function commOf(bytes) {
  const b = bytesOf(bytes);
  let out = "";
  for (const c of b) {
    if (!c) break;
    out += String.fromCharCode(c);
  }
  return out;
}

/* `__u64` as a hex string, which is what an opaque pointer is for: a
 * key that survives JSON and never meets arithmetic. */
export const hex64 = (v) => "0x" + BigInt(v ?? 0).toString(16);

/* An address from the 16-byte field: dotted quad for v4 (first four
 * bytes), eight hextets for v6 — uncompressed, so it is not canonical,
 * but it round-trips through a table cell. */
export function addrOf(family, bytes) {
  const b = bytesOf(bytes, 16);
  if (family === AF_INET6) {
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push((((b[i * 2] ?? 0) << 8) | (b[i * 2 + 1] ?? 0)).toString(16));
    return parts.join(":");
  }
  return `${b[0] ?? 0}.${b[1] ?? 0}.${b[2] ?? 0}.${b[3] ?? 0}`;
}

/* One `data_event`. `ts` stays a BigInt nanosecond count from
 * bpf_ktime_get_ns, because subtracting two as Numbers loses the low
 * bits; `at` is wall-clock milliseconds for display. */
export function dataRecord(wrapped) {
  const e = wrapped?.data_event ?? wrapped;
  const family = Number(e.family ?? 0);
  const capLen = Number(e.cap_len ?? 0);
  return {
    ts: BigInt(e.ts ?? 0),
    at: Date.now(),
    conn: hex64(e.conn),
    pid: Number(e.pid ?? 0),
    tid: Number(e.tid ?? 0),
    len: Number(e.len ?? 0),
    off: Number(e.off ?? 0),
    capLen,
    dir: Number(e.dir ?? 0),
    transport: Number(e.transport ?? 0),
    flags: Number(e.flags ?? 0),
    family,
    sport: Number(e.sport ?? 0),
    dport: Number(e.dport ?? 0),
    saddr: family ? addrOf(family, e.saddr) : null,
    daddr: family ? addrOf(family, e.daddr) : null,
    data: bytesOf(e.data, capLen),
  };
}

/* One `peer_event`: a TLS connection id and the socket it was seen on. */
export function peerRecord(wrapped) {
  const e = wrapped?.peer_event ?? wrapped;
  const family = Number(e.family ?? 0);
  return {
    ts: BigInt(e.ts ?? 0),
    at: Date.now(),
    conn: hex64(e.conn),
    sk: hex64(e.sk),
    pid: Number(e.pid ?? 0),
    family,
    sport: Number(e.sport ?? 0),
    dport: Number(e.dport ?? 0),
    saddr: addrOf(family, e.saddr),
    daddr: addrOf(family, e.daddr),
  };
}

/* One `wire_event`: a TCP segment's payload as it crossed a device,
 * with the packet's own addressing (src → dst) and sequence number. */
export function wireRecord(wrapped) {
  const e = wrapped?.wire_event ?? wrapped;
  const family = Number(e.family ?? 0);
  const capLen = Number(e.cap_len ?? 0);
  return {
    ts: BigInt(e.ts ?? 0),
    at: Date.now(),
    ifindex: Number(e.ifindex ?? 0),
    hook: Number(e.hook ?? 0),
    family,
    tcpflags: Number(e.tcpflags ?? 0),
    sport: Number(e.sport ?? 0),
    dport: Number(e.dport ?? 0),
    saddr: addrOf(family, e.saddr),
    daddr: addrOf(family, e.daddr),
    seq: Number(e.seq ?? 0) >>> 0,
    ack: Number(e.ack ?? 0) >>> 0,
    len: Number(e.len ?? 0),
    off: Number(e.off ?? 0),
    capLen,
    data: bytesOf(e.data, capLen),
  };
}

/* Printable preview of a byte window, for logs and tables. */
export function ascii(bytes, max = 80) {
  let out = "";
  const n = Math.min(bytes.length, max);
  for (let i = 0; i < n; i++) {
    const c = bytes[i];
    out += c >= 32 && c < 127 ? String.fromCharCode(c) : c === 10 ? "⏎" : c === 13 ? "" : ".";
  }
  return bytes.length > max ? out + "…" : out;
}

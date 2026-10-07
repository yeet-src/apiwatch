/* Loading the TLS taps: four boundaries, attached best-effort.
 *
 * A target offers some subset of these — an OpenSSL program has CLASSIC
 * (and EX on 1.1.1+), a Go program has GO, a rustls program has RUST, a
 * BoringSSL program only CLASSIC — and start() rejects an object with
 * any unattached uprobe. So each boundary is its own object and its own
 * attach, and a miss on one is expected rather than fatal. If none bind
 * the caller falls back to the socket tap, which sees plaintext only
 * where the wire carries it.
 *
 * Every tap emits the same `data_event` and `peer_event` records (see
 * bpf/include/tap.h), so one `onData`/`onPeer` serves them all.
 */

import { ArrayMap, BpfObject, RingBuf } from "yeet:bpf";

import { dataRecord, peerRecord } from "./records.js";

/* The classic byte-count API: Node, Rust native-tls, uSockets, curl. */
export const CLASSIC = {
  id: "openssl",
  file: "ssl.bpf.o",
  probes: [
    ["ssl_write", { symbol: "SSL_write" }],
    ["ssl_read_enter", { symbol: "SSL_read" }],
    ["ssl_read_exit", { symbol: "SSL_read" }],
  ],
};

/* OpenSSL 1.1.1+ `_ex`: CPython, and anything built against it. */
export const EX = {
  id: "openssl_ex",
  file: "ssl_ex.bpf.o",
  probes: [
    ["ssl_write_ex", { symbol: "SSL_write_ex" }],
    ["ssl_read_ex_enter", { symbol: "SSL_read_ex" }],
    ["ssl_read_ex_exit", { symbol: "SSL_read_ex" }],
  ],
};

/* Go's crypto/tls, egress and ingress. Both attach by raw file offset
 * rather than by symbol: the offsets come from the binary's own
 * .gopclntab (app/lib/probes/gopclntab.js, read on the host), which a
 * stripped binary keeps when it has lost .symtab. Passed in as `go`:
 *   { write: { entry }, read: { entry, rets: [...] } }
 * Without it the Go taps are skipped.
 *
 * The ingress return is caught by plain uprobes at each RET of Read — a
 * uretprobe kills a Go process (its stack copier trips over the
 * trampoline). The object has RET_SLOTS identical programs: slot i goes
 * at RET i, spare slots repeat the last RET, where they find nothing to
 * do. */
const RET_SLOTS = 8;

export const GO = {
  id: "go",
  file: "gotls.bpf.o",
  probes: ({ go }) => {
    if (!go?.write) throw new Error("needs the Go binary's pclntab targets (scripts/go-rets.mjs)");
    return [["go_tls_write", { offset: go.write.entry }]];
  },
};

export const GO_READ = {
  id: "go_read",
  file: "gotls_read.bpf.o",
  probes: ({ go }) => {
    const read = go?.read;
    if (!read?.rets?.length) throw new Error("needs the RET offsets of crypto/tls.(*Conn).Read (scripts/go-rets.mjs)");
    if (read.rets.length > RET_SLOTS) throw new Error(`${read.rets.length} RETs but only ${RET_SLOTS} slots`);
    const list = [["go_tls_read_enter", { offset: read.entry }]];
    for (let i = 0; i < RET_SLOTS; i++) {
      list.push([`go_tls_read_ret${i}`, { offset: Number(read.rets[Math.min(i, read.rets.length - 1)]) }]);
    }
    return list;
  },
};

/* rustls. The symbols are mangled with a per-build hash, so they are
 * matched by regular expression against the demangled names — the
 * daemon resolves the match and attaches by offset. `write$` is
 * anchored so it cannot also take `write_vectored`; the `>?` tolerates
 * both spellings of an inherent method (legacy and v0 mangling). */
export const RUST = {
  id: "rustls",
  file: "rustls.bpf.o",
  probes: [
    ["rust_tls_write", { symbol: "PlaintextSink>::write$", match: "regex" }],
    ["rust_tls_read", { symbol: "CommonState>?::take_received_plaintext$", match: "regex" }],
  ],
};

export const TAPS = [CLASSIC, EX, GO, GO_READ, RUST];

/**
 * Attach every tap whose symbols `binary` has, scoped to `pid` when
 * given (otherwise every process that maps the binary, now and later).
 *
 *   objects   name → `{ exe, base? }` for each tap's `.bpf.o`
 *   binary    absolute path or a bare soname the loader can find
 *   go        the Go binary's attach points from gopclntab.js, if any
 *
 * Returns `{ taps, setFocus, stop }`; `taps` names the boundaries that
 * bound. Throws only if none did.
 */
export async function attachTls({ objects, binary, pid, go, onData, onPeer, onError, taps = TAPS }) {
  const attached = [];
  const failures = {};

  for (const tap of taps) {
    const object = objects[tap.id];
    if (!object) continue;
    try {
      attached.push(await attachOne(tap, object, { binary, pid, go, onData, onPeer, onError }));
    } catch (error) {
      failures[tap.id] = String(error?.message ?? error);
    }
  }

  if (attached.length === 0) {
    const why = Object.entries(failures)
      .map(([id, msg]) => `${id}: ${msg}`)
      .join("; ");
    throw new Error(`no TLS boundary in ${binary}${pid ? ` (pid ${pid})` : ""} — ${why}`);
  }

  return {
    taps: attached.map((t) => t.id),
    failures,
    /** Emit only for one connection id and/or pid; zero clears. */
    async setFocus({ conn = 0n, pid: focusPid = 0 } = {}) {
      for (const t of attached) await t.setFocus({ conn, pid: focusPid });
    },
    async stop() {
      for (const t of attached) await t.stop();
    },
  };
}

async function attachOne(tap, object, { binary, pid, go, onData, onPeer, onError }) {
  let builder = new BpfObject(object)
    .bind("events", { kind: "ringbuf", btf_struct: "data_event" })
    .bind("peers", { kind: "ringbuf", btf_struct: "peer_event" })
    .bind("focus", { kind: "array" });

  /* Entry versus return is taken from each program's section, not the
   * spec, so both probes on SSL_read carry the same target. A tap whose
   * probe list depends on the target (the Go offsets) computes it here. */
  const probes = typeof tap.probes === "function" ? tap.probes({ go }) : tap.probes;
  for (const [program, spec] of probes) {
    builder = builder.attach(program, { kind: "uprobe", binary, pid, ...spec });
  }
  const control = await builder.start();

  const guard = (fn, make) => (wrapped) => {
    try {
      fn?.(make(wrapped), tap.id);
    } catch (error) {
      onError?.(error);
    }
  };
  const fail = (error) => onError?.(error);

  const events = await new RingBuf(control, "events").subscribe(guard(onData, dataRecord), fail);
  const peers = await new RingBuf(control, "peers").subscribe(guard(onPeer, peerRecord), fail);
  const focus = new ArrayMap(control, "focus");

  return {
    id: tap.id,
    async setFocus({ conn = 0n, pid: focusPid = 0 } = {}) {
      await focus.update(0, BigInt(conn || 0));
      await focus.update(1, BigInt(focusPid || 0));
    },
    async stop() {
      await events.unsubscribe?.();
      await peers.unsubscribe?.();
      await control.stop();
    },
  };
}

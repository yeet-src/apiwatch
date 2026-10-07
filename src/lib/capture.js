/* Every HTTP exchange on the box, as transactions with a process attached.
 *
 * Three sources, one decoder:
 *
 *   socket tap   kprobes on tcp_sendmsg/tcp_recvmsg (bin/socket.bpf.o):
 *                plaintext HTTP/1.x and h2c on any port, both ends of a
 *                loopback hop, plus the ClientHello of every TLS call
 *   TLS taps     uprobes on SSL_read/SSL_write (+ _ex) and rustls, attached
 *                to each libssl the box maps and to node/deno/bun, which
 *                carry their own: HTTPS as plaintext
 *   inventory    the system graph's socket tables joined to process fds:
 *                which ports are listening, and whose they are
 *
 * The decoder (lib/http, from yeet-src/httpscope) turns records into
 * transactions; this module adds nothing to them but the bookkeeping a
 * caller needs: which TLS flows were decoded, which were only named.
 */

import { attachSocket } from "./probes/socketcore.js";
import { attachTls, CLASSIC, EX, RUST } from "./probes/tlscore.js";
import { snapshot } from "./probes/conns.js";
import { classify, libsslPath } from "./probes/runtimes.js";
import { DIR_WRITE, TRANSPORT_TCP } from "./probes/records.js";
import { Decoder } from "./http/decoder.js";
import { isClientHello, sniOf } from "./sni.js";

/* The tool's own plumbing, never reported as an API. */
export const SELF_COMMS = new Set(["yeetd", "yeet"]);

const flowKey = (f) => `${f.saddr}:${f.sport}>${f.daddr}:${f.dport}`;

const BINARIES = `{ procs { pid exe stat { comm } maps { path inode dev_major dev_minor } } }`;

/**
 *   base            the entry's directory (import.meta.dirname); the
 *                   objects are loaded from ../bin next to it
 *   ports           capture only these ports (local or remote); empty = everything
 *   onTransaction   (tx) for every decoded request/response pair
 *   onPid           (pid) for every captured record, so a short-lived
 *                   process can be named while it still exists
 *   onError         (error) for faults that cost a record, not the run
 *   bodyLimit       bytes of each body kept in memory
 */
export async function startCapture({ base, ports = [], onTransaction, onPid, onError, bodyLimit = 2048 }) {
  const spec = (file) => ({ exe: `../bin/${file}`, base });

  /* ---- inventory ---- */
  let rows = [];
  const listeners = new Map(); // port -> { port, pid, comm, laddr }
  const refresh = async () => {
    const fresh = await snapshot().catch((e) => {
      onError?.(e);
      return null;
    });
    if (!fresh) return;
    rows = fresh;
    listeners.clear();
    for (const r of fresh) {
      if (r.state !== "Listen" || r.pid == null) continue;
      const prev = listeners.get(r.lport);
      if (!prev || prev.pid > r.pid) listeners.set(r.lport, { port: r.lport, pid: r.pid, comm: r.comm, laddr: r.laddr });
    }
  };
  await refresh();
  const inventoryTimer = setInterval(refresh, 2000);

  /* ---- TLS naming bookkeeping ---- */
  const sniByFlow = new Map(); // flowKey -> { sni, pid, at }
  const decodedFlows = new Map(); // flowKey -> true, TLS flows a TLS tap bound to
  const remember = (map, key, value, cap = 4096) => {
    if (map.size >= cap) map.delete(map.keys().next().value);
    map.set(key, value);
  };

  /* ---- decoder ---- */
  const decoder = new Decoder({
    bodyLimit,
    onTransaction: (tx) => {
      try {
        onTransaction?.(tx);
      } catch (error) {
        onError?.(error);
      }
    },
  });

  /* ---- socket tap ---- */
  const socket = await attachSocket(spec("socket.bpf.o"), {
    onData: (r) => {
      onPid?.(r.pid);
      if (r.transport === TRANSPORT_TCP && r.dir === DIR_WRITE && r.off === 0 && isClientHello(r.data)) {
        const sni = sniOf(r.data);
        if (sni && r.saddr) remember(sniByFlow, flowKey(r), { sni, pid: r.pid, at: r.at, daddr: r.daddr, dport: r.dport });
      }
      decoder.push(r);
    },
    onError,
  });
  if (ports.length) for (const p of ports) await socket.focusPort(p);
  else await socket.captureAll(true);

  /* ---- TLS taps, attached per binary (inode), not per pid ---- */
  const tls = new Map(); // dev:inode -> { path, label, pids:Set, state, taps, error }
  const objects = { openssl: spec("ssl.bpf.o"), openssl_ex: spec("ssl_ex.bpf.o"), rustls: spec("rustls.bpf.o") };

  const scanTls = async () => {
    const r = await yeet.graph.query(BINARIES).catch(() => null);
    for (const p of r?.data?.procs ?? []) {
      if (SELF_COMMS.has(p.stat?.comm)) continue;
      const maps = p.maps ?? [];
      const ssl = libsslPath(maps.map((m) => m.path));
      const profile = classify({ exe: p.exe, comm: p.stat?.comm, maps: ssl ? [ssl] : [] });
      const path = ssl ?? (profile.tap === "exe" ? p.exe : null);
      if (!path) continue;
      const m = maps.find((x) => x.path === path);
      const key = m ? `${m.dev_major}:${m.dev_minor}:${m.inode}` : path;
      let entry = tls.get(key);
      if (!entry) {
        entry = { path, label: profile.label ?? p.stat?.comm, pids: new Set(), state: "attaching", taps: [], error: null };
        tls.set(key, entry);
        /* Through /proc/<pid>/root so a container's own libssl is the
         * file attached; for a host process it is the same inode. */
        attachTls({
          objects,
          taps: [CLASSIC, EX, RUST],
          binary: `/proc/${p.pid}/root${path}`,
          onData: (rec) => {
            onPid?.(rec.pid);
            decoder.push(rec);
          },
          onPeer: (peer) => {
            decoder.peer(peer);
            if (peer.saddr) remember(decodedFlows, flowKey(peer), true);
          },
          onError,
        }).then(
          (h) => Object.assign(entry, { state: "attached", taps: h.taps, handle: h }),
          (e) => Object.assign(entry, { state: "failed", error: String(e?.message ?? e) }),
        );
      }
      entry.pids.add(p.pid);
    }
  };
  await scanTls();
  const tlsTimer = setInterval(scanTls, 60_000);

  /* ---- clocks ---- */
  const tick = setInterval(() => decoder.tick(), 25);
  /* The socket tap never sees a close, so a finished connection's parser
   * state lives until it idles out. Thirty seconds keeps that small on a
   * box that opens a connection per request; a keep-alive connection that
   * wakes up later is simply sniffed again. */
  const sweep = setInterval(() => decoder.sweep(30_000), 10_000);

  return {
    /** Listening TCP ports: Map port -> { port, pid, comm, laddr }. */
    listeners: () => listeners,
    /** The last socket inventory rows. */
    rows: () => rows,
    /** Is this address one of this machine's own? */
    isLocal: (addr) => isLocalAddr(addr, rows),
    /** TLS calls that were named by SNI but never decoded: [{ sni, pid, daddr, dport, flows }]. */
    unreadableTls() {
      const out = new Map();
      for (const [key, v] of sniByFlow) {
        if (decodedFlows.has(key)) continue;
        const k = `${v.pid}|${v.sni}`;
        const e = out.get(k) ?? { sni: v.sni, pid: v.pid, daddr: v.daddr, dport: v.dport, flows: 0, lastAt: 0 };
        e.flows++;
        e.lastAt = Math.max(e.lastAt, v.at);
        out.set(k, e);
      }
      return [...out.values()];
    },
    /** Each TLS binary and whether its taps bound. */
    tlsStatus: () =>
      [...tls.values()].map((e) => ({ path: e.path, label: e.label, state: e.state, taps: e.taps, error: e.error, pids: e.pids.size })),
    async stop() {
      clearInterval(inventoryTimer);
      clearInterval(tlsTimer);
      clearInterval(tick);
      clearInterval(sweep);
      decoder.drain();
      await socket.stop().catch(() => {});
      for (const e of tls.values()) await e.handle?.stop().catch(() => {});
    },
  };
}

const LOOPBACK = /^(127\.|0:0:0:0:0:0:0:1$|::1$|0\.0\.0\.0$)/;

/* Local when loopback, or when some socket on the box is bound to it. */
function isLocalAddr(addr, rows) {
  if (!addr) return false;
  if (LOOPBACK.test(addr)) return true;
  return rows.some((r) => r.laddr === addr);
}

/* Which connections exist, and whose they are — from the system graph.
 *
 * No kernel code: the graph's `tcp`/`tcp6` tables give every socket with
 * its state and inode, and each process's `fds` name the socket inodes
 * it holds. Joining the two attributes a connection to a pid and comm.
 * Two queries, a few milliseconds each, once a second.
 *
 * Compared with tracing connect/accept in BPF this also sees what was
 * already open before the tool started, and every listening socket —
 * which is the list of services worth pointing the tap at. What it
 * misses is a connection shorter than one poll, and that costs nothing:
 * the socket tap stamps every captured byte with its pid and 4-tuple,
 * so the HTTP layer never depends on this inventory.
 *
 * Pure with respect to the runtime: the graph is injected (defaulting
 * to the global) so a test can feed it fixtures.
 */

const SOCKETS = `{
  tcp  { inode state uid local_address { addr port } remote_address { addr port } }
  tcp6 { inode state uid local_address { addr port } remote_address { addr port } }
}`;

const OWNERS = `{ procs { pid stat { comm } fds { inode kind } } }`;

/* The graph renders `addr` as "ip:port" (v6 as "[ip]:port"); the port
 * is also a field, so only the ip has to be cut out. */
const ipOf = (a) => {
  const s = String(a?.addr ?? "");
  if (s.startsWith("[")) return s.slice(1, s.indexOf("]"));
  const i = s.lastIndexOf(":");
  return i > 0 ? s.slice(0, i) : s;
};

const defaultGraph = () => yeet.graph;

/* A walk of every process's fds fails when one of them exits half way
 * ("File not found: /proc/<pid>/fd"); the next walk will not meet that
 * pid. So a failed query is asked again, a few times, before it counts. */
const RETRIES = 3;
async function query(graph, q) {
  let error;
  for (let i = 0; i <= RETRIES; i++) {
    try {
      return await graph.query(q);
    } catch (e) {
      error = e;
    }
  }
  throw error;
}

/**
 * One snapshot: `[{ inode, state, uid, laddr, lport, raddr, rport, pid,
 * comm }]`, pid/comm null for a socket no process owns (TIME_WAIT).
 */
export async function snapshot(graph = defaultGraph()) {
  const [sockets, owners] = await Promise.all([query(graph, SOCKETS), query(graph, OWNERS)]);

  const byInode = new Map();
  for (const proc of owners?.data?.procs ?? []) {
    for (const fd of proc.fds ?? []) {
      if (fd.kind === "SOCKET" && fd.inode) byInode.set(fd.inode, { pid: proc.pid, comm: proc.stat?.comm ?? null });
    }
  }

  const rows = [];
  for (const row of [...(sockets?.data?.tcp ?? []), ...(sockets?.data?.tcp6 ?? [])]) {
    const owner = byInode.get(row.inode);
    rows.push({
      inode: row.inode,
      state: row.state,
      uid: row.uid,
      laddr: ipOf(row.local_address),
      lport: row.local_address?.port ?? 0,
      raddr: ipOf(row.remote_address),
      rport: row.remote_address?.port ?? 0,
      pid: owner?.pid ?? null,
      comm: owner?.comm ?? null,
    });
  }
  return rows;
}

/** The listening sockets only: the services on this box. */
export const listeners = (rows) => rows.filter((r) => r.state === "Listen");

/**
 * Poll on an interval and call `onChange(rows)` when the set differs
 * from last time. Returns a stop function. A failed poll is reported
 * to `onError` and the previous snapshot stands.
 */
export function watch({ every = 1000, onChange, onError, graph = defaultGraph() } = {}) {
  let last = "";
  let stopped = false;

  const tick = async () => {
    try {
      const rows = await snapshot(graph);
      if (stopped) return;
      const key = rows.map((r) => `${r.inode}:${r.state}:${r.pid}`).sort().join(",");
      if (key !== last) {
        last = key;
        onChange?.(rows);
      }
    } catch (error) {
      onError?.(error);
    }
  };

  tick();
  const timer = setInterval(tick, every);
  return () => {
    stopped = true;
    clearInterval(timer);
  };
}

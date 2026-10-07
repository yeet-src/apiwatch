/* Who a pid is, in the words a person would use for it.
 *
 * "python3" names nothing; "shop-orders" (its systemd unit) or
 * "orders_api.py" (its script) does. In order of preference:
 *
 *   a systemd unit      /system.slice/shop-orders.service → shop-orders
 *   a container         …/docker-<id>.scope → container <id12>
 *   a script            python3 /opt/shop/orders_api.py → orders_api.py
 *   the command         stat.comm
 *
 * All from the system graph, cached per pid. A pid that is gone keeps
 * the name it had, so an alert about a crashed process still says which.
 */

const INTERPRETERS = /^(python[0-9.]*|node|nodejs|deno|bun|ruby[0-9.]*|perl[0-9.]*|php[0-9.]*|java|bash|sh)$/;
const GENERIC_UNITS = /^(user@\d+|session-.*|init|getty@.*|serial-getty@.*)$/;

const MAX_CACHED = 5000;
const cache = new Map();
const pending = new Map();

const base = (p) => String(p ?? "").split("/").pop();

/** The name for a graph `proc` row: `{ exe, cmdline, stat { comm }, cgroups { pathname } }`. */
export function labelOf(p) {
  const comm = p?.stat?.comm ?? null;
  const cgroup = (p?.cgroups ?? []).find((c) => c.hierarchy === 0)?.pathname ?? p?.cgroups?.[0]?.pathname ?? "";

  const unit = /\/([^/]+)\.service$/.exec(cgroup)?.[1];
  if (unit && !GENERIC_UNITS.test(unit)) return { label: unit, unit: `${unit}.service`, container: null, comm };

  const docker = /(?:docker-|\/docker\/)([0-9a-f]{12,64})/.exec(cgroup)?.[1];
  if (docker) return { label: `container ${docker.slice(0, 12)}`, unit: null, container: docker, comm };

  const cmd = p?.cmdline ?? [];
  if (INTERPRETERS.test(base(cmd[0]) || comm || "")) {
    const script = cmd.slice(1).find((a) => a && !a.startsWith("-"));
    if (script) return { label: base(script), unit: null, container: null, comm };
  }
  return { label: comm ?? base(p?.exe) ?? "unknown", unit: null, container: null, comm };
}

/** `{ pid, label, unit, container, comm, exe }` for a pid, or a placeholder if the graph has no such pid. */
export function describe(pid) {
  pid = Number(pid);
  const hit = cache.get(pid);
  if (hit) return Promise.resolve(hit);
  let p = pending.get(pid);
  if (!p) {
    p = lookup(pid).finally(() => pending.delete(pid));
    pending.set(pid, p);
  }
  return p;
}

async function lookup(pid) {
  const r = await yeet.graph
    .query(`{ proc(pid: ${pid}) { exe cmdline stat { comm } cgroups { hierarchy pathname } } }`)
    .catch(() => null);
  const p = r?.data?.proc;
  const info = p
    ? { pid, exe: p.exe ?? null, ...labelOf(p) }
    : { pid, label: `pid ${pid}`, unit: null, container: null, comm: null, exe: null, gone: true };
  /* Bounded: a loop of short-lived processes mints a pid a second. */
  if (cache.size >= MAX_CACHED) cache.delete(cache.keys().next().value);
  cache.set(pid, info);
  return info;
}

/** The cached name for a pid, without waiting; null if not looked up yet. */
export const known = (pid) => cache.get(Number(pid)) ?? null;

/* Per-runtime knowledge: how to recognise a process's TLS stack and where
 * its plaintext boundary is. Everything that knows a runtime by name
 * lives here, so supporting another is one row.
 *
 *   "exe"     OpenSSL linked statically into the executable (node, deno,
 *             bun; also a vendored-static Rust or C++ build): attach the
 *             exe itself.
 *   "libssl"  dynamic OpenSSL: attach the mapped libssl. Detected from
 *             the process's maps regardless of name; a profile names it
 *             only for the label.
 *   "go"      crypto/tls: the Go tap, if the binary keeps its symbols.
 *   "none"    nothing hookable (the browser's own TLS, a stripped static
 *             build): shown, marked opaque.
 */

const base = (p) => (p || "").split("/").pop() || "";

/* `python3.13`, `ruby3.3`: a versioned basename still counts. comm is
 * the fallback, since a worker may have renamed itself. */
export const nameMatches = (exe, comm, name) => {
  const b = base(exe);
  return b === name || (b.startsWith(name) && /^[0-9.]+$/.test(b.slice(name.length))) || comm === name;
};

const LIBSSL = /libssl/i;

/** The libssl a process maps (dynamic OpenSSL), or null. */
export const libsslPath = (paths) => (paths || []).find((p) => p && LIBSSL.test(p)) ?? null;

export const RUNTIMES = [
  { id: "node", label: "node", names: ["node"], tap: "exe" },
  { id: "deno", label: "deno", names: ["deno"], tap: "exe" },
  { id: "bun", label: "bun", names: ["bun"], tap: "exe" },
  { id: "python", label: "python", names: ["python3", "python"], tap: "libssl" },
  { id: "ruby", label: "ruby", names: ["ruby"], tap: "libssl" },
  { id: "curl", label: "curl", names: ["curl"], tap: "libssl" },
];

export const profileFor = (exe, comm) =>
  RUNTIMES.find((r) => r.names.some((n) => nameMatches(exe, comm, n))) ?? null;

/**
 * Place a process from graph-visible facts: `{ exe, comm, maps }`, maps
 * being the mapped file paths. Returns `{ label, tap, decodable }` where
 * decodable is true (a boundary will bind), false (known not to), or
 * null (unknown — only attaching tells: a static-OpenSSL or Go binary
 * under its own name looks like this).
 */
export function classify({ exe, comm, maps }) {
  const profile = profileFor(exe, comm);
  if (libsslPath(maps)) return { label: profile?.label ?? "libssl", tap: "libssl", decodable: true };
  if (profile) return { label: profile.label, tap: profile.tap, decodable: profile.tap !== "none" };
  return { label: null, tap: "unknown", decodable: null };
}

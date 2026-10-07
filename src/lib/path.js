/* Request targets → the endpoint they name.
 *
 * `/users/42/orders/9f1c…` and `/users/7/orders/00a3…` are one endpoint.
 * The segments that vary are identifiers, and most identifiers wear a
 * uniform: digits, a UUID, a hex hash, a long base64 token, a date. Those
 * are recognised on sight. A vocabulary of names (`/users/alice`) is not
 * recognisable from one path, so the model also collapses a position
 * once it has seen more distinct literals there than a route table would
 * hold (model.js, `collapseAfter`).
 *
 * Pure.
 */

const RULES = [
  [/^\d+$/, "{n}"],
  [/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, "{uuid}"],
  [/^\d{4}-\d{2}-\d{2}(T[\d:.]+Z?)?$/, "{date}"],
  [/^[0-9a-f]{16,}$/i, "{hex}"],
  [/^(?=.*\d)(?=.*[a-f])[0-9a-f]{8,15}$/i, "{hex}"],
  [/^[^@\s/]+@[^@\s/]+\.[^@\s/]+$/, "{email}"],
  [/^(?=.*\d)[A-Za-z0-9_-]{20,}$/, "{token}"],
  [/^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_.~-]{24,}$/, "{token}"],
];

/** `"{n}"` and friends for an identifier-shaped segment, else null. */
export function classify(segment) {
  for (const [re, name] of RULES) if (re.test(segment)) return name;
  return null;
}

export const isParam = (segment) => segment.startsWith("{") && segment.endsWith("}");

/**
 * Split a request target: `{ path, segments, query }`. `segments` are
 * the decoded path segments with identifiers replaced by their class;
 * `literals` keeps what stood at each parameter position. `query` is
 * `[[name, value]]` in order. An absolute-form target is reduced to its
 * path; `*` and authority-form targets give a single segment.
 */
export function parseTarget(target) {
  let t = target ?? "/";
  const m = /^https?:\/\/[^/?#]+(.*)$/i.exec(t);
  if (m) t = m[1] || "/";
  const hash = t.indexOf("#");
  if (hash >= 0) t = t.slice(0, hash);
  const q = t.indexOf("?");
  const rawPath = q >= 0 ? t.slice(0, q) : t;
  const rawQuery = q >= 0 ? t.slice(q + 1) : "";

  const query = [];
  if (rawQuery) {
    for (const part of rawQuery.split("&")) {
      if (!part) continue;
      const eq = part.indexOf("=");
      const name = decode(eq >= 0 ? part.slice(0, eq) : part);
      const value = eq >= 0 ? decode(part.slice(eq + 1)) : "";
      query.push([name, value]);
    }
  }

  if (!rawPath.startsWith("/")) return { path: rawPath, segments: [rawPath], literals: [null], query };
  const parts = rawPath.split("/").slice(1).filter((s, i, a) => s !== "" || i === a.length - 1);
  const segments = [];
  const literals = [];
  for (const raw of parts) {
    if (raw === "") continue; /* the trailing slash */
    const s = decode(raw);
    const cls = classify(s);
    segments.push(cls ?? s);
    literals.push(cls ? s : null);
  }
  return { path: rawPath, segments, literals, query };
}

const decode = (s) => {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
};

/** The template string for templated segments. */
export const templateOf = (segments) => "/" + segments.join("/");

/** What kind of value a query parameter carries. */
export function valueKind(v) {
  if (v === "") return "empty";
  if (/^-?\d+$/.test(v)) return "int";
  if (/^-?\d*\.\d+$/.test(v)) return "number";
  if (/^(true|false)$/i.test(v)) return "bool";
  const c = classify(v);
  if (c) return c.slice(1, -1);
  if (v.includes(",")) return "list";
  return "string";
}

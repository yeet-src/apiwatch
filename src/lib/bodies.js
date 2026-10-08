/* The request and response an alert shows, with secrets taken out.
 *
 * An alert that says "POST /orders → 502" tells you something broke; the
 * body the client sent and the error the server gave back usually tell
 * you why. Both are already in the captured transaction. What this module
 * adds is the care they need before they leave the box: request bodies
 * carry passwords, tokens and card numbers, and an alert goes through
 * yeet's servers into a Slack channel.
 *
 *   redacted   (the default) values under a sensitive-looking key are
 *              replaced in JSON, form and query strings, and bearer
 *              tokens, JWTs and card numbers are replaced anywhere
 *   raw        bodies as captured, still cut to `limit`
 *   off        method, path and status only
 *
 * Headers are never shown except the content type. Pure: `inflate`
 * (yeet:compression's decodeContentEncoding) is injected.
 */

import { header } from "./http/h1.js";
import { utf8 } from "./http/bytes.js";

export const MODES = ["redacted", "raw", "off"];
const MASK = "[redacted]";

/* A key is sensitive when its words, split on separators and camelCase,
 * name a secret. Whole words, so `shipping` is not a `pin` and `author`
 * is not `auth`. */
const SECRET_WORDS = new Set([
  "password", "passwd", "pass", "pwd", "passphrase", "secret", "token", "auth", "authorization",
  "credential", "credentials", "cookie", "session", "sessionid", "sid", "otp", "pin", "cvv", "cvc",
  "ssn", "card", "iban", "signature", "sig", "apikey", "key", "jwt", "bearer",
]);
/* A run-together word (`accesstoken`, `clientsecret`, `userpassword`)
 * counts when it ends in a secret, or starts with `password`; that keeps
 * `tokenize` and `secretary` out. */
const SECRET_ENDINGS = /(password|passwd|passphrase|secret|token|apikey|accesskey|privatekey|authorization|credentials?|cardnumber|ccnumber|cvv|cvc|ssn|iban)$/;
const SECRET_START = /^(password|passwd)/;

export function isSecretKey(key) {
  const words = String(key)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return words.some((w) => SECRET_WORDS.has(w) || SECRET_ENDINGS.test(w) || SECRET_START.test(w)) || SECRET_ENDINGS.test(words.join(""));
}

/* 13 to 19 digits, spaced or dashed, passing Luhn: a card number. */
const luhn = (digits) => {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
};

/** Secrets that are recognisable by their shape, wherever they sit. */
export function scrubText(s) {
  return String(s)
    .replace(/\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}/gi, `$1 ${MASK}`)
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, MASK)
    .replace(/\b\d(?:[ -]?\d){12,18}\b/g, (m) => {
      const digits = m.replace(/\D/g, "");
      return digits.length >= 13 && digits.length <= 19 && luhn(digits) ? MASK : m;
    });
}

export function redactJson(value) {
  if (Array.isArray(value)) return value.map(redactJson);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = isSecretKey(k) ? MASK : redactJson(v);
    return out;
  }
  return typeof value === "string" ? scrubText(value) : value;
}

/** `a=1&password=x` with the sensitive values replaced. */
export function redactForm(s) {
  return String(s)
    .split("&")
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq < 0) return pair;
      let key = pair.slice(0, eq);
      try {
        key = decodeURIComponent(key.replace(/\+/g, " "));
      } catch {
        /* keep it as written */
      }
      return isSecretKey(key) ? `${pair.slice(0, eq)}=${MASK}` : scrubText(pair);
    })
    .join("&");
}

/** A request target with its query string redacted. */
export function redactTarget(target) {
  const t = String(target ?? "");
  const q = t.indexOf("?");
  return q < 0 ? scrubText(t) : `${scrubText(t.slice(0, q))}?${redactForm(t.slice(q + 1))}`;
}

const cut = (s, limit) => (s.length > limit ? `${s.slice(0, limit)}… (${s.length} characters, cut)` : s);

function isText(bytes) {
  const n = Math.min(bytes.length, 512);
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const c = bytes[i];
    if (c === 0 || (c < 32 && c !== 9 && c !== 10 && c !== 13)) bad++;
  }
  return bad * 20 < n;
}

/** One body as text for an alert, or a note saying why there is none. */
export function bodyText(body, headers, { mode = "redacted", inflate = null, limit = 1000 } = {}) {
  if (mode === "off" || !body || !body.len) return null;
  let data = body.data ?? new Uint8Array(0);
  const partial = body.truncated || body.holes || !body.complete;
  const enc = (header(headers, "content-encoding") ?? "").toLowerCase();
  if (enc && enc !== "identity") {
    if (partial || !inflate) return `[${enc} body, ${body.len} bytes, not decoded]`;
    try {
      data = inflate(enc, data);
    } catch {
      return `[${enc} body, ${body.len} bytes, did not decode]`;
    }
  }
  if (!isText(data)) return `[binary body, ${body.len} bytes]`;
  let text = utf8(data);
  const ct = (header(headers, "content-type") ?? "").toLowerCase();
  if (mode === "redacted") {
    const first = text.trimStart()[0];
    let done = false;
    if (!partial && (ct.includes("json") || first === "{" || first === "[")) {
      try {
        text = JSON.stringify(redactJson(JSON.parse(text)));
        done = true;
      } catch {
        /* not JSON after all */
      }
    }
    if (!done) text = ct.includes("x-www-form-urlencoded") ? redactForm(text) : scrubText(text);
  }
  text = cut(text, limit);
  return partial ? `${text} (captured in part)` : text;
}

/**
 * The exchange an alert shows: `{ request, response }`, each with a first
 * line and a body (string or null). Never throws.
 */
export function sampleOf(tx, opts = {}) {
  const mode = opts.mode ?? "redacted";
  try {
    const target = mode === "raw" ? String(tx.target ?? "") : redactTarget(tx.target);
    const reqType = header(tx.reqHeaders ?? [], "content-type");
    const resType = header(tx.resHeaders ?? [], "content-type");
    return {
      request: {
        line: `${tx.method ?? "?"} ${target}`,
        type: reqType,
        body: bodyText(tx.reqBody, tx.reqHeaders ?? [], opts),
      },
      response: {
        line: `${tx.status ?? "no response"}${tx.reason ? ` ${tx.reason}` : ""}`,
        type: resType,
        body: bodyText(tx.resBody, tx.resHeaders ?? [], opts),
      },
    };
  } catch (error) {
    return { request: { line: `${tx.method ?? "?"} ?`, body: null }, response: { line: String(tx.status ?? "?"), body: null }, error: String(error) };
  }
}

/* Slack mrkdwn needs &, < and > escaped, and a code block cannot hold
 * three backticks in a row. */
const slackSafe = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/```/g, "``​`");

/** A sample as Slack mrkdwn: the request and the response, each in a code block. */
export function sampleMrkdwn(sample, label = "Latest failing request") {
  if (!sample) return null;
  const block = (part) => {
    const lines = [part.line];
    if (part.type) lines.push(`content-type: ${part.type}`);
    if (part.body) lines.push("", part.body);
    return "```" + slackSafe(lines.join("\n")) + "```";
  };
  return `*${label}*\n${block(sample.request)}\n*Response*\n${block(sample.response)}`;
}

import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { isSecretKey, redactForm, redactTarget, scrubText, bodyText, sampleOf, sampleMrkdwn } from "../src/lib/bodies.js";

const enc = (s) => new TextEncoder().encode(s);
const body = (s, extra = {}) => ({ len: enc(s).length, data: enc(s), complete: true, holes: 0, truncated: false, ...extra });

test("secret keys are whole words, not substrings", () => {
  for (const k of ["password", "user_password", "apiKey", "api_key", "X-Api-Key", "accessToken", "client_secret", "cardNumber", "cvv", "ssn", "pin", "Authorization", "session_id", "accesstoken", "clientSecret", "passwordHash"]) {
    assert.ok(isSecretKey(k), k);
  }
  for (const k of ["shipping", "author", "passenger", "keyboard_layout", "amount", "email", "spinner", "tokenize_count", "secretary"]) {
    assert.ok(!isSecretKey(k), k);
  }
});

test("JSON bodies have secret values replaced, everything else kept", () => {
  const t = bodyText(body('{"user":"ana","password":"hunter2","card":{"number":"4111111111111111"},"amount":2599,"note":"Bearer abcdefghijklmnop"}'), [["content-type", "application/json"]]);
  const o = JSON.parse(t);
  assert.equal(o.user, "ana");
  assert.equal(o.password, "[redacted]");
  assert.equal(o.card, "[redacted]");
  assert.equal(o.amount, 2599);
  assert.equal(o.note, "Bearer [redacted]");
});

test("card numbers are caught by Luhn, other long numbers are not", () => {
  assert.equal(scrubText("pay 4111 1111 1111 1111 now"), "pay [redacted] now");
  assert.equal(scrubText("order 1234567890123"), "order 1234567890123");
});

test("JWTs are replaced anywhere", () => {
  assert.equal(scrubText("t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij"), "t=[redacted]");
});

test("forms and query strings", () => {
  assert.equal(redactForm("user=ana&password=x&amount=3"), "user=ana&password=[redacted]&amount=3");
  assert.equal(redactTarget("/login?next=%2Fhome&token=abc123"), "/login?next=%2Fhome&token=[redacted]");
  assert.equal(redactTarget("/orders/42"), "/orders/42");
});

test("raw mode leaves bodies alone, off mode drops them", () => {
  const b = body('{"password":"hunter2"}');
  assert.equal(bodyText(b, [], { mode: "raw" }), '{"password":"hunter2"}');
  assert.equal(bodyText(b, [], { mode: "off" }), null);
});

test("compressed bodies are inflated when an inflater is given", () => {
  const z = gzipSync(Buffer.from('{"error":"payments unreachable","token":"zzz"}'));
  const b = { len: z.length, data: new Uint8Array(z), complete: true, holes: 0, truncated: false };
  const inflate = (_enc, data) => new Uint8Array(require_gunzip(data));
  assert.equal(JSON.parse(bodyText(b, [["content-encoding", "gzip"]], { inflate })).token, "[redacted]");
  assert.match(bodyText(b, [["content-encoding", "gzip"]]), /gzip body, \d+ bytes, not decoded/);
});
import { gunzipSync } from "node:zlib";
function require_gunzip(d) { return gunzipSync(Buffer.from(d)); }

test("binary bodies are shown as a size", () => {
  const b = { len: 4, data: new Uint8Array([0, 1, 2, 0]), complete: true, holes: 0, truncated: false };
  assert.equal(bodyText(b, []), "[binary body, 4 bytes]");
});

test("long bodies are cut, partial ones are marked", () => {
  assert.match(bodyText(body("x".repeat(3000)), [], { limit: 100 }), /3000 characters, cut/);
  assert.match(bodyText(body("abc", { complete: false }), []), /captured in part/);
});

test("a sample renders as Slack mrkdwn with escaping", () => {
  const tx = { method: "POST", target: "/orders?api_key=k1", status: 502, reason: "Bad Gateway",
    reqHeaders: [["content-type", "application/json"]], reqBody: body('{"amount":1,"password":"p"}'),
    resHeaders: [["content-type", "text/html"]], resBody: body("<h1>502 Bad Gateway</h1>") };
  const md = sampleMrkdwn(sampleOf(tx), "Latest failing request");
  assert.match(md, /POST \/orders\?api_key=\[redacted\]/);
  assert.match(md, /"password":"\[redacted\]"/);
  assert.match(md, /&lt;h1&gt;502 Bad Gateway&lt;\/h1&gt;/);
  assert.match(md, /^\*Latest failing request\*/);
});

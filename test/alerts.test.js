import { test } from "node:test";
import assert from "node:assert/strict";
import { Apis } from "../src/lib/apis.js";
import { Alerts } from "../src/lib/alerts.js";

/* A served API on port 3000, fed synthetic transactions at chosen times. */
function rig(opts = {}) {
  let now = 1_000_000_000_000;
  const realNow = Date.now;
  Date.now = () => now;
  const apis = new Apis({ name: () => "users-api", listeners: () => new Map([[3000, { pid: 1 }]]) });
  const sent = [];
  const alerts = new Alerts({ apis, listeners: () => new Map([[3000, { pid: 1 }]]), send: (m) => sent.push(m.render()), host: "box", sample: () => "*sample*", ...opts });
  const tx = (status) => apis.observe({ role: "server", pid: 1, method: "GET", target: "/users/7", status, flow: { sport: 3000, daddr: "10.0.0.9", dport: 5555 } });
  const advance = (ms, perSec, share404) => {
    for (let t = 0; t < ms; t += 1000) {
      now += 1000;
      for (let i = 0; i < perSec; i++) tx(i < perSec * share404 ? 404 : 200);
      alerts.check(now);
    }
  };
  return { apis, alerts, sent, advance, restore: () => (Date.now = realNow), now: () => now };
}

test("a normal 404 rate never alerts", () => {
  const r = rig();
  r.advance(15 * 60_000, 10, 0.1);
  assert.equal(r.sent.filter((m) => m.event === "failing_4xx").length, 0);
  r.restore();
});

test("a jump far above the learned baseline alerts once, with the sample, then recovers", () => {
  const r = rig();
  r.advance(10 * 60_000, 10, 0.1); // learn: 10% normal
  r.advance(90_000, 10, 0.6); // spike to 60%
  const fired = r.sent.filter((m) => m.event === "failing_4xx");
  assert.equal(fired.length, 1);
  assert.match(fired[0].title, /4xx jumped to/);
  assert.match(fired[0].text, /against 10% normally/);
  assert.equal(fired[0].detail, "*sample*");
  r.advance(3 * 60_000, 10, 0.1); // back to normal
  assert.equal(r.sent.filter((m) => m.event === "recovered_4xx").length, 1);
  r.restore();
});

test("nothing fires before the baseline is learned", () => {
  const r = rig();
  r.advance(3 * 60_000, 10, 0.9);
  assert.equal(r.sent.filter((m) => m.event === "failing_4xx").length, 0);
  r.restore();
});

test("a long spike does not become the new normal while it fires", () => {
  const r = rig({ remind: 100_000 });
  r.advance(10 * 60_000, 10, 0.05);
  r.advance(20 * 60_000, 10, 0.5);
  assert.equal(r.sent.filter((m) => m.event === "recovered_4xx").length, 0);
  r.restore();
});

test("--client-errors all fires on the first 4xx; off never does", () => {
  const a = rig({ clientErrors: "all" });
  a.advance(5_000, 10, 0.1);
  assert.equal(a.sent.filter((m) => m.event === "failing_4xx").length, 1);
  a.restore();
  const o = rig({ clientErrors: "off" });
  o.advance(15 * 60_000, 10, 0.9);
  assert.equal(o.sent.filter((m) => /4xx/.test(m.event)).length, 0);
  o.restore();
});

test("5xx still alerts on the first error and carries the sample", () => {
  const r = rig();
  r.advance(5_000, 10, 0);
  r.apis.observe({ role: "server", pid: 1, method: "POST", target: "/users", status: 502, flow: { sport: 3000, daddr: "10.0.0.9", dport: 5555 } });
  r.alerts.check(r.now());
  const f = r.sent.filter((m) => m.event === "failing");
  assert.equal(f.length, 1);
  assert.equal(f[0].detail, "*sample*");
  r.restore();
});

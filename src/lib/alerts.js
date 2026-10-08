/* When an API is broken, and the messages that say so.
 *
 * Three signals, all measured, none guessed:
 *
 *   5xx       an API answered `minErrors` or more 5xx responses within
 *             the last `window` seconds. Served APIs are counted from the
 *             server's side, called APIs from the caller's.
 *   4xx       an API's share of 4xx answers in the last `window` seconds
 *             is far above its own normal share (`clientErrors:
 *             "baseline"`), or any 4xx at all (`"all"`). A 404 for a
 *             missing record is normal traffic for many APIs, so the
 *             default compares an API with itself rather than with zero.
 *   down      a served API's port stopped listening (the process exited
 *             or closed it) for `downAfter` seconds. Only ports that have
 *             served HTTP, or were named with --ports, are watched.
 *
 * Every 5xx and 4xx message carries the latest failing exchange, request
 * and response, through the injected `sample(api, cls)`, which redacts.
 *
 * Each API is latched: one message when it breaks, one when it recovers
 * (no 5xx for `recover` seconds, or the port is back), and a reminder
 * every `remind` seconds while it stays broken. Nothing in between.
 *
 * `send(message)` delivers; it is injected so --dry-run prints and the
 * service posts to Slack through yeet.alert.
 */

const clock = (ms) => new Date(ms).toISOString().slice(11, 19) + " UTC";
const span = (ms) => {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  return m < 90 ? `${m} min` : `${(m / 60).toFixed(1)} h`;
};
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const pct = (x) => `${Math.round(x * 100)}%`;

/* How far above normal a 4xx share must be to count as a spike: three
 * times the normal share and ten points above it, so an API that is 2%
 * 404s normally needs 12%, and one that is 30% needs 90%. Back to normal
 * once it falls under one and a half times, and five points above. */
const spikeLevel = (base) => Math.max(base * 3, base + 0.1);
const normalLevel = (base) => Math.max(base * 1.5, base + 0.05);

/* The span a baseline is learned from, before the current window. */
const BASELINE_MS = 30 * 60_000;
const BASELINE_MIN_REQUESTS = 50;

export class Alerts {
  constructor({
    apis, listeners, send, log = () => {}, host = "this host", window = 60, minErrors = 1, recover = 120, remind = 1800,
    downAfter = 5, ports = [], ignore = [], clientErrors = "baseline", minClient = 5, learnMinutes = 5, sample = () => null,
  }) {
    Object.assign(this, { apis, listeners, send, log, host, window, minErrors, recover, remind, downAfter, clientErrors, minClient, learnMinutes, sample });
    this.state = new Map(); // api key -> { state, since, sentAt, total, missingSince }
    this.watchPorts = new Set(ports.map(Number));
    this.ignore = new Set(ignore.map((x) => String(x).toLowerCase()));
  }

  /* --ignore matches an API's name, its host, or its port. */
  ignored(row) {
    if (!this.ignore.size) return false;
    return [row.name, row.host, row.port].some((v) => v != null && this.ignore.has(String(v).toLowerCase()));
  }

  st(key) {
    let s = this.state.get(key);
    if (!s) this.state.set(key, (s = { state: "ok", since: 0, sentAt: 0, total: 0, missingSince: null }));
    return s;
  }

  /** Evaluate every API; call about once a second. */
  check(now = Date.now()) {
    const listeners = this.listeners();
    for (const port of this.watchPorts) {
      if (!this.apis.get(`served:${port}`) && listeners.has(port)) {
        this.apis.ensure(`served:${port}`, { kind: "served", port, transport: 0 }).procs.add(listeners.get(port).pid);
      }
    }

    for (const api of this.apis.byKey.values()) {
      const s = this.st(api.key);
      const row = this.apis.row(api);
      if (this.ignored(row)) continue;

      /* down / up: served ports only */
      if (api.kind === "served" && api.port != null && (api.n > 0 || this.watchPorts.has(api.port))) {
        if (!listeners.has(api.port)) {
          s.missingSince ??= now;
          if (s.state !== "down" && now - s.missingSince >= this.downAfter * 1000) {
            s.state = "down";
            s.since = s.missingSince;
            s.sentAt = now;
            this.emit("down", row, {
              title: `${row.name} stopped listening`,
              body: `Nothing on ${this.host} is listening on port ${api.port} any more (it was *${row.name}*). Every request to it fails until it is back.`,
            });
          }
          continue;
        }
        if (s.state === "down") {
          s.state = "ok";
          this.emit("up", row, {
            title: `${row.name} is listening again`,
            body: `*${row.name}* is listening on port ${api.port} again, after ${span(now - s.since)} down.`,
          });
        }
        s.missingSince = null;
      }

      this.check5xx(api, row, s, now);
      this.check4xx(api, row, now);
    }
  }

  check5xx(api, row, s, now) {
    const recent = this.apis.errorsWithin(api, this.window * 1000, now);
    if (s.state === "ok" && recent >= this.minErrors) {
      s.state = "failing";
      s.since = api.errorTimes[api.errorTimes.length - recent] ?? now;
      s.sentAt = now;
      s.total = recent;
      s.errorsSeen = api.errorTimes.length;
      this.emit("failing", row, () => this.failing(api, this.apis.row(api), this.apis.errorsWithin(api, this.window * 1000), Date.now()));
      return;
    }
    if (s.state !== "failing") return;
    s.total += api.errorTimes.length - s.errorsSeen;
    s.errorsSeen = api.errorTimes.length;
    const last = api.errorTimes[api.errorTimes.length - 1] ?? s.since;
    if (now - last >= this.recover * 1000) {
      s.state = "ok";
      this.emit("recovered", row, {
        title: `${row.name} recovered`,
        body: `No 5xx from *${row.name}* for ${span(now - last)}. It returned ${plural(s.total, "5xx response")} over ${span(last - s.since)}, starting ${clock(s.since)}.`,
      });
    } else if (now - s.sentAt >= this.remind * 1000) {
      s.sentAt = now;
      this.emit("reminder", row, {
        title: `${row.name} is still returning 5xx`,
        body: `*${row.name}* has returned ${plural(s.total, "5xx response")} since ${clock(s.since)} (${span(now - s.since)}), ${recent} in the last ${this.window}s.`,
      });
    }
  }

  /* 4xx, against the API's own normal share ("baseline") or any at all
   * ("all"). Its state is kept apart from the 5xx state, so an API can be
   * both failing and drowning in 401s, and each recovers on its own. */
  check4xx(api, row, now) {
    if (this.clientErrors === "off") return;
    const s = this.st(`${api.key}#4xx`);
    const w = this.window * 1000;
    const cur = this.apis.counts(api, now - w, now + 1);
    const share = cur.req ? cur.c4 / cur.req : 0;

    if (this.clientErrors === "all") {
      const last = api.recent4xx[api.recent4xx.length - 1]?.at ?? 0;
      if (s.state === "ok" && cur.c4 >= this.minErrors && now - last < w) {
        Object.assign(s, { state: "failing", since: now, sentAt: now, last });
        this.emit("failing_4xx", row, () => this.failing4xx(api, this.apis.row(api), null, Date.now()));
      } else if (s.state === "failing" && now - last >= this.recover * 1000) {
        s.state = "ok";
        this.emit("recovered_4xx", row, {
          title: `${row.name} stopped returning 4xx`,
          body: `No 4xx from *${row.name}* for ${span(now - last)}, since it started at ${clock(s.since)}.`,
        });
      }
      return;
    }

    /* baseline: armed once the API has been watched long enough to know
     * what normal is, and only against requests outside this window. */
    if (s.state === "ok") {
      if (now - api.firstAt < this.learnMinutes * 60_000) return;
      const base = this.apis.counts(api, now - BASELINE_MS, now - w);
      if (base.req < BASELINE_MIN_REQUESTS) return;
      const baseShare = base.c4 / base.req;
      if (cur.c4 >= this.minClient && share >= spikeLevel(baseShare)) {
        Object.assign(s, { state: "failing", since: now, sentAt: now, lastSpike: now, baseline: baseShare });
        this.emit("failing_4xx", row, () => this.failing4xx(api, this.apis.row(api), baseShare, Date.now()));
      }
      return;
    }
    /* The baseline is frozen while it is firing: a long spike would
     * otherwise teach the window that the spike is normal. */
    if (share > normalLevel(s.baseline)) s.lastSpike = now;
    if (now - s.lastSpike >= this.recover * 1000) {
      s.state = "ok";
      this.emit("recovered_4xx", row, {
        title: `${row.name} 4xx back to normal`,
        body: `*${row.name}* answered ${pct(share)} of the last ${this.window}s with a 4xx, against ${pct(s.baseline)} normally. The spike started ${clock(s.since)} and lasted ${span(s.lastSpike - s.since)}.`,
      });
    } else if (now - s.sentAt >= this.remind * 1000) {
      s.sentAt = now;
      this.emit("reminder_4xx", row, {
        title: `${row.name} 4xx still above normal`,
        body: `*${row.name}* answered ${pct(share)} of the last ${this.window}s with a 4xx, against ${pct(s.baseline)} normally, since ${clock(s.since)} (${span(now - s.since)}).`,
      });
    }
  }

  failing4xx(api, row, baseShare, now) {
    const w = this.window * 1000;
    const cur = this.apis.counts(api, now - w, now + 1);
    const errs = api.recent4xx.filter((e) => e.at >= now - w);
    const codes = [...new Set(errs.map((e) => e.status))].sort();
    const byEndpoint = new Map();
    for (const e of errs) {
      const k = `${e.method} ${e.path} → ${e.status}`;
      byEndpoint.set(k, (byEndpoint.get(k) ?? 0) + 1);
    }
    const lines = [...byEndpoint].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, n]) => `\`${k}\` ×${n}`);
    const share = cur.req ? cur.c4 / cur.req : 0;
    const who = api.kind === "served"
      ? `*${row.name}* (port ${api.port} on ${this.host}) answered ${cur.c4} of ${cur.req} requests with a 4xx in the last ${this.window}s`
      : `*${row.name}* returned a 4xx to ${cur.c4} of ${cur.req} calls from ${row.process ?? this.host} in the last ${this.window}s`;
    const vs = baseShare == null ? "." : ` (${pct(share)}), against ${pct(baseShare)} normally.`;
    return {
      title: baseShare == null
        ? `${row.name} is returning ${codes.length ? codes.join(" and ") : "4xx"}`
        : `${row.name} 4xx jumped to ${pct(share)}${codes.length ? ` (${codes.join(", ")})` : ""}`,
      body: [who + vs, lines.length ? `Latest (sampled): ${lines.join(", ")}` : null].filter(Boolean).join("\n"),
      detail: this.sample(api, "4xx"),
    };
  }

  failing(api, row, recent, now) {
    const cut = now - this.window * 1000;
    const errs = api.recentErrors.filter((e) => e.at >= cut);
    const codes = [...new Set(errs.map((e) => e.status))].sort();
    const byEndpoint = new Map();
    for (const e of errs) {
      const k = `${e.method} ${e.path} → ${e.status}`;
      byEndpoint.set(k, (byEndpoint.get(k) ?? 0) + 1);
    }
    const lines = [...byEndpoint].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, n]) => `\`${k}\` ×${n}`);
    const total = this.requestsWithin(api, cut);
    const of = total ? `${recent} of ${total}` : `${recent}`;
    const body = api.kind === "served"
      ? `*${row.name}* (port ${api.port} on ${this.host}) answered ${of} requests with a 5xx in the last ${this.window}s.`
      : `*${row.name}* returned a 5xx to ${of} calls from ${row.process ?? this.host} in the last ${this.window}s.`;
    /* Only for an API this box serves: a stopped local port explains a
     * proxy's 502, and says nothing about a third party's 503. */
    const related = api.kind === "served" ? this.related(api.key) : null;
    return {
      title: `${row.name} is returning ${codes.length ? codes.join(" and ") : "5xx"}`,
      body: [body, lines.length ? `Latest: ${lines.join(", ")}` : null, related].filter(Boolean).join("\n"),
      detail: this.sample(api, "5xx"),
    };
  }

  requestsWithin(api, cut) {
    let n = 0;
    const t = api.reqTimes ?? [];
    for (let i = t.length - 1; i >= 0 && t[i] >= cut; i--) n++;
    return n;
  }

  /* A served API on this box whose port is gone is the likeliest reason
   * for a 502 next to it, so a failing message names any such port, even
   * one not yet gone long enough to be called down. */
  related(key) {
    const gone = [];
    for (const [k, s] of this.state) {
      if (k === key || s.missingSince == null) continue;
      const api = this.apis.get(k);
      if (api) gone.push(`${this.apis.label(api)} (port ${api.port}) stopped listening at ${clock(s.missingSince)}`);
    }
    return gone.length ? `On this host, ${gone.join("; ")}.` : null;
  }

  /* `content` is `{ title, body }`, or a function returning it, which is
   * called when the message is sent: a batch goes out seconds after its
   * first entry, and the counts should be the ones at that moment. */
  emit(event, row, content) {
    const at = Date.now();
    const render = () => {
      const { title, body, detail = null } = typeof content === "function" ? content() : content;
      /* Slack refuses a section over 3000 characters. */
      const fit = (t) => (t.length > 2900 ? `${t.slice(0, 2900)}…` : t);
      return {
        event,
        api: row.name,
        title,
        detail,
        text: `${title}: ${body.replace(/[*`]/g, "")}`,
        blocks: [
          { type: "header", text: { type: "plain_text", text: title.slice(0, 150) } },
          { type: "section", text: { type: "mrkdwn", text: fit(body) } },
          ...(detail ? [{ type: "section", text: { type: "mrkdwn", text: fit(detail) } }] : []),
          { type: "context", elements: [{ type: "mrkdwn", text: `${this.host} · ${clock(at)} · apiwatch on yeet` }] },
        ],
      };
    };
    const { title } = typeof content === "function" ? content() : content;
    this.log({ event, api: row.name, kind: row.kind, port: row.port, title });
    this.send({ event, render });
  }
}

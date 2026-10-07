/* When an API is broken, and the messages that say so.
 *
 * Two signals, both measured, neither guessed:
 *
 *   5xx       an API answered `minErrors` or more 5xx responses within
 *             the last `window` seconds. Served APIs are counted from the
 *             server's side, called APIs from the caller's.
 *   down      a served API's port stopped listening (the process exited
 *             or closed it) for `downAfter` seconds. Only ports that have
 *             served HTTP, or were named with --ports, are watched.
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

export class Alerts {
  constructor({ apis, listeners, send, log = () => {}, host = "this host", window = 60, minErrors = 1, recover = 120, remind = 1800, downAfter = 5, ports = [], ignore = [] }) {
    Object.assign(this, { apis, listeners, send, log, host, window, minErrors, recover, remind, downAfter });
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

      /* 5xx */
      const recent = this.apis.errorsWithin(api, this.window * 1000, now);
      if (s.state === "ok" && recent >= this.minErrors) {
        s.state = "failing";
        s.since = api.errorTimes[api.errorTimes.length - recent] ?? now;
        s.sentAt = now;
        s.total = recent;
        s.errorsSeen = api.errorTimes.length;
        this.emit("failing", row, () => this.failing(api, this.apis.row(api), this.apis.errorsWithin(api, this.window * 1000), Date.now()));
        continue;
      }
      if (s.state === "failing") {
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
    }
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
    const related = this.related(api.key);
    return {
      title: `${row.name} is returning ${codes.length ? codes.join(" and ") : "5xx"}`,
      body: [body, lines.length ? `Latest: ${lines.join(", ")}` : null, related].filter(Boolean).join("\n"),
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
      const { title, body } = typeof content === "function" ? content() : content;
      return {
        event,
        api: row.name,
        title,
        text: `${title}: ${body.replace(/[*`]/g, "")}`,
        blocks: [
          { type: "header", text: { type: "plain_text", text: title.slice(0, 150) } },
          { type: "section", text: { type: "mrkdwn", text: body } },
          { type: "context", elements: [{ type: "mrkdwn", text: `${this.host} · ${clock(at)} · apiwatch on yeet` }] },
        ],
      };
    };
    const { title } = typeof content === "function" ? content() : content;
    this.log({ event, api: row.name, kind: row.kind, port: row.port, title });
    this.send({ event, render });
  }
}

# `apiwatch`

> `ss -tlnp` for the HTTP APIs on a box, plus a Slack message when one of them starts returning 502s.

<p align="center">
  <a href="#requirements"><img src="https://img.shields.io/badge/platform-Linux-1793D1" alt="Linux: kernel 6.1+ with BTF, kprobes and uprobes"></a>
  <a href="https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=apiwatch&utm_content=badge"><img src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-8A2BE2" alt="Built with yeet and eBPF"></a>
  <a href="#what-youre-looking-at"><img src="https://img.shields.io/badge/category-HTTP%20APIs-005A9C" alt="Category: HTTP API inventory and 5xx alerting"></a>
  <a href="https://discord.gg/JxVseaAVAU"><img src="https://img.shields.io/badge/chat-Discord-5865F2" alt="Chat with the yeet team on Discord"></a>
</p>

<!-- <p align="center"><img src="assets/apiwatch.gif" width="820" alt="apiwatch --discover listing the APIs a test box serves and calls"></p> -->

**`apiwatch` is an eBPF API watchdog for Linux: it lists every HTTP API a machine serves and calls, from live traffic, and messages Slack with the failing request when one breaks.**

## Quick start

```sh
curl -fsSL https://yeet.cx | sh    # install yeet, once
yeet run gh:yeet-src/apiwatch      # clone, build, and list this box's APIs from 30s of traffic
```

Point it at a server you didn't build and a minute later you have the list nobody wrote down: which ports answer HTTP and which process owns each one, the endpoints they actually serve and the status codes they return, who calls them, and which outside APIs (Stripe, a weather service, a partner's endpoint) the machine calls in turn, with the status codes those return. It comes from the traffic itself, so an API that exists only in a config file nobody reads still shows up, and a route the docs promise but nobody calls doesn't.

The usual way to get that list is `ss -tlnp`, which gives you ports and process names but not whether a port speaks HTTP, plus reading every nginx config and service unit by hand. The usual way to get told when one of those APIs breaks is an uptime checker or a synthetic test, which only knows about the endpoints you remembered to configure and only sees its own requests. `apiwatch --watch` alerts on the responses your real clients got, for every API it has seen, and it is one process on the box rather than a monitoring stack.

> [!TIP]
> It reads HTTP where the kernel hands it to the socket (kprobes on `tcp_sendmsg` and `tcp_recvmsg`) and reads HTTPS where OpenSSL decrypts it (uprobes on `SSL_read` and `SSL_write`). So it sees both ends of a loopback hop like nginx → your app, and the plaintext of your app's outbound HTTPS calls, with no proxy, no sidecar, and no change to the app.

## Contents

**Run it** — [Get started](#get-started) · [Leave it running](#leave-it-running-as-a-service) · [Agent setup](#have-an-agent-set-it-up) · [Without a TTY](#reading-it-without-a-tty)<br>
**Understand it** — [A 30-second primer](#a-30-second-primer-on-reading-apis-from-the-kernel) · [Questions this tool answers](#questions-this-tool-answers) · [What you're looking at](#what-youre-looking-at) · [How it works](#how-it-works)<br>
**Reference** — [Demo traffic](#try-it-without-real-traffic) · [Requirements](#requirements) · [What it can't see](#what-it-cant-see) · [FAQ](#faq)<br>
**Contribute** — [Building from source](#building-from-source) · [Testing across kernels](#testing-across-kernels)

## Get started

```sh
curl -fsSL https://yeet.cx | sh
git clone https://github.com/yeet-src/apiwatch && cd apiwatch && make   # compile bin/*.bpf.o (toolchain auto-fetched)
yeet run . -- --discover                                                  # watch for 30s, print the APIs, exit
```
<sub>[Manual install guide](https://yeet.cx/docs/install/manual-installation?utm_source=github&utm_medium=readme&utm_campaign=apiwatch) | Linux only</sub>

`apiwatch` has three modes, and every flag goes after `--` so `yeet run` hands it to the script instead of reading it as its own.

```sh
yeet run . -- --discover --seconds 60          # list the APIs seen in a 60s window, as text
yeet run . -- --discover --seconds 60 --json   # the same, as one JSON object
yeet run . -- --watch --dry-run                # keep watching, print alerts instead of sending them
yeet run . -- --test-alert --slack "#api-alerts" --name web-1   # post one message to prove Slack works
yeet run . -- --watch --slack "#api-alerts" --name web-1        # the real thing; see below to keep it running
```

`yeet run .` runs whatever is in `bin/`, it does not build, so run `make` after every pull. `yeet run gh:yeet-src/apiwatch` is the exception: a remote source is cloned and built for you.

The thresholds `--watch` uses, and why each default is what it is:

| flag | default | what it decides |
| --- | --- | --- |
| `--min-errors` | `1` | 5xx responses within the window that make an API broken. One, because "502 even once" is what most people mean by broken; raise it for an API that is flaky by design. |
| `--window` | `60` | Seconds of history each check counts 5xx in. |
| `--recover` | `120` | Seconds without a 5xx before an API counts as recovered. Never shorter than `--window`, so a recovery can't be announced while errors are still in the window. |
| `--remind` | `1800` | Seconds between "still broken" messages, so a long outage is one alert plus a reminder every half hour, not a stream. |
| `--down-after` | `5` | Seconds a served port must be gone before "stopped listening" fires, so a restart doesn't page you. |
| `--ignore` | none | APIs never to alert on, by name, host or port: `--ignore httpbin.org,8082`. |
| `--ports` | all | Capture only these ports, filtered in the kernel. Also watches them for going down from the first second, before any traffic is seen. |
| `--client-errors` | `baseline` | 4xx alerts. `baseline` learns each API's normal 4xx share over its first five minutes and alerts when the last minute is at least three times that and ten points higher, because a 404 for a missing record is normal traffic for many APIs. `all` alerts on any 4xx like a 5xx; `off` never. |
| `--client-codes` | every 4xx | Count only these statuses as 4xx, e.g. `--client-codes 401,403,429` to watch auth failures and rate limiting and ignore 404s. |
| `--min-client-errors` | `5` | 4xx answers within the window before a jump can fire, so three 404s on a quiet API are not a spike. |
| `--bodies` | `redacted` | The failing request and its response in each 5xx and 4xx alert, about 1000 characters each. `redacted` blanks values under secret-looking keys (password, token, api_key, authorization, card, cvv, ssn and similar) in JSON, forms and query strings, plus bearer tokens, JWTs and card numbers anywhere. `raw` sends them as captured; `off` sends method, path and status only. |

### Slack, once

Messages go out through yeet's own Slack connection rather than a webhook you manage. Two one-time steps, both on the host that runs `apiwatch`:

1. Sign the host in with `yeet login`. It prints a `https://yeet.cx/x/…` link and waits until you approve it in a browser.
2. Connect your Slack workspace at [yeet.cx/settings](https://yeet.cx/settings?utm_source=github&utm_medium=readme&utm_campaign=apiwatch), and invite the yeet app to the channel if it is private.

Then `--test-alert` sends one message through `yeet.alert`. If the host isn't signed in, or the post is refused, it prints why and exits non-zero.

Alerts carry the failing request and response, and like every alert they travel through yeet's servers to Slack. Secret fields are blanked by default; other personal data, an email address for instance, is not. Use `--bodies off` if request bodies must not leave the host.

### Leave it running as a service

`--watch` belongs in a [yeet service](https://yeet.cx/docs/cli/services?utm_source=github&utm_medium=readme&utm_campaign=apiwatch), which the daemon keeps running after your shell closes, restarts if it dies, and starts again at boot:

```sh
git clone --depth 1 https://github.com/yeet-src/apiwatch ~/.local/share/apiwatch
make -C ~/.local/share/apiwatch
yeet service new apiwatch -C ~/.local/share/apiwatch -R always
yeet service unit add apiwatch/watch -I ~/.local/share/apiwatch/src/main.js -- --watch --slack "#api-alerts" --name "$(hostname)"
yeet service unit add apiwatch/web -W http://127.0.0.1:9470
yeet service mount apiwatch/web -L /log -t watch -p console
yeet service enable apiwatch
yeet service start apiwatch
curl -sN http://127.0.0.1:9470/log   # the watcher's JSON lines, streamed as they happen
```

The `web` unit and the `/log` route serve the watcher's console over plain HTTP: a `GET` gets a chunked `text/plain` body, one JSON line per event, open until you disconnect. Routes on a service's web server answer only while the host is signed in, so on a signed-out host `/log` returns `403` with a "Pair this host" page. `127.0.0.1` keeps it on this machine; bind another address only if you mean to share the log.

Build it yourself and point the unit at the built checkout. A unit added straight from `gh:yeet-src/apiwatch` is cloned but never built, so it restarts forever on a missing `bin/socket.bpf.o`. Give `-I` an absolute path, since a relative one resolves against wherever you ran the command. The service runs its own copy of the directory, so a `git pull`, a `make` and a restart still run the old code. To update, stop the service, `yeet service unit remove apiwatch/watch`, add the unit again with the same arguments, and start it. Or create the service with `--dev`, which runs the checkout in place so a restart picks up a rebuild (and breaks if you delete the checkout).

`yeet service stop apiwatch` pauses it, `yeet service remove apiwatch` removes it.

## Have an agent set it up

Paste this into Claude Code, Codex or Cursor on the Linux machine:

```text
Set up apiwatch (https://github.com/yeet-src/apiwatch) on this machine and show me its APIs.
1. Check `uname -s` is Linux and `yeet --version` works; if not, install yeet with
   `curl -fsSL https://yeet.cx | sh`. Make sure `make` and `git` are installed.
2. Clone the repo, read its README, and run `make`. Never run `yeet` with sudo.
3. Run `yeet run . -- --discover --seconds 60`. Watch only: do not send requests to my
   services to generate traffic or errors.
4. If nothing is served because the machine is quiet, prove capture works with your own
   throwaway traffic: `python3 -m http.server 8099 --bind 127.0.0.1` plus a curl loop against
   it, run discovery again, confirm port 8099 appears, then stop both by PID.
5. Report what it found. "It compiled" is not the same as "it works": a row for a real
   port with real status codes is.
The trap: `yeet run .` never builds. If it fails with "Failed to open BPF object", run `make`.
```

Prefer to drive it yourself? [Get started](#get-started) is three lines.

## A 30-second primer on reading APIs from the kernel

Every HTTP request on a Linux box, from any language, ends up in two kernel functions: `tcp_sendmsg` when a process writes bytes to a TCP socket and `tcp_recvmsg` when it reads them. A **kprobe** is a hook on a kernel function, so a kprobe on those two sees every request and every response as it leaves or enters a process, along with which process it was. That is where the **served** APIs come from (a process reading a request on a port it listens on) and the **called** ones (a process writing a request to someone else).

A **loopback hop** is a call between two processes on the same box, like nginx forwarding to your app on `127.0.0.1:8081`. The kprobes see it twice, once from each side; `apiwatch` counts it once, on the served API, and records the other side as the caller.

HTTPS is ciphertext at that layer. The plaintext only exists inside the TLS library, before it encrypts and after it decrypts. A **uprobe** is a hook on a function in a user program or shared library, and a uprobe on OpenSSL's `SSL_write` and `SSL_read` reads the request and response in the clear. For a TLS library with no hook, the one readable thing is the **SNI**, the hostname the client asks for in its first plaintext message. So `apiwatch` can always say *which* API a process called over HTTPS, and can say *what it answered* only where the TLS library is hookable.

## Questions this tool answers

**I inherited a Linux server and nobody can tell me which APIs run on it or what they call. How do I get a list without reading every config file?**
Run `--discover` for a minute. It lists every port that answered HTTP with the process behind it (the systemd unit name when there is one), the endpoints actually requested, the status codes returned and who called them, then every outside API the box called. Ports that listen but carried no HTTP are listed separately, so you also see what was idle. See [What you're looking at](#what-youre-looking-at).

**My service keeps returning 502s and I can't tell whether it's nginx, my app, or something behind my app. How do I see which hop is actually failing?**
Each hop is its own row: nginx on `:80`, the app on `:8081`, its upstream on `:8082`, each with its own status codes and callers. A 502 counted at nginx but not at the app means the app never answered; a 502 at both means the app is passing on its upstream's failure. When a local upstream's port disappears, the alert names it in the same message.

**My app calls third-party APIs over HTTPS and I want to know when they return errors, without adding logging or putting a proxy in front of them. Can I?**
Yes, for programs that use OpenSSL through the system's `libssl` (Python's `urllib`, curl, and Node's `fetch` were all checked) or rustls. The hook is on the library file, so a process started after `apiwatch` is covered too. The uprobes on `SSL_read`/`SSL_write` read the response status in the clear, so `httpbin.org` returning a 503 to your sync job shows up as exactly that. Go's `crypto/tls` is not readable; those calls are listed by hostname with no status. See [What it can't see](#what-it-cant-see).

**How do I get a Slack message when an API on a host starts returning 5xx, based on what real clients got rather than a synthetic health check?**
Run `--watch --slack "#channel"` as a [service](#leave-it-running-as-a-service). It counts 5xx responses per API from live traffic and posts when an API crosses `--min-errors` within `--window` seconds, and separately when a served API's port stops listening, which catches a crashed process even when no requests are arriving.

**During an outage I don't want a Slack message for every single 502. How does it keep the noise down?**
Each API is latched: one message when it breaks, one when it recovers (no 5xx for `--recover` seconds, or its port is back), and a reminder every `--remind` seconds while it stays broken. Problems that start within six seconds of each other go out as one message, so an upstream that dies and takes nginx and the app down with it arrives as "3 APIs broke on web-1", not three pings. `--ignore` silences an API that is flaky by design.

**What's the lightest way to add 5xx alerting to one Linux box without standing up Prometheus, an exporter and Alertmanager?**
`apiwatch` is one process and one yeet service with no config file; the thresholds are flags. On a test box handling about seven HTTP exchanges a second, the script's JavaScript used about 0.3% of one core over five minutes with its heap between 4 and 9 MiB, and the kernel probes ran for 16 ms in two minutes (about 2 µs per send, under 1 µs per receive), not counting the kernel's own cost of firing a kprobe. That cost grows with how much TCP traffic the box carries, not just HTTP, so on a busy machine give it `--ports`. See [What it can't see](#what-it-cant-see).

**An API started answering 401s or 429s and nobody noticed until customers complained. How do I get told when an API's client errors jump, without paging on every 404?**
Leave `--client-errors baseline` on. Each API learns its own normal share of 4xx answers over its first five minutes, and the alert fires when the last minute is at least three times that share and ten points higher, with the request that got the 4xx and the response it got. An API that normally answers 15% 404s alerts at 45%, not at the first 404. `--client-codes 401,403,429` narrows it to auth failures and rate limiting.

**When an API starts failing, how do I see the actual request that failed and the error it returned, without turning on request logging?**
Every 5xx and 4xx alert carries the latest failing exchange: the method and path, the request body, the status, and the response body, about 1000 characters each, read off the socket. Passwords, tokens, API keys and card numbers are blanked before they leave the host; `--bodies off` drops the bodies. For HTTPS this needs a readable TLS library (see the question above).

**Is this a replacement for Datadog, New Relic, or Prometheus with Alertmanager?**
No. It watches one host, keeps nothing once it restarts, has no dashboards, no history, no latency alerts, no on-call routing or escalation, and posts to Slack only. It is for knowing which APIs a machine has and hearing about it when one of them starts returning 5xx, on hosts where a full observability stack isn't there or isn't watching these APIs.

**When should I use this instead of an uptime checker like UptimeRobot or Pingdom, Datadog Synthetics, or a deeper tool like httpscope?**
Use an uptime checker when the question is "can the outside world reach my site", since `apiwatch` sees only traffic that reached the box. Use synthetics when you need a scripted multi-step check, like a login followed by a checkout. Use [`httpscope`](https://github.com/yeet-src/httpscope) when you want the full shape of each API (request and response schemas, drift between deploys, a GraphQL interface an agent can query), and [`container-traffic`](https://github.com/yeet-src/container-traffic) for a live per-container rate, error and latency dashboard. Use `apiwatch` for the inventory plus a 5xx alert from real traffic, with nothing else to run.

## What you're looking at

`--discover` on a test box running nginx in front of two Python services, with a load generator as the clients, a sync job calling a partner API that fails one call in seven, and an order service fetching a weather forecast:

```console
$ yeet run gh:yeet-src/apiwatch -- --discover --seconds 60
apiwatch: watching this machine's HTTP traffic for 60s…

Saw 405 HTTP exchanges in 60s: 3 served APIs, 2 called.

Served by this machine
  nginx  port 80 on 0.0.0.0 (the network)  177 requests  200 ×139, 201 ×38
      GET /api/orders/{n} ×113 · POST /api/orders ×38 · GET /api/health ×16 · GET /payments/health ×10
      called by shop-loadgen, 160 short-lived processes that exited before they could be named
  shop-orders  port 8081 on 127.0.0.1 (this machine only)  167 requests  200 ×129, 201 ×38
      GET /orders/{n} ×113 · POST /orders ×38 · GET /health ×16
      called by nginx
  shop-payments  port 8082 on 127.0.0.1 (this machine only)  48 requests  200 ×48
      POST /charges ×38 · GET /health ×10
      called by shop-orders, nginx

Called by this machine
  httpbin.org  https  11 calls  200 ×10, 503 ×1  from shop-partner-sync
      POST /status/200,200,200,200,200,200,503 ×11
  api.open-meteo.com  https  2 calls  200 ×2  from shop-orders
      GET /v1/forecast ×2

Listening, but no HTTP seen in the window
  port 22 on 0.0.0.0 (the network)  ssh
  port 53 on 127.0.0.54 (this machine only)  systemd-resolved

TLS read through: /usr/lib/aarch64-linux-gnu/libssl.so.3 [openssl,openssl_ex]
```

The first line is the window. **Served by this machine** has one entry per listening port that answered HTTP; **Called by this machine** has one per API host the box called. A fourth group, **Called, named from the TLS handshake but not readable**, appears when a process made HTTPS calls through a library with no hook, and lists them by hostname. The last line says which TLS libraries were read.

| part of an entry | what it means |
| --- | --- |
| name | The systemd unit (`shop-orders.service` → `shop-orders`), else `container <id>`, else the script an interpreter runs (`orders_api.py`), else the command. For a called API, the host the caller asked for. |
| `port 80 on 0.0.0.0 (the network)` | The listening address. `the network` means any interface, `this machine only` means loopback. |
| `177 requests` | Exchanges seen in the window, counted once per hop. |
| `200 ×139, 201 ×38` | Every status code seen, most frequent first. Any 5xx here is what `--watch` would alert on. |
| `GET /api/orders/{n} ×113` | Top endpoints. Digits, UUIDs, hex ids, dates, emails and long tokens in a path become `{n}`, `{uuid}`, `{hex}` and so on, so one route is one line. |
| `called by` | Who sent the requests: local processes by name, or `remote clients` for anything off the box. A process that exits within milliseconds (a `curl` in a loop) is counted, not named. |
| `from shop-partner-sync` | For a called API, the process that made the calls. |

`--watch` writes one JSON line per event. Running as `--watch --dry-run --name shop-box --ignore httpbin.org` while the payments upstream was stopped and a client kept posting orders with a password and a card number in them:

```console
{"t":"2026-10-08T17:26:42.577Z","event":"failing","api":"shop-orders","kind":"served","port":8081,"title":"shop-orders is returning 502"}
{"t":"2026-10-08T17:26:42.577Z","event":"failing","api":"nginx","kind":"served","port":80,"title":"nginx is returning 502"}
{"t":"2026-10-08T17:26:47.575Z","event":"down","api":"shop-payments","kind":"served","port":8082,"title":"shop-payments stopped listening"}
```

Those three landed within six seconds, so they go out as one message. This is it as Slack would show it, from the same run:

````text
3 APIs broke on shop-box
shop-orders is returning 502
  shop-orders (port 8081 on shop-box) answered 25 of 82 requests with a 5xx in the last 60s.
  Latest: POST /orders → 502 ×8
  On this host, shop-payments (port 8082) stopped listening at 17:26:42 UTC.
  Latest failing request (secrets redacted)
  ```POST /orders
  content-type: application/json

  {"amount":1999,"email":"ana@example.com","card_number":"[redacted]","password":"[redacted]"}```
  Response
  ```502 Bad Gateway
  content-type: application/json

  {"error":"payments unreachable: <urlopen error [Errno 111] Connection refused>"}```
nginx is returning 502
  nginx (port 80 on shop-box) answered 45 of 105 requests with a 5xx in the last 60s.
  Latest: GET /payments/health → 502 ×4, POST /api/orders → 502 ×4
  On this host, shop-payments (port 8082) stopped listening at 17:26:42 UTC.
  Latest failing request (secrets redacted)
  ```GET /payments/health?region=us&access_token=[redacted]```
  Response
  ```502 Bad Gateway
  content-type: text/html

  <html><head><title>502 Bad Gateway</title></head> …```
shop-payments stopped listening
  Nothing on shop-box is listening on port 8082 any more (it was shop-payments).
  Every request to it fails until it is back.
shop-box · 17:26:42 UTC · apiwatch on yeet
````

A 4xx jump, from a Node API that normally answers 15% 404s for users that don't exist, when a client started asking for one that never would:

````text
users-api 4xx jumped to 52% (404)
  users-api (port 3000 on users-box) answered 39 of 75 requests with a 4xx in the last 60s (52%), against 15% normally.
  Latest (sampled): GET /users/{n} → 404 ×8
  Latest failing request (secrets redacted)
  ```GET /users/99?api_key=[redacted]```
  Response
  ```404 Not Found
  content-type: application/json

  {"error":"not found"}```
users-box · 17:28:41 UTC · apiwatch on yeet
````

Four minutes later the same API reported "users-api 4xx back to normal: 13% of the last 60s, against 15% normally."

| event | when |
| --- | --- |
| `start` | The watcher started: host label, channel, whether the host is signed in. |
| `status` | 20 s after start, then every minute: every API being watched with its request and 5xx counts, whether the host is signed in, the `--bodies` and `--client-errors` modes, which TLS libraries are tapped. |
| `failing` | An API crossed `--min-errors` 5xx within `--window`. |
| `failing_4xx` / `recovered_4xx` / `reminder_4xx` | An API's 4xx share jumped past its baseline (or, with `--client-errors all`, any 4xx), came back to normal, or is still high after `--remind` seconds. |
| `down` / `up` | A served port stopped listening for `--down-after` seconds, and came back. |
| `reminder` | Still failing after `--remind` seconds. |
| `recovered` | No 5xx for `--recover` seconds. |
| `sent` / `send_failed` | What happened to the Slack post, with the error when it failed. |
| `alert` | With `--dry-run`, the message that would have been posted, in place of `sent`. |

## Reading it without a TTY

`apiwatch` never draws a screen, so it is safe to pipe, redirect, and run from an agent or a CI job.

- `--discover` prints plain text and exits after `--seconds`. `--discover --json` prints one JSON object with `served`, `called`, `unreadable`, `quiet` and `tls` arrays and the same fields as the text.
- `--watch` prints JSON lines on stdout until stopped. As a service with the `/log` route, `curl -sN http://127.0.0.1:9470/log` streams them; without the route, `yeet attach -c <isolate id>` does, the id from `yeet service tree apiwatch`. Either way you see only lines printed after you connect, which is why `status` repeats every minute: connect at any time and one arrives within a minute.
- `--test-alert` exits non-zero and prints the reason when the host isn't signed in or Slack refuses the post, so it works as a check in a script.

To verify an install, run `--discover --seconds 30` with something generating HTTP, as in [Try it without real traffic](#try-it-without-real-traffic), and look for that port in the served list.

## How it works

There is no bundle step: `src/main.js` imports its modules by relative path and yeet runs it as is. `src/lib/probes/` is the only code that touches `yeet:bpf`; everything under `src/lib/http/` and the registry and alert modules are plain JavaScript with no runtime imports.

```text
bpf/
  socket/socket.bpf.c     kprobes on tcp_sendmsg and tcp_recvmsg: plaintext on any port
  ssl/ssl.bpf.c           uprobes on SSL_write / SSL_read
  ssl_ex/ssl_ex.bpf.c     uprobes on SSL_write_ex / SSL_read_ex (CPython, OpenSSL 1.1.1+)
  rustls/rustls.bpf.c     uprobes on rustls's plaintext sink and reader
  include/tap.h           the TLS taps' shared maps and the TLS-to-socket correlation
  include/events.h        the one record type every tap emits
src/
  main.js                 flags, the three modes, output, the Slack queue
  lib/capture.js          loads the taps, keeps the socket inventory, names TLS calls by SNI
  lib/apis.js             transactions → served and called APIs, endpoints, status counts
  lib/alerts.js           5xx, the 4xx baseline, port-down, latching, recovery and reminders
  lib/bodies.js           the request and response an alert shows, redacted
  lib/procs.js            pid → systemd unit, container, script or command
  lib/sni.js              the hostname in a TLS ClientHello
  lib/path.js             /users/42 → /users/{n}
  lib/http/               HTTP/1.x and HTTP/2 (HPACK) decoding
  lib/probes/             the BPF loaders, the socket inventory, TLS library discovery
```

### The BPF side

Every tap emits the same `data_event` (pid, an opaque connection id, direction, the 4-tuple, and up to 4095 bytes) into a 16 MiB `RINGBUF`, so one decoder serves them all. A single call is copied as up to eight such records, about 32 KiB.

| object | program | hook | captures |
| --- | --- | --- | --- |
| `socket` | `on_sendmsg` | `kprobe/tcp_sendmsg` | bytes a process writes to any TCP socket |
| `socket` | `on_recvmsg_enter` | `kprobe/tcp_recvmsg` | the read's buffer, stashed per thread |
| `socket` | `on_recvmsg_exit` | `kretprobe/tcp_recvmsg` | the bytes that read returned |
| `ssl` | `ssl_write`, `ssl_read_enter`, `ssl_read_exit` | uprobes on `SSL_write`, `SSL_read` | HTTPS plaintext, both directions |
| `ssl_ex` | `ssl_write_ex`, `ssl_read_ex_enter`, `ssl_read_ex_exit` | uprobes on `SSL_write_ex`, `SSL_read_ex` | the same, for the `_ex` API |
| `rustls` | `rust_tls_write`, `rust_tls_read` | uprobes matched by regex on demangled names | rustls plaintext |
| every TLS tap | `peer_sendmsg`, `peer_recvmsg` | kprobes on `tcp_sendmsg`, `tcp_recvmsg` | which socket a TLS connection is on |

The socket tap's filter runs in the kernel before anything is copied: `ignore_ports`, `focus_pids` and `focus_ports` are `HASH` maps, and a `capture_all` byte in `.bss` is patched from JavaScript. `--ports` arms `focus_ports`; without it, `capture_all` is on. A read's arguments travel from entry to return in `active_reads`, an `LRU_HASH` keyed per thread.

The TLS taps attach to a library file, not to a process: one uprobe on the box's `libssl` fires for every process that maps it, now and later, including a `curl` that lives for 50 ms and could never be attached by pid in time. Each library is found from the system graph's memory maps and attached through `/proc/<pid>/root`, so a container's own `libssl` is the file hooked. The two `peer_*` kprobes bind each TLS connection to its socket: the thread that just entered `SSL_write` is the thread about to call `tcp_sendmsg`.

<details>
<summary>The <code>iov_iter</code> reshuffle, and why one source builds on both sides of 6.4</summary>

Linux 6.4 renamed `iov_iter`'s iovec pointer from `iov` to `__iov` and renumbered `enum iter_type` with `ITER_UBUF` first. CO-RE handles that at load time, but only if the source compiles at all, and `vmlinux.h` is generated from the build host's own kernel. Built on 6.1, a plain `BPF_CORE_READ(it, __iov)` fails with `no member named '__iov'`.

So both spellings go through local flavors, `struct iov_iter___old { iov }` and `struct iov_iter___new { __iov; ubuf }` with `preserve_access_index`, and the enum through `enum iter_type___new { ITER_UBUF___new }`. libbpf strips the `___suffix` when it matches types and enumerators against the running kernel, so the branch for the layout the kernel doesn't have is pruned before the verifier sees it. `ITER_UBUF` is what a plain `write(2)` or `read(2)` on a socket produces, and 6.1 already has it, so its branch is guarded on the enum's existence rather than on `__iov`'s.

</details>

### The JS side

| file | does |
| --- | --- |
| `lib/http/decoder.js` | One entry per connection. Decides from the first bytes whether it carries HTTP/1, the HTTP/2 preface, a TLS record or something else, holds records 20 ms to put them back in kernel-timestamp order, pairs requests with responses, and accounts for bytes the copy missed so a gap costs a body, not the framing. |
| `lib/http/h1.js`, `h2.js`, `hpack.js` | HTTP/1.x (content-length, chunked, pipelining) and HTTP/2 frames with HPACK header decoding. |
| `lib/apis.js` | Keys each transaction to an API: served by local port, called by `Host`. Drops the client side of a loopback hop into the served API's caller list. Keeps request and 4xx counts in 10-second buckets for about half an hour, the baseline's memory, and the latest failing exchange of each class. |
| `lib/alerts.js` | Per-API state: `ok`, `failing`, `down` for 5xx and ports, and a separate `ok`/`failing` for 4xx with the baseline frozen while it fires. Only transitions and reminders produce messages. |
| `lib/bodies.js` | The exchange an alert shows: inflates gzip, deflate and brotli bodies through `yeet:compression`, cuts each to about 1000 characters, and redacts by key name in JSON, forms and query strings and by shape (bearer tokens, JWTs, Luhn-valid card numbers) everywhere else. Headers other than the content type are never shown. |
| `lib/procs.js` | Names a pid from its cgroup and command line, looked up the moment its first byte is captured, before a short-lived process can exit. |
| `lib/capture.js` | Polls the socket inventory every 2 s for listeners, rescans for TLS libraries every 60 s, and records the SNI of each ClientHello so an unreadable call still has a name. |

Everything the kernel could do but doesn't (parsing, pairing, templating paths, deciding what is broken) happens here, because a parser in BPF is a parser the verifier has to prove terminates, and every byte of it costs on every packet.

### Why kprobes on the socket, not a proxy, a packet tap, or fentry

A proxy sees only the traffic routed through it and, for HTTPS, has to terminate TLS to read it. A packet tap at the network interface sees loopback only if it is attached there too, and sees HTTPS as ciphertext with no process attached. `tcp_sendmsg` and `tcp_recvmsg` are where every TCP byte crosses between a process and the kernel, with the process in hand, on every interface including `lo`.

They are kprobes rather than fentry, which is cheaper and BTF-typed, because fentry cannot attach to kernel functions on arm64 before 6.4. That includes AWS Graviton on Amazon Linux 2023, which runs 6.1. A kprobe attaches everywhere this runs.

## Building from source

```sh
make              # compile every bpf/<name>/ into bin/<name>.bpf.o (the default goal)
make veristat     # load each object and let this kernel's verifier judge it (needs sudo)
make clean-bpf    # remove bin/*.bpf.o, .build/ and the generated vmlinux.h
```

`make` fetches a pinned, static clang and bpftool into a per-machine cache under `~/.cache/yeet/toolchain` on first use, generates `bpf/include/vmlinux.h` from the running kernel's BTF, compiles each `bpf/<name>/` directory, and links it into its own `bin/<name>.bpf.o`. Each TLS tap is a separate object because a library may offer some of those symbols and not others, and the daemon rejects an object with an unattached uprobe. No system clang, no Node and no npm are needed, only `make` itself. `bin/*.bpf.o`, `.build/` and `vmlinux.h` are build artifacts and gitignored. `build/bpf.mk` does not track header dependencies, so after editing anything under `bpf/include/`, run `make clean-bpf` first.

## Testing across kernels

A BPF program that loads on your laptop can be rejected by an older kernel's verifier. `sudo make veristat` checks every object against the kernel you are on; that `sudo` is correct, since it loads programs directly rather than through the yeet daemon.

`.github/workflows/kernel-matrix.yml` runs the same check on every push to `main` across 6.1, 6.6, 6.12, 6.18, 7.2 and bpf-next, booting each kernel under QEMU with cilium's little-vm-helper, and pivots the results into one grid of program × kernel. bpf-next runs but does not gate. `make veristat-matrix` runs the matrix locally on Linux with KVM. The matrix runs on x86_64 and proves each program verifies, which is not the same as attaching. Attaching and capturing have been run by hand on arm64 6.1 (Debian 12) and 6.12 (Debian 13).

## Try it without real traffic

The repo has no demo script. On a box with nothing serving HTTP, make some of your own:

```sh
python3 -m http.server 8099 --bind 127.0.0.1 &
( for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:8099/; curl -s -o /dev/null https://example.com; sleep 0.5; done ) &
yeet run . -- --discover --seconds 25
```

`http.server` on port 8099 should appear under **Served by this machine** with `GET /` and 200s, and `example.com` under **Called by this machine** over `https` from `curl`. Kill the two background jobs afterwards. To see an alert, run `--watch --dry-run` instead and stop the server: port 8099 stops listening and a `down` event follows within `--down-after` seconds.

## Requirements

> [!IMPORTANT]
> - **Linux 6.1 or newer**, the floor of the kernel matrix, on x86_64 or arm64.
> - **BTF** (`CONFIG_DEBUG_INFO_BTF=y`), for CO-RE: the objects relocate against the running kernel at load time, so there is no per-kernel rebuild. If `/sys/kernel/btf/vmlinux` exists, you have it.
> - **kprobes and uprobes** (`CONFIG_KPROBES`, `CONFIG_UPROBES`). `grep -E 'CONFIG_(K|U)PROBES=' /boot/config-$(uname -r)` shows both.
> - **`make` and `git`** to build. The compiler toolchain is downloaded by `make`.
> - **The yeet daemon**, which does the privileged load. `yeet run` itself never needs `sudo`.
> - **For Slack:** the host signed in with `yeet login`, and a workspace connected at [yeet.cx/settings](https://yeet.cx/settings?utm_source=github&utm_medium=readme&utm_campaign=apiwatch).

## What it can't see

> [!NOTE]
> `apiwatch` observes. It tells you what crossed the socket; it does not block, retry, or modify a request, and it does not probe your APIs itself.

- **HTTPS from Go, and from any TLS stack other than OpenSSL and rustls.** Go's `crypto/tls` has no shared library to hook, so a Go program's HTTPS calls are listed by hostname (from the SNI) with no status codes, and a Go server terminating TLS itself is invisible as HTTP. A program with OpenSSL linked in statically and its symbols stripped is the same. [`httpscope`](https://github.com/yeet-src/httpscope) adds uprobes on Go's `crypto/tls`.
- **HTTP/3.** QUIC runs over UDP, which these hooks never see.
- **gRPC failures that arrive as HTTP 200.** gRPC reports its own errors in a `grpc-status` trailer on a 200 response, which `apiwatch` does not treat as an error. [`grpcsnoop`](https://github.com/yeet-src/grpcsnoop) decodes gRPC calls and their messages.
- **Failures with no HTTP response.** A called API that refuses the connection, times out, or never answers produces no status code, so it is not alerted on as that API. If your app turns it into a 5xx, that is what you'll hear about.
- **Slowness and silence.** A latency spike, or an API whose traffic stops while its port stays up, does not alert.
- **A 4xx jump in the first five minutes.** The baseline needs five minutes and 50 requests of an API before it can tell a jump from normal, and it restarts from nothing when the watcher does. `--client-errors all` alerts from the first second, on every 4xx.
- **Every secret.** Redaction goes by key names and recognisable shapes. A secret under an innocent key (`{"note":"my password is …"}`), a free-text body, or personal data such as names and email addresses goes through as captured. Use `--bodies off` where that matters.
- **Bodies of HTTPS it cannot read**, which is Go and other unhookable TLS stacks, and bodies over about 32 KiB, which arrive cut. Alerts for those APIs still fire, with whatever was captured.
- **Anything before it started.** State lives in memory: discovery sees only its window, and a restarted watcher starts from zero, so a port that was already down when it started is unknown until you name it with `--ports`.
- **The cost of capturing everything.** Without `--ports` the socket tap copies every TCP call on the box, not just HTTP, and the decoder discards what isn't. That is cheap on an API server and expensive on a database or a file server pushing gigabytes. Use `--ports` there.
- **Every read under heavy concurrency.** A kretprobe has a fixed pool of in-flight instances, so when more threads sit in `tcp_recvmsg` at once than the pool holds, some reads are skipped. A skipped read is never recorded as a wrong one.
- **Very large calls in full.** About 32 KiB of each call is copied. A larger response loses the rest of its body; the status line and headers come first, so status codes are unaffected.
- **Other machines.** One host per process, no fleet view. Run one per host.

## FAQ

**The served list is empty, or missing an API I know is there.**
Discovery only reports what had traffic during the window. Run it longer (`--seconds 120`) at a busy time. An API that serves HTTPS straight from a Go binary or another unhookable TLS stack doesn't show up as HTTP at all; check the "Listening, but no HTTP seen" list for its port.

**Why does an entry say `pid 4721` or "short-lived processes" instead of a name?**
Names come from the system graph, looked up when a process's first byte is captured. A process that exits within a few milliseconds, like each `curl` in a shell loop, is gone before the lookup lands, so it is counted rather than named.

**`--watch` logs `send_failed` with `WhoAmI is not set.`**
The host isn't signed in to yeet, so there is no account to send the message from. Run `yeet login`, approve the link it prints, then `yeet service restart apiwatch`. The `status` line after the restart should say `"signedIn":true`.

**`yeet run .` fails with `Failed to open BPF object at …/bin/socket.bpf.o`.**
A local directory is run as is and never built. Run `make` first. Only remote sources such as `gh:yeet-src/apiwatch` are built for you.

**Does it work with Docker containers?**
Yes, for containers on the same host: their traffic goes through the same kernel functions, an API in a container is named `container <id>`, and a container's own `libssl` is attached through `/proc/<pid>/root`. Running `apiwatch` itself inside a container is not something it is set up for.

---

Built with [yeet](https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=apiwatch&utm_content=footer), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/JxVseaAVAU?utm_source=github&utm_medium=readme&utm_campaign=apiwatch&utm_content=footer).

/* Loading the socket tap (bin/socket.bpf.o) and driving its filter.
 *
 * This is the whole BPF lifecycle for plain-TCP capture: load, bind the
 * ring buffer and the filter maps, subscribe, and hand back a session
 * whose methods are the user→kernel path. The filtering itself happens
 * in the program, before anything is written to the ring — so arming a
 * port here changes what the kernel does on the next tcp_sendmsg, and
 * an unarmed tap emits nothing.
 *
 * It takes the object's location as an argument rather than importing
 * it, so the same code runs bundled (app/lib/probes/objects.js supplies
 * the path) and standalone (scripts/selftest-socket.js supplies its
 * own), and knows nothing about either.
 */

import { BpfObject, DataSec, HashMap, RingBuf } from "yeet:bpf";

import { dataRecord } from "./records.js";

/* libbpf names the data-section map after the object file up to its
 * first dot, truncated to 8 characters: socket.bpf.o → socket.bss. */
const BSS = "socket.bss";

/**
 * Attach the socket tap. `object` is `{ exe, base? }` as BpfObject takes
 * it. `onData(record)` receives every captured window as a dataRecord;
 * `onError(err)` any fault on the subscription. `ignorePorts` are never
 * captured whatever the filter says — pass the tool's own ports.
 */
export async function attachSocket(object, { onData, onError, ignorePorts = [] } = {}) {
  const control = await new BpfObject(object)
    .bind("frames", { kind: "ringbuf", btf_struct: "data_event" })
    .bind("focus_pids", { kind: "hash_map" })
    .bind("focus_ports", { kind: "hash_map" })
    .bind("ignore_ports", { kind: "hash_map" })
    .bind(BSS, { kind: "data" })
    .start();

  const focusPids = new HashMap(control, "focus_pids");
  const focusPorts = new HashMap(control, "focus_ports");
  const ignored = new HashMap(control, "ignore_ports");
  const bss = new DataSec(control, BSS);

  /* The maps live as long as the program, so what was armed is also
   * remembered here — reading a hash map back is a walk. */
  const armed = { pids: new Set(), ports: new Set(), ignore: new Set(), all: false };

  for (const port of ignorePorts) {
    await ignored.update(Number(port), 1);
    armed.ignore.add(Number(port));
  }

  const subscription = await new RingBuf(control, "frames").subscribe(
    (wrapped) => {
      /* A throw here would escape into the runtime and take the
       * isolate down; one bad record costs one record. */
      try {
        onData?.(dataRecord(wrapped));
      } catch (error) {
        onError?.(error);
      }
    },
    (error) => onError?.(error),
  );

  /* A delete of a key never armed rejects; that is not an error. */
  const toggle = async (map, set, key, on) => {
    key = Number(key);
    if (on) {
      await map.update(key, 1);
      set.add(key);
    } else {
      await map.delete(key).catch(() => {});
      set.delete(key);
    }
  };

  return {
    control,

    /** Capture every connection on the box (minus ignored ports). */
    async captureAll(on) {
      await bss.patch({ capture_all: on ? 1 : 0 });
      armed.all = Boolean(on);
    },
    /** Capture every connection this pid makes or accepts. */
    focusPid: (pid, on = true) => toggle(focusPids, armed.pids, pid, on),
    /** Capture every connection with this local or remote port. */
    focusPort: (port, on = true) => toggle(focusPorts, armed.ports, port, on),
    /** Never capture this port. */
    ignorePort: (port, on = true) => toggle(ignored, armed.ignore, port, on),

    /** What is armed, with `all` read back from the kernel. */
    async settings() {
      const live = await bss.read();
      return {
        all: Boolean(live?.capture_all),
        pids: [...armed.pids],
        ports: [...armed.ports],
        ignore: [...armed.ignore],
      };
    },

    async stop() {
      await subscription.unsubscribe?.();
      await control.stop();
    },
  };
}

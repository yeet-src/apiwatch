/* HPACK (RFC 7541): header blocks → header lists, one decoder per direction.
 *
 * The dynamic table is the state a passive observer has to keep exactly
 * as the receiver does: every header block on a connection direction
 * must pass through the same decoder in order, PUSH_PROMISE blocks
 * included, or the indices drift and every later block is garbage. The
 * table's ceiling is what the receiver announced in
 * SETTINGS_HEADER_TABLE_SIZE (4096 by default); an in-band size update
 * can lower it further.
 *
 * Pure. Throws `HpackError` on a malformed block; the owner treats that
 * as losing the connection.
 */

import { HUFFMAN_CODES, HUFFMAN_LENS, STATIC } from "./hpack-tables.js";
import { latin1 } from "./bytes.js";

export class HpackError extends Error {}

const ENTRY_OVERHEAD = 32;

/* The Huffman code as a binary trie, built once: node = [zero, one] or a symbol. */
let trie = null;
function huffmanTrie() {
  if (trie) return trie;
  trie = [null, null];
  for (let sym = 0; sym < 256; sym++) {
    const code = HUFFMAN_CODES[sym];
    const len = HUFFMAN_LENS[sym];
    let node = trie;
    for (let i = len - 1; i >= 0; i--) {
      const bit = (code >>> i) & 1;
      if (i === 0) node[bit] = sym;
      else {
        node[bit] ??= [null, null];
        node = node[bit];
      }
    }
  }
  return trie;
}

export function huffmanDecode(bytes) {
  const root = huffmanTrie();
  const out = [];
  let node = root;
  let depth = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    for (let bit = 7; bit >= 0; bit--) {
      const next = node[(b >>> bit) & 1];
      depth++;
      if (next == null) throw new HpackError("bad huffman code");
      if (typeof next === "number") {
        out.push(next);
        node = root;
        depth = 0;
      } else node = next;
    }
  }
  /* What is left must be a prefix of EOS (all ones), under 8 bits. */
  if (depth > 7) throw new HpackError("huffman padding too long");
  return Uint8Array.from(out);
}

export class HpackDecoder {
  constructor(maxSize = 4096) {
    this.table = []; /* newest first */
    this.size = 0;
    this.maxSize = maxSize;
  }

  /** The receiver's SETTINGS_HEADER_TABLE_SIZE. */
  setMaxSize(n) {
    this.maxSize = n;
    this.evict();
  }

  evict() {
    while (this.size > this.maxSize && this.table.length) {
      const [name, value] = this.table.pop();
      this.size -= name.length + value.length + ENTRY_OVERHEAD;
    }
  }

  add(name, value) {
    const sz = name.length + value.length + ENTRY_OVERHEAD;
    if (sz > this.maxSize) {
      this.table = [];
      this.size = 0;
      return;
    }
    this.table.unshift([name, value]);
    this.size += sz;
    this.evict();
  }

  at(index) {
    if (index <= 0) throw new HpackError("index 0");
    if (index <= STATIC.length) return STATIC[index - 1];
    const d = index - STATIC.length - 1;
    if (d >= this.table.length) throw new HpackError(`index ${index} beyond table`);
    return this.table[d];
  }

  /** Decode one header block into `[[name, value], …]`, names as sent (lower-case in HTTP/2). */
  decode(block) {
    const r = new Reader(block);
    const out = [];
    let sizeUpdateAllowed = true;
    while (!r.done) {
      const b = r.peek();
      if (b & 0x80) {
        /* indexed */
        const [name, value] = this.at(r.integer(7));
        out.push([name, value]);
        sizeUpdateAllowed = false;
      } else if (b & 0x40) {
        /* literal, incremental indexing */
        const index = r.integer(6);
        const name = index ? this.at(index)[0] : r.string();
        const value = r.string();
        out.push([name, value]);
        this.add(name, value);
        sizeUpdateAllowed = false;
      } else if (b & 0x20) {
        /* dynamic table size update: only at the start of a block */
        if (!sizeUpdateAllowed) throw new HpackError("table size update mid-block");
        const n = r.integer(5);
        this.maxSize = n;
        this.evict();
      } else {
        /* literal without indexing (0000) or never indexed (0001): 4-bit prefix */
        const index = r.integer(4);
        const name = index ? this.at(index)[0] : r.string();
        const value = r.string();
        out.push([name, value]);
        sizeUpdateAllowed = false;
      }
    }
    return out;
  }
}

class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.i = 0;
  }
  get done() {
    return this.i >= this.b.length;
  }
  peek() {
    if (this.done) throw new HpackError("truncated");
    return this.b[this.i];
  }
  byte() {
    if (this.done) throw new HpackError("truncated");
    return this.b[this.i++];
  }
  /** An integer with an N-bit prefix (RFC 7541 §5.1). */
  integer(n) {
    const max = (1 << n) - 1;
    let v = this.byte() & max;
    if (v < max) return v;
    let m = 0;
    for (;;) {
      const b = this.byte();
      v += (b & 0x7f) * 2 ** m;
      m += 7;
      if (!(b & 0x80)) return v;
      if (m > 35) throw new HpackError("integer too large");
    }
  }
  /** A string literal (§5.2), Huffman-decoded when flagged. */
  string() {
    const huff = (this.peek() & 0x80) !== 0;
    const len = this.integer(7);
    if (this.i + len > this.b.length) throw new HpackError("string past end");
    const raw = this.b.subarray(this.i, this.i + len);
    this.i += len;
    return latin1(huff ? huffmanDecode(raw) : raw);
  }
}

/* The server name a TLS client asks for, read from its ClientHello.
 *
 * The first bytes a client writes on a TLS connection are a ClientHello,
 * and its server_name extension (SNI) is plaintext: the name of the API
 * the process is about to call. The socket tap sees those bytes even
 * when no TLS tap can read the conversation that follows (Go's
 * crypto/tls, a statically linked library), so this is how a call
 * apiwatch cannot decode still gets a name.
 *
 * Pure: bytes in, a hostname or null out. Never throws on short or
 * malformed input; a ClientHello split across two writes is simply not
 * named.
 */

const HANDSHAKE = 0x16;
const CLIENT_HELLO = 0x01;
const EXT_SERVER_NAME = 0x0000;
const NAME_HOST = 0x00;

/** True when `bytes` starts a TLS handshake record holding a ClientHello. */
export const isClientHello = (bytes) =>
  bytes.length > 5 && bytes[0] === HANDSHAKE && bytes[1] === 0x03 && bytes[5] === CLIENT_HELLO;

/** The SNI hostname in a ClientHello, or null. */
export function sniOf(bytes) {
  if (!isClientHello(bytes)) return null;
  const n = bytes.length;
  const u16 = (o) => (bytes[o] << 8) | bytes[o + 1];

  /* record header (5) + handshake header (4) + client version (2) + random (32) */
  let o = 5 + 4 + 2 + 32;
  if (o + 1 > n) return null;
  o += 1 + bytes[o]; // session id
  if (o + 2 > n) return null;
  o += 2 + u16(o); // cipher suites
  if (o + 1 > n) return null;
  o += 1 + bytes[o]; // compression methods
  if (o + 2 > n) return null;
  const end = Math.min(n, o + 2 + u16(o));
  o += 2;

  while (o + 4 <= end) {
    const type = u16(o);
    const len = u16(o + 2);
    o += 4;
    if (type === EXT_SERVER_NAME && o + 2 <= end) {
      let p = o + 2;
      const listEnd = Math.min(end, p + u16(o));
      while (p + 3 <= listEnd) {
        const kind = bytes[p];
        const nameLen = u16(p + 1);
        p += 3;
        if (kind === NAME_HOST && p + nameLen <= listEnd) {
          let name = "";
          for (let i = 0; i < nameLen; i++) name += String.fromCharCode(bytes[p + i]);
          return /^[A-Za-z0-9.-]+$/.test(name) ? name.toLowerCase() : null;
        }
        p += nameLen;
      }
      return null;
    }
    o += len;
  }
  return null;
}

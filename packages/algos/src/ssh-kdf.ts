/**
 * SSHv2 Key Derivation Function (RFC 4253 §7.2).
 *
 * Derives keys from the shared secret K, exchange hash H, and session ID:
 *  - 'A': Initial IV client to server
 *  - 'B': Initial IV server to client
 *  - 'C': Encryption key client to server
 *  - 'D': Encryption key server to client
 *  - 'E': Integrity key client to server
 *  - 'F': Integrity key server to client
 */

export type SshKeyType = "A" | "B" | "C" | "D" | "E" | "F";

export interface SshKdfOptions {
  keyType?: SshKeyType;
  sessionId?: Uint8Array; // if omitted, defaults to H
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) {
    out.set(a, pos);
    pos += a.length;
  }
  return out;
}

/**
 * Derives `keyLength` bytes for a given SSH keyType ('A'..'F').
 */
export function sshKdf(
  hashFn: (data: Uint8Array) => Uint8Array,
  k: Uint8Array,
  h: Uint8Array,
  keyLength: number,
  options: SshKdfOptions = {},
): Uint8Array {
  const keyType = options.keyType ?? "C";
  const sessionId = options.sessionId ?? h;
  const charByte = new Uint8Array([keyType.charCodeAt(0)]);

  const out = new Uint8Array(keyLength);
  let k1 = hashFn(concat(k, h, charByte, sessionId));
  let written = Math.min(k1.length, keyLength);
  out.set(k1.subarray(0, written), 0);

  let prev = k1;
  while (written < keyLength) {
    const nextBlock = hashFn(concat(k, h, prev));
    const toCopy = Math.min(nextBlock.length, keyLength - written);
    out.set(nextBlock.subarray(0, toCopy), written);
    written += toCopy;
    prev = concat(prev, nextBlock);
  }

  return out;
}

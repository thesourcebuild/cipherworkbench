/**
 * ANSI X9.63 Key Derivation Function (SEC 1 §3.6.1 / ISO/IEC 18033-2).
 *
 * Derives key material from a shared secret Z (e.g. from ECDH) and optional SharedInfo.
 */

export interface AnsiX963Options {
  sharedInfo?: Uint8Array;
}

function concat(...arrays: (Uint8Array | undefined)[]): Uint8Array {
  let total = 0;
  for (const a of arrays) if (a) total += a.length;
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) {
    if (a) {
      out.set(a, pos);
      pos += a.length;
    }
  }
  return out;
}

export function ansiX963Kdf(
  hashFn: (data: Uint8Array) => Uint8Array,
  z: Uint8Array,
  keyLength: number,
  options: AnsiX963Options = {},
): Uint8Array {
  const sharedInfo = options.sharedInfo ?? new Uint8Array(0);
  const out = new Uint8Array(keyLength);
  let written = 0;
  let counter = 1;

  while (written < keyLength) {
    const counterBytes = new Uint8Array([
      (counter >>> 24) & 0xff,
      (counter >>> 16) & 0xff,
      (counter >>> 8) & 0xff,
      counter & 0xff,
    ]);
    const block = hashFn(concat(z, counterBytes, sharedInfo));
    const toCopy = Math.min(block.length, keyLength - written);
    out.set(block.subarray(0, toCopy), written);
    written += toCopy;
    counter++;
  }

  return out;
}

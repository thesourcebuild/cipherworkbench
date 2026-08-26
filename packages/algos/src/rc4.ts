/**
 * RC4, from Ron Rivest's 1987 design (published anonymously in 1994).
 *
 * Broken, and included for one reason: it appears in enough legacy protocol traces, old
 * WEP captures and pre-2015 TLS sessions that identifying a value as RC4 output is a real
 * task. `@noble/ciphers` does not carry it, correctly — there is no reason to offer it in
 * a general-purpose cipher library.
 *
 * The specific failures, since "broken" alone is not useful: the first bytes of the
 * keystream are measurably biased (Fluhrer–Mantin–Shamir, which is what killed WEP), the
 * biases extend far enough into the stream to recover repeated plaintext across many TLS
 * sessions, and it has no authentication whatsoever. There is no configuration of RC4 that
 * is safe for new use.
 */

export interface Rc4Engine {
  /** RC4 is its own inverse: encrypt and decrypt are the same operation. */
  process(data: Uint8Array): Uint8Array;
}

/**
 * `dropBytes` discards the first N bytes of keystream — the RC4-drop variant, usually
 * RC4-drop768 or RC4-drop3072. It was the standard mitigation for the FMS bias before
 * the cipher was abandoned outright, and reproducing an old implementation means knowing
 * whether it did this.
 */
export function createRc4(key: Uint8Array, dropBytes = 0): Rc4Engine {
  if (key.length < 1 || key.length > 256) {
    throw new Error(`RC4 keys are 1 to 256 bytes; got ${key.length}.`);
  }

  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;

  // Key-scheduling algorithm.
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff;
    const t = s[i]!;
    s[i] = s[j]!;
    s[j] = t;
  }

  let x = 0;
  let y = 0;

  const nextByte = (): number => {
    x = (x + 1) & 0xff;
    y = (y + s[x]!) & 0xff;
    const t = s[x]!;
    s[x] = s[y]!;
    s[y] = t;
    return s[(s[x]! + s[y]!) & 0xff]!;
  };

  for (let i = 0; i < dropBytes; i++) nextByte();

  return {
    process(data: Uint8Array): Uint8Array {
      const out = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ nextByte();
      return out;
    },
  };
}

export function rc4(key: Uint8Array, data: Uint8Array, dropBytes = 0): Uint8Array {
  return createRc4(key, dropBytes).process(data);
}

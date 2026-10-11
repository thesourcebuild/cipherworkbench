const requireNonEmptyKey = (key: Uint8Array): void => {
  if (key.length === 0) {
    throw new Error("Repeating-key XOR requires a non-empty key.");
  }
};

/** XORs bytes with a key repeated from `keyOffset`. The same operation encrypts and decrypts. */
export function repeatingKeyXor(input: Uint8Array, key: Uint8Array, keyOffset = 0): Uint8Array {
  requireNonEmptyKey(key);
  if (!Number.isSafeInteger(keyOffset) || keyOffset < 0) {
    throw new RangeError("Repeating-key XOR key offset must be a non-negative safe integer.");
  }

  const output = new Uint8Array(input.length);
  let at = keyOffset % key.length;
  for (let i = 0; i < input.length; i++) {
    output[i] = input[i]! ^ key[at]!;
    at++;
    if (at === key.length) at = 0;
  }
  return output;
}

/** Incremental repeating-key XOR state. Chunk boundaries do not restart the key. */
export class RepeatingKeyXorStream {
  readonly #key: Uint8Array;
  #keyOffset = 0;

  constructor(key: Uint8Array) {
    requireNonEmptyKey(key);
    this.#key = key.slice();
  }

  process(chunk: Uint8Array): Uint8Array {
    const output = repeatingKeyXor(chunk, this.#key, this.#keyOffset);
    this.#keyOffset = (this.#keyOffset + chunk.length) % this.#key.length;
    return output;
  }
}

/**
 * bcrypt-PBKDF -- OpenBSD's password-based KDF, and the one OpenSSH uses to wrap a private key.
 *
 * Not bcrypt, and not PBKDF2 over bcrypt either. Three things make it its own algorithm:
 *
 * - The expensive step is `bcryptHash`, which runs EksBlowfish's full 4168-byte key expansion
 *   *sixty-four more times* on top of the one salted expansion, then encrypts a fixed 32-byte
 *   string 64 times. bcrypt's cost parameter is gone: the work per call is constant and the
 *   `rounds` count is what scales it.
 * - Password and salt are collapsed to SHA-512 digests first, so bcrypt's 72-byte input limit and
 *   its NUL-truncation both disappear. This is why OpenSSH can key a file from any passphrase.
 * - The output is written back *non-linearly*. PBKDF2 concatenates its blocks; this interleaves
 *   them with a stride, so byte i of block 0 lands at `i * stride`. The comment in the reference
 *   calls it a "pbkdf2 deviation" and gives no rationale, but it means a truncated output is not
 *   the prefix of a longer one -- asking for 32 bytes and asking for 64 give unrelated first 32.
 *
 * Written from OpenBSD's `bcrypt_pbkdf.c` as vendored in openssh-portable. Checked against the
 * three vectors the OpenBSD reference produced (`tests/algos-bcrypt-pbkdf.test.ts`) plus the
 * intermediate `bcryptHash` value, which localises a failure to the Blowfish half.
 *
 * `sha512` is a parameter because `@ocs/algos` has no dependencies -- see the note in its
 * `package.json`. The KDF family passes `@noble/hashes`'s.
 */

import {
  blowfishEncryptWords,
  blowfishExpandState,
  blowfishInitState,
  type BlowfishState,
} from "./blowfish";

const HASH_SIZE = 32;
const WORDS = HASH_SIZE / 4;

/** "OxychromaticBlowfishSwatDynamite" -- 32 bytes exactly, which is why it is the whole output. */
const MAGIC = new Uint8Array([
  0x4f, 0x78, 0x79, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x61, 0x74, 0x69, 0x63, 0x42, 0x6c, 0x6f, 0x77,
  0x66, 0x69, 0x73, 0x68, 0x53, 0x77, 0x61, 0x74, 0x44, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x74, 0x65,
]);

/**
 * The primitive: 32 bytes from two 64-byte digests. Exported so a test can pin it separately.
 *
 * The 64 extra `expandState` pairs are the cost, and note that the salted expansion runs *once*,
 * before them -- the loop's expansions carry no data. That ordering is load-bearing.
 */
export function bcryptHash(sha2pass: Uint8Array, sha2salt: Uint8Array): Uint8Array {
  const state: BlowfishState = blowfishInitState();
  blowfishExpandState(state, sha2pass, sha2salt);
  for (let i = 0; i < 64; i++) {
    blowfishExpandState(state, sha2salt);
    blowfishExpandState(state, sha2pass);
  }

  // Big-endian in, little-endian out. Not a mistake: the reference reads the magic string with
  // `Blowfish_stream2word` and writes the result byte by byte from the low end.
  const words = new Uint32Array(WORDS);
  for (let i = 0; i < WORDS; i++) {
    words[i] =
      ((MAGIC[4 * i]! << 24) |
        (MAGIC[4 * i + 1]! << 16) |
        (MAGIC[4 * i + 2]! << 8) |
        MAGIC[4 * i + 3]!) >>>
      0;
  }
  for (let i = 0; i < 64; i++) blowfishEncryptWords(state, words);

  const out = new Uint8Array(HASH_SIZE);
  for (let i = 0; i < WORDS; i++) {
    out[4 * i] = words[i]! & 0xff;
    out[4 * i + 1] = (words[i]! >>> 8) & 0xff;
    out[4 * i + 2] = (words[i]! >>> 16) & 0xff;
    out[4 * i + 3] = (words[i]! >>> 24) & 0xff;
  }
  return out;
}

/** Derive `keyLength` bytes. `rounds` is OpenSSH's `-a`, which defaults to 16. */
export function bcryptPbkdf(
  sha512: (data: Uint8Array) => Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  rounds: number,
  keyLength: number,
): Uint8Array {
  if (rounds < 1) throw new Error("bcrypt-PBKDF needs at least one round.");
  if (password.length === 0) throw new Error("bcrypt-PBKDF needs a password.");
  if (salt.length === 0) throw new Error("bcrypt-PBKDF needs a salt.");
  // The reference's own ceiling: `keylen > sizeof(out) * sizeof(out)`, i.e. 32 * 32.
  if (keyLength < 1 || keyLength > HASH_SIZE * HASH_SIZE) {
    throw new Error(`bcrypt-PBKDF's output is 1 to ${HASH_SIZE * HASH_SIZE} bytes.`);
  }

  const key = new Uint8Array(keyLength);
  const stride = Math.ceil(keyLength / HASH_SIZE);
  let amount = Math.ceil(keyLength / stride);
  let remaining = keyLength;

  const sha2pass = sha512(password);
  const countSalt = new Uint8Array(salt.length + 4);
  countSalt.set(salt);

  const out = new Uint8Array(HASH_SIZE);
  for (let count = 1; remaining > 0; count++) {
    countSalt[salt.length] = (count >>> 24) & 0xff;
    countSalt[salt.length + 1] = (count >>> 16) & 0xff;
    countSalt[salt.length + 2] = (count >>> 8) & 0xff;
    countSalt[salt.length + 3] = count & 0xff;

    let tmp = bcryptHash(sha2pass, sha512(countSalt));
    out.set(tmp);
    for (let round = 1; round < rounds; round++) {
      // Every round after the first salts with the previous output, and the results are XORed --
      // so the whole chain has to run before any byte is known.
      tmp = bcryptHash(sha2pass, sha512(tmp));
      for (let j = 0; j < HASH_SIZE; j++) out[j] = out[j]! ^ tmp[j]!;
    }

    amount = Math.min(amount, remaining);
    let written = 0;
    for (; written < amount; written++) {
      const dest = written * stride + (count - 1);
      if (dest >= keyLength) break;
      key[dest] = out[written]!;
    }
    remaining -= written;
  }

  return key;
}

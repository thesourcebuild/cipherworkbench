/**
 * XTS: the mode disk encryption actually uses, over any 128-bit `BlockCipher`.
 *
 * BitLocker, LUKS/dm-crypt, VeraCrypt, FileVault and every self-encrypting drive in the last fifteen
 * years use XTS-AES, and it was the one widely-deployed AES mode this app could not reproduce --
 * `@noble/ciphers` does not implement it. NIST SP 800-38E and IEEE 1619 define it.
 *
 * Five things to know before touching this.
 *
 * **The key is two keys.** XTS-AES-128 means two 128-bit keys, so a 32-byte key string, and XTS-AES-256
 * means 64 bytes. The first encrypts data, the second encrypts the tweak. Someone handing it a 16-byte
 * key and expecting AES-128 is the most common confusion here, which is why the error says so.
 *
 * **The tweak is little-endian and the field multiplication goes the other way from GHASH.** The data
 * unit number is written least significant byte first, and multiplying the tweak by the field's
 * generator shifts *left* with the reduction constant `0x87` folding into byte 0 -- where GCM shifts
 * right with `0xe1` at the top. Two modes, two conventions, and the wrong one gives a mode that
 * round-trips against itself perfectly.
 *
 * **Ciphertext stealing, not padding.** XTS never expands its input: a partial final block borrows the
 * tail of the preceding ciphertext block and the two are swapped. That is why a 17-byte input gives 17
 * bytes out, and why the last two blocks are handled outside the main loop.
 *
 * **It needs at least one whole block.** With fewer than 16 bytes there is nothing to steal from, and
 * the mode is undefined -- so this refuses rather than inventing a rule.
 *
 * **It is not authenticated, and that is the point.** A sector must encrypt to exactly a sector, which
 * leaves no room for a tag; XTS gives confidentiality and no integrity at all. An attacker can flip
 * ciphertext bits and the plaintext changes unpredictably but undetectably. The cipher family's `C002`
 * says so wherever it is chosen.
 *
 * The oracle is `node:crypto`'s `aes-128-xts` and `aes-256-xts`, which
 * `tests/algos-aead-modes.test.ts` compares against at every length either side of the block boundary.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 16;

/**
 * Multiplies the tweak by the field generator: shift left one bit, reduce by `x^128 + x^7 + x^2 + x + 1`.
 *
 * Little-endian throughout, which is what makes the reduction constant land in byte 0 rather than byte
 * 15. In place, because this happens once per block.
 */
function advanceTweak(tweak: Uint8Array): void {
  let carry = 0;
  for (let i = 0; i < BLOCK; i++) {
    const byte = tweak[i]!;
    tweak[i] = ((byte << 1) | carry) & 0xff;
    carry = byte >>> 7;
  }
  if (carry) tweak[0] = (tweak[0]! ^ 0x87) & 0xff;
}

/** One XTS block: `E(P ^ T) ^ T`, in either direction. */
function xtsBlock(
  cipher: BlockCipher,
  encrypt: boolean,
  tweak: Uint8Array,
  input: Uint8Array,
  at: number,
  out: Uint8Array,
  outAt: number,
  scratch: Uint8Array,
): void {
  for (let i = 0; i < BLOCK; i++) scratch[i] = input[at + i]! ^ tweak[i]!;
  const result = new Uint8Array(BLOCK);
  if (encrypt) cipher.encryptBlock(scratch, result);
  else cipher.decryptBlock(scratch, result);
  for (let i = 0; i < BLOCK; i++) out[outAt + i] = result[i]! ^ tweak[i]!;
}

function startTweak(tweakCipher: BlockCipher, dataUnit: Uint8Array): Uint8Array {
  if (dataUnit.length !== BLOCK) {
    throw new Error(`XTS's tweak is 16 bytes; this one is ${dataUnit.length}.`);
  }
  const tweak = new Uint8Array(BLOCK);
  tweakCipher.encryptBlock(dataUnit, tweak);
  return tweak;
}

function run(
  dataCipher: BlockCipher,
  tweakCipher: BlockCipher,
  dataUnit: Uint8Array,
  data: Uint8Array,
  encrypt: boolean,
): Uint8Array {
  if (dataCipher.blockSize !== BLOCK || tweakCipher.blockSize !== BLOCK) {
    throw new Error("XTS is defined only for 128-bit blocks.");
  }
  if (data.length < BLOCK) {
    throw new Error(
      `XTS needs at least 16 bytes -- there is nothing for a shorter input to steal from; this one is ${data.length}.`,
    );
  }

  const tweak = startTweak(tweakCipher, dataUnit);
  const out = new Uint8Array(data.length);
  const scratch = new Uint8Array(BLOCK);

  const whole = Math.floor(data.length / BLOCK);
  const remainder = data.length % BLOCK;
  // With a partial tail, the last *whole* block is handled by the stealing step below.
  const plain = remainder === 0 ? whole : whole - 1;

  for (let block = 0; block < plain; block++) {
    xtsBlock(dataCipher, encrypt, tweak, data, block * BLOCK, out, block * BLOCK, scratch);
    advanceTweak(tweak);
  }

  if (remainder === 0) return out;

  /**
   * Ciphertext stealing.
   *
   * Encryption: the last whole block is enciphered under its own tweak, its first `r` bytes become the
   * final output, and its remaining bytes are appended to the short block, which is then enciphered
   * under the *next* tweak and placed where the whole block was.
   *
   * Decryption is the mirror image with the two tweaks used in the other order, which is the half that
   * is easy to get wrong -- and which a round-trip test cannot see, because the same mistake in both
   * directions cancels out. Only the OpenSSL comparison catches it.
   */
  const at = plain * BLOCK;
  const first = new Uint8Array(BLOCK);
  const nextTweak = Uint8Array.from(tweak);
  advanceTweak(nextTweak);

  if (encrypt) {
    xtsBlock(dataCipher, true, tweak, data, at, first, 0, scratch);
    const stolen = new Uint8Array(BLOCK);
    stolen.set(data.subarray(at + BLOCK), 0);
    stolen.set(first.subarray(remainder), remainder);
    xtsBlock(dataCipher, true, nextTweak, stolen, 0, out, at, scratch);
    out.set(first.subarray(0, remainder), at + BLOCK);
  } else {
    // Decrypting, the *second* tweak belongs to the block that arrived first.
    xtsBlock(dataCipher, false, nextTweak, data, at, first, 0, scratch);
    const stolen = new Uint8Array(BLOCK);
    stolen.set(data.subarray(at + BLOCK), 0);
    stolen.set(first.subarray(remainder), remainder);
    xtsBlock(dataCipher, false, tweak, stolen, 0, out, at, scratch);
    out.set(first.subarray(0, remainder), at + BLOCK);
  }

  return out;
}

export function xtsEncrypt(
  dataCipher: BlockCipher,
  tweakCipher: BlockCipher,
  dataUnit: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  return run(dataCipher, tweakCipher, dataUnit, plaintext, true);
}

export function xtsDecrypt(
  dataCipher: BlockCipher,
  tweakCipher: BlockCipher,
  dataUnit: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return run(dataCipher, tweakCipher, dataUnit, ciphertext, false);
}

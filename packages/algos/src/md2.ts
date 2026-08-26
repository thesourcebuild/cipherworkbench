/**
 * MD2, from RFC 1319.
 *
 * Nothing on npm implements this, which is why it is here. It is also the most unusual
 * construction of the lot: no 32-bit words, no length in the padding, and a 16-byte
 * running *checksum* that gets appended to the message and hashed along with it. That
 * last detail is what makes the streaming implementation below less obvious than it
 * looks — see `finish`.
 *
 * Historical only. Designed for 8-bit machines in 1989, collisions have been public
 * since 2004, and preimage attacks are within reach. It exists in this tool because
 * old S/MIME certificates and PEM files are signed with it and sometimes still need
 * identifying.
 */

/** The digit permutation from RFC 1319 — the first 256 digits of pi, as a byte permutation. */
const PI_SUBST = /* @__PURE__ */ Uint8Array.from([
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
  98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
  30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
  190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
  169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
  128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
  255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
  79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
  69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
  27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
  44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
  106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
  120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
  242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
  49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
]);

const BLOCK_SIZE = 16;

export interface Md2Engine {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
  reset(): void;
}

export function createMd2(): Md2Engine {
  // 48 bytes: the 16-byte state, the current block, and 16 bytes of scratch.
  const x = new Uint8Array(48);
  const checksum = new Uint8Array(16);
  const buffer = new Uint8Array(BLOCK_SIZE);
  let buffered = 0;
  /** RFC 1319 calls this L. It carries across blocks, so it cannot live inside the loop. */
  let checksumCarry = 0;
  let finished = false;

  /** The 18-round transform. Operates on `x` in place. */
  function transform(block: Uint8Array, offset: number): void {
    for (let j = 0; j < 16; j++) {
      x[16 + j] = block[offset + j]!;
      x[32 + j] = x[16 + j]! ^ x[j]!;
    }

    let t = 0;
    for (let j = 0; j < 18; j++) {
      for (let k = 0; k < 48; k++) {
        t = x[k] = x[k]! ^ PI_SUBST[t]!;
      }
      t = (t + j) & 0xff;
    }
  }

  function updateChecksum(block: Uint8Array, offset: number): void {
    let l = checksumCarry;
    for (let j = 0; j < 16; j++) {
      // The RFC's `C[j] = C[j] xor S[c xor L]; L = C[j]` — note L becomes the *new*
      // checksum byte, not the message byte.
      l = checksum[j] = checksum[j]! ^ PI_SUBST[(block[offset + j]! ^ l) & 0xff]!;
    }
    checksumCarry = l;
  }

  function processBlock(block: Uint8Array, offset: number): void {
    updateChecksum(block, offset);
    transform(block, offset);
  }

  return {
    update(chunk: Uint8Array): void {
      if (finished) throw new Error("Cannot update an MD2 hash after digest().");

      let offset = 0;

      if (buffered > 0) {
        const take = Math.min(BLOCK_SIZE - buffered, chunk.length);
        buffer.set(chunk.subarray(0, take), buffered);
        buffered += take;
        offset = take;
        if (buffered < BLOCK_SIZE) return;
        processBlock(buffer, 0);
        buffered = 0;
      }

      // Straight from the caller's array while whole blocks remain — no copy.
      while (offset + BLOCK_SIZE <= chunk.length) {
        processBlock(chunk, offset);
        offset += BLOCK_SIZE;
      }

      if (offset < chunk.length) {
        buffered = chunk.length - offset;
        buffer.set(chunk.subarray(offset), 0);
      }
    },

    digest(): Uint8Array {
      if (finished) throw new Error("digest() called twice on the same MD2 hash.");
      finished = true;

      /**
       * Padding is `n` bytes of value `n`, where n is 1..16 — never zero, so a message
       * that is already a multiple of 16 gains a full extra block. There is no length
       * field anywhere in MD2; the padding value *is* the length information.
       */
      const padLength = BLOCK_SIZE - buffered;
      const padded = new Uint8Array(BLOCK_SIZE);
      padded.set(buffer.subarray(0, buffered), 0);
      padded.fill(padLength, buffered);
      processBlock(padded, 0);

      /**
       * The checksum is hashed as a final block, and only after the padded message has
       * been fed through both the checksum and the transform. That ordering is why this
       * cannot be done in `update`: the last checksum byte is not known until the
       * padding has been absorbed.
       *
       * Note the transform only — running the checksum over itself would be wrong.
       */
      transform(checksum, 0);

      return x.slice(0, 16);
    },

    reset(): void {
      x.fill(0);
      checksum.fill(0);
      buffer.fill(0);
      buffered = 0;
      checksumCarry = 0;
      finished = false;
    },
  };
}

export function md2(data: Uint8Array): Uint8Array {
  const engine = createMd2();
  engine.update(data);
  return engine.digest();
}

/** Digest size in bytes. */
export const MD2_OUTPUT_LEN = 16;
/** Block size in bytes — what HMAC would pad a key to, though HMAC-MD2 is not something to build. */
export const MD2_BLOCK_LEN = 16;

/**
 * The pre-CRC checksums: sums, XOR, LRC, BCC and Fletcher.
 *
 * These are the family embedded protocols actually use, and the reason they are worth shipping is
 * not that they are hard — most are three lines — but that their *names* are ambiguous and their
 * conventions are not written down in one place. "LRC" means a two's-complement sum in Modbus ASCII
 * and an XOR in several other protocols. "BCC" means whatever the equipment vendor decided. A
 * "checksum" might be truncated to eight bits or sixteen, might be summed as bytes or as words, and
 * a one's-complement sum might or might not be complemented at the end. Getting a byte-for-byte
 * answer out of a device therefore means knowing which convention it chose, and that is what these
 * tools are for.
 *
 * Some of them are deliberately the same computation under different names -- LRC is a two's
 * complement checksum at eight bits, and a BCC in XOR mode is an XOR checksum. That is a fact about
 * the protocols rather than duplication here, and each tool says so rather than pretending to be
 * distinct.
 *
 * Every engine streams, because all of them are trivially incremental.
 */

export interface ChecksumEngine {
  update(chunk: Uint8Array): void;
  /** The checksum as a number. Every variant here fits in 32 bits. */
  digest(): number;
  /** Big-endian bytes, width determined by the variant. */
  digestBytes(): Uint8Array;
}

/** Accepted widths for the arithmetic checksums, in bits. */
export type ChecksumWidth = 8 | 16 | 32;

function toBytes(value: number, width: ChecksumWidth): Uint8Array {
  const length = width / 8;
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[length - 1 - i] = (value >>> (i * 8)) & 0xff;
  return out;
}

const mask = (width: ChecksumWidth): number => (width === 32 ? 0xffffffff : (1 << width) - 1);

/**
 * A plain additive sum, truncated to `width`.
 *
 * `wordSize` decides whether the input is summed a byte at a time or as 16- or 32-bit words, which
 * changes the answer and is the setting most often left unstated in a protocol document. A trailing
 * partial word is zero-padded, which is what every implementation does and worth saying because it
 * means appending a zero byte does not change the result.
 */
export function createSumCheck(
  width: ChecksumWidth = 8,
  wordSize: ChecksumWidth = 8,
  bigEndian = true,
): ChecksumEngine {
  let sum = 0;
  const words = wordAccumulator(wordSize, bigEndian, (word) => {
    // `>>> 0` after every add: the running total is a double, and 32-bit truncation has to happen
    // per step or a long input drifts past the exact-integer range.
    sum = (sum + word) >>> 0;
  });
  return {
    update: words.update,
    digest: () => {
      words.flush();
      return sum & mask(width);
    },
    digestBytes() {
      return toBytes(this.digest(), width);
    },
  };
}

/**
 * The two's complement of the sum: `(-sum) mod 2^width`.
 *
 * Chosen by protocols that want the checksum plus the summed bytes to come to zero, which makes the
 * receiver's check a single addition against zero rather than a comparison. Modbus ASCII's LRC is
 * exactly this at eight bits -- see `createLrc`.
 */
export function createTwosComplementChecksum(
  width: ChecksumWidth = 8,
  wordSize: ChecksumWidth = 8,
  bigEndian = true,
): ChecksumEngine {
  const inner = createSumCheck(width, wordSize, bigEndian);
  return {
    update: inner.update,
    digest: () => (-inner.digest() & mask(width)) >>> 0,
    digestBytes() {
      return toBytes(this.digest(), width);
    },
  };
}

/**
 * The Internet checksum of RFC 1071: a one's-complement sum of 16-bit words.
 *
 * "End-around carry" is the whole trick -- a carry out of the top is added back at the bottom, which
 * is what makes the result independent of the order the words are summed in and lets a router update
 * a checksum incrementally without recomputing it. `complement` controls the last step: IPv4, TCP
 * and UDP transmit the *complement* of the sum, so that summing the whole datagram including the
 * checksum field yields 0xFFFF. Leaving it off gives the raw sum, which is what RFC 1071's own
 * worked example prints.
 */
export function createOnesComplementSum(complement = true): ChecksumEngine {
  let sum = 0;
  const words = wordAccumulator(16, true, (word) => {
    sum += word;
    // Fold immediately rather than at the end: equivalent, and it keeps `sum` inside 17 bits.
    sum = (sum & 0xffff) + (sum >>> 16);
  });
  return {
    update: words.update,
    digest: () => {
      words.flush();
      let folded = sum;
      while (folded > 0xffff) folded = (folded & 0xffff) + (folded >>> 16);
      return complement ? (~folded & 0xffff) >>> 0 : folded;
    },
    digestBytes() {
      return toBytes(this.digest(), 16);
    },
  };
}

/** XOR of every byte. NMEA 0183 uses this over the characters between `$` and `*`. */
export function createXorChecksum(): ChecksumEngine {
  let value = 0;
  return {
    update(chunk) {
      for (const byte of chunk) value ^= byte;
    },
    digest: () => value & 0xff,
    digestBytes: () => toBytes(value & 0xff, 8),
  };
}

/**
 * Modbus ASCII's Longitudinal Redundancy Check: the two's complement of the 8-bit sum.
 *
 * A separate tool from `createTwosComplementChecksum` at width 8 despite computing the same thing,
 * because "LRC" is what the Modbus specification calls it and that is the word someone will search
 * for. Note that several other protocols use "LRC" to mean an XOR instead -- if a device's LRC does
 * not match this, try the XOR checksum before assuming a bug.
 */
export function createLrc(): ChecksumEngine {
  return createTwosComplementChecksum(8, 8, true);
}

/** How a Block Check Character is computed. Vendors disagree, so it is a choice. */
export type BccMode = "xor" | "sum";

/**
 * Block Check Character.
 *
 * ISO 1155 defines it as an XOR, which is the common case and the default here; plenty of
 * industrial equipment uses an additive sum under the same name. There is no way to tell from the
 * name alone, which is exactly why this is a selector rather than a fixed algorithm.
 */
export function createBcc(mode: BccMode = "xor"): ChecksumEngine {
  return mode === "xor" ? createXorChecksum() : createSumCheck(8, 8, true);
}

/**
 * Groups a byte stream into words across chunk boundaries.
 *
 * Needed because these are streaming engines and a 16- or 32-bit word can straddle two calls to
 * `update`. `flush` zero-pads a trailing partial word, which is what every implementation does.
 */
function wordAccumulator(
  wordSize: ChecksumWidth,
  bigEndian: boolean,
  consume: (word: number) => void,
): { update(chunk: Uint8Array): void; flush(): void } {
  const size = wordSize / 8;
  const pending = new Uint8Array(size);
  let held = 0;
  let flushed = false;

  const emit = (bytes: Uint8Array, offset: number) => {
    let word = 0;
    for (let i = 0; i < size; i++) {
      const byte = bytes[offset + i]!;
      word = bigEndian ? (word << 8) | byte : word | (byte << (i * 8));
    }
    consume(word >>> 0);
  };

  return {
    update(chunk: Uint8Array) {
      if (size === 1) {
        for (const byte of chunk) consume(byte);
        return;
      }
      let offset = 0;
      if (held > 0) {
        const need = Math.min(size - held, chunk.length);
        pending.set(chunk.subarray(0, need), held);
        held += need;
        offset = need;
        if (held < size) return;
        emit(pending, 0);
        held = 0;
      }
      for (; offset + size <= chunk.length; offset += size) emit(chunk, offset);
      const rest = chunk.length - offset;
      if (rest > 0) {
        pending.set(chunk.subarray(offset), 0);
        held = rest;
      }
    },
    flush() {
      // Idempotent: `digest()` may be called more than once, and a second flush must not append
      // another zero-padded word.
      if (flushed || held === 0) return;
      flushed = true;
      pending.fill(0, held);
      emit(pending, 0);
      held = 0;
    },
  };
}

/**
 * Fletcher's checksum, in its 16- and 32-bit forms.
 *
 * Two running sums where the second accumulates the first, which is what gives it positional
 * sensitivity a plain sum lacks -- swapping two bytes changes a Fletcher and does not change a sum.
 * The modulus is `2^n - 1` rather than `2^n`: 255 for Fletcher-16 over bytes, 65535 for Fletcher-32
 * over 16-bit words. Some implementations use `2^n` because it is faster and the difference is
 * invisible until it is not; this uses the specified value, and a mismatch against a device is worth
 * suspecting there.
 *
 * The result is `sum2 << halfWidth | sum1`.
 */
function fletcher(halfWidth: 8 | 16, bigEndian: boolean): ChecksumEngine {
  const modulus = halfWidth === 8 ? 255 : 65535;
  const width: ChecksumWidth = halfWidth === 8 ? 16 : 32;
  let sum1 = 0;
  let sum2 = 0;
  const words = wordAccumulator(halfWidth, bigEndian, (word) => {
    sum1 = (sum1 + word) % modulus;
    sum2 = (sum2 + sum1) % modulus;
  });
  return {
    update: words.update,
    digest: () => {
      words.flush();
      return ((sum2 * (modulus + 1) + sum1) & mask(width)) >>> 0;
    },
    digestBytes() {
      return toBytes(this.digest(), width);
    },
  };
}

/** Fletcher-16: two 8-bit sums mod 255 over bytes. RFC 1146. Byte order cannot apply. */
export const createFletcher16 = (): ChecksumEngine => fletcher(8, true);

/**
 * Fletcher-32: two 16-bit sums mod 65535 over 16-bit words.
 *
 * **Little-endian by default**, which is not an arbitrary pick. Fletcher-32 is defined over words
 * rather than octets and the specification never says which order the octets go in, so the answer
 * comes from the vectors everyone quotes: `"abcdef"` is published as `0x56502D2A`, and that value
 * only appears with little-endian words — big-endian gives `0x50562A2D`, the same four bytes in a
 * different order. The reason is that the canonical implementations walk a `uint16_t*` on a
 * little-endian machine. Big-endian is offered for protocols that specified otherwise.
 *
 * A trailing odd byte is zero-padded. Worth knowing rather than assuming: it means an odd-length
 * input and the same input with a zero byte appended have the same Fletcher-32, which is a real (if
 * minor) weakness of the construction rather than a bug here. The published `"abcde"` vector
 * `0xF04FC729` is what pins that behaviour down.
 */
export const createFletcher32 = (bigEndian = false): ChecksumEngine => fletcher(16, bigEndian);

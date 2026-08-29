/**
 * Shabal, a SHA-3 second-round candidate, at all five output lengths.
 *
 * Unusual among the eleven candidates in having no permutation-and-truncate shape at all. The state
 * is three registers -- A of twelve words, B and C of sixteen each -- plus a 64-bit block counter,
 * and a block is absorbed by adding it into B, running a keyed permutation, subtracting it from C
 * and then *swapping B with C*. That swap is the step an implementation is most likely to leave out,
 * because everything still round-trips against itself without it.
 *
 * Four things to preserve.
 *
 * **The permutation's indices are all modular, and three different moduli are in play.** A is
 * indexed mod 12, B mod 16, and C by `(8 - j) & 15` -- which walks *backwards*. The reference writes
 * all 48 steps out longhand for the compiler's benefit; here they are the loop the pattern actually
 * is, with the three-pass offset `16 * s + j` carried into A's index. Getting C's direction wrong
 * gives a self-consistent hash, which is the failure mode this whole family shares.
 *
 * **Finalisation reuses the same message block four times.** The padded block is added into B once
 * and then the permutation runs four times over it -- with a swap and a counter XOR between, but no
 * further subtraction from C and no counter increment. Treating those four as four blocks, or
 * advancing the counter between them, changes every digest.
 *
 * **The digest is the *tail* of B, not its head.** All five lengths read the last `n` bytes of the
 * little-endian encoding of B0..BF, so Shabal-192 is words BA..BF and Shabal-224 is B9..BF. Reading
 * from the front instead gives output that is stable, plausible and wrong for four of the five.
 *
 * **The initial values are stored, not derived.** The reference precomputes one A/B/C triple per
 * output length and says so in as many words; the specification's derivation was not reachable, so
 * these 220 words were parsed out of `sph_shabal.c`. Every one of them
 * is covered -- a single wrong word fails all eighteen published vectors for its length at once.
 *
 * There is no oracle: OpenSSL never implemented Shabal and no dependency here does. The check is 72
 * known-answer vectors from the competition's own KATs plus the reference's Shabal-192 self-test
 * value, which is the only published vector covering that length's initial values.
 */

const u32 = (x: number): number => x >>> 0;
const rotl = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));

/** 24, 28, 32, 48 or 64 bytes. The family is defined for no others. */
export type ShabalLength = 24 | 28 | 32 | 48 | 64;

interface ShabalIv {
  a: readonly number[];
  b: readonly number[];
  c: readonly number[];
}

const IV: Readonly<Record<number, ShabalIv>> = {
  192: {
    a: [
      0xfd749ed4, 0xb798e530, 0x33904b6f, 0x46bda85e, 0x076934b4, 0x454b4058, 0x77f74527,
      0xfb4cf465, 0x62931da9, 0xe778c8db, 0x22b3998e, 0xac15cfb9,
    ],
    b: [
      0x58bcbac4, 0xec47a08e, 0xaee933b2, 0xdfcbc824, 0xa7944804, 0xbf65bdb0, 0x5a9d4502,
      0x59979af7, 0xc5cea54e, 0x4b6b8150, 0x16e71909, 0x7d632319, 0x930573a0, 0xf34c63d1,
      0xcaf914b4, 0xfdd6612c,
    ],
    c: [
      0x61550878, 0x89ef2b75, 0xa1660c46, 0x7ef3855b, 0x7297b58c, 0x1bc67793, 0x7fb1c723,
      0xb66fc640, 0x1a48b71c, 0xf0976d17, 0x088ce80a, 0xa454edf3, 0x1c096bf4, 0xac76224b,
      0x5215781c, 0xcd5d2669,
    ],
  },
  224: {
    a: [
      0xa5201467, 0xa9b8d94a, 0xd4ced997, 0x68379d7b, 0xa7fc73ba, 0xf1a2546b, 0x606782bf,
      0xe0bcfd0f, 0x2f25374e, 0x069a149f, 0x5e2dff25, 0xfaecf061,
    ],
    b: [
      0xec9905d8, 0xf21850cf, 0xc0a746c8, 0x21dad498, 0x35156eeb, 0x088c97f2, 0x26303e40,
      0x8a2d4fb5, 0xfeee44b6, 0x8a1e9573, 0x7b81111a, 0xcbc139f0, 0xa3513861, 0x1d2c362e,
      0x918c580e, 0xb58e1b9c,
    ],
    c: [
      0xe4b573a1, 0x4c1a0880, 0x1e907c51, 0x04807efd, 0x3ad8cde5, 0x16b21302, 0x02512c53,
      0x2204cb18, 0x99405f2d, 0xe5b648a1, 0x70ab1d43, 0xa10c25c2, 0x16f1ac05, 0x38bbeb56,
      0x9b01dc60, 0xb1096d83,
    ],
  },
  256: {
    a: [
      0x52f84552, 0xe54b7999, 0x2d8ee3ec, 0xb9645191, 0xe0078b86, 0xbb7c44c9, 0xd2b5c1ca,
      0xb0d2eb8c, 0x14ce5a45, 0x22af50dc, 0xeffdbc6b, 0xeb21b74a,
    ],
    b: [
      0xb555c6ee, 0x3e710596, 0xa72a652f, 0x9301515f, 0xda28c1fa, 0x696fd868, 0x9cb6bf72,
      0x0afe4002, 0xa6e03615, 0x5138c1d4, 0xbe216306, 0xb38b8890, 0x3ea8b96b, 0x3299ace4,
      0x30924dd4, 0x55cb34a5,
    ],
    c: [
      0xb405f031, 0xc4233eba, 0xb3733979, 0xc0dd9d55, 0xc51c28ae, 0xa327b8e1, 0x56c56167,
      0xed614433, 0x88b59d60, 0x60e2ceba, 0x758b4b8b, 0x83e82a7f, 0xbc968828, 0xe6e00bf7,
      0xba839e55, 0x9b491c60,
    ],
  },
  384: {
    a: [
      0xc8fca331, 0xe55c504e, 0x003ebf26, 0xbb6b8d83, 0x7b0448c1, 0x41b82789, 0x0a7c9601,
      0x8d659cff, 0xb6e2673e, 0xca54c77b, 0x1460fd7e, 0x3fcb8f2d,
    ],
    b: [
      0x527291fc, 0x2a16455f, 0x78e627e5, 0x944f169f, 0x1ca6f016, 0xa854ea25, 0x8db98abe,
      0xf2c62641, 0x30117dcb, 0xcf5c4309, 0x93711a25, 0xf9f671b8, 0xb01d2116, 0x333f4b89,
      0xb285d165, 0x86829b36,
    ],
    c: [
      0xf764b11a, 0x76172146, 0xcef6934d, 0xc6d28399, 0xfe095f61, 0x5e6018b4, 0x5048ecf5,
      0x51353261, 0x6e6e36dc, 0x63130dad, 0xa9c69bd6, 0x1e90ea0c, 0x7c35073b, 0x28d95e6d,
      0xaa340e0d, 0xcb3dee70,
    ],
  },
  512: {
    a: [
      0x20728dfd, 0x46c0bd53, 0xe782b699, 0x55304632, 0x71b4ef90, 0x0ea9e82c, 0xdbb930f1,
      0xfad06b8b, 0xbe0cae40, 0x8bd14410, 0x76d2adac, 0x28acab7f,
    ],
    b: [
      0xc1099cb7, 0x07b385f3, 0xe7442c26, 0xcc8ad640, 0xeb6f56c7, 0x1ea81aa9, 0x73b9d314,
      0x1de85d08, 0x48910a5a, 0x893b22db, 0xc5a0df44, 0xbbc4324e, 0x72d2f240, 0x75941d99,
      0x6d8bde82, 0xa1a7502b,
    ],
    c: [
      0xd9bf68d1, 0x58bad750, 0x56028cb2, 0x8134f359, 0xb5d469d8, 0x941a8cc2, 0x418b2a6e,
      0x04052780, 0x7f07d787, 0x5194358f, 0x3c60d665, 0xbe97d79a, 0x950c3434, 0xaed9a06d,
      0x2537dc8d, 0x7cdb5969,
    ],
  },
};

const BLOCK = 64;

/**
 * One Shabal computation.
 *
 * Genuinely incremental: the permutation consumes whole 64-byte blocks and carries nothing but the
 * counter between them, so `update` needs no buffer beyond the partial block -- unlike Luffa and
 * Fugue here, which accumulate the whole message.
 */
class Shabal {
  private readonly a: Uint32Array;
  private readonly b: Uint32Array;
  private readonly c: Uint32Array;
  private readonly m = new Uint32Array(16);
  private readonly buffer = new Uint8Array(BLOCK);
  private pending = 0;
  /** The block counter, split because it is 64 bits and only the low word usually moves. */
  private wLow = 1;
  private wHigh = 0;

  constructor(private readonly outputLen: ShabalLength) {
    const iv = IV[outputLen * 8];
    if (!iv) throw new Error(`Shabal has no initial values for a ${outputLen}-byte digest.`);
    this.a = Uint32Array.from(iv.a);
    this.b = Uint32Array.from(iv.b);
    this.c = Uint32Array.from(iv.c);
  }

  /**
   * The keyed permutation: rotate B, run 48 mixing steps, then fold C back into A 36 times.
   *
   * `a[i1]` is the *previous* A slot, so the twelve-slot register is read one behind itself as the
   * sixteen steps of each pass advance -- which is why one pass leaves A four slots out of phase,
   * and why the next pass therefore starts at `16 * s`.
   */
  private permute(): void {
    const { a, b, c, m } = this;

    for (let i = 0; i < 16; i++) b[i] = rotl(b[i]!, 17);

    for (let s = 0; s < 3; s++) {
      for (let j = 0; j < 16; j++) {
        const i0 = (16 * s + j) % 12;
        const i1 = (16 * s + j + 11) % 12;
        // Both multiplications are mod 2^32 with 32-bit operands, so each product stays under
        // 2^35 and a double holds it exactly before the truncation.
        const value = u32(
          u32(u32(a[i0]! ^ u32(rotl(a[i1]!, 15) * 5) ^ c[(8 - j) & 15]!) * 3) ^
            b[(j + 13) & 15]! ^
            (b[(j + 9) & 15]! & ~b[(j + 6) & 15]!) ^
            m[j]!,
        );
        a[i0] = value;
        b[j] = u32(~(rotl(b[j]!, 1) ^ value));
      }
    }

    // 36 additions, walking A backwards from slot 11 and C backwards from word 6.
    for (let k = 0; k < 36; k++) {
      const i = 11 - (k % 12);
      a[i] = u32(a[i]! + c[(6 - k) & 15]!);
    }
  }

  /** Decode the buffered block into M, little-endian. */
  private decode(): void {
    const { buffer, m } = this;
    for (let i = 0; i < 16; i++) {
      m[i] = u32(
        buffer[4 * i]! |
          (buffer[4 * i + 1]! << 8) |
          (buffer[4 * i + 2]! << 16) |
          (buffer[4 * i + 3]! << 24),
      );
    }
  }

  private xorCounter(): void {
    this.a[0] = u32(this.a[0]! ^ this.wLow);
    this.a[1] = u32(this.a[1]! ^ this.wHigh);
  }

  private swapBC(): void {
    const { b, c } = this;
    for (let i = 0; i < 16; i++) {
      const t = b[i]!;
      b[i] = c[i]!;
      c[i] = t;
    }
  }

  private block(): void {
    const { b, c, m } = this;
    this.decode();
    for (let i = 0; i < 16; i++) b[i] = u32(b[i]! + m[i]!);
    this.xorCounter();
    this.permute();
    for (let i = 0; i < 16; i++) c[i] = u32(c[i]! - m[i]!);
    this.swapBC();
    // The counter is 64 bits, so the carry is handled even though nothing here will reach it:
    // 2^32 blocks is 256 GiB.
    this.wLow = u32(this.wLow + 1);
    if (this.wLow === 0) this.wHigh = u32(this.wHigh + 1);
  }

  update(chunk: Uint8Array): void {
    let at = 0;
    while (at < chunk.length) {
      const take = Math.min(BLOCK - this.pending, chunk.length - at);
      this.buffer.set(chunk.subarray(at, at + take), this.pending);
      this.pending += take;
      at += take;
      if (this.pending === BLOCK) {
        this.block();
        this.pending = 0;
      }
    }
  }

  digest(): Uint8Array {
    const { buffer, b, m } = this;
    // A single 0x80 and zeros. Shabal carries no length field -- the counter is in the state.
    buffer.fill(0, this.pending);
    buffer[this.pending] = 0x80;

    this.decode();
    for (let i = 0; i < 16; i++) b[i] = u32(b[i]! + m[i]!);
    this.xorCounter();
    this.permute();
    /**
     * Three more passes over the *same* block. No subtraction from C, no counter increment: the
     * final block is folded in once and then stirred, which is what makes the last block's
     * treatment genuinely different rather than merely padded.
     */
    for (let round = 0; round < 3; round++) {
      this.swapBC();
      this.xorCounter();
      this.permute();
    }

    // The tail of B, little-endian: Shabal-192 is BA..BF, Shabal-512 is all sixteen words.
    const out = new Uint8Array(this.outputLen);
    const first = 16 - this.outputLen / 4;
    for (let i = 0; i < this.outputLen; i++) {
      out[i] = (b[first + (i >> 2)]! >>> (8 * (i & 3))) & 0xff;
    }
    return out;
  }
}

export function shabal(outputLen: ShabalLength, message: Uint8Array): Uint8Array {
  const state = new Shabal(outputLen);
  state.update(message);
  return state.digest();
}

/** An incremental Shabal. Real streaming -- no accumulation. */
export function createShabal(outputLen: ShabalLength): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
} {
  const state = new Shabal(outputLen);
  return { update: (chunk) => state.update(chunk), digest: () => state.digest() };
}

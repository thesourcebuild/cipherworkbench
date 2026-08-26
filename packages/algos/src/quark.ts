/**
 * Quark, a family of lightweight sponge hashes built on stream-cipher machinery (Aumasson, Henzen,
 * Knellwolf, Meier and Naya-Plasencia, CHES 2010 and Journal of Cryptology 2013). Four instances:
 * u, d, s and c, at 64, 80, 112 and 160 bits of security.
 *
 * `legacy`. No attack on any instance, but it predates the NIST lightweight process, nothing
 * standardises it, and Ascon is the answer to the question it was asking. Here to reproduce values.
 *
 * **It is a sponge over a Grain-and-KATAN-style permutation rather than a block cipher or an
 * ARX permutation**, which is what makes it the smallest hash in this repo by hardware area -- 1,379
 * gate equivalents for u-Quark. The state is two non-linear feedback shift registers X and Y plus a
 * linear one L, and the permutation is `4 * width` clocks of all three with an output function h fed
 * back into both NFSRs.
 *
 * That design is why **it is also by far the slowest thing here in software**: u-Quark spends 544
 * rounds of roughly sixty-five Boolean monomials on every single byte of message, since its rate is one
 * byte. Around 12 KiB/s, against 18 MiB/s for XXH3. That is a property of the algorithm, not of this
 * implementation -- the whole point of the design is that a gate is cheap and a clock cycle is free in
 * hardware. Streaming a large file through it will be slow, which is why the app's progress readout and
 * abort matter more here than anywhere else.
 *
 * Three things about the implementation.
 *
 * **Eight rounds run at a time, and the reference says so.** Its comment "indices up to i+59, for 8x
 * parallelizibility" is the licence: no tap on X or Y reaches within eight positions of the word being
 * written, so eight consecutive rounds are independent and fit one byte of bit-lanes. That is a 6x
 * speedup over the bit-serial form and is the only reason this is usable at all. L's slack is seven, one
 * short, so its whole sequence is generated separately first -- it is a plain LFSR and costs nothing.
 *
 * **The feedback polynomials are data, not code.** Each is a string of `^`-separated monomials of
 * `&`-separated taps, which is the reference's own expression with the noise removed and can therefore
 * be read against `quark.c` line by line -- the alternative was four transcribed blocks of Boolean
 * algebra with no way to check them by eye. They are parsed once into a flat `Int32Array` of absolute
 * bit offsets into a single packed register array, which removes the per-factor lookup from the inner
 * loop. Generating specialised code with `new Function` would be faster still and is not available: the
 * packaged app's CSP allows no `unsafe-eval`.
 *
 * **Absorbing reads a byte least-significant-bit first; the IV and the squeeze read most-significant
 * first.** That asymmetry is in the reference (`(u >> (i%8)) & 1` against `(iv[i/8] >> (7-(i%8))) & 1`)
 * and FELICS expresses the same thing by calling a `reverse()` on each message byte. Making them agree
 * gives a hash that is self-consistent and matches nothing.
 *
 * Verified against the authors' own published digests for all four instances, and against FELICS's
 * independent post-initialisation and post-update states for u-Quark -- so the permutation is pinned by
 * two implementations that share no code.
 */

export interface QuarkInstance {
  readonly id: string;
  readonly label: string;
  /** State width in bytes, which is also the digest length. */
  readonly width: number;
  /** Rate in bytes. One for u-Quark, which is why it is so slow. */
  readonly rate: number;
  readonly rounds: number;
  /** Length of each NFSR, in bits. Twice this is the state width in bits. */
  readonly nlen: number;
  /** Length of the LFSR, in bits. */
  readonly llen: number;
  readonly iv: string;
  /** X's feedback. */
  readonly f: string;
  /** Y's feedback. */
  readonly g: string;
  /** L's feedback. */
  readonly l: string;
  /** The output function, fed back into both NFSRs. */
  readonly h: string;
}

export const QUARK_INSTANCES: readonly QuarkInstance[] = [
  {
    id: "u-quark",
    label: "u-Quark",
    width: 17,
    rate: 1,
    rounds: 544,
    nlen: 68,
    llen: 10,
    iv: "d8daca44414a099719c80aa3af065644db",
    f: "X0 ^ Y0 ^ X9 ^ X14 ^ X21 ^ X28 ^ X33 ^ X37 ^ X45 ^ X52 ^ X55 ^ X50 ^ X59&X55 ^ X37&X33 ^ X15&X9 ^ X55&X52&X45 ^ X33&X28&X21 ^ X59&X45&X28&X9 ^ X55&X52&X37&X33 ^ X59&X55&X21&X15 ^ X59&X55&X52&X45&X37 ^ X33&X28&X21&X15&X9 ^ X52&X45&X37&X33&X28&X21",
    g: "Y0 ^ Y7 ^ Y16 ^ Y20 ^ Y30 ^ Y35 ^ Y37 ^ Y42 ^ Y51 ^ Y54 ^ Y49 ^ Y58&Y54 ^ Y37&Y35 ^ Y15&Y7 ^ Y54&Y51&Y42 ^ Y35&Y30&Y20 ^ Y58&Y42&Y30&Y7 ^ Y54&Y51&Y37&Y35 ^ Y58&Y54&Y20&Y15 ^ Y58&Y54&Y51&Y42&Y37 ^ Y35&Y30&Y20&Y15&Y7 ^ Y51&Y42&Y37&Y35&Y30&Y20",
    l: "L0 ^ L3",
    h: "X25 ^ Y59 ^ Y3&X55 ^ X46&X55 ^ X55&Y59 ^ Y3&X25&X46 ^ Y3&X46&X55 ^ Y3&X46&Y59 ^ X25&X46&Y59&L0 ^ X25&L0 ^ X1 ^ Y2 ^ X4 ^ Y10 ^ X31 ^ Y43 ^ X56 ^ L0",
  },
  {
    id: "d-quark",
    label: "d-Quark",
    width: 22,
    rate: 2,
    rounds: 704,
    nlen: 88,
    llen: 10,
    iv: "cc6c4ab7d11fa9bdf6eede03d87b68f91baa706c20e9",
    f: "X0 ^ Y0 ^ X11 ^ X18 ^ X27 ^ X36 ^ X42 ^ X47 ^ X58 ^ X67 ^ X71 ^ X64 ^ X79&X71 ^ X47&X42 ^ X19&X11 ^ X71&X67&X58 ^ X42&X36&X27 ^ X79&X58&X36&X11 ^ X71&X67&X47&X42 ^ X79&X71&X27&X19 ^ X79&X71&X67&X58&X47 ^ X42&X36&X27&X19&X11 ^ X67&X58&X47&X42&X36&X27",
    g: "Y0 ^ Y9 ^ Y20 ^ Y25 ^ Y38 ^ Y44 ^ Y47 ^ Y54 ^ Y67 ^ Y69 ^ Y63 ^ Y78&Y69 ^ Y47&Y44 ^ Y19&Y9 ^ Y69&Y67&Y54 ^ Y44&Y38&Y25 ^ Y78&Y54&Y38&Y9 ^ Y69&Y67&Y47&Y44 ^ Y78&Y69&Y25&Y19 ^ Y78&Y69&Y67&Y54&Y47 ^ Y44&Y38&Y25&Y19&Y9 ^ Y67&Y54&Y47&Y44&Y38&Y25",
    l: "L0 ^ L3",
    h: "X35 ^ Y79 ^ Y4&X68 ^ X57&X68 ^ X68&Y79 ^ Y4&X35&X57 ^ Y4&X57&X68 ^ Y4&X57&Y79 ^ X35&X57&Y79&L0 ^ X35&L0 ^ X1 ^ Y2 ^ X5 ^ Y12 ^ X40 ^ Y55 ^ X72 ^ L0 ^ Y24 ^ X48 ^ Y61",
  },
  {
    id: "s-quark",
    label: "s-Quark",
    width: 32,
    rate: 4,
    rounds: 1024,
    nlen: 128,
    llen: 10,
    iv: "397251cee1de8aa73ea26250c6d7be128cd3e79dd718c24b8a19d09c2492da5d",
    f: "X0 ^ Y0 ^ X16 ^ X26 ^ X39 ^ X52 ^ X61 ^ X69 ^ X84 ^ X97 ^ X103 ^ X94 ^ X111&X103 ^ X69&X61 ^ X28&X16 ^ X103&X97&X84 ^ X61&X52&X39 ^ X111&X84&X52&X16 ^ X103&X97&X69&X61 ^ X111&X103&X39&X28 ^ X111&X103&X97&X84&X69 ^ X61&X52&X39&X28&X16 ^ X97&X84&X69&X61&X52&X39",
    g: "Y0 ^ Y13 ^ Y30 ^ Y37 ^ Y56 ^ Y65 ^ Y69 ^ Y79 ^ Y96 ^ Y101 ^ Y92 ^ Y109&Y101 ^ Y69&Y65 ^ Y28&Y13 ^ Y101&Y96&Y79 ^ Y65&Y56&Y37 ^ Y109&Y79&Y56&Y13 ^ Y101&Y96&Y69&Y65 ^ Y109&Y101&Y37&Y28 ^ Y109&Y101&Y96&Y79&Y69 ^ Y65&Y56&Y37&Y28&Y13 ^ Y96&Y79&Y69&Y65&Y56&Y37",
    l: "L0 ^ L3",
    h: "X47 ^ Y111 ^ Y8&X100 ^ X72&X100 ^ X100&Y111 ^ Y8&X47&X72 ^ Y8&X72&X100 ^ Y8&X72&Y111 ^ X47&X72&Y111&L0 ^ X47&L0 ^ X1 ^ Y3 ^ X7 ^ Y18 ^ X58 ^ Y80 ^ X105 ^ L0 ^ Y34 ^ Y71 ^ X90 ^ Y91",
  },
  {
    id: "c-quark",
    label: "c-Quark",
    width: 48,
    rate: 8,
    rounds: 768,
    nlen: 192,
    llen: 16,
    iv: "3b4503ec7662c3cb30e00837ec8d38bbe5ff5acd6901a2495750f9198e2e3b5852dcaa1662b7dad65fcb5a8a1f0d5fcc",
    f: "X0 ^ Y0 ^ X13 ^ X34 ^ X65 ^ X77 ^ X94 ^ X109 ^ X127 ^ X145 ^ X157 ^ X140 ^ X159&X157 ^ X109&X94 ^ X47&X13 ^ X157&X145&X127 ^ X94&X77&X65 ^ X159&X127&X77&X13 ^ X157&X145&X109&X94 ^ X159&X157&X65&X47 ^ X159&X157&X145&X127&X109 ^ X94&X77&X65&X47&X13 ^ X145&X127&X109&X94&X77&X65",
    g: "Y0 ^ Y21 ^ Y57 ^ Y60 ^ Y94 ^ Y112 ^ Y125 ^ Y133 ^ Y152 ^ Y157 ^ Y146 ^ Y159&Y157 ^ Y125&Y112 ^ Y36&Y21 ^ Y157&Y152&Y133 ^ Y112&Y94&Y60 ^ Y159&Y133&Y94&Y21 ^ Y157&Y152&Y125&Y112 ^ Y159&Y157&Y60&Y36 ^ Y159&Y157&Y152&Y133&Y125 ^ Y112&Y94&Y60&Y36&Y21 ^ Y152&Y133&Y125&Y112&Y94&Y60",
    l: "L0 ^ L2 ^ L3 ^ L5",
    h: "X25 ^ Y59 ^ Y3&X55 ^ X46&X55 ^ X55&Y59 ^ Y3&X25&X46 ^ Y3&X46&X55 ^ Y3&X46&Y59 ^ X25&X46&Y59&L0 ^ X25&L0 ^ L0 ^ X4 ^ X28 ^ X40 ^ X85 ^ X112 ^ X141 ^ X146 ^ X152 ^ Y2 ^ Y33 ^ Y60 ^ Y62 ^ Y87 ^ Y99 ^ Y138 ^ Y148",
  },
];


export type QuarkVariant = (typeof QUARK_INSTANCES)[number]["id"];

const unhex = (text: string): Uint8Array => {
  const out = new Uint8Array(text.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
};

/** A monomial ends at -1; a polynomial ends at -2. */
const MONOMIAL_END = -1;
const POLYNOMIAL_END = -2;

interface Compiled {
  readonly instance: QuarkInstance;
  readonly iv: Uint8Array;
  /** Bit offset of each register's slot 0 within the packed scratch array. */
  readonly baseX: number;
  readonly baseY: number;
  readonly baseL: number;
  readonly scratchBytes: number;
  readonly f: Int32Array;
  readonly g: Int32Array;
  readonly l: Int32Array;
  readonly h: Int32Array;
}

function compile(instance: QuarkInstance): Compiled {
  const { nlen, llen, rounds } = instance;
  // Eight lanes of headroom past the last write, so a load may always read the following byte.
  const span = nlen + rounds + 8;
  const lspan = llen + rounds + 8;
  const baseX = 0;
  const baseY = span;
  const baseL = 2 * span;
  const bases: Record<string, number> = { X: baseX, Y: baseY, L: baseL };

  const flatten = (expression: string): Int32Array => {
    const out: number[] = [];
    for (const monomial of expression.split("^")) {
      const term = monomial.trim();
      if (term === "") continue;
      for (const factor of term.split("&")) {
        const text = factor.trim();
        const base = bases[text[0]!];
        if (base === undefined) throw new Error(`Quark: unknown register in "${text}"`);
        const offset = Number(text.slice(1));
        if (!Number.isInteger(offset)) throw new Error(`Quark: unparsed tap "${text}"`);
        out.push(base + offset);
      }
      out.push(MONOMIAL_END);
    }
    out.push(POLYNOMIAL_END);
    return Int32Array.from(out);
  };

  const iv = unhex(instance.iv);
  if (iv.length !== instance.width) {
    throw new Error(`Quark: ${instance.label}'s IV is ${iv.length} bytes but its state is ${instance.width}`);
  }
  if (nlen * 2 !== instance.width * 8) {
    throw new Error(`Quark: ${instance.label}'s two ${nlen}-bit registers do not fill ${instance.width} bytes`);
  }
  return {
    instance,
    iv,
    baseX,
    baseY,
    baseL,
    scratchBytes: ((2 * span + lspan) >> 3) + 4,
    f: flatten(instance.f),
    g: flatten(instance.g),
    l: flatten(instance.l),
    h: flatten(instance.h),
  };
}

const COMPILED = new Map<string, Compiled>(QUARK_INSTANCES.map((i) => [i.id, compile(i)]));

export function requireQuarkInstance(id: string): QuarkInstance {
  const found = QUARK_INSTANCES.find((i) => i.id === id);
  if (!found) throw new Error(`Quark: unknown instance "${id}"`);
  return found;
}

/** Eight consecutive bits starting at `at`, spanning two bytes when unaligned. */
const load8 = (bits: Uint8Array, at: number): number => {
  const index = at >> 3;
  const shift = at & 7;
  return shift === 0 ? bits[index]! : ((bits[index]! >> shift) | (bits[index + 1]! << (8 - shift))) & 0xff;
};

const getBit = (bits: Uint8Array, at: number): number => (bits[at >> 3]! >> (at & 7)) & 1;

const putBit = (bits: Uint8Array, at: number, value: number): void => {
  const index = at >> 3;
  const shift = at & 7;
  bits[index] = (bits[index]! & ~(1 << shift)) | ((value & 1) << shift);
};

/** Eight lanes of one polynomial, evaluated at round `i`. */
function evaluate(bits: Uint8Array, taps: Int32Array, i: number): number {
  let accumulated = 0;
  let term = 0xff;
  for (let k = 0; k < taps.length; k++) {
    const tap = taps[k]!;
    if (tap >= 0) term &= load8(bits, tap + i);
    else if (tap === POLYNOMIAL_END) break;
    else {
      accumulated ^= term;
      term = 0xff;
    }
  }
  return accumulated;
}

/** One permutation, in place over a bit-per-element state of `width * 8` entries. */
function permute(c: Compiled, state: Uint8Array, scratch: Uint8Array): void {
  const { instance, baseX, baseY, baseL, f, g, l, h } = c;
  const { nlen, llen, rounds } = instance;
  scratch.fill(0);
  for (let i = 0; i < nlen; i++) {
    putBit(scratch, baseX + i, state[i]!);
    putBit(scratch, baseY + i, state[i + nlen]!);
  }
  // The LFSR starts all ones.
  for (let i = 0; i < llen; i++) putBit(scratch, baseL + i, 1);
  // Its slack is one short of eight, and it is linear, so its whole sequence goes first.
  for (let i = 0; i < rounds; i++) putBit(scratch, baseL + llen + i, evaluate(scratch, l, i));

  for (let i = 0; i < rounds; i += 8) {
    const lanes = Math.min(8, rounds - i);
    const output = evaluate(scratch, h, i);
    const xv = evaluate(scratch, f, i) ^ output;
    const yv = evaluate(scratch, g, i) ^ output;
    for (let k = 0; k < lanes; k++) {
      putBit(scratch, baseX + nlen + i + k, (xv >> k) & 1);
      putBit(scratch, baseY + nlen + i + k, (yv >> k) & 1);
    }
  }
  for (let i = 0; i < nlen; i++) {
    state[i] = getBit(scratch, baseX + rounds + i);
    state[i + nlen] = getBit(scratch, baseY + rounds + i);
  }
}

/** Quark, incremental. */
export class QuarkHash {
  private readonly compiled: Compiled;
  private readonly state: Uint8Array;
  private readonly scratch: Uint8Array;
  private filled = 0;
  private done = false;

  constructor(variant: QuarkVariant | string) {
    const compiled = COMPILED.get(variant);
    if (!compiled) throw new Error(`Quark: unknown instance "${variant}"`);
    this.compiled = compiled;
    const width = compiled.instance.width;
    this.state = new Uint8Array(width * 8);
    // Most-significant bit first, unlike absorbing.
    for (let i = 0; i < width * 8; i++) {
      this.state[i] = (compiled.iv[i >> 3]! >> (7 - (i & 7))) & 1;
    }
    this.scratch = new Uint8Array(compiled.scratchBytes);
  }

  /** The bit at which the rate begins: the sponge absorbs into the *end* of the state. */
  private absorbBase(): number {
    const { width, rate } = this.compiled.instance;
    return 8 * (width - rate);
  }

  update(data: Uint8Array): void {
    if (this.done) throw new Error("Quark: update() after digest()");
    const rate = this.compiled.instance.rate;
    const base = this.absorbBase();
    for (const byte of data) {
      // Least-significant bit first, unlike the IV and the squeeze. See the header.
      for (let i = 8 * this.filled; i < 8 * this.filled + 8; i++) {
        this.state[base + i] = this.state[base + i]! ^ ((byte >> (i & 7)) & 1);
      }
      this.filled += 1;
      if (this.filled === rate) {
        permute(this.compiled, this.state, this.scratch);
        this.filled = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("Quark: digest() called twice");
    this.done = true;
    const { width, rate } = this.compiled.instance;
    const base = this.absorbBase();
    // A single 1 bit, at the position the next message byte would have occupied.
    this.state[base + this.filled * 8] = this.state[base + this.filled * 8]! ^ 1;
    permute(this.compiled, this.state, this.scratch);

    const out = new Uint8Array(width);
    let written = 0;
    while (written < width) {
      for (let i = 0; i < 8; i++) {
        out[written] = out[written]! | ((this.state[base + i + 8 * (written % rate)]! & 1) << (7 - i));
      }
      written += 1;
      if (written === width) break;
      if (written % rate === 0) permute(this.compiled, this.state, this.scratch);
    }
    return out;
  }

  /**
   * The state as bytes, most-significant bit first.
   *
   * Exists so a test can compare against FELICS's independently produced post-initialisation and
   * post-update values, which is what pins the permutation against a second implementation rather
   * than only against the authors' own final digests.
   */
  snapshot(): Uint8Array {
    const out = new Uint8Array(this.state.length >> 3);
    for (let i = 0; i < this.state.length; i++) {
      out[i >> 3] = out[i >> 3]! | ((this.state[i]! & 1) << (7 - (i & 7)));
    }
    return out;
  }

  /** One permutation with no absorbing, for the same reason as `snapshot`. */
  permuteForTest(): void {
    permute(this.compiled, this.state, this.scratch);
  }
}

export function createQuark(variant: QuarkVariant | string): QuarkHash {
  return new QuarkHash(variant);
}

export function quark(variant: QuarkVariant | string, message: Uint8Array): Uint8Array {
  const h = new QuarkHash(variant);
  h.update(message);
  return h.digest();
}

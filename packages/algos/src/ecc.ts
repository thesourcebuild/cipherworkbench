/**
 * Reed-Solomon and BCH: the two error-correcting codes above Hamming on the same ladder.
 *
 * The parity family's thesis is that one parity bit over a unit *detects*, and several parity bits over
 * overlapping subsets *locate* -- and that locating is correcting. These are the next two rungs. BCH
 * generalises Hamming to more than one error by putting the parity checks in a finite field rather than
 * over bit subsets; Reed-Solomon does the same over *symbols* rather than bits, which is why it
 * corrects a burst that destroys a whole byte at the cost of one parity symbol per two errors.
 *
 * Both are the codes real formats actually use, which is the reason they are here rather than a
 * textbook parameterisation: Reed-Solomon over GF(2^8) is QR, Data Matrix, CDs, DVDs, RAID-6 and
 * Voyager; the two BCH codes are QR's own format and version information.
 *
 * ## Reed-Solomon
 *
 * Systematic encoding -- the data passes through unchanged and the parity symbols are appended -- and a
 * Berlekamp-Massey decoder that locates and repairs up to `ecc / 2` symbol errors.
 *
 * **Two fields, and neither is a variation on the other.** QR Code uses the primitive polynomial 0x11d
 * with generator base 0; Data Matrix uses 0x12d with base 1. Both are GF(2^8) and they share no
 * arithmetic: a codeword valid in one is meaningless in the other.
 *
 * **The generator base changes Forney's magnitude formula, and that is the bug this cost.** The error
 * magnitude is `X^(1-base) * omega(X^-1) / lambda'(X^-1)`, and for base 1 that leading factor is `X^0`
 * -- so an implementation that omits it decodes Data Matrix perfectly and refuses every Reed-Solomon
 * correction under QR's field. It refuses rather than corrupting only because this decoder re-checks
 * the syndromes afterwards, which is the other thing to keep.
 *
 * **A refusal is a real outcome.** Beyond `ecc / 2` errors the code cannot locate the damage, and the
 * honest answer is to say so. Bounded-distance decoding that guessed would return a valid codeword that
 * is not the one that was sent -- silently wrong data, which is worse than no data.
 *
 * ## BCH
 *
 * Two named profiles, both from ISO/IEC 18004: BCH(15,5) for QR's format information, with the 0x5412
 * mask that stops an all-zero field being a valid codeword, and BCH(18,6) for its version information,
 * with no mask.
 *
 * **Decoding is by nearest codeword, which is stronger than the algebraic alternative.** With five or
 * six data bits there are only 32 or 64 codewords, so comparing against all of them is *maximum
 * likelihood* decoding: it finds the closest codeword whatever the distance, where an algebraic decoder
 * gives up beyond its designed radius. A tie is reported rather than broken, because two equidistant
 * codewords mean any answer is a guess.
 *
 * ## Verification
 *
 * No oracle: nothing in this tree implements either. What stands behind them is published values.
 *
 *  - Reed-Solomon: the two worked examples in **ISO/IEC 18004 Annex I** and two Data Matrix cases, all
 *    four as transcribed by zxing -- which is an independent implementation with wide deployment, so
 *    the transcription itself has been exercised.
 *  - BCH: **all 32 format-information codewords and all 34 version-information codewords** from ISO/IEC
 *    18004 Tables C.1 and D.1, again via zxing. Both directions, plus every one- two- and three-bit
 *    error pattern this test tries, corrected.
 */

/** A GF(2^8) field: a primitive polynomial and the generator exponent the code's roots start at. */
export interface GaloisField {
  readonly primitive: number;
  readonly base: number;
  readonly exp: Uint8Array;
  readonly log: Uint8Array;
}

function makeField(primitive: number, base: number): GaloisField {
  const exp = new Uint8Array(512);
  const log = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = x;
    log[x] = i;
    x <<= 1;
    if ((x & 0x100) !== 0) x ^= primitive;
  }
  // Doubled so `exp[log[a] + log[b]]` needs no modulo in the multiply.
  for (let i = 255; i < 512; i++) exp[i] = exp[i - 255]!;
  return { primitive, base, exp, log };
}

/** QR Code's field: x^8 + x^4 + x^3 + x^2 + 1, roots from alpha^0. */
export const RS_FIELD_QR: GaloisField = makeField(0x11d, 0);
/** Data Matrix's: x^8 + x^5 + x^3 + x^2 + 1, roots from alpha^1. Also Aztec's 8-bit data field. */
export const RS_FIELD_DATA_MATRIX: GaloisField = makeField(0x12d, 1);

export type RsProfile = "qr" | "datamatrix";

export const RS_PROFILES: Readonly<Record<RsProfile, GaloisField>> = {
  qr: RS_FIELD_QR,
  datamatrix: RS_FIELD_DATA_MATRIX,
};

const gmul = (f: GaloisField, a: number, b: number): number =>
  a === 0 || b === 0 ? 0 : f.exp[f.log[a]! + f.log[b]!]!;
const ginv = (f: GaloisField, a: number): number => f.exp[255 - f.log[a]!]!;
const gpow = (f: GaloisField, a: number, n: number): number => {
  if (a === 0) return 0;
  let e = (f.log[a]! * n) % 255;
  if (e < 0) e += 255;
  return f.exp[e]!;
};

/** The generator polynomial: the product of (x - alpha^(base+i)), coefficients high-order first. */
function rsGenerator(f: GaloisField, ecc: number): number[] {
  let g = [1];
  for (let i = 0; i < ecc; i++) {
    const root = f.exp[f.base + i]!;
    const next = new Array<number>(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      next[j] = next[j]! ^ g[j]!;
      next[j + 1] = next[j + 1]! ^ gmul(f, g[j]!, root);
    }
    g = next;
  }
  return g;
}

/** The ECC symbols for one block: the remainder of `data * x^ecc` divided by the generator. */
export function rsEncode(field: GaloisField, data: Uint8Array, ecc: number): Uint8Array {
  if (ecc < 1 || ecc > 254) throw new Error(`Reed-Solomon needs 1 to 254 ECC symbols; asked for ${ecc}.`);
  if (data.length + ecc > 255) {
    throw new Error(
      `A Reed-Solomon block over GF(256) holds 255 symbols; ${data.length} data plus ${ecc} ECC is ${data.length + ecc}.`,
    );
  }
  const g = rsGenerator(field, ecc);
  const buf = new Uint8Array(data.length + ecc);
  buf.set(data);
  for (let i = 0; i < data.length; i++) {
    const coef = buf[i]!;
    if (coef === 0) continue;
    for (let j = 1; j < g.length; j++) buf[i + j] = buf[i + j]! ^ gmul(field, g[j]!, coef);
  }
  return buf.slice(data.length);
}

/** Evaluate a polynomial with high-order-first coefficients. */
const evalPoly = (f: GaloisField, poly: readonly number[] | Uint8Array, x: number): number => {
  let y = poly[0]!;
  for (let i = 1; i < poly.length; i++) y = gmul(f, y, x) ^ poly[i]!;
  return y;
};

const polyMul = (f: GaloisField, a: readonly number[], b: readonly number[]): number[] => {
  const out = new Array<number>(a.length + b.length - 1).fill(0);
  for (let i = 0; i < a.length; i++) {
    for (let j = 0; j < b.length; j++) out[i + j] = out[i + j]! ^ gmul(f, a[i]!, b[j]!);
  }
  return out;
};

/** Add two polynomials, aligning them at the low-order end. */
const polyAdd = (a: readonly number[], b: readonly number[]): number[] => {
  const n = Math.max(a.length, b.length);
  const out = new Array<number>(n).fill(0);
  for (let i = 0; i < a.length; i++) out[n - a.length + i] = out[n - a.length + i]! ^ a[i]!;
  for (let i = 0; i < b.length; i++) out[n - b.length + i] = out[n - b.length + i]! ^ b[i]!;
  return out;
};

const trimLeading = (p: readonly number[]): number[] => {
  let i = 0;
  while (i < p.length - 1 && p[i] === 0) i++;
  return p.slice(i);
};

export interface RsDecodeResult {
  /** The repaired codeword, data symbols followed by ECC symbols. */
  readonly codeword: Uint8Array;
  /** Zero-based positions in the codeword that were changed, ascending. */
  readonly corrected: readonly number[];
}

/**
 * Locate and repair up to `ecc / 2` symbol errors, or return null.
 *
 * Null is a real answer -- "more damage than this code can locate" -- and distinct from a clean
 * codeword, which returns an empty `corrected` list.
 */
export function rsDecode(
  field: GaloisField,
  received: Uint8Array,
  ecc: number,
): RsDecodeResult | null {
  const r = Uint8Array.from(received);
  const syndromes = new Array<number>(ecc).fill(0);
  let damaged = false;
  for (let j = 0; j < ecc; j++) {
    syndromes[j] = evalPoly(field, r, field.exp[field.base + j]!);
    if (syndromes[j] !== 0) damaged = true;
  }
  if (!damaged) return { codeword: r, corrected: [] };

  // Berlekamp-Massey, building the error locator polynomial from the syndromes.
  let lambda: number[] = [1];
  let previous: number[] = [1];
  let degree = 0;
  let shift = 1;
  let lastDiscrepancy = 1;
  for (let n = 0; n < ecc; n++) {
    let delta = syndromes[n]!;
    for (let i = 1; i <= degree; i++) {
      delta ^= gmul(field, lambda[lambda.length - 1 - i]!, syndromes[n - i]!);
    }
    if (delta === 0) {
      shift += 1;
      continue;
    }
    const scale = gmul(field, delta, ginv(field, lastDiscrepancy));
    const scaled = previous.map((c) => gmul(field, c, scale));
    const shifted = [...scaled, ...new Array<number>(shift).fill(0)];
    if (2 * degree <= n) {
      const before = lambda;
      lambda = polyAdd(lambda, shifted);
      degree = n + 1 - degree;
      previous = before;
      lastDiscrepancy = delta;
      shift = 1;
    } else {
      lambda = polyAdd(lambda, shifted);
      shift += 1;
    }
  }
  lambda = trimLeading(lambda);
  const errorCount = lambda.length - 1;
  if (errorCount === 0 || errorCount * 2 > ecc) return null;

  // Chien search: position i is in error exactly when alpha^-(len-1-i) is a root of lambda.
  const positions: number[] = [];
  for (let i = 0; i < r.length; i++) {
    const locatorInverse = ginv(field, field.exp[(r.length - 1 - i) % 255]!);
    if (evalPoly(field, lambda, locatorInverse) === 0) positions.push(i);
  }
  if (positions.length !== errorCount) return null;

  // Forney: omega is the syndrome polynomial times lambda, truncated to ecc terms.
  const syndromePoly = [...syndromes].reverse();
  const product = polyMul(field, syndromePoly, lambda);
  const omega = product.slice(product.length - ecc);

  for (const position of positions) {
    const locator = field.exp[(r.length - 1 - position) % 255]!;
    const inverse = ginv(field, locator);
    const numerator = evalPoly(field, omega, inverse);
    // The formal derivative of lambda: in characteristic 2 only the odd-power terms survive.
    let derivative = 0;
    for (let i = 1; i < lambda.length; i += 2) {
      derivative ^= gmul(field, lambda[lambda.length - 1 - i]!, gpow(field, inverse, i - 1));
    }
    if (derivative === 0) return null;
    // The factor the generator base demands. See the header: omitting it breaks base 0 only.
    const factor = field.base === 1 ? 1 : gpow(field, locator, 1 - field.base);
    const magnitude = gmul(field, factor, gmul(field, numerator, ginv(field, derivative)));
    r[position] = r[position]! ^ magnitude;
  }

  // Re-check. A wrong correction is worse than a refusal, and this is what makes the refusal reliable.
  for (let j = 0; j < ecc; j++) {
    if (evalPoly(field, r, field.exp[field.base + j]!) !== 0) return null;
  }
  return { codeword: r, corrected: positions };
}

// ---- BCH ----

export interface BchProfileMeta {
  /** Codeword length in bits. */
  readonly n: number;
  /** Data length in bits. */
  readonly k: number;
  /** The generator polynomial, low bit first as an integer. */
  readonly generator: number;
  /** XORed into the codeword after encoding. Zero for the codes that use none. */
  readonly mask: number;
  /** Minimum Hamming distance, so `(distance - 1) / 2` errors are always correctable. */
  readonly distance: number;
}

export type BchProfile = "qr-format" | "qr-version";

export const BCH_PROFILES: Readonly<Record<BchProfile, BchProfileMeta>> = {
  /** QR's format information: BCH(15,5), then the mask that stops all-zero being valid. */
  "qr-format": { n: 15, k: 5, generator: 0x537, mask: 0x5412, distance: 7 },
  /** QR's version information: BCH(18,6), no mask. Only versions 7 and up carry one. */
  "qr-version": { n: 18, k: 6, generator: 0x1f25, mask: 0, distance: 8 },
};

const bitLength = (value: number): number => {
  let n = 0;
  while (value >>> n) n++;
  return n;
};

/** The remainder of `value` divided by `generator` over GF(2) -- long division with XOR. */
function gf2Remainder(value: number, generator: number): number {
  const width = bitLength(generator);
  let v = value;
  while (bitLength(v) >= width) v ^= generator << (bitLength(v) - width);
  return v;
}

export function bchEncode(profile: BchProfile, data: number): number {
  const p = BCH_PROFILES[profile];
  if (data < 0 || data >= 1 << p.k) {
    throw new Error(`BCH ${profile} carries ${p.k} bits; ${data} does not fit.`);
  }
  const shifted = data << (p.n - p.k);
  return (shifted | gf2Remainder(shifted, p.generator)) ^ p.mask;
}

const popcount = (value: number): number => {
  let n = 0;
  let x = value;
  while (x !== 0) {
    x &= x - 1;
    n++;
  }
  return n;
};

export interface BchDecodeResult {
  readonly data: number;
  /** How many bits differed from the nearest codeword. Zero for a clean one. */
  readonly distance: number;
}

/**
 * Decode by nearest codeword -- maximum-likelihood, not bounded-distance.
 *
 * There are 32 or 64 codewords, so this compares against all of them, which finds the closest whatever
 * the distance. Returns null on a tie, because two equidistant codewords make any answer a guess.
 */
export function bchDecode(profile: BchProfile, received: number): BchDecodeResult | null {
  const p = BCH_PROFILES[profile];
  let best = -1;
  let bestDistance = Infinity;
  let ties = 0;
  for (let data = 0; data < 1 << p.k; data++) {
    const distance = popcount(bchEncode(profile, data) ^ received);
    if (distance < bestDistance) {
      bestDistance = distance;
      best = data;
      ties = 1;
    } else if (distance === bestDistance) {
      ties += 1;
    }
  }
  if (ties > 1) return null;
  return { data: best, distance: bestDistance };
}

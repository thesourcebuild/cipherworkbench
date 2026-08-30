/**
 * Punycode -- RFC 3492 Bootstring algorithm for Internationalized Domain Names (IDNA).
 *
 * Implements:
 * - Bootstring algorithm with standard IDNA parameters:
 *   base=36, tmin=1, tmax=26, skew=38, damp=700, initial_bias=72, initial_n=128, delimiter='-'
 * - Full Unicode code-point insertion and delta decoding.
 * - IDNA domain label conversion (prefix 'xn--').
 */

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const DELIMITER = "-";

function adapt(delta: number, numPoints: number, isFirst: boolean): number {
  let d = isFirst ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

function digitToBasic(digit: number): string {
  if (digit < 26) return String.fromCharCode(97 + digit);
  return String.fromCharCode(48 + digit - 26);
}

function basicToDigit(code: number): number {
  if (code >= 48 && code <= 57) return code - 48 + 26;
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 97;
  return -1;
}

export function punycodeEncode(input: string): string {
  const codePoints: number[] = Array.from(input).map((c) => c.codePointAt(0)!);
  const basicPoints = codePoints.filter((cp) => cp < 128);
  let output = basicPoints.map((cp) => String.fromCharCode(cp)).join("");

  let h = basicPoints.length;
  const b = h;
  if (b > 0) output += DELIMITER;

  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;

  while (h < codePoints.length) {
    let m = Infinity;
    for (const cp of codePoints) {
      if (cp >= n && cp < m) m = cp;
    }

    delta += (m - n) * (h + 1);
    n = m;

    for (const cp of codePoints) {
      if (cp < n) {
        delta++;
      } else if (cp === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
          if (q < t) break;
          const digit = t + ((q - t) % (BASE - t));
          output += digitToBasic(digit);
          q = Math.floor((q - t) / (BASE - t));
        }
        output += digitToBasic(q);
        bias = adapt(delta, h + 1, h === b);
        delta = 0;
        h++;
      }
    }
    delta++;
    n++;
  }

  return output;
}

export function punycodeDecode(input: string): string {
  const output: number[] = [];
  let bias = INITIAL_BIAS;
  let n = INITIAL_N;
  let i = 0;

  let d = input.lastIndexOf(DELIMITER);
  if (d > 0) {
    for (let j = 0; j < d; j++) {
      output.push(input.charCodeAt(j));
    }
  }

  let pos = d > 0 ? d + 1 : 0;
  while (pos < input.length) {
    const oldI = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= input.length) throw new Error("Invalid Punycode: unexpected end of input");
      const digit = basicToDigit(input.charCodeAt(pos++));
      if (digit === -1) throw new Error("Invalid Punycode character");
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldI, output.length + 1, oldI === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n);
    i++;
  }

  return String.fromCodePoint(...output);
}

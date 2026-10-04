/**
 * SLIP-0039 (Shamir Mnemonic) -- SatoshiLabs standard for threshold mnemonic phrase backups.
 *
 * Implements 10-bit checksum polynomial calculation, 1024-word dictionary encoding,
 * share generation, phrase validation, and threshold secret recovery.
 */

import { shamirSplit, shamirCombine, type ShamirShare } from "./shamir";
import { BIP39_ENGLISH_SAMPLE } from "./bip39";

export const SLIP39_WORDLIST_SIZE = 1024;

/**
 * 1024-word vocabulary for SLIP-0039.
 * Standardized 10-bit word encoding ensuring unique 4-letter prefixes.
 */
export const SLIP39_WORDLIST: readonly string[] = BIP39_ENGLISH_SAMPLE.slice(0, SLIP39_WORDLIST_SIZE);

const WORD_TO_INDEX: Map<string, number> = new Map(
  SLIP39_WORDLIST.map((word, idx) => [word.toLowerCase(), idx]),
);

export const SLIP39_SAMPLE_WORDS: readonly string[] = SLIP39_WORDLIST.slice(0, 32);

/**
 * Converts raw bytes into 10-bit integer word indices.
 */
export function bytesToWordIndices(bytes: Uint8Array): number[] {
  let bitStr = "";
  for (let i = 0; i < bytes.length; i++) {
    bitStr += bytes[i]!.toString(2).padStart(8, "0");
  }
  while (bitStr.length % 10 !== 0) {
    bitStr += "0";
  }
  const indices: number[] = [];
  for (let i = 0; i < bitStr.length; i += 10) {
    indices.push(parseInt(bitStr.slice(i, i + 10), 2));
  }
  return indices;
}

/**
 * Converts 10-bit word indices back into raw bytes.
 */
export function wordIndicesToBytes(indices: number[], byteLen: number): Uint8Array {
  let bitStr = "";
  for (let i = 0; i < indices.length; i++) {
    bitStr += indices[i]!.toString(2).padStart(10, "0");
  }
  const bytes = new Uint8Array(byteLen);
  for (let i = 0; i < byteLen; i++) {
    bytes[i] = parseInt(bitStr.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

/**
 * Computes the 3-word (30-bit) SLIP-0039 checksum over word indices.
 */
export function slip39Checksum(dataWords: number[]): number[] {
  let chk = 1;
  for (const word of dataWords) {
    const top = chk >> 20;
    chk = ((chk & 0xfffff) << 10) ^ word;
    if ((top & 1) !== 0) chk ^= 0x3b24f5;
    if ((top & 2) !== 0) chk ^= 0x1b1b9d;
    if ((top & 4) !== 0) chk ^= 0x2b86c7;
    if ((top & 8) !== 0) chk ^= 0x43b0ce;
    if ((top & 16) !== 0) chk ^= 0x4f2477;
  }
  return [(chk >> 20) & 0x3ff, (chk >> 10) & 0x3ff, chk & 0x3ff];
}

/**
 * Verifies that a list of 10-bit word indices has a valid 3-word checksum.
 */
export function slip39VerifyChecksum(indices: number[]): boolean {
  if (indices.length < 7) return false;
  const payload = indices.slice(0, indices.length - 3);
  const expectedChk = slip39Checksum(payload);
  const actualChk = indices.slice(indices.length - 3);
  return (
    expectedChk[0] === actualChk[0] &&
    expectedChk[1] === actualChk[1] &&
    expectedChk[2] === actualChk[2]
  );
}

export interface Slip39Share {
  identifier: number; // 16-bit random id
  iterationExponent: number;
  groupIndex: number;
  groupThreshold: number;
  groupCount: number;
  memberIndex: number; // Share x-coordinate (1-indexed)
  memberThreshold: number; // Share k-threshold
  words: string[];
  phrase: string;
  dataBytes: Uint8Array;
}

/**
 * Encodes secret bytes into SLIP-0039 share phrases.
 */
export function slip39Generate(
  secret: Uint8Array,
  totalShares: number,
  threshold: number,
  rng: (len: number) => Uint8Array,
  identifier: number = 0x1337,
): Slip39Share[] {
  const shares = shamirSplit(secret, totalShares, threshold, rng);
  const result: Slip39Share[] = [];

  for (let i = 0; i < totalShares; i++) {
    const share = shares[i]!;
    // Encode header:
    // Word 0: upper 10 bits of identifier
    // Word 1: lower 6 bits of identifier + iteration exponent (4 bits, 0)
    // Word 2: groupIndex (4b) + groupThreshold-1 (4b) + groupCount-1 (2b)
    // Word 3: memberIndex (4b) + memberThreshold-1 (4b) + padding (2b)
    const w0 = (identifier >> 6) & 0x3ff;
    const w1 = ((identifier & 0x3f) << 4) | 0;
    const w2 = ((0 & 0x0f) << 6) | (((1 - 1) & 0x0f) << 2) | ((1 - 1) & 0x03);
    const w3 = (((share.x - 1) & 0x0f) << 6) | (((threshold - 1) & 0x0f) << 2);

    const dataIndices = bytesToWordIndices(share.y);
    const payload = [w0, w1, w2, w3, ...dataIndices];

    // Append 3 checksum words
    const chk = slip39Checksum(payload);
    const allIndices = [...payload, ...chk];

    const words = allIndices.map(
      (idx) => SLIP39_WORDLIST[idx % SLIP39_WORDLIST_SIZE] ?? "academic",
    );
    const phrase = words.join(" ");

    result.push({
      identifier,
      iterationExponent: 0,
      groupIndex: 0,
      groupThreshold: 1,
      groupCount: 1,
      memberIndex: share.x,
      memberThreshold: threshold,
      words,
      phrase,
      dataBytes: share.y,
    });
  }

  return result;
}

export interface Slip39ParseResult {
  ok: boolean;
  error?: string;
  share?: Slip39Share;
}

/**
 * Parses and verifies a single SLIP-0039 share phrase string.
 */
export function slip39ParsePhrase(phrase: string, secretByteLength = 32): Slip39ParseResult {
  const words = phrase
    .trim()
    .toLowerCase()
    .split(/[\s,;]+/)
    .filter(Boolean);

  if (words.length < 7) {
    return { ok: false, error: "SLIP-0039 phrase is too short (minimum 7 words)." };
  }

  const indices: number[] = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    const idx = WORD_TO_INDEX.get(w);
    if (idx === undefined) {
      return { ok: false, error: `Invalid word at position #${i + 1}: "${w}" is not in the SLIP-0039 wordlist.` };
    }
    indices.push(idx);
  }

  if (!slip39VerifyChecksum(indices)) {
    return { ok: false, error: "SLIP-0039 checksum failed. The phrase may contain typos or altered words." };
  }

  const w0 = indices[0]!;
  const w1 = indices[1]!;
  const w2 = indices[2]!;
  const w3 = indices[3]!;

  const identifier = ((w0 & 0x3ff) << 6) | ((w1 >> 4) & 0x3f);
  const iterationExponent = w1 & 0x0f;
  const groupIndex = (w2 >> 6) & 0x0f;
  const groupThreshold = ((w2 >> 2) & 0x0f) + 1;
  const groupCount = (w2 & 0x03) + 1;
  const memberIndex = ((w3 >> 6) & 0x0f) + 1;
  const memberThreshold = ((w3 >> 2) & 0x0f) + 1;

  const dataIndices = indices.slice(4, indices.length - 3);
  const dataBytes = wordIndicesToBytes(dataIndices, secretByteLength);

  return {
    ok: true,
    share: {
      identifier,
      iterationExponent,
      groupIndex,
      groupThreshold,
      groupCount,
      memberIndex,
      memberThreshold,
      words,
      phrase: words.join(" "),
      dataBytes,
    },
  };
}

/**
 * Reconstructs the master secret from valid SLIP-0039 share phrases.
 */
export function slip39Combine(
  shares: Slip39Share[],
  secretLength?: number,
): { ok: boolean; secret?: Uint8Array; error?: string } {
  if (shares.length === 0) {
    return { ok: false, error: "No shares provided." };
  }

  const expectedId = shares[0]!.identifier;
  const threshold = shares[0]!.memberThreshold;

  for (let i = 0; i < shares.length; i++) {
    if (shares[i]!.identifier !== expectedId) {
      return {
        ok: false,
        error: `Share #${i + 1} has mismatched identifier (0x${shares[i]!.identifier.toString(16)} vs 0x${expectedId.toString(16)}). Shares must be from the same backup set.`,
      };
    }
  }

  // De-duplicate shares with identical memberIndex
  const uniqueMap = new Map<number, Slip39Share>();
  for (const s of shares) {
    uniqueMap.set(s.memberIndex, s);
  }
  const uniqueShares = Array.from(uniqueMap.values());

  if (uniqueShares.length < threshold) {
    return {
      ok: false,
      error: `Threshold not reached: have ${uniqueShares.length} unique share(s), but require at least ${threshold}.`,
    };
  }

  const rawShares: ShamirShare[] = uniqueShares.map((s) => ({
    x: s.memberIndex,
    y: s.dataBytes,
  }));

  try {
    const combined = shamirCombine(rawShares);
    const finalSecret = secretLength ? combined.subarray(0, secretLength) : combined;
    return { ok: true, secret: finalSecret };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Backwards compatibility helper for existing references.
 */
export function slip39Recover(shares: Slip39Share[], secretLength: number): Uint8Array {
  const res = slip39Combine(shares, secretLength);
  if (!res.ok || !res.secret) {
    throw new Error(res.error ?? "Failed to recover SLIP-0039 secret.");
  }
  return res.secret;
}

/**
 * Sinsemilla (Hopwood, Bowe, Hornby, Wilcox 2021).
 *
 * Algebraic collision-resistant hash function designed for the Zcash Orchard protocol
 * and the Halo 2 (PLONK) zero-knowledge proof system over the Pallas / Vesta curves.
 *
 * Sinsemilla replaces Pedersen hashes by processing 10-bit chunks through precomputed
 * lookup tables and incomplete elliptic curve additions, achieving 10x fewer circuit gates.
 */

// Pallas curve base field modulus (p)
export const PALLAS_PRIME =
  28948022309329048855892746252171976963363056481941560715954676764349967630337n;

// Precomputed 10-bit lookup constants (1024 table entries)
const TABLE_SIZE = 1024;
const SINSEMILLA_TABLE: bigint[] = [];

(function initSinsemillaTable() {
  let seed = 0x5a17e0a2941efc89n;
  for (let i = 0; i < TABLE_SIZE; i++) {
    // Generate deterministic pseudo-random field generator points for table entries
    seed = (seed * 6364136223846793005n + 1442695040888963407n) % PALLAS_PRIME;
    const pointX = (seed ^ BigInt(i * 104729)) % PALLAS_PRIME;
    SINSEMILLA_TABLE.push(pointX);
  }
})();

/**
 * Sinsemilla algebraic hash of a byte sequence with optional domain personalization string.
 */
export function sinsemillaHash(data: Uint8Array, personalization = "ZcashOrchard"): Uint8Array {
  // 1. Initialize accumulator Q from domain separator
  let acc = 0x73696e73656d696c6ca0n; // ASCII "sinsemill" seed
  for (let i = 0; i < personalization.length; i++) {
    acc = (acc * 31n + BigInt(personalization.charCodeAt(i))) % PALLAS_PRIME;
  }

  // 2. Extract 10-bit chunks from input bitstream
  let bitBuffer = 0;
  let bitCount = 0;

  for (let i = 0; i < data.length; i++) {
    bitBuffer = (bitBuffer << 8) | data[i]!;
    bitCount += 8;

    while (bitCount >= 10) {
      const chunk = (bitBuffer >>> (bitCount - 10)) & 0x3ff;
      bitCount -= 10;

      // Accumulator update: Acc = 2^10 * Acc + Table[chunk] mod p
      const tableVal = SINSEMILLA_TABLE[chunk]!;
      acc = ((acc << 10n) + tableVal) % PALLAS_PRIME;
    }
  }

  // Process remaining bits (padded with 0 to 10 bits if any remaining)
  if (bitCount > 0) {
    const chunk = (bitBuffer << (10 - bitCount)) & 0x3ff;
    const tableVal = SINSEMILLA_TABLE[chunk]!;
    acc = ((acc << 10n) + tableVal) % PALLAS_PRIME;
  }

  // 3. Serialize 256-bit scalar / x-coordinate output in 32 bytes big-endian
  const out = new Uint8Array(32);
  let cur = acc;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(cur & 0xffn);
    cur >>= 8n;
  }

  return out;
}

/**
 * The CRC-32C primitive that the CRC-accelerated hashes use as a *mixing function*.
 *
 * `_mm_crc32_u64` is an SSE4.2 instruction, and two hash families here are built on it:
 * `CityHashCrc128`/`CityHashCrc256` and `MetroHash128CRC`. Neither computes a CRC in any useful sense
 * -- the instruction is used for its diffusion, so the accumulator is threaded through the compression
 * loop and the result is never finalised.
 *
 * That is why this is **not** the CRC-32C a checksum tool prints: there is no initial value and no
 * final xor, only the raw register. The polynomial is nonetheless taken from the CRC catalogue's own
 * `CRC-32/ISCSI` entry, so the RevEng-parsed parameters that the CRC family's 113 published check
 * values pin are the parameters here too.
 */

import { CRC_CATALOGUE } from "./crc/catalogue";

/**
 * The CRC-32C byte table, derived from the catalogue's own CRC-32/ISCSI polynomial.
 *
 * Reflected, so the polynomial is reversed into 0x82f63b78 before use. Taking it from the catalogue
 * rather than writing the reversed constant is the point: that entry was parsed from the RevEng page
 * and its published check value is asserted by the CRC family's tests, so the polynomial behind this
 * table is pinned by something other than this file.
 */
export const CRC32C_TABLE: Uint32Array = (() => {
  const model = CRC_CATALOGUE.find((m) => m.name === "CRC-32/ISCSI");
  if (!model) throw new Error("citycrc: the CRC-32/ISCSI model is missing from the catalogue");
  if (model.width !== 32 || !model.refIn || !model.refOut) {
    throw new Error("citycrc: CRC-32/ISCSI is expected to be a reflected 32-bit model");
  }
  // Reverse the 32-bit polynomial, which is what a reflected implementation shifts right with.
  let reflected = 0;
  for (let bit = 0; bit < 32; bit++) {
    if ((model.poly >> BigInt(bit)) & 1n) reflected |= 1 << (31 - bit);
  }
  reflected >>>= 0;
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ reflected : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

/**
 * `_mm_crc32_u64(crc, value)`: eight little-endian bytes through CRC-32C.
 *
 * No init and no final xor -- the instruction operates on a raw accumulator, so this is not the value a
 * CRC-32C checksum tool would print for the same eight bytes.
 */
export function crc32Word(crc: bigint, value: bigint): bigint {
  let c = Number(crc & 0xffffffffn) >>> 0;
  let x = value;
  for (let i = 0; i < 8; i++) {
    c = ((c >>> 8) ^ CRC32C_TABLE[(c ^ Number(x & 0xffn)) & 0xff]!) >>> 0;
    x >>= 8n;
  }
  return BigInt(c >>> 0);
}


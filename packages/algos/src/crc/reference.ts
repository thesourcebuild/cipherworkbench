import { assertSupported, mask, reflect, reflectByte, type CrcModel } from "./model";

/**
 * The bit-at-a-time reference implementation, in BigInt.
 *
 * Slow by construction — one shift per bit of input, with BigInt arithmetic — and
 * that is the point. It is a direct transcription of the model's definition with no
 * table, no width-dependent fast path and nothing clever, so it is the thing the
 * optimised engine in `./engine.ts` is checked *against*.
 *
 * That pairing is what makes the fast path trustworthy. A table-driven CRC has
 * exactly two interesting bugs — a table built with the wrong bit order, and a
 * reflection applied at the wrong end — and both produce plausible-looking constant
 * output that a single check value can miss. `tests/crc.test.ts` runs both
 * implementations over random inputs for every model in the catalogue and requires
 * them to agree, which neither can fake.
 *
 * Not exported from the package's public entry point: nothing in the app should use
 * this. It exists for the test suite and for building tables.
 */
export function crcReference(model: CrcModel, data: Uint8Array): bigint {
  assertSupported(model);

  const width = BigInt(model.width);
  const m = mask(model.width);
  const topBit = 1n << (width - 1n);

  let crc = model.init;

  /**
   * One message bit at a time, which is the definition and works at every width.
   *
   * The byte-at-a-time form -- `crc ^= byte << (width - 8)` and then eight shifts -- is equivalent
   * for width >= 8 and silently wrong below it: the shift goes negative, and a negative BigInt shift
   * is a *right* shift, so five bits of every byte fell off the bottom. Feeding bits individually
   * removes the special case rather than adding one, and this is the slow obviously-correct path
   * whose whole job is to have no special cases.
   */
  for (const rawByte of data) {
    const byte = model.refIn ? reflectByte(rawByte) : rawByte;
    for (let bit = 7; bit >= 0; bit--) {
      const incoming = (byte >> bit) & 1;
      const outgoing = (crc & topBit) !== 0n ? 1 : 0;
      crc = ((crc << 1n) & m) ^ (outgoing !== incoming ? model.poly : 0n);
    }
  }

  if (model.refOut) crc = reflect(crc, model.width);
  return (crc ^ model.xorOut) & m;
}

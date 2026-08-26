/**
 * RC2, from RFC 2268, over the shared `BlockCipher` interface.
 *
 * Rivest's 1987 replacement for DES, and the reason it is still worth having: it is the cipher inside
 * a great deal of 1990s and 2000s data. S/MIME's `rc2CBC`, PKCS#12 files with `pbeWithSHAAnd40BitRC2`,
 * old Word and Excel encryption, and Netscape-era TLS all used it. OpenSSL 3 still implements it, in
 * the legacy provider -- which Node does not load, so there is no oracle here and RFC 2268's own eight
 * test vectors are the check instead.
 *
 * Four things to know.
 *
 * **The "effective key length" is a separate parameter from the key.** RC2 was designed for an era of
 * export rules, so the key schedule deliberately throws strength away: `T1` says how many key bits
 * should actually matter, and the schedule masks the expanded key down to that. A 128-byte key with
 * `T1 = 40` has 40 bits of strength. Both must match for two implementations to agree, and that is the
 * commonest reason RC2 output differs between tools -- OpenSSL defaults the effective length to the
 * key length in bits, and several other implementations default it to 1024.
 *
 * **`PITABLE` is a stored table, unlike Blowfish's.** RFC 2268 calls it "random bytes based on the
 * digits of PI", but it is a *permutation* of 0..255 derived by an unpublished process rather than the
 * digits themselves -- so unlike `blowfish.ts` there is nothing to derive, and the 256 bytes below
 * were parsed out of the RFC by script. The load-time permutation check is what stands in for a
 * derivation: a mistyped entry almost certainly breaks it.
 *
 * **Sixteen mixing rounds and two mashing rounds, in the pattern 5-1-6-1-5.** Each mixing round
 * consumes four key words, so all 64 are used exactly once; the mashing rounds index into the key
 * array with data, which is what makes the cipher's key use non-uniform.
 *
 * **Everything is little-endian 16-bit words.** The block is four of them, and reading it big-endian
 * gives a cipher that inverts perfectly and matches nothing.
 */
import type { BlockCipher } from "./blockmodes";

const BLOCK = 8;

/**
 * RFC 2268's `PITABLE`, parsed from the RFC's own 16x16 grid.
 *
 * A permutation of 0..255, which is asserted at load: the property is cheap to check and a single
 * mistyped byte would give a cipher that keys, encrypts, decrypts and reproduces none of the eight
 * published vectors.
 */
const PITABLE: readonly number[] = [
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79,
  0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 0x17, 0x9a, 0x59, 0xf5,
  0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22,
  0x5c, 0x6b, 0x4e, 0x82, 0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f,
  0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b,
  0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 0x08, 0xe8, 0xea, 0xde,
  0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e,
  0x04, 0x18, 0xa4, 0xec, 0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85,
  0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10,
  0x67, 0x6c, 0xba, 0xc9, 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 0x0d, 0x38, 0x34, 0x1b,
  0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68,
  0xfe, 0x7f, 0xc1, 0xad,
];

if (new Set(PITABLE).size !== 256) {
  throw new Error("RC2's PITABLE is not a permutation of 0..255.");
}

/** The rotation amounts for the four words of the mixing round. */
const MIX_ROTATIONS = [1, 2, 3, 5] as const;

/**
 * The expanded key: 64 16-bit words, masked down to the effective key length.
 *
 * `T8` is the effective length in bytes and `TM` the mask for its topmost byte, which together are
 * what reduce the search space to `effectiveBits` -- the expanded key depends on nothing else.
 */
function expandKey(key: Uint8Array, effectiveBits: number): Uint16Array {
  if (key.length < 1 || key.length > 128) {
    throw new Error(`RC2's key is 1 to 128 bytes; this one is ${key.length}.`);
  }
  if (effectiveBits < 1 || effectiveBits > 1024) {
    throw new Error(`RC2's effective key length is 1 to 1024 bits; this one is ${effectiveBits}.`);
  }

  const t8 = Math.ceil(effectiveBits / 8);
  const tm = 255 % Math.pow(2, 8 + effectiveBits - 8 * t8);

  const l = new Uint8Array(128);
  l.set(key);
  for (let i = key.length; i < 128; i++) {
    l[i] = PITABLE[(l[i - 1]! + l[i - key.length]!) & 0xff]!;
  }
  // The masking step, and then the second loop that spreads it back through the whole array.
  l[128 - t8] = PITABLE[l[128 - t8]! & tm]!;
  for (let i = 127 - t8; i >= 0; i--) l[i] = PITABLE[l[i + 1]! ^ l[i + t8]!]!;

  const expanded = new Uint16Array(64);
  for (let i = 0; i < 64; i++) expanded[i] = l[2 * i]! + 256 * l[2 * i + 1]!;
  return expanded;
}

const rol16 = (x: number, n: number): number => ((x << n) | (x >>> (16 - n))) & 0xffff;
const ror16 = (x: number, n: number): number => ((x >>> n) | (x << (16 - n))) & 0xffff;

/**
 * RC2 as a `BlockCipher`.
 *
 * `effectiveBits` defaults to the key length in bits, which is what OpenSSL does and therefore what
 * someone comparing output most likely wants. It is a separate argument rather than being inferred
 * because it genuinely is a separate parameter of the cipher.
 */
export function createRc2(key: Uint8Array, effectiveBits = key.length * 8): BlockCipher {
  const k = expandKey(key, effectiveBits);

  const load = (src: Uint8Array): number[] =>
    [0, 1, 2, 3].map((i) => src[2 * i]! + 256 * src[2 * i + 1]!);
  const store = (r: readonly number[], dst: Uint8Array): void => {
    for (let i = 0; i < 4; i++) {
      dst[2 * i] = r[i]! & 0xff;
      dst[2 * i + 1] = r[i]! >>> 8;
    }
  };

  return {
    blockSize: BLOCK,
    encryptBlock: (src, dst) => {
      const r = load(src);
      let j = 0;
      const mix = (i: number): void => {
        // The "composite" word: R[i-2] where R[i-1] is one, R[i-3] where it is zero.
        const composite = (r[(i + 3) % 4]! & r[(i + 2) % 4]!) | (~r[(i + 3) % 4]! & r[(i + 1) % 4]!);
        r[i] = (r[i]! + k[j]! + composite) & 0xffff;
        j += 1;
        r[i] = rol16(r[i]!, MIX_ROTATIONS[i]!);
      };
      const mash = (i: number): void => {
        r[i] = (r[i]! + k[r[(i + 3) % 4]! & 63]!) & 0xffff;
      };
      const rounds = (count: number, step: (i: number) => void): void => {
        for (let round = 0; round < count; round++) for (let i = 0; i < 4; i++) step(i);
      };

      rounds(5, mix);
      rounds(1, mash);
      rounds(6, mix);
      rounds(1, mash);
      rounds(5, mix);
      store(r, dst);
    },
    decryptBlock: (src, dst) => {
      const r = load(src);
      // j walks backwards from the end of the key, which is what makes r-mix the inverse of mix.
      let j = 63;
      const rMix = (i: number): void => {
        r[i] = ror16(r[i]!, MIX_ROTATIONS[i]!);
        const composite = (r[(i + 3) % 4]! & r[(i + 2) % 4]!) | (~r[(i + 3) % 4]! & r[(i + 1) % 4]!);
        r[i] = (r[i]! - k[j]! - composite) & 0xffff;
        j -= 1;
      };
      const rMash = (i: number): void => {
        r[i] = (r[i]! - k[r[(i + 3) % 4]! & 63]!) & 0xffff;
      };
      const rounds = (count: number, step: (i: number) => void): void => {
        for (let round = 0; round < count; round++) for (let i = 3; i >= 0; i--) step(i);
      };

      rounds(5, rMix);
      rounds(1, rMash);
      rounds(6, rMix);
      rounds(1, rMash);
      rounds(5, rMix);
      store(r, dst);
    },
  };
}

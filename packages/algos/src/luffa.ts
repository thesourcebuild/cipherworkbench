/**
 * Luffa, a SHA-3 second-round candidate, at all four output lengths.
 *
 * A sponge-like design with an unusual shape: the state is `w` independent 256-bit lanes -- three for
 * Luffa-224 and -256, four for -384, five for -512 -- and a message block is injected into all of them
 * at once before each is permuted separately. That makes the wide variants genuinely wider rather than
 * differently truncated, and it is why the message-injection step below is written three times: its
 * structure changes with the lane count, not just its length.
 *
 * Four things to know.
 *
 * **The lane transform is multiplication by x in GF(2^8)[y].** `m2` looks like an odd rotation with two
 * extra XORs, and that is exactly what multiplying a lane by the generator comes to. It appears in the
 * injection step for every lane and again for the message, which is what spreads one block across all
 * `w` lanes.
 *
 * **Injection differs per lane count and the reference writes three versions.** For three lanes it is
 * a sum, a multiply and a message XOR. Four and five add one and two further "multiply this lane and
 * fold in its neighbour" passes respectively, and the five-lane version walks them in the *opposite*
 * direction from the four-lane one. Deriving one from the other looked possible and was wrong; they
 * are written out.
 *
 * **The tweak happens once per permutation, not once per round.** Lane `j` rotates the upper half of
 * its own state left by `j` bits before its eight rounds begin. Doing it per round instead leaves
 * lane 0 correct and every other lane wrong.
 *
 * **Absorbing a block is inject-then-permute, and the finalisation is two more of the same.** The
 * padded block goes in, then an all-zero block, and the digest is the XOR of the lanes -- with one
 * further inject-and-permute for the sizes that need more than 32 bytes of output.
 *
 * There is no oracle: OpenSSL never implemented Luffa and no dependency here does. The check is 72
 * known-answer vectors from the SHA-3 competition's own KATs, four output lengths at eighteen message
 * lengths each. Two bugs those caught, in the order they appeared: the absorb loop injected without
 * permuting, which left every message under 32 bytes correct; and the four- and five-lane injections
 * were guessed from the three-lane one.
 */

const u32 = (x: number): number => x >>> 0;
const rotl = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));

/** The per-lane initial values, parsed from the reference implementation. */
const V_INIT: readonly (readonly number[])[] = [
  [
    0x6d251e69, 0x44b051e0, 0x4eaa6fb4, 0xdbf78465,
    0x6e292011, 0x90152df4, 0xee058139, 0xdef610bb,
  ],
  [
    0xc3b44b95, 0xd9d2f256, 0x70eee9a0, 0xde099fa3,
    0x5d9b0557, 0x8fc944b3, 0xcf1ccf0e, 0x746cd581,
  ],
  [
    0xf7efc89d, 0x5dba5781, 0x04016ce5, 0xad659c05,
    0x0306194f, 0x666d1836, 0x24aa230a, 0x8b264ae7,
  ],
  [
    0x858075d5, 0x36d79cce, 0xe571f7d7, 0x204b1f67,
    0x35870c6a, 0x57e9e923, 0x14bcb808, 0x7cde72ce,
  ],
  [
    0x6c68e9be, 0x5ec41e22, 0xc825b7c7, 0xaffb4363,
    0xf5df3999, 0x0fc688f1, 0xb07224cc, 0x03e86cea,
  ],
];

/**
 * The round constants: sixteen per lane, the first eight applied to word 0 and the rest to word 4.
 *
 * Parsed from the reference rather than transcribed. They are not derivable from anything -- the
 * specification simply tabulates them -- so what stands behind them is the vector set.
 */
const RC: readonly (readonly number[])[] = [
  [
    0x303994a6, 0xc0e65299, 0x6cc33a12, 0xdc56983e,
    0x1e00108f, 0x7800423d, 0x8f5b7882, 0x96e1db12,
    0xe0337818, 0x441ba90d, 0x7f34d442, 0x9389217f,
    0xe5a8bce6, 0x5274baf4, 0x26889ba7, 0x9a226e9d,
  ],
  [
    0xb6de10ed, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51,
    0x707a3d45, 0xaeb28562, 0xbaca1589, 0x40a46f3e,
    0x01685f3d, 0x05a17cf4, 0xbd09caca, 0xf4272b28,
    0x144ae5cc, 0xfaa7ae2b, 0x2e48f1c1, 0xb923c704,
  ],
  [
    0xfc20d9d2, 0x34552e25, 0x7ad8818f, 0x8438764a,
    0xbb6de032, 0xedb780c8, 0xd9847356, 0xa2c78434,
    0xe25e72c1, 0xe623bb72, 0x5c58a4a4, 0x1e38e2e7,
    0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7,
  ],
  [
    0xb213afa5, 0xc84ebe95, 0x4e608a22, 0x56d858fe,
    0x343b138f, 0xd0ec4e3d, 0x2ceb4882, 0xb3ad2208,
    0xe028c9bf, 0x44756f91, 0x7e8fce32, 0x956548be,
    0xfe191be2, 0x3cb226e5, 0x5944a28e, 0xa1c4c355,
  ],
  [
    0xf0d2e9e3, 0xac11d7fa, 0x1bcb66f2, 0x6f2d9bc9,
    0x78602649, 0x8edae952, 0x3b6ba548, 0xedae9520,
    0x5090d577, 0x2d1925ab, 0xb46496ac, 0xd1925ab0,
    0x29131ab6, 0x0fc053c3, 0x3f014f0c, 0xfc053c31,
  ],
];

/** Lanes by output length: three for 224 and 256, four for 384, five for 512. */
function lanesFor(outputLen: number): 3 | 4 | 5 {
  if (outputLen <= 32) return 3;
  return outputLen === 48 ? 4 : 5;
}

/** Multiplication by the field generator, which is what mixes one lane into the next. */
function m2(s: readonly number[]): number[] {
  const t = s[7]!;
  return [t, u32(s[0]! ^ t), s[1]!, u32(s[2]! ^ t), u32(s[3]! ^ t), s[4]!, s[5]!, s[6]!];
}

const xor8 = (a: readonly number[], b: readonly number[]): number[] =>
  a.map((x, i) => u32(x ^ b[i]!));

/** Luffa's 4-bit S-box, applied bitsliced across four words of a lane. */
function subCrumb(v: number[], i0: number, i1: number, i2: number, i3: number): void {
  let a0 = v[i0]!;
  let a1 = v[i1]!;
  let a2 = v[i2]!;
  let a3 = v[i3]!;
  const tmp = a0;
  a0 = u32(a0 | a1);
  a2 = u32(a2 ^ a3);
  a1 = u32(~a1);
  a0 = u32(a0 ^ a3);
  a3 = u32(a3 & tmp);
  a1 = u32(a1 ^ a3);
  a3 = u32(a3 ^ a2);
  a2 = u32(a2 & a0);
  a0 = u32(~a0);
  a2 = u32(a2 ^ a1);
  a1 = u32(a1 | a3);
  const rotated = u32(tmp ^ a1);
  a3 = u32(a3 ^ a2);
  a2 = u32(a2 & a1);
  a1 = u32(a1 ^ a0);
  v[i0] = rotated;
  v[i1] = a1;
  v[i2] = a2;
  v[i3] = a3;
}

/** The linear step, pairing each of the lower four words with one of the upper four. */
function mixWord(v: number[], lower: number, upper: number): void {
  let u = v[lower]!;
  let w = v[upper]!;
  w = u32(w ^ u);
  u = u32(rotl(u, 2) ^ w);
  w = u32(rotl(w, 14) ^ u);
  u = u32(rotl(u, 10) ^ w);
  w = rotl(w, 1);
  v[lower] = u;
  v[upper] = w;
}

/** The permutation: the tweak once, then eight rounds per lane with that lane's own constants. */
function permute(lanes: number[][]): void {
  for (let j = 1; j < lanes.length; j++) {
    for (let i = 4; i < 8; i++) lanes[j]![i] = rotl(lanes[j]![i]!, j);
  }
  for (let j = 0; j < lanes.length; j++) {
    const v = lanes[j]!;
    const rc = RC[j]!;
    for (let r = 0; r < 8; r++) {
      subCrumb(v, 0, 1, 2, 3);
      subCrumb(v, 5, 6, 7, 4);
      mixWord(v, 0, 4);
      mixWord(v, 1, 5);
      mixWord(v, 2, 6);
      mixWord(v, 3, 7);
      v[0] = u32(v[0]! ^ rc[r]!);
      v[4] = u32(v[4]! ^ rc[8 + r]!);
    }
  }
}

/** Message injection. Three shapes, one per lane count; see the header. */
function inject(lanes: number[][], block: Uint8Array): void {
  const w = lanes.length;
  let m: number[] = [];
  for (let i = 0; i < 8; i++) {
    m.push(
      u32(
        (block[4 * i]! << 24) |
          (block[4 * i + 1]! << 16) |
          (block[4 * i + 2]! << 8) |
          block[4 * i + 3]!,
      ),
    );
  }

  let a = lanes[0]!;
  for (let j = 1; j < w; j++) a = xor8(a, lanes[j]!);
  a = m2(a);
  for (let j = 0; j < w; j++) lanes[j] = xor8(lanes[j]!, a);

  if (w === 4) {
    const b = xor8(m2(lanes[0]!), lanes[3]!);
    lanes[3] = xor8(m2(lanes[3]!), lanes[2]!);
    lanes[2] = xor8(m2(lanes[2]!), lanes[1]!);
    lanes[1] = xor8(m2(lanes[1]!), lanes[0]!);
    // An assignment rather than an XOR: the reference sets lane 0 from `b` and the message together.
    lanes[0] = xor8(b, m);
    m = m2(m);
    for (let j = 1; j < 4; j++) {
      lanes[j] = xor8(lanes[j]!, m);
      if (j < 3) m = m2(m);
    }
    return;
  }

  if (w === 5) {
    // Note the direction: this walks upward where the four-lane version walks down.
    const b = xor8(m2(lanes[0]!), lanes[1]!);
    lanes[1] = xor8(m2(lanes[1]!), lanes[2]!);
    lanes[2] = xor8(m2(lanes[2]!), lanes[3]!);
    lanes[3] = xor8(m2(lanes[3]!), lanes[4]!);
    lanes[4] = xor8(m2(lanes[4]!), lanes[0]!);
    lanes[0] = xor8(m2(b), lanes[4]!);
    lanes[4] = xor8(m2(lanes[4]!), lanes[3]!);
    lanes[3] = xor8(m2(lanes[3]!), lanes[2]!);
    lanes[2] = xor8(m2(lanes[2]!), lanes[1]!);
    lanes[1] = xor8(m2(lanes[1]!), b);
  }

  for (let j = 0; j < w; j++) {
    lanes[j] = xor8(lanes[j]!, m);
    m = m2(m);
  }
}

/** The XOR of every lane, which is what the digest is read from. */
function squeeze(lanes: readonly number[][]): number[] {
  const out: number[] = [];
  for (let i = 0; i < 8; i++) {
    let acc = 0;
    for (const lane of lanes) acc = u32(acc ^ lane[i]!);
    out.push(acc);
  }
  return out;
}

/** A Luffa digest of any of the four standardised lengths. */
export function luffa(outputLen: 28 | 32 | 48 | 64, message: Uint8Array): Uint8Array {
  const w = lanesFor(outputLen);
  const lanes: number[][] = [];
  for (let j = 0; j < w; j++) lanes.push([...V_INIT[j]!]);

  let at = 0;
  for (; at + 32 <= message.length; at += 32) {
    inject(lanes, message.subarray(at, at + 32));
    permute(lanes);
  }

  // Padding is a single 0x80 and zeros; Luffa carries no length field anywhere.
  const tail = new Uint8Array(32);
  tail.set(message.subarray(at));
  tail[message.length - at] = 0x80;

  inject(lanes, tail);
  permute(lanes);
  inject(lanes, new Uint8Array(32));
  permute(lanes);

  const out = new Uint8Array(outputLen);
  const first = squeeze(lanes);
  for (let i = 0; i < Math.min(outputLen, 32); i++) {
    out[i] = (first[i >> 2]! >>> (8 * (3 - (i & 3)))) & 0xff;
  }

  if (outputLen > 32) {
    // One more squeeze for the lengths that need more than the state's own 32 bytes.
    inject(lanes, new Uint8Array(32));
    permute(lanes);
    const second = squeeze(lanes);
    for (let i = 32; i < outputLen; i++) {
      out[i] = (second[(i - 32) >> 2]! >>> (8 * (3 - ((i - 32) & 3)))) & 0xff;
    }
  }
  return out;
}

/** An incremental Luffa. Buffered, so the manifest reports `streaming: false`. */
export function createLuffa(outputLen: 28 | 32 | 48 | 64): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
} {
  const chunks: Uint8Array[] = [];
  let length = 0;
  return {
    update: (chunk) => {
      chunks.push(chunk);
      length += chunk.length;
    },
    digest: () => {
      const all = new Uint8Array(length);
      let at = 0;
      for (const chunk of chunks) {
        all.set(chunk, at);
        at += chunk.length;
      }
      return luffa(outputLen, all);
    },
  };
}

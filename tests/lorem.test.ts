import crypto from "node:crypto";
import zlib from "node:zlib";
import { beforeAll, describe, expect, it } from "vitest";
import {
  createAria,
  createCamellia,
  createCrc,
  createSm4,
  createTripleDes,
  crcHex,
  CRC_CATALOGUE,
  requireCrcModel,
  decryptBlockMode,
  encryptBlockMode,
  gcmDecrypt,
  gcmEncrypt,
  type BlockMode,
} from "@ocs/algos";
import { hashToolDefinition, prepareHashAlgorithm } from "@ocs/hash/definition";
import { HASH_ALGORITHMS } from "@ocs/hash";
import { crcToolDefinition } from "@ocs/crc/definition";
import { encodeHex, runStream } from "@ocs/engine";
import { LOREM } from "../apps/web/app/test-inputs";
// Reached by path, like `algos-crc.test.ts` does: the bit-at-a-time reference is deliberately not
// part of the package's public surface, and only the test suite has a reason to touch it.
import { crcReference } from "../packages/algos/src/crc/reference";

/**
 * Prepare every hash algorithm before anything else runs, exactly as `loadTool()` does.
 *
 * Each algorithm implemented in `@ocs/algos` is a dynamic import of its own module, so a hash tool
 * downloads its own tables and nobody else's -- see the header of `packages/tools/hash/src/bindings.ts`.
 * This file reaches `hashToolDefinition` directly and therefore bypasses the registry, so it has to do
 * what the registry does. The sync accessor throws with a message naming this call rather than
 * returning a zeroed table, which is why a missing prepare fails loudly instead of producing a
 * plausible wrong digest.
 */
beforeAll(async () => {
  await Promise.all(HASH_ALGORITHMS.map((meta) => prepareHashAlgorithm(meta.id)));
}, 60_000);

/**
 * The Lorem test input, run through CRC, the hashes and the ciphers at its real size.
 *
 * Everything else in this suite is either a published vector -- almost all of which are under 64 bytes,
 * 77 of the 141 digest vectors being the empty string -- or a generated sweep of short lengths. So the
 * *multi-kilobyte* path was covered only incidentally, and this file covers it deliberately, over the
 * exact string the app's Test input menu loads. That matters for a reason beyond block loops: it is the
 * value somebody will compare against this app by hand, so it is worth knowing it is right.
 *
 * **Nothing here records what this implementation produced.** Every assertion is against something
 * independent: OpenSSL through `node:crypto` for the ciphers, zlib's own CRC-32 for the one CRC that
 * has a third-party oracle, and the bit-at-a-time `crcReference` -- a genuinely different formulation,
 * not the same loop twice -- for all 113 models. The hashes and HMACs are covered by adding this input
 * to `openssl-parity.test.ts`'s own array, which is one line there rather than a second copy of that
 * file's nineteen mappings and its completeness gates.
 *
 * Three properties of 3,832 bytes are what make it worth its own file, and they were read off the
 * string rather than chosen -- which is why the numbers are asserted first:
 *
 *  - **59 blocks of 64, then 56 bytes.** A hash's padding needs nine more -- one 0x80 and an eight-byte
 *    length -- and 56 + 9 is 65, so it spills into a sixty-first block. SHA-512 does the same on its
 *    own scale: 120 bytes into the last 128-byte block, plus one and a sixteen-byte length, is 137.
 *    That two-block finalisation is the case nine bytes cannot reach at all.
 *  - **Exactly 479 blocks of 8.** An eight-byte-block cipher lands precisely on a boundary, so PKCS#7
 *    must add a *whole* padding block -- which an implementation that pads only when there is a
 *    remainder gets wrong, silently, on one input in eight. DES and 3DES are that case here.
 *  - **239 blocks of 16 and eight bytes over.** A sixteen-byte-block cipher gets the other case, filling
 *    its final block with eight bytes of padding. So one input covers both, decided by block size --
 *    and reading the block size off the wrong thing is a mistake this repo has actually made.
 */

const bytes = new TextEncoder().encode(LOREM);

/**
 * One OpenSSL AEAD cipher object for an algorithm name built at runtime.
 *
 * `@types/node` keys `setAAD` and `getAuthTag` off a *literal* algorithm name, so
 * `createCipheriv("aes-128-gcm", ...)` returns `CipherGCM` while `createCipheriv(someString, ...)`
 * returns the plain `Cipher`, which has neither. The name below is a template literal over a key size,
 * so it lands on the plain overload. Same cast and same reason as `algos-aead-modes.test.ts`, which is
 * where the longer note lives.
 */
type AeadCipher = crypto.Cipher & {
  setAAD(buffer: Uint8Array, options?: { plaintextLength?: number }): AeadCipher;
  getAuthTag(): Buffer;
};

function aeadCipher(name: string, key: Uint8Array, nonce: Uint8Array): AeadCipher {
  return crypto.createCipheriv(name, key, nonce, {
    authTagLength: 16,
  } as never) as unknown as AeadCipher;
}

/** `runStream` takes an async iterable, which is what a `File`'s stream is. */
async function* chunksOf(size: number): AsyncIterable<Uint8Array> {
  for (let at = 0; at < bytes.length; at += size) yield bytes.subarray(at, at + size);
}

describe("the fixture itself", () => {
  /**
   * The numbers the rest of this file reasons about, asserted rather than assumed.
   *
   * If the string is ever edited, these fail and say what changed -- which is better than the block
   * arithmetic above quietly ceasing to be true while every test still passes.
   */
  it("is 3,832 bytes, which puts it either side of three different boundaries", () => {
    expect(bytes.length).toBe(3832);
    // 59 whole 64-byte blocks and 56 bytes over, so a hash's 9 bytes of padding spill into a 61st.
    expect(Math.floor(bytes.length / 64)).toBe(59);
    expect(bytes.length % 64).toBe(56);
    expect((bytes.length % 64) + 9).toBeGreaterThan(64);
    // And on SHA-512's scale: 120 into the last 128-byte block, plus 1 and a 16-byte length.
    expect(bytes.length % 128).toBe(120);
    expect((bytes.length % 128) + 17).toBeGreaterThan(128);
    // Exactly aligned for an 8-byte block, so PKCS#7 adds a whole one; 8 short of a 16-byte block.
    expect(bytes.length % 8).toBe(0);
    expect(bytes.length / 8).toBe(479);
    expect(bytes.length % 16).toBe(8);
  });

  /**
   * Pure ASCII, which is why a byte count and a character count agree here.
   *
   * Worth pinning because the app's Test input menu labels it in *characters*, and under UTF-16LE --
   * which this app offers and people pick -- the byte count doubles while the character count does not.
   * An accented character slipped into the prose would make the label wrong for one encoding and the
   * numbers above wrong for all of them.
   */
  it("is pure ASCII, so its byte and character counts agree", () => {
    expect(bytes.length).toBe(LOREM.length);
    for (let i = 0; i < bytes.length; i++) {
      expect(bytes[i]! < 0x80, `byte ${i} is not ASCII`).toBe(true);
    }
  });

  it("is five paragraphs separated by blank lines", () => {
    const paragraphs = LOREM.split("\n\n");
    expect(paragraphs).toHaveLength(5);
    for (const paragraph of paragraphs) expect(paragraph.trim()).not.toBe("");
  });
});

// ── CRC ─────────────────────────────────────────────────────────────────────

describe("CRC over 3,832 bytes", () => {
  /**
   * All 113 models, engine against the bit-at-a-time reference.
   *
   * The engine is byte-wise over a 256-entry table; `crcReference` shifts one bit at a time straight
   * from the definition. Two genuinely different formulations, which is what makes agreement over
   * 30,656 bits meaningful -- and why this is not the same loop twice. The published check values in
   * the catalogue cover nine bytes; this covers the table-driven loop running four hundred times per
   * model, and the reflected and non-reflected paths at every width from 3 to 82.
   */
  it("agrees with the bit-at-a-time reference for every one of the 113 models", () => {
    const disagreed: string[] = [];
    for (const model of CRC_CATALOGUE) {
      const engine = crcHex(model, bytes);
      const reference = crcReference(model, bytes)
        .toString(16)
        .padStart(Math.ceil(model.width / 4), "0");
      if (engine !== reference) disagreed.push(`${model.name}: ${engine} vs ${reference}`);
    }
    expect(disagreed, "models where the two formulations differ").toEqual([]);
    // Guards the guard: a catalogue that failed to load would make the loop above vacuous.
    expect(CRC_CATALOGUE.length).toBe(113);
  });

  /**
   * And one model against a third-party implementation, which nothing here had before.
   *
   * `zlib.crc32` is the CRC-32 every zip file, PNG and gzip stream carries -- CRC-32/ISO-HDLC in the
   * RevEng catalogue's naming. It is the only CRC in this repo's dependency tree with an outside
   * oracle, so it is the only one that can be checked against something that is not ours; the other
   * 112 rest on the two-formulation agreement above and their published check values.
   */
  it("matches zlib's own CRC-32 for the model zip and PNG use", () => {
    const model = requireCrcModel("CRC-32/ISO-HDLC");
    const theirs = zlib.crc32(Buffer.from(bytes)).toString(16).padStart(8, "0");
    expect(crcHex(model, bytes)).toBe(theirs);
    // The same agreement over nine bytes, so a failure above cannot be blamed on the length.
    expect(crcHex(model, new TextEncoder().encode("123456789"))).toBe(
      zlib.crc32(Buffer.from("123456789")).toString(16).padStart(8, "0"),
    );
  });

  /**
   * Streaming equals one-shot, at chunk sizes chosen to be awkward.
   *
   * 3,832 bytes is the first input in this suite where chunking means anything: one byte at a time is
   * 3,832 update calls, and 1,000 splits it into three whole chunks and a remainder of 832. A CRC is
   * trivially incremental so this is cheap insurance rather than a likely bug -- but it is the property
   * the whole file-streaming path depends on, and it has never been exercised over a real input.
   */
  it("streams to the same value at every chunk size", async () => {
    const model = requireCrcModel("CRC-32/ISO-HDLC");
    const expected = crcHex(model, bytes);
    for (const size of [1, 7, 64, 1000, 3832, 9999]) {
      const engine = createCrc(model);
      for (let at = 0; at < bytes.length; at += size)
        engine.update(bytes.subarray(at, at + size));
      expect(engine.digest().toString(16).padStart(8, "0"), `chunks of ${size}`).toBe(expected);
    }
  });

  /** And through the tool, which is what the app actually calls. */
  it("gives the same value through the CRC tool as through the engine", async () => {
    const tool = crcToolDefinition("crc32");
    const result = await tool.compute(tool.createSpec(), bytes);
    expect(result.error).toBeUndefined();
    expect(encodeHex(result.bytes!)).toBe(crcHex(requireCrcModel("CRC-32/ISO-HDLC"), bytes));
  });
});

// ── Hashes ──────────────────────────────────────────────────────────────────

describe("hashes over 3,832 bytes", () => {
  /**
   * The digests themselves are checked against OpenSSL in `openssl-parity.test.ts`, which now has this
   * input in its own array -- nineteen digests and sixteen HMACs, for one line there.
   *
   * What is left for here is the *streaming* path, which that file does not exercise: `runStream` over
   * a `ToolStream`, at chunk sizes that do not divide the input, must equal the one-shot compute. This
   * is the invariant the whole file-input path rests on, and 3,832 bytes is the first input in the
   * suite big enough for a chunk boundary to fall anywhere interesting.
   */
  it("streams to the same digest as it computes in one shot", async () => {
    /**
     * Seven, chosen for the shapes rather than for coverage: a 64-byte block (md5, sha1, sha256), a
     * 128-byte one (sha512), a sponge (sha3-256), a tree-capable one (blake2b) and one written here
     * from scratch (sm3). The digests themselves are OpenSSL's problem in `openssl-parity.test.ts`;
     * what this asserts is that chunking cannot change them.
     */
    for (const id of ["md5", "sha1", "sha256", "sha512", "sha3-256", "blake2b", "sm3"]) {
      const tool = hashToolDefinition(id);
      const spec = tool.createSpec();
      const oneShot = await tool.compute(spec, bytes);
      expect(oneShot.error, `${id}: ${oneShot.error}`).toBeUndefined();

      for (const size of [1, 7, 63, 64, 65, 1000]) {
        const streamed = await runStream(tool.createStream!(spec), chunksOf(size));
        expect(encodeHex(streamed.bytes!), `${id} in chunks of ${size}`).toBe(
          encodeHex(oneShot.bytes!),
        );
      }
    }
  });

  /**
   * A one-byte change anywhere must change the digest, checked at the ends and in the middle.
   *
   * Not a cryptographic claim -- one flipped bit changing a digest is not news -- but a check that
   * every byte of a 3,832-byte input is actually *read*. A loop that dropped a final partial block, or
   * started at the wrong offset, would still produce a plausible digest for the whole input and would
   * pass every fixed vector under 64 bytes.
   */
  it("reads every byte, including the first and the last", async () => {
    const tool = hashToolDefinition("sha256");
    const spec = tool.createSpec();
    const baseline = encodeHex((await tool.compute(spec, bytes)).bytes!);

    for (const at of [0, 1, 63, 64, 1915, 3830, 3831]) {
      const altered = Uint8Array.from(bytes);
      altered[at] = altered[at]! ^ 0x01;
      const digest = encodeHex((await tool.compute(spec, altered)).bytes!);
      expect(digest, `flipping byte ${at} did not change the digest`).not.toBe(baseline);
    }
  });
});

// ── Ciphers ─────────────────────────────────────────────────────────────────

describe("ciphers over 3,832 bytes", () => {
  const key = (length: number) => Uint8Array.from({ length }, (_, i) => (i * 37 + 11) & 0xff);
  const iv = key(16);

  /**
   * Every cipher OpenSSL has, in every chaining mode, against OpenSSL -- over prose rather than a
   * pattern.
   *
   * `algos-camellia-aria.test.ts` and `algos-blockciphers.test.ts` already do this at thirteen short
   * lengths, and the addition here is the length itself: 3,832 bytes is 239 whole blocks and a part, so the mode loop
   * runs 240 times and CBC's chaining, CFB's feedback and CTR's counter all have room to drift. A
   * counter that failed to carry out of its low byte is correct for the first 256 blocks and wrong
   * after -- which every one of those thirteen lengths is too short to see, and this is not.
   */
  const FAMILIES = [
    {
      label: "camellia",
      openssl: (bits: number, mode: string) => `camellia-${bits}-${mode}`,
      create: createCamellia,
      keys: [16, 24, 32],
    },
    {
      label: "aria",
      openssl: (bits: number, mode: string) => `aria-${bits}-${mode}`,
      create: createAria,
      keys: [16, 24, 32],
    },
    {
      label: "sm4",
      openssl: (_bits: number, mode: string) => `sm4-${mode}`,
      create: createSm4,
      keys: [16],
    },
  ];
  const MODES: readonly BlockMode[] = ["ecb", "cbc", "cfb", "ofb", "ctr"];

  for (const family of FAMILIES) {
    for (const keyBytes of family.keys) {
      it(`${family.label}-${keyBytes * 8} matches OpenSSL in every mode`, () => {
        const k = key(keyBytes);
        const cipher = family.create(k);
        for (const mode of MODES) {
          const name = family.openssl(keyBytes * 8, mode);
          const options = mode === "ecb" ? {} : { iv };
          const ours = encryptBlockMode(cipher, mode, bytes, options);

          const openssl = crypto.createCipheriv(name, k, mode === "ecb" ? null : iv);
          openssl.setAutoPadding(mode === "ecb" || mode === "cbc");
          const theirs = Buffer.concat([openssl.update(bytes), openssl.final()]);
          expect(encodeHex(ours), name).toBe(theirs.toString("hex"));

          const back = decryptBlockMode(cipher, mode, ours, options);
          expect(encodeHex(back), `${name} round trip`).toBe(encodeHex(bytes));
        }
      });
    }
  }

  /**
   * 3DES, whose block is eight bytes -- so 3,832 is 479 blocks, exactly aligned.
   *
   * Worth having alongside the 128-bit ciphers precisely because the block size differs: a mode layer
   * that read its block size from the wrong place is right for one family and wrong for the other,
   * which is a mistake this repo has actually made (`requiredNonceLength` reading AES's 16 for DES).
   */
  it("3DES matches OpenSSL in every mode it offers", () => {
    const k = key(24);
    const cipher = createTripleDes(k);
    const iv8 = key(8);
    // No `des-ede3-ctr`: OpenSSL does not offer one, and inventing the comparison would be comparing
    // our CTR against our CTR. `crypto.getCiphers()` is the list, and this is the four it has.
    for (const mode of ["ecb", "cbc", "cfb", "ofb"] as const satisfies readonly BlockMode[]) {
      const name = mode === "ecb" ? "des-ede3" : `des-ede3-${mode}`;
      const options = mode === "ecb" ? {} : { iv: iv8 };
      const ours = encryptBlockMode(cipher, mode, bytes, options);

      const openssl = crypto.createCipheriv(name, k, mode === "ecb" ? null : iv8);
      openssl.setAutoPadding(mode === "ecb" || mode === "cbc");
      const theirs = Buffer.concat([openssl.update(bytes), openssl.final()]);
      expect(encodeHex(ours), name).toBe(theirs.toString("hex"));
      expect(
        encodeHex(decryptBlockMode(cipher, mode, ours, options)),
        `${name} round trip`,
      ).toBe(encodeHex(bytes));
    }
  });

  /**
   * The padding block, which is the reason this length was worth choosing.
   *
   * 3,824 is exactly 239 sixteen-byte blocks, so PKCS#7 must append a *whole* block of sixteen 0x10
   * bytes. An implementation that pads only when there is a remainder produces 239 blocks instead of
   * 240 -- correct for fifteen inputs in sixteen, and undetectable without a length like this one.
   */
  it("pads to the same length two different ways, decided by the block size", () => {
    /**
     * 3,832 is exactly 479 blocks of eight and 239-and-a-half blocks of sixteen, so this one input hits
     * both PKCS#7 cases at once -- and lands on 3,840 bytes either way, for opposite reasons.
     *
     * The eight-byte block is the one that matters: it is exactly aligned, so a *whole* padding block
     * of eight 0x08 bytes has to be appended. An implementation that pads only when there is a
     * remainder produces 3,832 here and is wrong on one input in eight, undetectably, unless something
     * feeds it a length like this.
     */
    const wide = createCamellia(key(16));
    const narrow = createTripleDes(key(24));

    const wideEcb = encryptBlockMode(wide, "ecb", bytes, {});
    const narrowEcb = encryptBlockMode(narrow, "ecb", bytes, {});
    // Sixteen-byte block: eight bytes short, so the final block is *filled*.
    expect(wideEcb.length).toBe(3840);
    // Eight-byte block: exactly aligned, so a whole block is *added*.
    expect(narrowEcb.length).toBe(3840);
    expect(narrowEcb.length).toBe(bytes.length + 8);

    expect(encodeHex(decryptBlockMode(wide, "ecb", wideEcb, {}))).toBe(encodeHex(bytes));
    expect(encodeHex(decryptBlockMode(narrow, "ecb", narrowEcb, {}))).toBe(encodeHex(bytes));

    /**
     * And the other way round, one byte shorter: 3,831 is no longer eight-aligned, so the narrow
     * cipher fills a block instead of adding one, while the wide cipher's padding grows to nine.
     * Asserting both directions is what stops "always add a block" passing as easily as "never do".
     */
    const short = bytes.subarray(0, bytes.length - 1);
    expect(encryptBlockMode(narrow, "ecb", short, {}).length).toBe(3832);
    expect(encryptBlockMode(wide, "ecb", short, {}).length).toBe(3840);
  });

  /**
   * Our generic GCM against OpenSSL's, over 3,832 bytes and with associated data.
   *
   * ARIA because it is the widest overlap available: `aria-128/192/256-gcm` are all in
   * `crypto.getCiphers()`, and the GCM in this repo is a *generic* construction over the
   * `BlockCipher` interface rather than a sealed AES-only one -- so this checks the mode and not the
   * cipher. Length is what it adds over the existing parity tests: GHASH accumulates over 240 blocks
   * here, and the length block it finalises with encodes 30,656 bits rather than a couple of hundred.
   *
   * Associated data is included because the tag covers it separately from the ciphertext, and a
   * construction that mixed the two lengths into GHASH the wrong way round is right whenever one of
   * them is empty -- which is every AEAD test in this suite that does not pass one.
   */
  it("our generic GCM matches OpenSSL's over the whole input, with associated data", () => {
    const nonce = key(12);
    const ad = new TextEncoder().encode("Lorem ipsum, as associated data");

    for (const keyBytes of [16, 24, 32]) {
      const k = key(keyBytes);
      const name = `aria-${keyBytes * 8}-gcm`;

      const ours = gcmEncrypt(createAria(k), nonce, bytes, ad);

      const openssl = aeadCipher(name, k, nonce);
      openssl.setAAD(ad);
      const body = Buffer.concat([openssl.update(bytes), openssl.final()]);
      const theirs = Buffer.concat([body, openssl.getAuthTag()]);

      // Ciphertext and tag together: ours appends the tag, which is the shape noble uses too.
      expect(encodeHex(ours), name).toBe(theirs.toString("hex"));
      expect(ours.length, `${name} length`).toBe(bytes.length + 16);

      const opened = gcmDecrypt(createAria(k), nonce, ours, ad);
      expect(opened, `${name} rejected its own output`).not.toBeNull();
      expect(encodeHex(opened!), `${name} round trip`).toBe(encodeHex(bytes));

      // And the tag is load-bearing: one flipped bit anywhere in 3,848 must refuse.
      const tampered = Uint8Array.from(ours);
      tampered[1900] = tampered[1900]! ^ 0x01;
      expect(
        gcmDecrypt(createAria(k), nonce, tampered, ad),
        `${name} accepted a tampered body`,
      ).toBeNull();
      expect(
        gcmDecrypt(createAria(k), nonce, ours, new Uint8Array(0)),
        `${name} accepted the wrong associated data`,
      ).toBeNull();
    }
  });
});

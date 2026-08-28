import { createCipheriv, type Cipher } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AES_MODES,
  CIPHER_MANIFESTS,
  CIPHER_TOOLS,
  OPTION_AAD,
  OPTION_COUNTER,
  OPTION_DIRECTION,
  OPTION_PADDING,
  PADDING_SCHEMES,
  OPTION_DROP,
  OPTION_ANUBIS_VARIANT,
  OPTION_EFFECTIVE_KEY_BITS,
  OPTION_KEY,
  OPTION_KEY_SIZE,
  OPTION_MODE,
  OPTION_PARAM_SET,
  OPTION_NONCE,
  OPTION_TAG_LEN,
  getAesMode,
  requireCipherTool,
  type AesModeMeta,
  type CipherSpec,
} from "@ocs/cipher";
import {
  acceptedNonceLengths,
  applyAllFixes,
  cipherAcceptedByteLengths,
  cipherCatalogueFor,
  cipherGenerateLength,
  cipherToolDefinition,
  createSpec,
  describeSpec,
  lint,
  modeForSpec,
  requiredNonceLength,
  resolveCipher,
} from "@ocs/cipher/definition";
import { encodeHex, isAvailableOn, validateCatalogue, withAvailableChoices } from "@ocs/engine";
import { SIMON_SPECK_VARIANTS } from "@ocs/algos";
import { keySourceOptions } from "@ocs/kdf/key-source";
import { ASCON_AEAD128_KAT } from "./ascon-kat";
import { AEGIS128L_VECTORS, AEGIS256_VECTORS } from "./aegis-vectors";
import { CHAM_VECTORS, SIMECK_VECTORS, SKINNY_VECTORS } from "./lightweight-block-vectors";
import { LIGHTWEIGHT_BLOCK4_VECTORS } from "./lightweight-block4-vectors";
import { LS_VECTORS } from "./ls-design-vectors";

const ascii = (text: string) => new TextEncoder().encode(text);
const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));

function specFor(variant: string, options: CipherSpec["options"] = {}): CipherSpec {
  const base = createSpec({ variant });
  const merged = { ...base.options, ...options };
  /**
   * AES's key size is derived from the key when a test supplies one and does not say otherwise.
   *
   * `createSpec` seeds AES-256, because that is what Generate produced before the Key size control
   * existed. Every published AES-128 vector here passes a 16-byte key and would now be refused for
   * disagreeing with that seed -- eighteen of them were, the first time this ran. Setting the size
   * from the key is what a person does: paste a 16-byte key, choose AES-128. Doing it here rather
   * than at eighteen call sites keeps the vectors reading as vectors, and a test that wants the
   * mismatch can still pass `keySize` explicitly, which is how `C005`'s wrong-key-size case works.
   */
  /*
   * Keyed off whether the *caller* mentioned it, not off comparing values.
   *
   * The first version asked whether the merged value still equalled the seed, which cannot tell "the
   * test said nothing" from "the test deliberately said 256" -- so the case below that asserts a
   * 16-byte key is refused under AES-256 had its size silently rewritten to 128 and stopped testing
   * anything. Detecting intent by value equality is the bug; `in` asks the actual question.
   */
  if (variant === "aes" && !(OPTION_KEY_SIZE in options)) {
    const keyHex = merged[OPTION_KEY];
    if (typeof keyHex === "string" && merged.keyEncoding === "hex" && keyHex.length % 2 === 0) {
      const bytes = keyHex.length / 2;
      if (([16, 24, 32] as number[]).includes(bytes))
        merged[OPTION_KEY_SIZE] = String(bytes * 8);
    }
  }
  return { ...base, options: merged };
}

/** Key and nonce as the `bytes` options store them. */
function keyed(keyHex: string, nonceHex?: string, extra: CipherSpec["options"] = {}) {
  return {
    [OPTION_KEY]: keyHex,
    keyEncoding: "hex",
    ...(nonceHex === undefined ? {} : { [OPTION_NONCE]: nonceHex, nonceEncoding: "hex" }),
    ...extra,
  } satisfies CipherSpec["options"];
}

/**
 * The key length and the mode list a tool actually accepts.
 *
 * Both were written inline as `32` and `AES_MODES` until DES arrived with an eight-byte key and a
 * mode list of its own. Any test that seeds every entry in `CIPHER_TOOLS` has to ask the metadata
 * instead, or adding a cipher breaks it for a reason unrelated to what it is checking.
 */
function seedKeyLength(id: string): number {
  const tool = requireCipherTool(id);
  if (tool.block) {
    /**
     * A range, for the one cipher that has one.
     *
     * `keyLengths` is empty for Blowfish, so reading its last entry gave `undefined` and every loop
     * over `CIPHER_TOOLS` produced a zero-length key. That is what `keyRange` is for, and asking for
     * it here rather than special-casing the id keeps a second variable-key cipher free.
     */
    if (tool.block.keyRange) return tool.block.keyRange.max;
    /**
     * A parameterised cipher's key length belongs to the *set*, not to the union.
     *
     * `keyLengths` is the union across every set, so its last entry is the largest anything takes --
     * which for Threefish is 128 bytes while the tool opens on the 512-bit set that wants 64. Reading
     * the union gave "Threefish-512 needs a key of 64 bytes; this one is 128" from six unrelated
     * tests. Same rule the resolver follows and the same one `CipherToolMeta.paramSets` documents.
     */
    if (tool.paramSets) {
      const set = tool.paramSets.find((p) => p.id === tool.defaultParamSet);
      if (set) return set.keyLength;
    }
    return tool.block.keyLengths[tool.block.keyLengths.length - 1]!;
  }
  /**
   * A shaped tool's instance pins its key length, exactly as a parameter set does.
   *
   * `shape.keyLengths` is the union across every instance, so its last entry is 32 for Schwaemm while
   * the tool opens on Schwaemm256-128, which wants 16. Third time this repo has hit the union-versus-
   * default trap -- after Blowfish's range and Threefish's parameter sets.
   */
  const instance = tool.shape?.instances?.find((i) => i.id === tool.shape!.defaultInstance);
  if (instance) return instance.keyLen;
  /**
   * Otherwise ask the tool's own catalogue rather than assuming 32.
   *
   * Every stream cipher here took a 256-bit key until Ascon-AEAD128 arrived with a 128-bit one, at
   * which point a hardcoded 32 made two unrelated tests fail with a key-length error. The catalogue
   * is where that fact already lives.
   */
  /*
   * Asked of the tool's *default spec* rather than of the catalogue's union -- the fourth time this
   * helper has hit the union-versus-default trap, after Blowfish's range, Threefish's parameter sets
   * and Schwaemm's instances.
   *
   * AES's declared union widened to 16/24/32/48/64 when XTS and SIV gained their own key lengths, so
   * the last entry became 64 and this seeded a 64-byte key for every AES mode -- which GCM refuses.
   * `cipherAcceptedByteLengths` is the function the *form* asks, so it already knows that the seeded
   * AES-256 under GCM means 32 while XTS accepts 32 or 64.
   */
  const accepted = cipherAcceptedByteLengths(createSpec({ variant: id }), OPTION_KEY);
  if (accepted && accepted.length > 0) return accepted[accepted.length - 1]!;
  const exact = cipherCatalogueFor(id).require(OPTION_KEY).bytesLength?.exact;
  return exact?.[exact.length - 1] ?? 32;
}

/**
 * The option ids a tool has, ignoring key derivation.
 *
 * `keySourceOptions()` is spliced into every catalogue, so the seventeen controls it adds would swamp
 * any assertion about what a *tool* offers. Filtering them out keeps these tests about the thing they
 * were written to check -- that a lightweight AEAD has no mode and no drop count -- rather than turning
 * them into a list of the derivation controls. The derivation options have their own coverage in
 * `tests/cipher-key-source.test.ts`, including a sweep asserting none of them is unreachable.
 */
function toolOwnOptionIds(toolId: string): string[] {
  const derivation = new Set(
    keySourceOptions({ select: "algorithm", input: "key", settings: "derivation" }).map(
      (o) => o.id,
    ),
  );
  return cipherCatalogueFor(toolId)
    .options.map((o) => o.id)
    .filter((id) => !derivation.has(id))
    .sort();
}

/** `undefined` for a tool with no mode option at all -- the stream ciphers. */
function seedModes(id: string): readonly (AesModeMeta | undefined)[] {
  const tool = requireCipherTool(id);
  if (id === "aes") return AES_MODES;
  if (tool.block) return tool.block.modes.map((m) => getAesMode(m)!);
  return [undefined];
}

/**
 * One mode per tool, for the tests that want a single representative combination.
 *
 * CBC by preference rather than `modes[0]`, because the order of `block.modes` is a *sidebar* decision
 * -- SM4 lists GCM and CCM first, since RFC 8998 makes those the standardised use -- and a test that
 * read position zero broke the moment that order was reconsidered. CBC is the mode every one of these
 * ciphers has.
 */
function seedMode(id: string): AesModeMeta | undefined {
  const modes = seedModes(id);
  return modes.find((m) => m?.id === "cbc") ?? modes[0];
}

/** Like `run`, but returns the result whatever it is -- for the cases where a refusal is the point. */
async function compute(variant: string, options: CipherSpec["options"], input: Uint8Array) {
  return cipherToolDefinition(variant).compute(specFor(variant, options), input);
}

async function run(variant: string, options: CipherSpec["options"], input: Uint8Array) {
  const tool = cipherToolDefinition(variant);
  const result = await tool.compute(specFor(variant, options), input);
  expect(result.error, `${variant} reported: ${result.error}`).toBeUndefined();
  return result;
}

// ── AES-GCM: NIST vectors ───────────────────────────────────────────────────

describe("AES-GCM — NIST GCM test cases", () => {
  it("case 1 — empty plaintext, all-zero key and IV", async () => {
    const result = await run(
      "aes",
      keyed("00".repeat(16), "00".repeat(12), { [OPTION_MODE]: "gcm" }),
      new Uint8Array(0),
    );
    // The whole output is the tag, since there is no ciphertext.
    expect(encodeHex(result.bytes!)).toBe("58e2fccefa7e3061367f1d57a4e7455a");
  });

  it("case 2 — 16 zero bytes of plaintext", async () => {
    const result = await run(
      "aes",
      keyed("00".repeat(16), "00".repeat(12), { [OPTION_MODE]: "gcm" }),
      new Uint8Array(16),
    );
    expect(encodeHex(result.bytes!)).toBe(
      "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
    );
  });

  it("case 3 — the full 64-byte plaintext, no AAD", async () => {
    // Note the plaintext ends `1aafd255`: case 3 uses 64 bytes and case 4 uses the first 60.
    // Mixing those up is what makes the tags disagree while the ciphertext prefix matches.
    const result = await run(
      "aes",
      keyed("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", {
        [OPTION_MODE]: "gcm",
      }),
      fromHex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
      ),
    );
    expect(encodeHex(result.bytes!)).toBe(
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4",
    );
  });

  it("case 4 — with AAD (additional authenticated data)", async () => {
    const result = await run(
      "aes",
      keyed("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", {
        [OPTION_MODE]: "gcm",
        [OPTION_AAD]: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        aadEncoding: "hex",
      }),
      fromHex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
      ),
    );
    // 60-byte plaintext with AAD. The tag `5bc94fbc3221a5db94fae95ae7121a47` is what NIST
    // publishes for this case.
    expect(encodeHex(result.bytes!)).toBe(
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47",
    );
  });

  it("separates the tag from the ciphertext in the reported fields", async () => {
    const result = await run(
      "aes",
      keyed("00".repeat(32), "00".repeat(12), { [OPTION_MODE]: "gcm" }),
      ascii("hello"),
    );
    const tag = result.fields!.find((f) => f.label === "Tag")!.value;
    const body = result.fields!.find((f) => f.label === "Ciphertext without tag")!.value;
    expect(tag).toHaveLength(32);
    // The two must reassemble into exactly the primary output.
    expect(body + tag).toBe(encodeHex(result.bytes!));
  });
});

// ── ChaCha20-Poly1305: RFC 8439 ─────────────────────────────────────────────

describe("ChaCha20-Poly1305 — RFC 8439 section 2.8.2", () => {
  const KEY = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
  const NONCE = "070000004041424344454647";
  const AAD = "50515253c0c1c2c3c4c5c6c7";
  const PLAINTEXT =
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";

  it("encrypts to the published ciphertext and tag", async () => {
    const result = await run(
      "chacha20poly1305",
      keyed(KEY, NONCE, { [OPTION_AAD]: AAD, aadEncoding: "hex" }),
      fromHex(PLAINTEXT),
    );
    expect(encodeHex(result.bytes!)).toBe(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691",
    );
  });

  it("decrypts back to the plaintext", async () => {
    const encrypted = await run(
      "chacha20poly1305",
      keyed(KEY, NONCE, { [OPTION_AAD]: AAD, aadEncoding: "hex" }),
      fromHex(PLAINTEXT),
    );
    const decrypted = await run(
      "chacha20poly1305",
      keyed(KEY, NONCE, {
        [OPTION_DIRECTION]: "decrypt",
        [OPTION_AAD]: AAD,
        aadEncoding: "hex",
      }),
      encrypted.bytes!,
    );
    expect(encodeHex(decrypted.bytes!)).toBe(PLAINTEXT);
  });

  it("refuses to decrypt when the AAD differs", async () => {
    /**
     * The whole point of additional authenticated data: it is not encrypted, and changing it
     * still invalidates the tag. A cipher that decrypted anyway would give no binding at all.
     */
    const encrypted = await run(
      "chacha20poly1305",
      keyed(KEY, NONCE, { [OPTION_AAD]: AAD, aadEncoding: "hex" }),
      fromHex(PLAINTEXT),
    );
    const tool = cipherToolDefinition("chacha20poly1305");
    const result = await tool.compute(
      specFor(
        "chacha20poly1305",
        keyed(KEY, NONCE, {
          [OPTION_DIRECTION]: "decrypt",
          [OPTION_AAD]: "00000000c0c1c2c3c4c5c6c7",
          aadEncoding: "hex",
        }),
      ),
      encrypted.bytes!,
    );
    expect(result.bytes).toBeUndefined();
    expect(result.error).toMatch(/authentication tag did not verify/);
  });

  it("refuses to decrypt a single altered ciphertext byte", async () => {
    const encrypted = await run("chacha20poly1305", keyed(KEY, NONCE), fromHex(PLAINTEXT));
    const tampered = Uint8Array.from(encrypted.bytes!);
    // `noUncheckedIndexedAccess` is on, so the read needs a non-null assertion even though a
    // non-empty ciphertext is guaranteed here.
    tampered[0] = tampered[0]! ^ 0x01;

    const tool = cipherToolDefinition("chacha20poly1305");
    const result = await tool.compute(
      specFor("chacha20poly1305", keyed(KEY, NONCE, { [OPTION_DIRECTION]: "decrypt" })),
      tampered,
    );
    expect(result.bytes).toBeUndefined();
    expect(result.error).toMatch(/No plaintext is returned/);
  });
});

// ── ChaCha20 raw: RFC 8439 section 2.4.2 ────────────────────────────────────

describe("ChaCha20 — RFC 8439 section 2.4.2", () => {
  it("matches the published keystream with counter 1", async () => {
    const result = await run(
      "chacha20",
      keyed(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "000000000000004a00000000",
        { [OPTION_COUNTER]: 1 },
      ),
      ascii(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
      ),
    );
    expect(encodeHex(result.bytes!)).toBe(
      "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
    );
  });

  it("is its own inverse, as a stream cipher", async () => {
    const key = keyed("11".repeat(32), "22".repeat(12));
    const plaintext = ascii("stream ciphers are symmetric in the simplest way");
    const encrypted = await run("chacha20", key, plaintext);
    const decrypted = await run(
      "chacha20",
      { ...key, [OPTION_DIRECTION]: "decrypt" },
      encrypted.bytes!,
    );
    expect(encodeHex(decrypted.bytes!)).toBe(encodeHex(plaintext));
  });

  it("the counter changes the keystream", async () => {
    const key = keyed("11".repeat(32), "22".repeat(12));
    const a = await run("chacha20", { ...key, [OPTION_COUNTER]: 0 }, ascii("abc"));
    const b = await run("chacha20", { ...key, [OPTION_COUNTER]: 1 }, ascii("abc"));
    expect(encodeHex(a.bytes!)).not.toBe(encodeHex(b.bytes!));
  });
});

// ── AES-CBC / CTR / ECB: NIST SP 800-38A ────────────────────────────────────

describe("AES modes — NIST SP 800-38A vectors", () => {
  const KEY = "2b7e151628aed2a6abf7158809cf4f3c";
  const IV = "000102030405060708090a0b0c0d0e0f";
  const BLOCK1 = "6bc1bee22e409f96e93d7e117393172a";

  it("ECB encrypts one block to the published value", async () => {
    const result = await run(
      "aes",
      keyed(KEY, undefined, { [OPTION_MODE]: "ecb" }),
      fromHex(BLOCK1),
    );
    // SP 800-38A F.1.1. noble pads, so the first block is what to compare.
    expect(encodeHex(result.bytes!).slice(0, 32)).toBe("3ad77bb40d7a3660a89ecaf32466ef97");
  });

  it("CBC encrypts the first block to the published value", async () => {
    const result = await run("aes", keyed(KEY, IV, { [OPTION_MODE]: "cbc" }), fromHex(BLOCK1));
    // SP 800-38A F.2.1.
    expect(encodeHex(result.bytes!).slice(0, 32)).toBe("7649abac8119b246cee98e9b12e9197d");
  });

  it("CTR encrypts to the published keystream", async () => {
    const result = await run(
      "aes",
      keyed(KEY, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", { [OPTION_MODE]: "ctr" }),
      fromHex(BLOCK1),
    );
    // SP 800-38A F.5.1.
    expect(encodeHex(result.bytes!)).toBe("874d6191b620e3261bef6864990db6ce");
  });

  it("ECB really does encrypt identical blocks identically", async () => {
    /**
     * The property `C001` exists to warn about, asserted rather than only described. Two
     * identical 16-byte blocks must produce two identical ciphertext blocks — which is exactly
     * why the mode leaks plaintext structure.
     */
    const block = fromHex("aa".repeat(16));
    const doubled = new Uint8Array(32);
    doubled.set(block, 0);
    doubled.set(block, 16);

    const result = await run("aes", keyed(KEY, undefined, { [OPTION_MODE]: "ecb" }), doubled);
    const hex = encodeHex(result.bytes!);
    expect(hex.slice(0, 32)).toBe(hex.slice(32, 64));
  });

  it("CBC does not, because of the chaining", async () => {
    const block = fromHex("aa".repeat(16));
    const doubled = new Uint8Array(32);
    doubled.set(block, 0);
    doubled.set(block, 16);

    const result = await run("aes", keyed(KEY, IV, { [OPTION_MODE]: "cbc" }), doubled);
    const hex = encodeHex(result.bytes!);
    expect(hex.slice(0, 32)).not.toBe(hex.slice(32, 64));
  });

  it("round-trips through every mode and key size", async () => {
    // Sixteen bytes: a whole AES block, and a multiple of 8 so the key-wrap modes accept it too.
    const plaintext = ascii("sixteen byte len");
    for (const mode of AES_MODES) {
      // SIV takes a double-length key, so the sizes come from the mode rather than from AES.
      for (const keySize of mode.keyLengths ?? [16, 24, 32]) {
        const options = keyed(
          "11".repeat(keySize),
          mode.nonceLen > 0 ? "22".repeat(mode.nonceLen) : undefined,
          { [OPTION_MODE]: mode.id },
        );
        const encrypted = await run("aes", options, plaintext);
        const decrypted = await run(
          "aes",
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          encrypted.bytes!,
        );
        expect(encodeHex(decrypted.bytes!), `${mode.id}/${keySize}`).toBe(encodeHex(plaintext));
      }
    }
  });

  it("GCM-SIV survives a repeated nonce where GCM would not", async () => {
    /**
     * Not a security proof, but the observable difference: under GCM-SIV two identical
     * plaintexts under one nonce give identical ciphertexts and nothing more leaks, which is
     * the property that makes it the answer to `C003`.
     */
    const options = keyed("11".repeat(32), "22".repeat(12), { [OPTION_MODE]: "gcm-siv" });
    const a = await run("aes", options, ascii("same message"));
    const b = await run("aes", options, ascii("same message"));
    expect(encodeHex(a.bytes!)).toBe(encodeHex(b.bytes!));

    const decrypted = await run("aes", { ...options, [OPTION_DIRECTION]: "decrypt" }, a.bytes!);
    expect(new TextDecoder().decode(decrypted.bytes!)).toBe("same message");
  });
});

// ── RC4 ─────────────────────────────────────────────────────────────────────

describe("RC4", () => {
  it("matches the classic test vectors", async () => {
    const cases: readonly [string, string, string][] = [
      ["Key", "Plaintext", "bbf316e8d940af0ad3"],
      ["Wiki", "pedia", "1021bf0420"],
      ["Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5"],
    ];
    for (const [key, plaintext, expected] of cases) {
      const result = await run(
        "rc4",
        { [OPTION_KEY]: key, keyEncoding: "utf-8" },
        ascii(plaintext),
      );
      expect(encodeHex(result.bytes!), `${key}/${plaintext}`).toBe(expected);
    }
  });

  it("drop changes the keystream", async () => {
    const base = { [OPTION_KEY]: "Key", keyEncoding: "utf-8" };
    const plain = await run("rc4", base, ascii("Plaintext"));
    const dropped = await run("rc4", { ...base, [OPTION_DROP]: 768 }, ascii("Plaintext"));
    expect(encodeHex(plain.bytes!)).not.toBe(encodeHex(dropped.bytes!));
  });

  it("is its own inverse, drop included", async () => {
    const options = { [OPTION_KEY]: "aa".repeat(16), keyEncoding: "hex", [OPTION_DROP]: 3072 };
    const plaintext = ascii("legacy traffic");
    const encrypted = await run("rc4", options, plaintext);
    const decrypted = await run(
      "rc4",
      { ...options, [OPTION_DIRECTION]: "decrypt" },
      encrypted.bytes!,
    );
    expect(encodeHex(decrypted.bytes!)).toBe(encodeHex(plaintext));
  });

  it("accepts any key length from 1 to 256 bytes", async () => {
    for (const size of [1, 5, 16, 256]) {
      const result = await run(
        "rc4",
        { [OPTION_KEY]: "ab".repeat(size), keyEncoding: "hex" },
        ascii("x"),
      );
      expect(result.bytes, `${size}-byte key`).toHaveLength(1);
    }
  });
});

// ── lint rules ──────────────────────────────────────────────────────────────

describe("lint rules", () => {
  const good = keyed("11".repeat(32), "22".repeat(12));

  it("C001 marks ECB insecure without blocking it", () => {
    /**
     * Deliberately not an error. ECB is a real mode with real uses — a single block, or a
     * building block inside another construction — so blocking it would make the tool unable
     * to do things people legitimately come here for. `insecure` is the accurate claim.
     */
    const spec = specFor("aes", keyed("11".repeat(32), undefined, { [OPTION_MODE]: "ecb" }));
    const found = lint(spec).diagnostics.find((d) => d.code === "C001");
    expect(found?.level).toBe("insecure");
    expect(lint(spec).hasErrors).toBe(false);
    expect(found?.message).toMatch(/identical ciphertext blocks/);
  });

  it("C001's fix moves to GCM and generates the nonce it now needs", () => {
    const spec = specFor("aes", keyed("11".repeat(32), undefined, { [OPTION_MODE]: "ecb" }));
    const fixed = applyAllFixes(spec);
    expect(fixed.options[OPTION_MODE]).toBe("gcm");
    // And the result must actually be usable, not merely a different mode with no nonce.
    expect(resolveCipher(fixed).ok).toBe(true);
  });

  it("C002 warns on unauthenticated modes and stays quiet on AEADs", () => {
    for (const mode of AES_MODES) {
      const spec = specFor(
        "aes",
        keyed("11".repeat(32), mode.nonceLen > 0 ? "22".repeat(mode.nonceLen) : undefined, {
          [OPTION_MODE]: mode.id,
        }),
      );
      const has = lint(spec).diagnostics.some((d) => d.code === "C002");
      // ECB gets C001 instead — saying both would be piling on.
      expect(has, mode.id).toBe(!mode.aead && mode.id !== "ecb");
    }
  });

  it("C002 fires for raw ChaCha20 and not for the AEAD variants", () => {
    expect(lint(specFor("chacha20", good)).diagnostics.some((d) => d.code === "C002")).toBe(
      true,
    );
    expect(
      lint(specFor("chacha20poly1305", good)).diagnostics.some((d) => d.code === "C002"),
    ).toBe(false);
  });

  /**
   * C003 is silent wherever the construction has no nonce, even with one left in the spec.
   *
   * Reported: the note appeared on ECB and the key-wrap modes, which have no IV field at all. The cause
   * is that switching mode does not clear the previous mode's IV -- the field stops rendering, so the
   * value is invisible, but it is still stored and still decodes. The rule asked `r.nonce.length`, saw
   * sixteen bytes, and believed there was a nonce to reuse.
   *
   * Nothing else caught it because the *resolver* is right to ignore that value: with
   * `acceptedNonceLengths` empty both of its length checks skip, so ECB computes correctly. Only the
   * diagnostic was wrong, which is why this asserts the diagnostic rather than the output.
   *
   * The sweep matters more than the single case. Every tool crossed with every mode it offers, each
   * given a stored nonce, and the question asked of `acceptedNonceLengths` rather than of a list of
   * mode ids -- so a mode added later with no nonce is covered without anyone remembering to.
   */
  it("C003 stays silent for every mode that takes no nonce, even with one stored", () => {
    const stale = (variant: string, mode?: string) => {
      const base = createSpec({ variant });
      const options: CipherSpec["options"] = {
        ...base.options,
        /*
         * 32 bytes, not 64. The first version used a 64-byte key, which the AES-256 seed refuses --
         * so `resolveCipher` failed, every rule bailed, and the test was asserting C003's absence for
         * the wrong reason entirely.
         */
        [OPTION_KEY]: "11".repeat(32),
        keyEncoding: "hex",
        // Deliberately left behind, which is exactly what switching mode does.
        [OPTION_NONCE]: "22".repeat(16),
        nonceEncoding: "hex",
        ...(mode === undefined ? {} : { [OPTION_MODE]: mode }),
      };
      return { ...base, options };
    };

    // The reported pair, spelled out: CBC says it, ECB must not.
    expect(lint(stale("aes", "cbc")).diagnostics.map((d) => d.code)).toContain("C003");
    expect(
      lint(stale("aes", "ecb")).diagnostics.map((d) => d.code),
      "ECB has no IV field, so there is no nonce to reuse",
    ).not.toContain("C003");

    const leaks: string[] = [];
    let nonceless = 0;
    let withNonce = 0;
    for (const tool of CIPHER_TOOLS) {
      const modes: readonly (string | undefined)[] =
        tool.id === "aes"
          ? AES_MODES.map((m) => m.id)
          : [...(tool.block?.modes ?? [undefined])];
      for (const mode of modes) {
        const spec = stale(tool.id, mode);
        const takes = acceptedNonceLengths(tool.id, modeForSpec(spec), undefined).length > 0;
        const fires = lint(spec).diagnostics.some((d) => d.code === "C003");
        if (takes) withNonce += 1;
        else {
          nonceless += 1;
          if (fires) leaks.push(`${tool.id}/${mode ?? "-"}`);
        }
      }
    }
    // Guards the guard: a broken sweep would pass by checking almost nothing.
    expect(nonceless, "suspiciously few nonceless combinations").toBeGreaterThan(20);
    expect(withNonce, "suspiciously few with a nonce").toBeGreaterThan(100);
    expect(leaks, "C003 fired where there is no nonce").toEqual([]);
  });

  it("C003 always mentions nonce reuse when encrypting, because it cannot detect it", () => {
    /**
     * The tool sees one computation at a time, so it has no way to know whether a nonce has
     * been used before. That is exactly why the note is unconditional rather than conditional
     * on something observable.
     */
    const spec = specFor("aes", good);
    const found = lint(spec).diagnostics.find((d) => d.code === "C003");
    expect(found?.level).toBe("info");
    expect(found?.detail).toMatch(/authentication key/);
  });

  it("C003 stays quiet for GCM-SIV, which is built to survive it", () => {
    const spec = specFor(
      "aes",
      keyed("11".repeat(32), "22".repeat(12), { [OPTION_MODE]: "gcm-siv" }),
    );
    expect(lint(spec).diagnostics.some((d) => d.code === "C003")).toBe(false);
  });

  it("C003 stays quiet when decrypting, where a repeat is not the user's problem", () => {
    const spec = specFor("aes", { ...good, [OPTION_DIRECTION]: "decrypt" });
    expect(lint(spec).diagnostics.some((d) => d.code === "C003")).toBe(false);
  });

  it("C003's fix alone generates a nonce of the right length for the current mode", () => {
    // Applied in isolation, so the mode does not change underneath it.
    for (const mode of AES_MODES.filter(
      (m) => m.nonceLen > 0 && m.id !== "gcm-siv" && m.id !== "xts",
    )) {
      const spec = specFor(
        "aes",
        keyed("11".repeat(32), "22".repeat(mode.nonceLen), { [OPTION_MODE]: mode.id }),
      );
      const before = spec.options[OPTION_NONCE];
      const c003 = lint(spec).diagnostics.find((d) => d.code === "C003");
      expect(c003?.fix, mode.id).toBeDefined();

      const fixed = c003!.fix!.apply(spec);
      expect(fixed.options[OPTION_NONCE], mode.id).not.toBe(before);
      expect(fixed.options[OPTION_MODE], mode.id).toBe(mode.id);

      const resolved = resolveCipher(fixed);
      expect(resolved.ok, mode.id).toBe(true);
      if (resolved.ok) expect(resolved.resolved.nonce, mode.id).toHaveLength(mode.nonceLen);
    }
  });

  it("applyAllFixes always leaves a spec that resolves, whatever order the fixes ran in", () => {
    /**
     * The invariant that matters, and the one an earlier version of these fixes broke.
     * `applyAllFixes` is a single pass in code order, so C002's switch to GCM can land before
     * C003 generates a nonce — and a nonce sized from the mode captured at check time would be
     * 16 bytes under a mode that now wants 12. Neither rule was wrong alone; the combination
     * was. Every fix therefore reads the mode from the spec it is handed.
     */
    for (const meta of CIPHER_TOOLS) {
      /**
       * One seed per mode wherever the mode is what decides the nonce length -- AES, and every
       * block cipher this repo implements. A stream cipher gets a single mode-less seed, and RC4
       * has no nonce at all.
       */
      const starts: CipherSpec[] = seedModes(meta.id).map((mode) => {
        const nonceLen = requiredNonceLength(meta.id, mode);
        return specFor(
          meta.id,
          keyed(
            "11".repeat(seedKeyLength(meta.id)),
            nonceLen > 0 ? "22".repeat(nonceLen) : undefined,
            mode ? { [OPTION_MODE]: mode.id } : {},
          ),
        );
      });

      for (const spec of starts) {
        const fixed = applyAllFixes(spec);
        const resolved = resolveCipher(fixed);
        expect(resolved.ok, `${meta.id}/${String(spec.options[OPTION_MODE])}`).toBe(true);
        // And where the construction uses a nonce, its length must match whichever mode
        // actually ended up set.
        if (resolved.ok) {
          const needed = requiredNonceLength(fixed.variant, resolved.resolved.mode);
          if (needed > 0) {
            expect(resolved.resolved.nonce.length, `${meta.id} nonce`).toBe(needed);
          }
        }
      }
    }
  });

  it("C004 fires for exactly the ciphers whose metadata says broken", () => {
    /**
     * Posture-driven, and asserted that way on purpose. The rule reads `tool.security` rather
     * than matching an id list, so DES joining RC4 as `broken` needed no rule edit -- and this
     * test says so, instead of naming RC4 and having to be corrected every time.
     */
    const broken = CIPHER_TOOLS.filter((t) => t.security === "broken").map((t) => t.id);
    expect(broken).toContain("rc4");
    expect(broken).toContain("des");

    for (const meta of CIPHER_TOOLS) {
      const spec = specFor(
        meta.id,
        keyed(
          "11".repeat(seedKeyLength(meta.id)),
          "22".repeat(requiredNonceLength(meta.id, getAesMode("cbc")) || 12),
        ),
      );
      const has = lint(spec).diagnostics.some((d) => d.code === "C004");
      expect(has, meta.id).toBe(meta.security === "broken");
    }
  });

  it("C005 blocks a missing key, a wrong key size and a wrong nonce size", () => {
    // No key at all.
    expect(lint(specFor("aes", {})).hasErrors).toBe(true);

    /*
     * 20 bytes is not an AES key size, and the message names the size that was *chosen*.
     *
     * It used to assert `/16, 24, 32/`, which was the best the resolver could say when the key size
     * was inferred from what had been typed: the catalogue's union was the only fact available. With a
     * Key size control there is a better one -- the user picked AES-256, so the number they need is 32
     * and the two ways out are changing the key or changing the size. A message listing three lengths
     * left a reader to work out which of their two mistakes it was.
     */
    const badKey = specFor("aes", keyed("11".repeat(20), "22".repeat(12)));
    const keyMessage = lint(badKey).diagnostics.find((d) => d.code === "C005")?.message ?? "";
    expect(keyMessage).toMatch(/AES-256/);
    expect(keyMessage).toMatch(/32 bytes/);
    expect(keyMessage).toMatch(/this one is 20/);

    /*
     * And a key that *is* a valid AES length is still refused when it disagrees with the chosen size,
     * which is the whole point of the control being enforced rather than decorative.
     */
    const mismatched = specFor("aes", {
      ...keyed("11".repeat(16), "22".repeat(12)),
      [OPTION_KEY_SIZE]: "256",
    });
    expect(lint(mismatched).diagnostics.find((d) => d.code === "C005")?.message).toMatch(
      /Key size is set to AES-256/,
    );

    // 16 bytes is a valid nonce length for CTR but not for GCM, which is the case the shared
    // AES catalogue cannot express in `bytesLength` alone.
    const badNonce = specFor(
      "aes",
      keyed("11".repeat(32), "22".repeat(16), { [OPTION_MODE]: "gcm" }),
    );
    const found = lint(badNonce).diagnostics.find((d) => d.code === "C005");
    expect(found?.message).toMatch(/AES-GCM needs exactly 12 bytes/);
  });

  it("accepts a 16-byte nonce for CTR and CBC, where it is correct", () => {
    for (const mode of ["ctr", "cbc"]) {
      const spec = specFor(
        "aes",
        keyed("11".repeat(32), "22".repeat(16), { [OPTION_MODE]: mode }),
      );
      expect(lint(spec).hasErrors, mode).toBe(false);
    }
  });
});

// ── catalogue and manifests ─────────────────────────────────────────────────

describe("catalogue and manifests", () => {
  it("every tool's catalogue is internally consistent", () => {
    for (const meta of CIPHER_TOOLS) {
      expect(
        validateCatalogue(cipherToolDefinition(meta.id).catalogue.options),
        meta.id,
      ).toEqual([]);
    }
  });

  it("marks the key secret and the nonce not", () => {
    /**
     * The nonce is deliberately public. It travels in the clear beside the ciphertext in every
     * real protocol, so marking it secret would misrepresent how it is used and strip it from
     * share links for no benefit. What matters about a nonce is that it never repeats, which is
     * `C003`'s job rather than the option's.
     */
    for (const meta of CIPHER_TOOLS) {
      const catalogue = cipherToolDefinition(meta.id).catalogue;
      expect(catalogue.secretIds(), meta.id).toContain(OPTION_KEY);
      const nonce = catalogue.get(OPTION_NONCE);
      if (nonce) expect(nonce.secret, `${meta.id} nonce`).toBeFalsy();
    }
  });

  it("declares both directions, because decryption is real here", () => {
    for (const manifest of CIPHER_MANIFESTS) {
      expect(manifest.directions).toEqual(["forward", "inverse"]);
    }
  });

  it("claims streaming only for tools that implement it (Cobblestone)", () => {
    for (const meta of CIPHER_TOOLS) {
      const tool = cipherToolDefinition(meta.id);
      if (meta.streaming) {
        expect(tool.streaming, meta.id).toBe(true);
        expect(tool.createStream, meta.id).toBeDefined();
      } else {
        expect(tool.streaming, meta.id).toBe(false);
        expect(tool.createStream, meta.id).toBeUndefined();
      }
    }
  });

  it("offers latin1 output, which no other family does, but not as the default", () => {
    for (const manifest of CIPHER_MANIFESTS) {
      expect(manifest.outputEncodings).toContain("latin1");
      if (manifest.id === "fernet") {
        expect(manifest.outputEncodings[0]).toBe("base64url");
      } else {
        expect(manifest.outputEncodings[0]).toBe("hex-upper");
      }
    }
  });

  it("defaults Fernet key, IV and result encodings to base64url", () => {
    const fernetDef = cipherToolDefinition("fernet");
    const keyDef = fernetDef.catalogue.get(OPTION_KEY);
    const nonceDef = fernetDef.catalogue.get(OPTION_NONCE);
    expect(keyDef?.defaultBytesEncoding).toBe("base64url");
    expect(nonceDef?.defaultBytesEncoding).toBe("base64url");
    const fernetManifest = CIPHER_MANIFESTS.find((m) => m.id === "fernet");
    expect(fernetManifest?.outputEncodings[0]).toBe("base64url");
  });

  it("hides the nonce under ECB and the AAD under the unauthenticated modes", () => {
    const tool = cipherToolDefinition("aes");
    const visible = (modeId: string) => {
      const tag = tool.variantTag!(specFor("aes", { [OPTION_MODE]: modeId }));
      // Through the engine's own matcher rather than reimplementing it: `variantTag` may return
      // several tags now, and a test that duplicates the matching logic stops testing the real one.
      return tool.catalogue.options.filter((o) => isAvailableOn(o, tag)).map((o) => o.id);
    };

    expect(visible("ecb")).not.toContain(OPTION_NONCE);
    expect(visible("gcm")).toContain(OPTION_NONCE);
    expect(visible("gcm")).toContain(OPTION_AAD);
    // AAD is meaningless without a tag to cover it.
    expect(visible("cbc")).not.toContain(OPTION_AAD);
    expect(visible("ctr")).not.toContain(OPTION_AAD);
  });

  it("shows the counter only for raw ChaCha20 and drop only for RC4", () => {
    /*
     * `variantTag` returns an *array* now -- the mode or per-tool tag, plus the key source, plus the
     * IV-is-manual conjunction. It had to: it returned `undefined` for the 45 tools with no mode, and
     * `isAvailableOn` reads a missing tag as "not available", so gating the Key field on a tag would
     * have deleted the key input for all of them. So this asks whether *some* tag the tool emits
     * matches, which is the question `isAvailableOn` itself asks.
     */
    const tagsOf = (toolId: string) => {
      const tag = cipherToolDefinition(toolId).variantTag!(specFor(toolId));
      return tag === undefined ? [] : Array.isArray(tag) ? [...tag] : [tag];
    };
    const counterOn =
      cipherToolDefinition("chacha20").catalogue.get(OPTION_COUNTER)?.availableOn ?? [];
    expect(tagsOf("chacha20").some((tag) => counterOn.includes(tag))).toBe(true);
    const dropOn = cipherToolDefinition("rc4").catalogue.get(OPTION_DROP)?.availableOn ?? [];
    expect(tagsOf("rc4").some((tag) => dropOn.includes(tag))).toBe(true);
    expect(
      cipherToolDefinition("chacha20poly1305").catalogue.get(OPTION_COUNTER),
    ).toBeUndefined();
  });

  it("defaults AES to GCM, not ECB", () => {
    // The default a tool opens on is what most people will compute with.
    expect(createSpec({ variant: "aes" }).options[OPTION_MODE]).toBe("gcm");
    expect(createSpec({ variant: "aes" }).options[OPTION_DIRECTION]).toBe("encrypt");
  });

  it("never pre-fills a key", () => {
    for (const meta of CIPHER_TOOLS) {
      expect(createSpec({ variant: meta.id }).options[OPTION_KEY], meta.id).toBeUndefined();
    }
  });

  it("rejects an unknown variant", () => {
    /**
     * This name has had to change twice, which is the good kind of test failure: it was "blowfish"
     * until Blowfish became a tool and "twofish" until Twofish did. Anything genuinely absent works;
     * `rijndael` is AES's own competition name and will never be a separate tool here.
     */
    expect(() => createSpec({ variant: "rijndael" })).toThrow(/Unknown cipher tool/);
    expect(() => requireCipherTool("rijndael")).toThrow(/rijndael/);
  });
});

// ------------------------------------------------- Generate offers a legal length ---

/**
 * Every Generate button offers a length the resolver will accept.
 *
 * This is a *measured* gate rather than a precaution. Before `ToolDefinition.generateLength` existed,
 * the catalogue's static `bytesLength.generate` was the only answer available -- and the catalogue is
 * resolved once per tool, so it could not know the mode. Eleven cipher/mode combinations offered a
 * length the very next check refused:
 *
 *   aes/ctr, aes/cbc, aes/ofb, aes/cfb, aes/xts   offered 12, require 16
 *   camellia|aria|sm4 in gcm                       offered 16, require 12
 *   camellia|aria|sm4 in ccm                       offered 16, require 7..13
 *
 * Nothing failed, because a 12-byte IV under CBC looks exactly like a 12-byte IV somebody mistyped.
 * That is the whole reason this walks the cross product rather than spot-checking AES-GCM: the broken
 * cases were the ones nobody was looking at.
 */
describe("Generate offers a length the tool accepts", () => {
  /** Every (tool, mode) pair the app can actually be in, which is what the form sees. */
  function combinations(): { tool: string; modeId: string | undefined }[] {
    const out: { tool: string; modeId: string | undefined }[] = [];
    for (const tool of CIPHER_TOOLS) {
      /*
       * AES declares no `block.modes` -- its modes live in `AES_MODES` and include the four that no
       * other cipher here offers. Iterating `block?.modes` alone silently skipped it, which is how the
       * first version of this audit reported six mismatches instead of eleven.
       */
      const modes: (string | undefined)[] =
        tool.id === "aes"
          ? AES_MODES.map((mode) => mode.id)
          : tool.block?.modes
            ? [...tool.block.modes]
            : [undefined];
      for (const modeId of modes) out.push({ tool: tool.id, modeId });
    }
    return out;
  }

  it("never offers a nonce length the resolver would refuse", () => {
    const bad: string[] = [];
    let checked = 0;
    for (const { tool, modeId } of combinations()) {
      const base = createSpec({ variant: tool });
      const spec = modeId ? { ...base, options: { ...base.options, mode: modeId } } : base;
      const accepted = acceptedNonceLengths(tool, modeForSpec(spec), undefined);
      const offered =
        cipherGenerateLength(spec, OPTION_NONCE) ??
        cipherCatalogueFor(tool).options.find((option) => option.id === OPTION_NONCE)
          ?.bytesLength?.generate;
      if (accepted.length === 0) {
        // No nonce at all -- ECB, key wrap, SIV. Nothing should be offered, and the field is not shown.
        if (cipherGenerateLength(spec, OPTION_NONCE) !== undefined) {
          bad.push(`${tool}/${modeId ?? "-"}: offers ${offered} where the mode takes no nonce`);
        }
        continue;
      }
      checked += 1;
      if (offered === undefined || !accepted.includes(offered)) {
        bad.push(
          `${tool}/${modeId ?? "-"}: offers ${String(offered)}, accepts ${accepted.join(",")}`,
        );
      }
    }
    // Guards the guard: a broken cross product would pass this by checking almost nothing.
    expect(checked, "suspiciously few tool/mode pairs have a nonce").toBeGreaterThan(200);
    expect(bad, "Generate would fill the field with a value the tool refuses").toEqual([]);
  });

  /**
   * And the length is one the *resolver* is happy with end to end, not merely one the metadata lists.
   *
   * Spot-checked on the five AES modes that were broken plus the two that were not, by generating a
   * nonce of the offered length and resolving: a metadata answer that disagreed with the resolver's
   * own check would pass the test above and still leave the button useless.
   */
  it("produces a nonce the resolver accepts, for every AES mode", () => {
    for (const mode of AES_MODES) {
      const base = createSpec({ variant: "aes" });
      const withMode = { ...base, options: { ...base.options, mode: mode.id } };
      const length = cipherGenerateLength(withMode, OPTION_NONCE);
      if (length === undefined) continue;
      const spec = {
        ...withMode,
        options: {
          ...withMode.options,
          [OPTION_KEY]: "00".repeat(32),
          keyEncoding: "hex",
          [OPTION_NONCE]: "11".repeat(length),
          nonceEncoding: "hex",
        },
      };
      const resolved = resolveCipher(spec);
      expect(
        resolved.ok,
        `aes/${mode.id}: a generated ${length}-byte nonce was refused: ${resolved.ok ? "" : resolved.problem}`,
      ).toBe(true);
    }
  });
});

// ── describe ────────────────────────────────────────────────────────────────

describe("describeSpec", () => {
  it("names the construction and whether it authenticates", () => {
    const gcm = describeSpec(specFor("aes", keyed("11".repeat(32), "22".repeat(12))));
    expect(gcm).toContain("AES-256-GCM");
    expect(gcm).toContain("authentication tag");

    const cbc = describeSpec(
      specFor("aes", keyed("11".repeat(16), "22".repeat(16), { [OPTION_MODE]: "cbc" })),
    );
    expect(cbc).toContain("AES-128-CBC");
    expect(cbc).toContain("no authentication");
  });

  it("says which direction it will go", () => {
    const spec = specFor(
      "aes",
      keyed("11".repeat(32), "22".repeat(12), { [OPTION_DIRECTION]: "decrypt" }),
    );
    expect(describeSpec(spec)).toMatch(/^Decrypts/);
  });

  it("mentions additional data when there is some", () => {
    const spec = specFor(
      "chacha20poly1305",
      keyed("11".repeat(32), "22".repeat(12), { [OPTION_AAD]: "header", aadEncoding: "utf-8" }),
    );
    expect(describeSpec(spec)).toContain("6 bytes of additional data");
  });

  it("says what is missing", () => {
    expect(describeSpec(specFor("aes"))).toMatch(/key/i);
  });
});

describe("error messages", () => {
  it("names the block-alignment problem and its usual cause", async () => {
    const tool = cipherToolDefinition("aes");
    const options = keyed("11".repeat(32), "22".repeat(16), {
      [OPTION_MODE]: "cbc",
      [OPTION_DIRECTION]: "decrypt",
    });

    // 17 bytes cannot be CBC ciphertext at all.
    const misaligned = await tool.compute(specFor("aes", options), ascii("seventeen bytes.."));
    expect(misaligned.error).toMatch(/whole number of 16-byte blocks/);
    expect(misaligned.error).toMatch(/input encoding/);

    // 32 bytes is aligned, so it reaches the cipher and fails on padding instead — with its
    // own explanation of why the two cases are indistinguishable.
    const aligned = await tool.compute(
      specFor("aes", options),
      ascii("thirty two bytes exactly here!!!"),
    );
    expect(aligned.error).toMatch(/padding/);
    expect(aligned.error).toMatch(/padding-oracle/);
  });

  it("explains a too-short AEAD ciphertext rather than throwing", async () => {
    const tool = cipherToolDefinition("chacha20poly1305");
    const result = await tool.compute(
      specFor(
        "chacha20poly1305",
        keyed("11".repeat(32), "22".repeat(12), { [OPTION_DIRECTION]: "decrypt" }),
      ),
      ascii("short"),
    );
    expect(result.error).toMatch(/16-byte authentication tag/);
  });
});

/**
 * The modes and ciphers added after the first five, each against a published value.
 *
 * Every number below was checked against one recalled independently of this implementation before
 * being written down, and AES-CFB additionally agrees with OpenSSL through `openssl-parity`'s route.
 * Where no such value was available -- XSalsa20 and its AEAD -- the gap is stated rather than papered
 * over with a self-consistent round trip pretending to be a vector.
 */
describe("published vectors for the later modes", () => {
  it("AES-KW matches RFC 3394 section 4.1", async () => {
    // The RFC's own worked example: a 128-bit KEK wrapping 128 bits of key data.
    const result = await run(
      "aes",
      keyed("000102030405060708090A0B0C0D0E0F", undefined, { [OPTION_MODE]: "kw" }),
      fromHex("00112233445566778899AABBCCDDEEFF"),
    );
    expect(encodeHex(result.bytes!).toUpperCase()).toBe(
      "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
    );
  });

  it("AES-KW unwraps what it wrapped, and refuses what has been altered", async () => {
    // The integrity check is the reason to use KW over ECB for a key, so it gets an assertion.
    const options = keyed("000102030405060708090A0B0C0D0E0F", undefined, {
      [OPTION_MODE]: "kw",
    });
    const wrapped = fromHex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    const unwrapped = await run("aes", { ...options, [OPTION_DIRECTION]: "decrypt" }, wrapped);
    expect(encodeHex(unwrapped.bytes!).toUpperCase()).toBe("00112233445566778899AABBCCDDEEFF");

    const tampered = Uint8Array.from(wrapped);
    // `!` because the index is a literal inside a fixed-length array; strict mode cannot see that.
    tampered[0] = tampered[0]! ^ 1;
    const result = await compute(
      "aes",
      { ...options, [OPTION_DIRECTION]: "decrypt" },
      tampered,
    );
    expect(result.error, "an altered wrapped key unwrapped anyway").toBeTruthy();
  });

  it("AES-KWP takes a length RFC 3394 would refuse", async () => {
    // The whole difference between the two: 5 bytes is not a whole number of semiblocks.
    const options = keyed("000102030405060708090A0B0C0D0E0F", undefined, {
      [OPTION_MODE]: "kwp",
    });
    const key = ascii("hello");
    const wrapped = await run("aes", options, key);
    const back = await run(
      "aes",
      { ...options, [OPTION_DIRECTION]: "decrypt" },
      wrapped.bytes!,
    );
    expect(encodeHex(back.bytes!)).toBe(encodeHex(key));

    // And the unpadded form says which rule was broken, rather than throwing from inside noble.
    // Two distinct rules, so two inputs: 5 bytes is below RFC 3394's two-semiblock floor, and 17 is
    // above it but not a whole number of semiblocks.
    const kw = keyed("000102030405060708090A0B0C0D0E0F", undefined, { [OPTION_MODE]: "kw" });
    expect((await compute("aes", kw, key)).error).toMatch(/at least 16 bytes/);
    expect((await compute("aes", kw, new Uint8Array(17))).error).toMatch(/whole 8-byte units/);
  });

  it("AES-CFB matches NIST SP 800-38A F.3.13", async () => {
    const result = await run(
      "aes",
      keyed("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", {
        [OPTION_MODE]: "cfb",
      }),
      fromHex("6bc1bee22e409f96e93d7e117393172a"),
    );
    expect(encodeHex(result.bytes!)).toBe("3b3fd92eb72dad20333449f8e83cfb4a");
  });

  it("AES-SIV matches RFC 5297 appendix A.1", async () => {
    // Note the key: 32 bytes for AES-128-SIV, because the mode splits it between the CMAC and the
    // CTR. That is the thing users get wrong, so the vector is the one from the RFC that shows it.
    const result = await run(
      "aes",
      keyed("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", undefined, {
        [OPTION_MODE]: "aessiv",
        [OPTION_AAD]: "101112131415161718191a1b1c1d1e1f2021222324252627",
        aadEncoding: "hex",
      }),
      fromHex("112233445566778899aabbccddee"),
    );
    expect(encodeHex(result.bytes!)).toBe(
      "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c",
    );
  });

  it("AES-SIV is deterministic, which is the point and the caveat", async () => {
    // No nonce, so the same plaintext gives the same ciphertext every time -- exactly what you want
    // for wrapping and exactly what leaks equality of messages.
    const options = keyed("11".repeat(32), undefined, { [OPTION_MODE]: "aessiv" });
    const a = await run("aes", options, ascii("same message"));
    const b = await run("aes", options, ascii("same message"));
    expect(encodeHex(a.bytes!)).toBe(encodeHex(b.bytes!));
  });

  it("AEGIS matches the draft's vectors through the family, at both tag lengths", async () => {
    /**
     * The vector with a partial final block (A.2.5 / A.3.5 in the draft) at both tag lengths, which
     * is what exercises the tag-length option end to end -- the option, the resolver's `tagLen`, and
     * the compute path's tag split all have to agree or the "Tag" field names the wrong bytes.
     */
    for (const [tool, vectors] of [
      ["aegis128l", AEGIS128L_VECTORS],
      ["aegis256", AEGIS256_VECTORS],
    ] as const) {
      const vector = vectors.find(
        (v) => !v.invalid && v.msg === "000102030405060708090a0b0c0d",
      );
      expect(vector, `${tool} partial-block vector`).toBeTruthy();

      for (const tagLen of [16, 32]) {
        const result = await run(
          tool,
          keyed(vector!.key, vector!.nonce, {
            [OPTION_AAD]: vector!.ad,
            aadEncoding: "hex",
            /**
             * As a *string*, which is what an `enum` control stores. Written as a number here
             * originally, and that is a shape the form never produces -- so `optNumber` accepted it
             * in the test and returned `undefined` in the app, leaving the 256-bit choice inert.
             */
            [OPTION_TAG_LEN]: String(tagLen),
          }),
          fromHex(vector!.msg!),
        );
        const expectedTag = tagLen === 16 ? vector!.tag128 : vector!.tag256;
        expect(encodeHex(result.bytes!), `${tool}/${tagLen}`).toBe(vector!.ct + expectedTag);
        expect(result.fields?.find((f) => f.label === "Tag")?.value).toBe(expectedTag);
      }
    }
  });

  it("AEGIS decryption needs the tag length it was encrypted with", async () => {
    // Not a tag failure in the usual sense -- the bytes are right, the split is wrong -- but the
    // family reports it the same way, because from the cipher's point of view it is a bad tag.
    const options = keyed("11".repeat(16), "22".repeat(16), { [OPTION_TAG_LEN]: "32" });
    const sealed = await run("aegis128l", options, ascii("hello aegis"));
    expect(sealed.bytes!.length).toBe("hello aegis".length + 32);

    const mismatched = await compute(
      "aegis128l",
      { ...options, [OPTION_TAG_LEN]: "16", [OPTION_DIRECTION]: "decrypt" },
      sealed.bytes!,
    );
    expect(mismatched.error).toMatch(/tag did not verify/i);

    const correct = await run(
      "aegis128l",
      { ...options, [OPTION_DIRECTION]: "decrypt" },
      sealed.bytes!,
    );
    expect(new TextDecoder().decode(correct.bytes!)).toBe("hello aegis");
  });

  it("Ascon-AEAD128 matches the reference KAT through the family", async () => {
    /**
     * One vector from the file `tests/algos-ascon.test.ts` runs 144 of, chosen because it exercises
     * both a partial message block and associated data: 17 bytes of each, either side of the 16-byte
     * rate. What this adds over the algorithm-level test is the trip through options and the resolver
     * -- in particular that the AAD arrives hex-decoded rather than as its own ASCII.
     */
    const vector = ASCON_AEAD128_KAT.find((v) => v.pt.length === 34 && v.ad.length === 34);
    expect(vector, "the 17-byte/17-byte KAT vector").toBeTruthy();
    // The KAT's own bytes rather than a hand-written pattern: its plaintext runs from 0x20 and its
    // associated data from 0x30, which is a detail worth reading off the fixture instead of guessing.
    const result = await run(
      "ascon",
      keyed(vector!.key, vector!.nonce, {
        [OPTION_AAD]: vector!.ad,
        aadEncoding: "hex",
      }),
      fromHex(vector!.pt),
    );
    expect(encodeHex(result.bytes!)).toBe(vector!.ct);
  });

  it("Ascon-AEAD128 reports a failed tag as a result, not an exception", async () => {
    const options = keyed("11".repeat(16), "22".repeat(16));
    const sealed = await run("ascon", options, ascii("hello ascon"));
    const tampered = Uint8Array.from(sealed.bytes!);
    tampered[0] = tampered[0]! ^ 1;
    const failed = await compute(
      "ascon",
      { ...options, [OPTION_DIRECTION]: "decrypt" },
      tampered,
    );
    expect(failed.bytes).toBeUndefined();
    expect(failed.error).toMatch(/authentication tag did not verify/i);
    // And the tag is the last 16 bytes of the output, as for every other AEAD here.
    expect(sealed.bytes!.length).toBe("hello ascon".length + 16);
    expect(sealed.fields?.find((f) => f.label === "Tag")?.value).toBe(
      encodeHex(sealed.bytes!.subarray("hello ascon".length)),
    );
  });

  it("Salsa20 matches the eSTREAM Set 1 vector for a 256-bit key", async () => {
    // Key 0x80 then zeros, nonce all zeros: the keystream's first 64 bytes are published, so
    // encrypting 64 zero bytes reproduces them exactly.
    const result = await run(
      "salsa20",
      keyed("80" + "00".repeat(31), "00".repeat(8)),
      new Uint8Array(64),
    );
    expect(encodeHex(result.bytes!).toUpperCase()).toBe(
      "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844" +
        "B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117",
    );
  });

  it("XSalsa20 and its AEAD round-trip, and the AEAD is not the raw keystream", async () => {
    /**
     * No published vector for these two, stated plainly.
     *
     * NaCl's secretbox vector is a 131-byte message the reference prints in full, and reproducing it
     * from memory is exactly the mistake this repo has made once already. What is asserted instead is
     * the structural fact that a wrong wiring would break: secretbox spends the first 64-byte
     * keystream block on the Poly1305 key and starts the message at block 1, so its ciphertext is
     * *not* the raw XSalsa20 keystream applied to the plaintext. An implementation that forgot the
     * offset would pass a round-trip test and fail against libsodium.
     */
    const key = "22".repeat(32);
    const nonce = "33".repeat(24);
    const plaintext = ascii("hello secretbox");

    for (const tool of ["xsalsa20", "xsalsa20poly1305"]) {
      const options = keyed(key, nonce);
      const sealed = await run(tool, options, plaintext);
      const opened = await run(
        tool,
        { ...options, [OPTION_DIRECTION]: "decrypt" },
        sealed.bytes!,
      );
      expect(encodeHex(opened.bytes!), tool).toBe(encodeHex(plaintext));
    }

    const raw = await run("xsalsa20", keyed(key, nonce), plaintext);
    const sealed = await run("xsalsa20poly1305", keyed(key, nonce), plaintext);
    expect(sealed.bytes!.length).toBe(plaintext.length + 16);
    expect(encodeHex(sealed.bytes!.slice(0, plaintext.length))).not.toBe(encodeHex(raw.bytes!));
  });
});

/**
 * The seventeen block ciphers this repo implements itself, over one mode layer.
 *
 * The byte-level correctness of the primitives and of the shared mode layer is settled in
 * `tests/algos-blockciphers.test.ts`, which compares every mode against OpenSSL's `des-ede3-*`,
 * `des-ede-*` and `sm4-*` at thirteen input lengths. What is checked here is the *family wiring*:
 * that the published vector survives the trip through options, resolver and compute, that every mode
 * a tool advertises actually runs, and that the option form reveals the right controls.
 */
describe("the block ciphers this repo implements", () => {
  const BLOCK_TOOLS = CIPHER_TOOLS.filter((t) => t.block !== undefined);

  it("covers every cipher built on the shared mode layer", () => {
    /**
     * The list is derived from the metadata and the expectation is written out, so adding another
     * block cipher fails here once -- and is then covered by every loop below for free. It has already
     * done that job six times: Camellia and ARIA together, then Magma, then Blowfish with PRESENT and
     * one member each of Speck and Simon, then the seven whose specifications were fetched -- RC2,
     * IDEA, CAST5, SEED, Twofish, Serpent and Kuznyechik -- and then the other eighteen Simon and
     * Speck sizes.
     *
     * Kalyna is the seventh, and the first cipher here whose *block* size is a parameter: one tool
     * covering 128-, 256- and 512-bit blocks, which is why every loop below reads `ResolvedCipher`
     * rather than `tool.block.size`.
     *
     * Simon and Speck are one tool each now rather than ten. Their twenty parameter sets are checked
     * against `SIMON_SPECK_VARIANTS` in the test below instead, which is the assertion that actually
     * matters -- the ids here would not notice a set going missing.
     */
    expect(BLOCK_TOOLS.map((t) => t.id).sort()).toEqual(
      [
        "3des",
        "anubis",
        "chaskeylts",
        "cham",
        "aria",
        "belt",
        "blowfish",
        "camellia",
        "clefia",
        "cast5",
        "des",
        "idea",
        "kalyna",
        "kasumi",
        "khazad",
        "kuznyechik",
        "magma",
        "mars",
        "misty1",
        "present",
        "rc2",
        "seed",
        "serpent",
        "lblock",
        "led",
        "lilliput",
        "fantomas",
        "piccolo",
        "pride",
        "prince",
        "rectangle",
        "roadrunner80",
        "roadrunner128",
        "robin",
        "robinstar",
        "saferp",
        "simeck",
        "skinny",
        "sm4",
        "sparx",
        "twine",
        "twofish",
        // One tool each, ten parameter sets apiece.
        "simon",
        "speck",
        // The seventh batch: two AES finalists, RC5 with its round count, Threefish with its tweak,
        // and the three legacy 64-bit ciphers.
        "cast6",
        "rc6",
        "rc5",
        "threefish",
        "tea",
        "xtea",
        "xxtea",
        "skipjack",
        // The eighth batch, all four with Bouncy Castle vectors: two NESSIE entries, Korea's ISO
        // lightweight cipher, and the Soviet standard whose S-boxes are a parameter.
        "noekeon",
        "lea",
        "shacal2",
        "gost28147",
        "hight",
      ].sort(),
    );
  });

  it("offers every Simon and Speck parameter set the implementation defines", () => {
    /**
     * The assertion the id list used to make, moved to where it belongs.
     *
     * `SIMON_SPECK_VARIANTS` in `@ocs/algos` is the paper's own table and the single source both
     * halves read. A set present in the implementation and missing from the metadata would be
     * unreachable from the app; one present in the metadata and missing from the implementation
     * throws in `simonSpeckWordBits` rather than producing output. Both directions are checked.
     */
    const expected = SIMON_SPECK_VARIANTS.map((v) => `${v.blockBits}-${v.keyBits}`).sort();
    for (const toolId of ["speck", "simon"] as const) {
      const tool = requireCipherTool(toolId);
      expect(tool.paramSets, toolId).toBeDefined();
      expect(tool.paramSets!.map((set) => set.id).sort(), toolId).toEqual(expected);
      // A declared default that is not in the list would silently fall back to the first entry.
      expect(
        tool.paramSets!.some((set) => set.id === tool.defaultParamSet),
        `${toolId} default`,
      ).toBe(true);
      // Block and key sizes must agree with the ids they are named for.
      for (const set of tool.paramSets!) {
        const [blockBits, keyBits] = set.id.split("-").map(Number) as [number, number];
        expect(set.blockSize, `${toolId} ${set.id} block`).toBe(blockBits / 8);
        expect(set.keyLength, `${toolId} ${set.id} key`).toBe(keyBits / 8);
      }
    }
  });

  it("DES-ECB matches the FIPS 46-3 known-answer test", async () => {
    // Key 0123456789abcdef over "Now is t". PKCS#7 appends a whole block, so the first is the one
    // to compare, exactly as the AES-ECB vector above.
    const result = await run(
      "des",
      keyed("0123456789abcdef", undefined, { [OPTION_MODE]: "ecb" }),
      fromHex("4e6f772069732074"),
    );
    expect(encodeHex(result.bytes!).slice(0, 16)).toBe("3fa40e8a984d4815");
  });

  it("3DES with one key repeated three times is single DES", async () => {
    /**
     * The identity that gives single DES an oracle it would otherwise lack.
     *
     * OpenSSL 3 moved `des-cbc` to the legacy provider, so `crypto.getCiphers()` offers
     * `des-ede3-*` and not `des-*`. EDE with K1 = K2 = K3 is E(D(E(m))) = E(m), so 3DES under a
     * tripled key must reproduce the FIPS vector above -- and 3DES *is* checked against OpenSSL.
     * Single DES therefore rides on that comparison rather than on nothing.
     */
    const result = await run(
      "3des",
      keyed("0123456789abcdef".repeat(3), undefined, { [OPTION_MODE]: "ecb" }),
      fromHex("4e6f772069732074"),
    );
    expect(encodeHex(result.bytes!).slice(0, 16)).toBe("3fa40e8a984d4815");
  });

  it("SM4-ECB matches the GB/T 32907-2016 example", async () => {
    // The standard's own worked example, and the memorable part of it: key and plaintext are the
    // same 16 bytes.
    const result = await run(
      "sm4",
      keyed("0123456789abcdeffedcba9876543210", undefined, { [OPTION_MODE]: "ecb" }),
      fromHex("0123456789abcdeffedcba9876543210"),
    );
    expect(encodeHex(result.bytes!).slice(0, 32)).toBe("681edf34d206965e86b3e94f536e4246");
  });

  it("BelT-ECB matches STB 34.101.31 tests A.1 and A.4", async () => {
    /**
     * Two published vectors at two different keys, both driven forward through the tool.
     *
     * A.4 is published as a *decryption* -- decrypt(K, C) = P -- and is asserted here as the
     * equivalent encryption, because ECB pads: feeding a bare 16-byte ciphertext to the decrypt
     * direction fails padding validation before it reaches the cipher, and there is no option to turn
     * that off. The inverse itself is pinned where padding cannot interfere, in
     * `tests/algos-belt.test.ts`, against A.4 as the standard states it -- which matters for BelT more
     * than for most: it has no key schedule, and encryption and decryption index the eight subkeys in
     * orders that are not reverses of each other, so a round trip can pass with both halves wrong in
     * matching ways.
     *
     * The standard draws its inputs from the H-block, which is why the keys and plaintexts look like
     * arbitrary constants: they are slices of the S-box.
     */
    for (const [key, plaintext, expected] of [
      [
        "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6",
        "b194bac80a08f53b366d008e584a5de4",
        "69cca1c93557c9e3d66bc3e0fa88fa6e",
      ],
      [
        "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511",
        "0dc5300600cab840b38448e5e993f421",
        "e12bdc1ae28257ec703fccf095ee8df1",
      ],
    ] as const) {
      const result = await run(
        "belt",
        keyed(key, undefined, { [OPTION_MODE]: "ecb" }),
        fromHex(plaintext),
      );
      expect(result.error, key).toBeUndefined();
      // The first block only: a whole-block input under ECB produces a second, all-padding block.
      expect(encodeHex(result.bytes!).slice(0, 32), key).toBe(expected);
    }
  });

  it("AES-OFB matches NIST SP 800-38A F.4.1", async () => {
    /**
     * The one AES mode built by composition rather than taken from noble: its ECB with padding
     * disabled, used as the bare block permutation, under the generic OFB from `@ocs/algos`.
     *
     * The first block of OFB and of CFB are the same value -- both are the plaintext XOR E(IV) --
     * which is a useful cross-check on the composition and not a coincidence.
     */
    const result = await run(
      "aes",
      keyed("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", {
        [OPTION_MODE]: "ofb",
      }),
      fromHex("6bc1bee22e409f96e93d7e117393172a"),
    );
    expect(encodeHex(result.bytes!)).toBe("3b3fd92eb72dad20333449f8e83cfb4a");
  });

  it("Camellia matches RFC 3713 appendix A at all three key sizes", async () => {
    // The appendix reuses one plaintext, and for the 128-bit case the key is that same value again.
    const PLAINTEXT = "0123456789abcdeffedcba9876543210";
    const CASES = [
      { key: PLAINTEXT, ciphertext: "67673138549669730857065648eabe43" },
      { key: PLAINTEXT + "0011223344556677", ciphertext: "b4993401b3e996f84ee5cee7d79b09b9" },
      {
        key: PLAINTEXT + "00112233445566778899aabbccddeeff",
        ciphertext: "9acc237dff16d76c20ef7c919e3a7509",
      },
    ];

    for (const { key, ciphertext } of CASES) {
      const result = await run(
        "camellia",
        keyed(key, undefined, { [OPTION_MODE]: "ecb" }),
        fromHex(PLAINTEXT),
      );
      // PKCS#7 adds a block, so the published one is the first.
      expect(encodeHex(result.bytes!).slice(0, 32), `${key.length / 2}-byte key`).toBe(
        ciphertext,
      );
    }
  });

  it("ARIA matches RFC 5794 appendix A at all three key sizes", async () => {
    const PLAINTEXT = "00112233445566778899aabbccddeeff";
    const KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const CASES = [
      { bytes: 16, ciphertext: "d718fbd6ab644c739da95f3be6451778" },
      { bytes: 24, ciphertext: "26449c1805dbe7aa25a468ce263a9e79" },
      { bytes: 32, ciphertext: "f92bd7c79fb72e2f2b8f80c1972d24fc" },
    ];

    for (const { bytes, ciphertext } of CASES) {
      const result = await run(
        "aria",
        keyed(KEY.slice(0, bytes * 2), undefined, { [OPTION_MODE]: "ecb" }),
        fromHex(PLAINTEXT),
      );
      expect(encodeHex(result.bytes!).slice(0, 32), `${bytes}-byte key`).toBe(ciphertext);
    }
  });

  it("names each construction after itself, with no shared fallback", async () => {
    /**
     * The regression this pins: `constructionLabel` used to end in `default: "ChaCha20-Poly1305"`,
     * which was accurate for the five tools that existed when it was written and silently wrong for
     * every one added afterwards -- a DES-CBC result carrying a ChaCha20-Poly1305 label.
     *
     * Checked through `compute` rather than by calling the label function, because the panel reads
     * the field and not the function.
     */
    const labels = new Map<string, string>();
    for (const meta of CIPHER_TOOLS) {
      const mode = seedMode(meta.id);
      const nonceLen = requiredNonceLength(meta.id, mode);
      const result = await run(
        meta.id,
        keyed(
          "11".repeat(seedKeyLength(meta.id)),
          nonceLen > 0 ? "22".repeat(nonceLen) : undefined,
          mode ? { [OPTION_MODE]: mode.id } : {},
        ),
        ascii("x"),
      );
      const construction = result.fields?.find((f) => f.label === "Construction")?.value;
      expect(construction, meta.id).toBeTruthy();
      labels.set(meta.id, construction!);
    }

    // Distinct for every tool, and each one recognisably its own cipher.
    expect(new Set(labels.values()).size).toBe(labels.size);
    expect(labels.get("des")).toBe("DES-CBC");
    expect(labels.get("3des")).toBe("3DES-EDE3-CBC");
    expect(labels.get("camellia")).toBe("Camellia-256-CBC");
    expect(labels.get("aria")).toBe("ARIA-256-CBC");
    expect(labels.get("sm4")).toBe("SM4-CBC");
    expect(labels.get("salsa20")).toBe("Salsa20");
    expect(labels.get("chacha20poly1305")).toBe("ChaCha20-Poly1305");
  });

  it("every advertised mode round-trips, at a length that is not a whole block", async () => {
    // 23 bytes: not a multiple of 8 or of 16, so both padded modes exercise their padding and the
    // three stream modes exercise their partial final block.
    const message = ascii("twenty-three bytes here");
    expect(message.length).toBe(23);

    for (const meta of BLOCK_TOOLS) {
      for (const mode of seedModes(meta.id)) {
        const nonceLen = requiredNonceLength(meta.id, mode);
        const options = keyed(
          "11".repeat(seedKeyLength(meta.id)),
          nonceLen > 0 ? "22".repeat(nonceLen) : undefined,
          { [OPTION_MODE]: mode!.id },
        );
        const label = `${meta.id}/${mode!.id}`;
        const sealed = await run(meta.id, options, message);
        const opened = await run(
          meta.id,
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          sealed.bytes!,
        );
        expect(encodeHex(opened.bytes!), label).toBe(encodeHex(message));

        /**
         * Only two things grow the message, and they grow it by different amounts: PKCS#7 rounds up
         * to the block, and an AEAD appends its tag. Anything else must come out byte-for-byte the
         * same length -- which is the assertion that catches a stream mode quietly padding.
         */
        const grew = sealed.bytes!.length - message.length;
        if (mode!.blockAligned) expect(grew > 0, label).toBe(true);
        else if (mode!.aead) expect(grew, label).toBe(16);
        else expect(grew, label).toBe(0);
      }
    }
  });

  it("shows an IV for the chaining modes and none for ECB, per cipher", () => {
    /**
     * The regression this exists for: `variantTag` returned `undefined` for these three, and
     * `isAvailableOn` reads a missing tag as "not available" -- so an IV option gated on a mode list
     * was unreachable in every mode. ECB computed fine, which is what made it easy to miss.
     */
    for (const meta of BLOCK_TOOLS) {
      const tool = cipherToolDefinition(meta.id);
      const visible = (modeId: string) => {
        const tag = tool.variantTag!(specFor(meta.id, { [OPTION_MODE]: modeId }));
        return tool.catalogue.options.filter((o) => isAvailableOn(o, tag)).map((o) => o.id);
      };

      expect(visible("cbc"), meta.id).toContain(OPTION_NONCE);
      expect(visible("ctr"), meta.id).toContain(OPTION_NONCE);
      expect(visible("ecb"), meta.id).not.toContain(OPTION_NONCE);
      // AAD follows authentication, per mode rather than per cipher: CBC never offers it, and GCM
      // does wherever the cipher actually offers GCM -- which is a metadata question, not a width one.
      expect(visible("cbc"), meta.id).not.toContain(OPTION_AAD);
      if (meta.block!.modes.includes("gcm")) {
        expect(visible("gcm"), meta.id).toContain(OPTION_AAD);
        expect(visible("ccm"), meta.id).toContain(OPTION_AAD);
      }
    }
  });

  it("offers the two portable AEADs where the block is 128 bits, and no AES-only construction", () => {
    for (const meta of BLOCK_TOOLS) {
      const offered = new Set(meta.block!.modes);
      /**
       * GCM and CCM need nothing but a 128-bit block permutation, so `@ocs/algos` can give them to
       * any cipher of that width -- but *offering* one is a separate judgement from being able to.
       *
       * Camellia, ARIA and SM4 get both because standards specify them: RFC 5528/5529, RFC 6209 and
       * RFC 8998 respectively, the last making SM4-GCM and SM4-CCM the standardised pair for TLS 1.3.
       * Speck and Simon have the block width and no such standard, so pairing them with GCM would be
       * inventing a construction nothing else implements. And a 64-bit block cannot have either at
       * all: GCM's field is GF(2^128) and CCM's counter formatting assumes 16 bytes.
       */
      const STANDARDISED_AEAD = ["camellia", "aria", "sm4"];
      for (const aead of ["gcm", "ccm"]) {
        expect(offered.has(aead), `${meta.id}/${aead}`).toBe(
          STANDARDISED_AEAD.includes(meta.id),
        );
      }
      // The necessary condition, whichever ciphers are offered them: never on a 64-bit block.
      if (meta.block!.size === 8) {
        expect(offered.has("gcm"), meta.id).toBe(false);
        expect(offered.has("ccm"), meta.id).toBe(false);
      }
      /**
       * These four stay AES-only, and for reasons rather than by omission. GCM-SIV and AES-SIV both
       * derive their keys with a construction defined over AES specifically, and RFC 3394 key wrap
       * *is* an AES specification -- there is no Camellia-KW to be compatible with.
       */
      for (const aesOnly of ["gcm-siv", "aessiv", "kw", "kwp", "xts"]) {
        expect(offered.has(aesOnly), `${meta.id}/${aesOnly}`).toBe(false);
      }
      // And the resolver agrees the construction is unauthenticated, which is what C002 reads.
      const resolved = resolveCipher(
        specFor(
          meta.id,
          keyed("11".repeat(seedKeyLength(meta.id)), "22".repeat(meta.block!.size), {
            [OPTION_MODE]: "cbc",
          }),
        ),
      );
      expect(resolved.ok, meta.id).toBe(true);
      if (resolved.ok) expect(resolved.resolved.aead, meta.id).toBe(false);
    }
  });

  it("names the key sizes each cipher actually takes", () => {
    /**
     * 32 bytes is right for AES and for two of these five, which is the mistake to catch. CBC is named
     * explicitly and the IV sized from it, so nothing else can be what C005 reports -- an earlier
     * version left the mode to the default and started reading "Camellia-GCM needs exactly 12 bytes"
     * the moment GCM became the first mode Camellia lists. For DES and 3DES the resolver checks the
     * key before the IV, so the key message still wins there.
     */
    const message = (id: string) => {
      const mode = seedMode(id)!;
      return lint(
        specFor(
          id,
          keyed("11".repeat(32), "22".repeat(requiredNonceLength(id, mode)), {
            [OPTION_MODE]: mode.id,
          }),
        ),
      ).diagnostics.find((d) => d.code === "C005")?.message;
    };

    expect(message("des")).toMatch(/8/);
    expect(message("3des")).toMatch(/16, 24|16 or 24/);
    expect(message("sm4")).toMatch(/16/);
    // 32 bytes is legal for these two, so there is nothing for C005 to say.
    expect(message("camellia")).toBeUndefined();
    expect(message("aria")).toBeUndefined();
  });

  it("explains a failed DES decrypt rather than passing noble's message through", async () => {
    // Wrong key under a padded mode. `unpadPkcs7` writes the explanation from the situation --
    // direction is decrypt, the mode is block-aligned -- because there is no library string here
    // worth matching on.
    const options = keyed("0123456789abcdef", "22".repeat(8), { [OPTION_MODE]: "cbc" });
    const sealed = await run("des", options, ascii("some plaintext"));
    const result = await compute(
      "des",
      { ...options, [OPTION_KEY]: "fedcba9876543210", [OPTION_DIRECTION]: "decrypt" },
      sealed.bytes!,
    );
    expect(result.error).toBeTruthy();
    expect(result.error).toMatch(/padding|key|decrypt/i);
  });

  it("C007 states the data limit for the parameter set actually selected", () => {
    /**
     * The diagnostic that replaced twenty static security notes.
     *
     * Across one dropdown the honest figure moves from 256 kilobytes to no practical limit -- four
     * orders of magnitude -- so a note fixed at write time is wrong for nine of the ten sets. This
     * asserts the number tracks the selection, and that it goes quiet where there is nothing to act
     * on rather than saying something reassuring.
     */
    const at = (setId: string) =>
      lint(
        specFor(
          "speck",
          keyed(
            "11".repeat(
              requireCipherTool("speck").paramSets!.find((p) => p.id === setId)!.keyLength,
            ),
            undefined,
            {
              [OPTION_MODE]: "ecb",
              [OPTION_PARAM_SET]: setId,
            },
          ),
        ),
      ).diagnostics.find((d) => d.code === "C007");

    /**
     * 2^(n/2) *blocks*, not bytes -- which is what the notes this rule replaced got wrong.
     *
     * A 32-bit block gives 2^16 blocks of 4 bytes = 256 KB, and a 48-bit block 2^24 blocks of 6
     * bytes = 96 MB. The inherited prose said 64 KB and 16 MB, counting the block count as a byte
     * count; the 64-bit figure was right only because 2^32 blocks x 8 bytes = 32 GB is the number
     * SWEET32 made famous. Computing it is what caught that.
     */
    expect(at("32-64")?.message).toContain("256 KB");
    expect(at("48-96")?.message).toContain("96 MB");
    expect(at("64-128")?.message).toContain("32 GB");
    // Above a 64-bit block the figure is astronomical, so the rule says nothing at all.
    expect(at("96-144")).toBeUndefined();
    expect(at("128-256")).toBeUndefined();
    // It names the set, not the tool -- the block size is what the number depends on.
    expect(at("32-64")?.message).toContain("Speck32/64");
    // And no fix: the answer is a different cipher, which would mean leaving this tool.
    expect(at("32-64")?.fix).toBeUndefined();
  });

  it("C007 is silent for every cipher with only one shape", () => {
    // It reads `paramSet`, which is undefined everywhere else. A rule that fired on AES would be
    // noise, and noise is why people stop reading the panel.
    for (const id of ["aes", "des", "blowfish", "camellia", "present"]) {
      const spec = specFor(
        id,
        keyed("11".repeat(16), "22".repeat(requiredNonceLength(id, getAesMode("cbc")) || 12), {
          [OPTION_MODE]: "cbc",
        }),
      );
      expect(
        lint(spec).diagnostics.some((d) => d.code === "C007"),
        id,
      ).toBe(false);
    }
  });

  it("C006 flags a weak DES key, and its fix silences it", () => {
    // 0101010101010101 is the first of the four weak keys: all-zero after the parity bits drop, so
    // the sixteen round keys are identical and DES becomes its own inverse.
    const spec = specFor(
      "des",
      keyed("0101010101010101", "22".repeat(8), { [OPTION_MODE]: "cbc" }),
    );
    const found = lint(spec).diagnostics.find((d) => d.code === "C006");
    expect(found?.level).toBe("warning");
    expect(found?.message).toMatch(/weak or semi-weak/);
    expect(lint(found!.fix!.apply(spec)).diagnostics.some((d) => d.code === "C006")).toBe(
      false,
    );
  });

  it("C006 counts how many of a 3DES bundle's three keys are weak", () => {
    const weak = "0101010101010101";
    const strong = "0123456789abcdef";
    const one = lint(
      specFor("3des", keyed(weak + strong + strong, undefined, { [OPTION_MODE]: "ecb" })),
    ).diagnostics.find((d) => d.code === "C006");
    expect(one?.message).toMatch(/1 of the 3/);

    const all = lint(
      specFor("3des", keyed(weak.repeat(3), undefined, { [OPTION_MODE]: "ecb" })),
    ).diagnostics.find((d) => d.code === "C006");
    expect(all?.message).toMatch(/Every 8-byte key/);

    // And a bundle with no weak key at all says nothing.
    expect(
      lint(
        specFor("3des", keyed(strong.repeat(3), undefined, { [OPTION_MODE]: "ecb" })),
      ).diagnostics.some((d) => d.code === "C006"),
    ).toBe(false);
  });

  it("C006 stays out of the way of the other ciphers", () => {
    // An 8-byte weak DES key repeated to 32 bytes is not a weak AES key -- the concept does not
    // exist there -- and the rule must not go looking.
    for (const meta of CIPHER_TOOLS) {
      if (meta.id === "des" || meta.id === "3des") continue;
      const spec = specFor(
        meta.id,
        keyed(
          "0101010101010101".repeat(seedKeyLength(meta.id) / 8),
          "22".repeat(requiredNonceLength(meta.id, getAesMode("cbc")) || 12),
        ),
      );
      expect(
        lint(spec).diagnostics.some((d) => d.code === "C006"),
        meta.id,
      ).toBe(false);
    }
  });

  it("C002 names the mode it is warning about", () => {
    const spec = specFor(
      "sm4",
      keyed("11".repeat(16), "22".repeat(16), { [OPTION_MODE]: "cbc" }),
    );
    const found = lint(spec).diagnostics.find((d) => d.code === "C002");
    // "SM4 encrypts but does not authenticate" would be true of SM4 in every mode; the reader is
    // looking at one combination.
    expect(found?.message).toBe("SM4 in CBC mode encrypts but does not authenticate.");
    expect(found?.detail).toMatch(/AES-GCM/);
  });
});

/**
 * The four modes added after the family was built, driven through `compute` rather than through
 * `@ocs/algos`.
 *
 * `tests/algos-aead-modes.test.ts` already checks the mode implementations against OpenSSL at length.
 * What is unchecked there, and what has broken before, is the layer between: the option catalogue, the
 * resolver's length rules, the tag-length binding and the labels. Every assertion here therefore goes
 * through the tool the way the panel does, and the reference values come from `node:crypto` -- the
 * oracle -- or from a published vector, never from a second copy of our own arithmetic.
 */
describe("CCM, OCB and XTS through the cipher family", () => {
  const key128 = "000102030405060708090a0b0c0d0e0f";
  const key256 = key128 + "101112131415161718191a1b1c1d1e1f";
  const nonce12 = "101112131415161718191a1b";
  const message = ascii("sixteen bytes.. and a little more");

  /** OpenSSL's answer for one of the two AEAD modes, tag appended as this family transmits it. */
  function opensslAead(
    name: string,
    keyHex: string,
    nonceHex: string,
    plaintext: Uint8Array,
    aad: Uint8Array,
    tagLen: number,
  ): string {
    /**
     * Cast, because `@types/node` gives `setAAD` and `getAuthTag` only to the overloads taking a
     * *literal* algorithm name -- and this name is a parameter. Same reasoning as `aeadCipher` in
     * `tests/algos-aead-modes.test.ts`.
     */
    const cipher = createCipheriv(name, fromHex(keyHex), fromHex(nonceHex), {
      authTagLength: tagLen,
    } as never) as unknown as Cipher & {
      setAAD(buffer: Uint8Array, options?: { plaintextLength?: number }): void;
      getAuthTag(): Buffer;
    };
    /**
     * `setAAD` only when there is associated data -- and for CCM it carries the plaintext length,
     * which CCM needs before any data because the length goes into its first MAC block. Calling it
     * with an empty buffer is not the same as not calling it: OpenSSL then formats a zero-length AAD
     * block and the output differs.
     */
    if (aad.length > 0) {
      cipher.setAAD(
        Buffer.from(aad),
        name.endsWith("-ccm") ? { plaintextLength: plaintext.length } : undefined,
      );
    }
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([body, cipher.getAuthTag()]).toString("hex");
  }

  it("matches OpenSSL for AES-CCM at every nonce and tag length the form offers", async () => {
    const ccm = getAesMode("ccm")!;
    for (const nonceLen of ccm.nonceLens!) {
      for (const tagLen of ccm.tagLens!) {
        const nonce = "aa".repeat(nonceLen);
        const options = keyed(key256, nonce, {
          [OPTION_MODE]: "ccm",
          [OPTION_TAG_LEN]: String(tagLen),
        });
        const label = `ccm/n${nonceLen}/t${tagLen}`;
        const result = await run("aes", options, message);
        expect(encodeHex(result.bytes!), label).toBe(
          opensslAead("aes-256-ccm", key256, nonce, message, new Uint8Array(0), tagLen),
        );

        // And the same options decrypt it, which is the half a fixed 16-byte tag length broke.
        const opened = await run(
          "aes",
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          result.bytes!,
        );
        expect(encodeHex(opened.bytes!), label).toBe(encodeHex(message));
      }
    }
  });

  it("matches OpenSSL for AES-OCB, including with associated data", async () => {
    const aad = ascii("counted, not encrypted");
    for (const tagLen of [16, 12, 8]) {
      const options = keyed(key128, nonce12, {
        [OPTION_MODE]: "ocb",
        [OPTION_TAG_LEN]: String(tagLen),
        [OPTION_AAD]: "counted, not encrypted",
        aadEncoding: "utf-8",
      });
      const result = await run("aes", options, message);
      expect(encodeHex(result.bytes!), `ocb/t${tagLen}`).toBe(
        opensslAead("aes-128-ocb", key128, nonce12, message, aad, tagLen),
      );
    }
  });

  it("matches OpenSSL for AES-XTS at both key sizes, including a partial final block", async () => {
    // 32 bytes of key is XTS-AES-128 and 64 is XTS-AES-256; there is no 192-bit XTS to test.
    /**
     * The two halves must differ. OpenSSL refuses `xts duplicated keys` outright, which is a real
     * check rather than pedantry: identical halves make the tweak encryption and the data encryption
     * the same permutation, and the mode's security argument no longer holds.
     */
    const key512 = key256 + "20".repeat(32);
    for (const [keyHex, name] of [
      [key256, "aes-128-xts"],
      [key512, "aes-256-xts"],
    ] as const) {
      for (const length of [16, 17, 31, 32, 33]) {
        const data = message.subarray(0, length);
        const options = keyed(keyHex, "22".repeat(16), { [OPTION_MODE]: "xts" });
        const label = `${name}/${length}`;
        const result = await run("aes", options, data);

        const cipher = createCipheriv(name, fromHex(keyHex), fromHex("22".repeat(16)));
        const expected = Buffer.concat([cipher.update(data), cipher.final()]).toString("hex");
        expect(encodeHex(result.bytes!), label).toBe(expected);

        // XTS never expands its input; that is why it can encrypt a sector into a sector.
        expect(result.bytes!.length, label).toBe(length);
        const opened = await run(
          "aes",
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          result.bytes!,
        );
        expect(encodeHex(opened.bytes!), label).toBe(encodeHex(data));
      }
    }
  });

  it("names XTS after the cipher it uses, not after the key string it was handed", async () => {
    const construction = async (keyHex: string) => {
      const result = await run(
        "aes",
        keyed(keyHex, "22".repeat(16), { [OPTION_MODE]: "xts" }),
        message.subarray(0, 16),
      );
      return result.fields?.find((f) => f.label === "Construction")?.value;
    };
    /**
     * The arithmetic this family does everywhere else -- key bytes times eight -- is wrong exactly
     * here: a 32-byte XTS key is two AES-128 keys, so it is XTS-AES-128 and there is no 256-bit AES
     * anywhere in it. Written the way SP 800-38E writes it, too.
     */
    expect(await construction(key256)).toBe("XTS-AES-128");
    expect(await construction(key256 + "20".repeat(32))).toBe("XTS-AES-256");
  });

  it("calls XTS's tweak a data unit and does not tell the user never to reuse it", async () => {
    /**
     * Reusing the tweak is what XTS is *for*: sector 7 is written with tweak 7 every time it is
     * rewritten. The generic nonce hint -- "never reuse it under this key" -- would be advice nobody
     * encrypting a disk can follow, and it describes a different mode.
     */
    const result = await run(
      "aes",
      keyed(key256, "22".repeat(16), { [OPTION_MODE]: "xts" }),
      message.subarray(0, 16),
    );
    const field = result.fields?.find((f) => f.label === "Data unit");
    expect(field).toBeDefined();
    expect(field!.hint).not.toMatch(/never reuse/i);
    expect(field!.hint).toMatch(/sector/i);
  });

  it("asks for a doubled key under XTS, and says why", () => {
    const result = resolveCipher(
      specFor("aes", keyed(key128, "22".repeat(16), { [OPTION_MODE]: "xts" })),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // 16 bytes is a perfectly good AES key and is refused here, so the message has to name the
      // two lengths rather than leaving the user to guess which of AES's three sizes went wrong.
      expect(result.problem).toMatch(/32|64/);
    }
  });

  it("refuses a CCM nonce outside 7 to 13, and names the range", () => {
    for (const nonceLen of [6, 14, 16]) {
      const result = resolveCipher(
        specFor("aes", keyed(key256, "aa".repeat(nonceLen), { [OPTION_MODE]: "ccm" })),
      );
      expect(result.ok, `n${nonceLen}`).toBe(false);
      // "needs exactly 12 bytes" would be the old fixed-length message and a wrong answer here.
      if (!result.ok) expect(result.problem, `n${nonceLen}`).toMatch(/7 to 13/);
    }
    for (const nonceLen of [7, 10, 13]) {
      const result = resolveCipher(
        specFor("aes", keyed(key256, "aa".repeat(nonceLen), { [OPTION_MODE]: "ccm" })),
      );
      expect(result.ok, `n${nonceLen}`).toBe(true);
    }
  });

  it("shows the tag it actually appended, at whatever length was chosen", async () => {
    for (const tagLen of [16, 8, 4]) {
      const result = await run(
        "aes",
        keyed(key256, nonce12, { [OPTION_MODE]: "ccm", [OPTION_TAG_LEN]: String(tagLen) }),
        message,
      );
      const tag = result.fields?.find((f) => f.label === "Tag")?.value;
      expect(tag, `t${tagLen}`).toBeDefined();
      expect(tag!.length, `t${tagLen}`).toBe(tagLen * 2);
      expect(result.bytes!.length, `t${tagLen}`).toBe(message.length + tagLen);
    }
  });

  it("falls back to a 16-byte tag when a share link names a length the mode disallows", async () => {
    /**
     * `readTagLenFrom` validates against the mode's own list rather than trusting the stored value.
     * A link carrying `tagLen=32` -- legal for AEGIS, not for CCM -- must not produce a tag nothing
     * can verify.
     */
    const result = await run(
      "aes",
      keyed(key256, nonce12, { [OPTION_MODE]: "ccm", [OPTION_TAG_LEN]: "32" }),
      message,
    );
    expect(result.bytes!.length).toBe(message.length + 16);
  });

  it("offers a tag-length control for exactly the modes whose tag length is a choice", () => {
    const tool = cipherToolDefinition("aes");
    const visible = (modeId: string) => {
      const tag = tool.variantTag!(specFor("aes", { [OPTION_MODE]: modeId }));
      return tool.catalogue.options.filter((o) => isAvailableOn(o, tag)).map((o) => o.id);
    };
    for (const mode of AES_MODES) {
      const offered = visible(mode.id).includes(OPTION_TAG_LEN);
      expect(offered, mode.id).toBe(mode.tagLens !== undefined);
    }
    // GCM's tag is 16 bytes in every specification that uses it, so there is nothing to choose.
    expect(visible("gcm")).not.toContain(OPTION_TAG_LEN);
  });

  it("reproduces RFC 8998's SM4-GCM and SM4-CCM vectors through the tool", async () => {
    /**
     * The one place the shared mode layer earns its keep visibly: RFC 8998 specifies SM4-GCM and
     * SM4-CCM for TLS 1.3 with SM3, and OpenSSL here has neither -- `sm4-gcm` is absent from
     * `getCiphers()`. The published vectors are the oracle instead, and they run through the tool so
     * the option plumbing is covered as well as the arithmetic. The same two values are asserted
     * against `@ocs/algos` directly in `tests/algos-aead-modes.test.ts`; here they have to survive
     * the catalogue, the resolver's nonce rules and the AAD encoding as well.
     */
    const key = "0123456789ABCDEFFEDCBA9876543210";
    const nonce = "00001234567800000000ABCD";
    const aad = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2";
    const plaintext =
      "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD" +
      "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA";

    const cases = [
      {
        mode: "gcm",
        expected:
          "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735" +
          "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d" +
          "83de3541e4c2b58177e065a9bf7b62ec",
      },
      {
        mode: "ccm",
        expected:
          "48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094" +
          "fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b" +
          "16842d4fa186f56ab33256971fa110f4",
      },
    ] as const;

    for (const { mode, expected } of cases) {
      const options = keyed(key, nonce, {
        [OPTION_MODE]: mode,
        [OPTION_AAD]: aad,
        aadEncoding: "hex",
      });
      const result = await run("sm4", options, fromHex(plaintext));
      expect(encodeHex(result.bytes!), mode).toBe(expected);

      const opened = await run(
        "sm4",
        { ...options, [OPTION_DIRECTION]: "decrypt" },
        result.bytes!,
      );
      expect(encodeHex(opened.bytes!), mode).toBe(plaintext.toLowerCase());

      // Altering the associated data must fail the tag, not silently return plaintext.
      const tampered = await compute(
        "sm4",
        { ...options, [OPTION_DIRECTION]: "decrypt", [OPTION_AAD]: `${aad.slice(0, -2)}00` },
        result.bytes!,
      );
      expect(tampered.error, mode).toMatch(/tag/i);
      expect(tampered.bytes, mode).toBeUndefined();
    }
  });

  it("tells the truth about XTS's integrity, and offers no fix for it", () => {
    const spec = specFor("aes", keyed(key256, "22".repeat(16), { [OPTION_MODE]: "xts" }));
    const diagnostics = lint(spec).diagnostics;

    const c002 = diagnostics.find((d) => d.code === "C002");
    expect(c002).toBeDefined();
    /**
     * Two claims the generic warning would have made here, both wrong. Flipping a ciphertext bit
     * under XTS randomises its whole block rather than flipping the same plaintext bit -- so the
     * text must not say otherwise -- and "switch to GCM" is not advice a disk format can take, so
     * there is deliberately no fix.
     */
    expect(c002!.level).toBe("info");
    expect(c002!.detail).not.toMatch(/flipping a bit/i);
    expect(c002!.detail).toMatch(/sector/i);
    expect(c002!.fix).toBeUndefined();

    // And C003 stays quiet: reusing the tweak for a given sector is what the mode is for.
    expect(diagnostics.some((d) => d.code === "C003")).toBe(false);
  });

  it("explains a sub-block XTS input in terms of ciphertext stealing", async () => {
    const result = await compute(
      "aes",
      keyed(key256, "22".repeat(16), { [OPTION_MODE]: "xts" }),
      ascii("short"),
    );
    expect(result.bytes).toBeUndefined();
    expect(result.error).toMatch(/borrow/i);
  });
});

describe("the reduced-round and original-nonce ChaCha variants", () => {
  /**
   * `draft-strombergson-chacha-test-vectors`, TC1: a 256-bit all-zero key and an all-zero nonce, at
   * every round count the draft covers. These are the vectors every ChaCha implementation is checked
   * against, and the reason the reduced-round variants can be tools at all -- `@noble/ciphers`
   * implements them, but a library agreeing with itself proves nothing about the round count.
   */
  const TC1: Record<string, string> = {
    chacha8: "3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e",
    chacha12: "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f",
    chacha20orig: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
  };

  it("reproduces TC1 at eight, twelve and twenty rounds", async () => {
    for (const [toolId, expected] of Object.entries(TC1)) {
      const nonceLen = requiredNonceLength(toolId, undefined);
      const result = await run(
        toolId,
        keyed("00".repeat(32), "00".repeat(nonceLen)),
        // The keystream itself: encrypting zeros is what the draft tabulates.
        new Uint8Array(32),
      );
      expect(encodeHex(result.bytes!), toolId).toBe(expected);
    }
  });

  it("gives each round count a different keystream, which is the point of having three", async () => {
    const digests = new Set<string>();
    for (const toolId of ["chacha8", "chacha12", "chacha20"]) {
      const result = await run(
        toolId,
        keyed("00".repeat(32), "00".repeat(12)),
        new Uint8Array(32),
      );
      digests.add(encodeHex(result.bytes!));
    }
    // Three tools, three keystreams. A `Record` miss defaulting to twenty rounds would collapse this.
    expect(digests.size).toBe(3);
  });

  it("places the original 64-bit nonce where RFC 8439 puts its last eight bytes", async () => {
    /**
     * The one substantive difference between the two ChaCha20 tools, checked against the RFC layout
     * rather than against a second recollection of a vector.
     *
     * RFC 8439's state is `counter, n0, n1, n2`; the original's is `counter_lo, counter_hi, iv0, iv1`.
     * So at counter zero, a 12-byte nonce of four zero bytes followed by the 8-byte IV produces
     * exactly the original layout -- and `chacha20` is already checked against RFC 8439's own
     * vectors elsewhere in this file, which makes it a real oracle for this.
     */
    const iv = "0102030405060708";
    const original = await run("chacha20orig", keyed("11".repeat(32), iv), new Uint8Array(64));
    const rfc = await run(
      "chacha20",
      keyed("11".repeat(32), `00000000${iv}`),
      new Uint8Array(64),
    );
    expect(encodeHex(original.bytes!)).toBe(encodeHex(rfc.bytes!));

    // And the eight-byte nonce is *required*: RFC 8439's twelve is refused, rather than truncated.
    const twelve = resolveCipher(
      specFor("chacha20orig", keyed("11".repeat(32), "22".repeat(12))),
    );
    expect(twelve.ok).toBe(false);
  });

  it("says the round count is reduced rather than that the cipher is broken", () => {
    for (const toolId of ["chacha8", "chacha12"]) {
      const meta = requireCipherTool(toolId);
      // `broken` would be an overclaim: the best published cryptanalysis reaches seven rounds.
      // That reasoning used to be asserted through the tool's `securityNote`, which no longer
      // exists; the posture is the part that is load-bearing, since `C004` fires on `broken`.
      expect(meta.security, toolId).toBe("legacy");
    }
  });

  it("round-trips every variant and warns that none of them authenticates", async () => {
    const message = ascii("reduced rounds, same lack of a tag");
    for (const toolId of ["chacha8", "chacha12", "chacha20orig"]) {
      const options = keyed(
        "33".repeat(32),
        "44".repeat(requiredNonceLength(toolId, undefined)),
      );
      const sealed = await run(toolId, options, message);
      // A stream cipher never changes the length, whatever the round count.
      expect(sealed.bytes!.length, toolId).toBe(message.length);
      const opened = await run(
        toolId,
        { ...options, [OPTION_DIRECTION]: "decrypt" },
        sealed.bytes!,
      );
      expect(encodeHex(opened.bytes!), toolId).toBe(encodeHex(message));

      const c002 = lint(specFor(toolId, options)).diagnostics.find((d) => d.code === "C002");
      expect(c002, toolId).toBeDefined();
      expect(c002!.detail, toolId).toMatch(/ChaCha20-Poly1305/);
    }
  });
});

describe("the four ciphers added on top of the mode layer", () => {
  /**
   * Published vectors through the tool, not through `@ocs/algos`.
   *
   * `tests/algos-lightweight.test.ts` owns the byte-level question. What these check is that the
   * vector survives the trip through the option catalogue, the resolver's key rules and compute --
   * which is where this family's bugs have been, every time.
   *
   * Each is asserted on the *first* block of an ECB result: PKCS#7 appends a whole extra block, so the
   * comparison is against the leading block exactly as the AES-ECB and DES-ECB vectors above.
   */
  const cases: readonly {
    readonly id: string;
    /** Simon and Speck only -- the other two have one shape. */
    readonly paramSet?: string;
    readonly key: string;
    readonly plaintext: string;
    readonly expected: string;
  }[] = [
    {
      id: "blowfish",
      key: "3000000000000000",
      plaintext: "1000000000000001",
      expected: "7d856f9a613063f2",
    },
    {
      id: "present",
      key: "00000000000000000000",
      plaintext: "0000000000000000",
      expected: "5579c1387b228445",
    },
    {
      id: "speck",
      paramSet: "128-128",
      key: "0f0e0d0c0b0a09080706050403020100",
      plaintext: "6c617669757165207469206564616d20",
      expected: "a65d9851797832657860fedf5c570d18",
    },
    {
      id: "simon",
      paramSet: "128-128",
      key: "0f0e0d0c0b0a09080706050403020100",
      plaintext: "63736564207372656c6c657661727420",
      expected: "49681b1e1e54fe3f65aa832af84e0bbc",
    },
    // Two of the small sizes as well, since those are where the parameter table earns its keep: a
    // 32-bit block uses a different rotation pair and a 48-bit one a word size that is not a power of
    // two, and both are new ground for the mode layer.
    {
      id: "speck",
      paramSet: "32-64",
      key: "1918111009080100",
      plaintext: "6574694c",
      expected: "a86842f2",
    },
    {
      id: "simon",
      paramSet: "48-96",
      key: "1a19181211100a0908020100",
      plaintext: "72696320646e",
      expected: "6e06a5acf156",
    },
  ];

  it("reproduces each published vector through the tool", async () => {
    for (const { id, paramSet, key, plaintext, expected } of cases) {
      const result = await run(
        id,
        keyed(key, undefined, {
          [OPTION_MODE]: "ecb",
          ...(paramSet ? { [OPTION_PARAM_SET]: paramSet } : {}),
        }),
        fromHex(plaintext),
      );
      expect(
        encodeHex(result.bytes!).slice(0, expected.length),
        `${id}${paramSet ? `/${paramSet}` : ""}`,
      ).toBe(expected);
    }
  });

  it("accepts Blowfish's whole key range and nothing outside it", () => {
    /**
     * The only variable-length key in the family, which is why `block.keyRange` exists at all. The
     * catalogue declares `min`/`max` rather than a list, so `decodeBytesOption` enforces it -- and the
     * resolver's exact-length check has to *skip* this cipher rather than compare against a second set
     * of bounds that could drift.
     */
    for (const bytes of [4, 16, 56]) {
      const result = resolveCipher(
        specFor(
          "blowfish",
          keyed("11".repeat(bytes), "22".repeat(8), { [OPTION_MODE]: "cbc" }),
        ),
      );
      expect(result.ok, `${bytes} bytes`).toBe(true);
    }
    for (const bytes of [3, 57]) {
      const result = resolveCipher(
        specFor(
          "blowfish",
          keyed("11".repeat(bytes), "22".repeat(8), { [OPTION_MODE]: "cbc" }),
        ),
      );
      expect(result.ok, `${bytes} bytes`).toBe(false);
    }
  });

  it("generates a Blowfish key at the top of the range, not the bottom", () => {
    // A key whose length nobody chose should be the strongest one available.
    const option = cipherCatalogueFor("blowfish").require(OPTION_KEY);
    expect(option.bytesLength?.generate).toBe(56);
    expect(option.bytesLength?.exact).toBeUndefined();
  });

  it("names each of them after itself", async () => {
    const label = async (id: string, key: string, paramSet?: string) => {
      const result = await run(
        id,
        keyed(key, undefined, {
          [OPTION_MODE]: "ecb",
          ...(paramSet ? { [OPTION_PARAM_SET]: paramSet } : {}),
        }),
        ascii("x"),
      );
      return result.fields?.find((f) => f.label === "Construction")?.value;
    };
    // Blowfish's key size is a range, so naming it is the honest thing -- 8 bytes is 64-bit Blowfish.
    expect(await label("blowfish", "11".repeat(8))).toBe("Blowfish-64-ECB");
    expect(await label("present", "11".repeat(10))).toBe("PRESENT-80-ECB");
    /**
     * A parameter set names itself, and that is the point of the change.
     *
     * `Speck-96-ECB` would name the key and lose the block -- and the block is the half with a
     * practical consequence. So the label is the set's own, which is also what the paper calls it.
     */
    expect(await label("speck", "11".repeat(16), "128-128")).toBe("Speck128/128-ECB");
    expect(await label("simon", "11".repeat(16), "128-128")).toBe("Simon128/128-ECB");
    expect(await label("speck", "11".repeat(8), "32-64")).toBe("Speck32/64-ECB");
    expect(await label("simon", "11".repeat(18), "96-144")).toBe("Simon96/144-ECB");
  });

  it("gives every parameter set a distinct construction name", async () => {
    // The property the old twenty-tool test asserted across tools, now asserted across sets --
    // twenty labels, no duplicates, none of them the bare tool name.
    const seen = new Set<string>();
    for (const toolId of ["speck", "simon"] as const) {
      const tool = requireCipherTool(toolId);
      for (const set of tool.paramSets!) {
        const result = await run(
          toolId,
          keyed("11".repeat(set.keyLength), undefined, {
            [OPTION_MODE]: "ecb",
            [OPTION_PARAM_SET]: set.id,
          }),
          ascii("x"),
        );
        const name = result.fields?.find((f) => f.label === "Construction")?.value;
        expect(name, `${toolId}/${set.id}`).toBe(`${set.label}-ECB`);
        expect(seen.has(name!), `${name} is a duplicate`).toBe(false);
        seen.add(name!);
      }
    }
    expect(seen.size).toBe(20);
  });

  it("refuses a key the selected parameter set does not take, and names the set", () => {
    /**
     * The catalogue declares the *union* of the ten sets' key lengths, so a 32-byte key is a legal
     * value for the control and has to be refused by the resolver instead -- with a message naming
     * the set rather than listing all seven legal lengths.
     */
    const result = resolveCipher(
      specFor(
        "speck",
        keyed("11".repeat(32), "22".repeat(4), {
          [OPTION_MODE]: "cbc",
          [OPTION_PARAM_SET]: "32-64",
        }),
      ),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.problem).toContain("Speck32/64");
    expect(result.problem).toContain("8 bytes");
  });

  it("takes the IV length from the parameter set, not from the tool", () => {
    /**
     * The reason `ResolvedCipher.blockSize` exists. One Speck tool spans 4-, 6-, 8-, 12- and 16-byte
     * blocks, and CBC's IV is one block of whichever is selected -- reading the tool's own
     * `block.size` would ask for sixteen bytes at every set and produce something nothing decrypts.
     */
    for (const [setId, expected] of [
      ["32-64", 4],
      ["48-96", 6],
      ["64-128", 8],
      ["96-144", 12],
      ["128-256", 16],
    ] as const) {
      expect(requiredNonceLength("speck", getAesMode("cbc"), setId), setId).toBe(expected);
      expect(requiredNonceLength("simon", getAesMode("cbc"), setId), setId).toBe(expected);
    }
    // And with no set named, the tool's declared default answers.
    expect(requiredNonceLength("speck", getAesMode("cbc"))).toBe(16);
  });
});

describe("Anubis and SAFER+, the two LibTomCrypt unblocked", () => {
  /**
   * `tests/algos-legacy-ciphers.test.ts` owns the byte-level question -- 28 Anubis vectors across seven
   * key lengths and three SAFER+ ones, plus the derivation assertions. What is checked here is the
   * family wiring, and for Anubis one thing more: the variant control has to *reach* the binding.
   *
   * That is not belt-and-braces. A control that renders and does nothing is this repo's most-repeated
   * defect, and Anubis's variant is the fifth per-tool option in this family -- so the assertion below
   * runs both values and requires different ciphertext, which is the only thing that could show it.
   */
  it("reproduces each published vector through the tool", async () => {
    const cases = [
      {
        id: "anubis",
        key: "80000000000000000000000000000000",
        plaintext: "00000000000000000000000000000000",
        expected: "b835bdc334829d8371bfa371e4b3c4fd",
        note: "the default tweaked variant",
      },
      {
        id: "saferp",
        key: "2923be84e16cd6ae529049f1f1bbe9eb",
        plaintext: "b3a6db3c870c3e99245e0d1c06b747de",
        expected: "e01fb60a0cff54467f0d59f90939a5dc",
        note: "the 128-bit key, which is eight rounds",
      },
    ];
    for (const { id, key, plaintext, expected, note } of cases) {
      const result = await run(
        id,
        keyed(key, undefined, { [OPTION_MODE]: "ecb" }),
        Uint8Array.from(plaintext.match(/../g)!.map((p) => parseInt(p, 16))),
      );
      expect(result.error, `${id} (${note}) reported: ${result.error}`).toBeUndefined();
      expect(encodeHex(result.bytes!).slice(0, expected.length), `${id} (${note})`).toBe(
        expected,
      );
    }
  });

  it("wires Anubis's variant control through to the cipher", async () => {
    const encrypt = async (variant: string) => {
      const result = await run(
        "anubis",
        keyed("80000000000000000000000000000000", undefined, {
          [OPTION_MODE]: "ecb",
          [OPTION_ANUBIS_VARIANT]: variant,
        }),
        new Uint8Array(16),
      );
      expect(result.error, variant).toBeUndefined();
      return encodeHex(result.bytes!).slice(0, 32);
    };
    // Both LibTomCrypt self-test values for the same key and plaintext, one per variant.
    expect(await encrypt("tweaked")).toBe("b835bdc334829d8371bfa371e4b3c4fd");
    expect(await encrypt("original")).toBe("f06860fc6730e818f132c78af4132afe");
  });

  it("gives the variant control to Anubis and no other cipher", () => {
    expect(cipherCatalogueFor("anubis").options.map((o) => o.id)).toContain(
      OPTION_ANUBIS_VARIANT,
    );
    for (const meta of CIPHER_TOOLS) {
      if (meta.id === "anubis") continue;
      expect(
        cipherCatalogueFor(meta.id).options.map((o) => o.id),
        `${meta.id} should not offer the Anubis variant`,
      ).not.toContain(OPTION_ANUBIS_VARIANT);
    }
  });
});

describe("the three LS-designs", () => {
  /**
   * `tests/algos-ls-designs.test.ts` owns the byte-level question. What is checked here is the family
   * wiring plus one thing that only exists at this layer: **`C004` must fire for Robin and not for the
   * other two.** Robin is the only cipher added in these four waves whose posture is `broken`, and it is
   * broken for an unusual reason -- an invariant-subspace attack on the *full* cipher rather than a
   * reduced-round result -- so the lint rule reading the metadata is worth pinning.
   */
  it("reproduces each published vector through the tool", async () => {
    const cases = LS_VECTORS.map((v) => ({ id: v.design, ...v }));
    expect(cases).toHaveLength(3);
    for (const v of cases) {
      const result = await run(
        v.id,
        keyed(v.key, undefined, { [OPTION_MODE]: "ecb" }),
        Uint8Array.from(v.plaintext.match(/../g)!.map((p) => parseInt(p, 16))),
      );
      expect(encodeHex(result.bytes!).slice(0, v.ciphertext.length), v.id).toBe(v.ciphertext);
    }
  });

  it("marks Robin broken and the other two not, which is a judgement not a pattern", () => {
    /**
     * `C004` is already asserted across every tool from the metadata by the lint-rule test above, so this
     * one is about the *metadata* rather than the rule. Robin's invariant-subspace attack is on the full
     * cipher and gives weak-key classes, which is what `broken` means here; Robin* is the authors' own fix
     * and Fantomas was never affected. Marking all three broken would be as wrong as marking none, and
     * they are near enough that a future edit could easily do either.
     */
    expect(requireCipherTool("robin").security).toBe("broken");
    expect(requireCipherTool("robinstar").security).toBe("legacy");
    expect(requireCipherTool("fantomas").security).toBe("legacy");
  });

  it("round-trips every mode all three advertise", async () => {
    for (const id of ["robin", "robinstar", "fantomas"] as const) {
      const tool = requireCipherTool(id);
      for (const modeId of tool.block!.modes) {
        const mode = getAesMode(modeId);
        const options = keyed(
          "11".repeat(seedKeyLength(id)),
          requiredNonceLength(id, mode) > 0
            ? "22".repeat(requiredNonceLength(id, mode))
            : undefined,
          { [OPTION_MODE]: modeId },
        );
        const message = ascii("a message of some length");
        const sealed = await run(id, options, message);
        const opened = await run(
          id,
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          sealed.bytes!,
        );
        expect(encodeHex(opened.bytes!), `${id}/${modeId}`).toBe(encodeHex(message));
      }
    }
  });
});

describe("RoadRunneR and Lilliput", () => {
  /**
   * `tests/algos-lightweight-block4.test.ts` owns the byte-level question, in both directions. What is
   * checked here is the family wiring -- and the vectors are *imported* from the same fixture that test
   * reads rather than restated, which is the arrangement CHAM, Simeck and SKINNY were switched to after a
   * hand-written tool-level vector turned out to have a wrong key, plaintext and ciphertext all three.
   *
   * RoadRunneR is the fourth cipher pair here registered as two tools rather than one with a parameter
   * set, after SPARX, RECTANGLE and the Simon/Speck merge went the other way. The reason is the same one
   * SPARX has: the two are named separately in the paper and each has its own published vectors, and the
   * key handling differs by more than a length -- see `keyNoteFor`.
   */
  it("reproduces every published vector through the tool", async () => {
    expect(LIGHTWEIGHT_BLOCK4_VECTORS).toHaveLength(5);
    for (const v of LIGHTWEIGHT_BLOCK4_VECTORS) {
      const result = await run(
        v.tool,
        keyed(v.key, undefined, { [OPTION_MODE]: "ecb" }),
        Uint8Array.from(v.plaintext.match(/../g)!.map((p) => parseInt(p, 16))),
      );
      expect(encodeHex(result.bytes!).slice(0, v.ciphertext.length), `${v.tool} ${v.key}`).toBe(
        v.ciphertext,
      );
    }
  });

  it("covers all three tools", () => {
    expect(new Set(LIGHTWEIGHT_BLOCK4_VECTORS.map((v) => v.tool))).toEqual(
      new Set(["roadrunner80", "roadrunner128", "lilliput"]),
    );
  });

  it("gives the two RoadRunneR tools different key lengths and the same block", () => {
    // The pair differs in key length *and* in how the key is read, which is why it is two tools.
    expect(seedKeyLength("roadrunner80")).toBe(10);
    expect(seedKeyLength("roadrunner128")).toBe(16);
    for (const id of ["roadrunner80", "roadrunner128", "lilliput"] as const) {
      expect(requireCipherTool(id).block!.size, id).toBe(8);
    }
  });

  it("round-trips every mode all three advertise", async () => {
    for (const id of ["roadrunner80", "roadrunner128", "lilliput"] as const) {
      const tool = requireCipherTool(id);
      for (const modeId of tool.block!.modes) {
        const mode = getAesMode(modeId);
        const options = keyed(
          "11".repeat(seedKeyLength(id)),
          requiredNonceLength(id, mode) > 0
            ? "22".repeat(requiredNonceLength(id, mode))
            : undefined,
          { [OPTION_MODE]: modeId },
        );
        const message = ascii("a message of some length");
        const sealed = await run(id, options, message);
        const opened = await run(
          id,
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          sealed.bytes!,
        );
        expect(encodeHex(opened.bytes!), `${id}/${modeId}`).toBe(encodeHex(message));
      }
    }
  });

  it("refuses the other RoadRunneR variant's key length", () => {
    const refused = resolveCipher(
      specFor("roadrunner80", keyed("11".repeat(16), undefined, { [OPTION_MODE]: "ecb" })),
    );
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.problem).toMatch(/10/);
  });
});

describe("PRINCE, LBlock, RECTANGLE, PRIDE and Piccolo", () => {
  /**
   * `tests/algos-lightweight-block3.test.ts` owns the byte-level question -- twelve published vectors in
   * both directions plus four derivation checks. What is checked here is the family wiring, and one thing
   * more: **RECTANGLE is the first parameter-set tool whose block size does *not* move with the set.**
   * Simon, Speck, SKINNY, CHAM and Simeck all change block size across their sets; RECTANGLE's stays at
   * 64 bits and only the key length moves, so this is the case that would catch a resolver assuming the
   * two always travel together.
   */
  it("reproduces a published vector through the tool", async () => {
    const cases: readonly {
      id: string;
      key: string;
      plaintext: string;
      expected: string;
      set?: string;
    }[] = [
      {
        id: "prince",
        key: "ffeeddccbbaa99887766554433221100",
        plaintext: "efcdab8967452301",
        expected: "29ebb59fb1ea67fc",
      },
      {
        id: "lblock",
        key: "dcfeefcdab8967452301",
        plaintext: "efcdab8967452301",
        expected: "260ceeebd879714b",
      },
      {
        id: "pride",
        key: "00".repeat(16),
        plaintext: "00".repeat(8),
        expected: "82b4109fcc70bd1f",
      },
      {
        id: "piccolo",
        key: "11003322554477669988",
        plaintext: "efcdab8967452301",
        expected: "5640f83599ff2b8d",
      },
      {
        id: "rectangle",
        key: "ff".repeat(10),
        plaintext: "ff".repeat(8),
        expected: "9945aa34ae3d0112",
        set: "64-80",
      },
      {
        id: "rectangle",
        key: "ff".repeat(16),
        plaintext: "ff".repeat(8),
        expected: "e83eefee4a157a46",
        set: "64-128",
      },
    ];
    for (const { id, key, plaintext, expected, set } of cases) {
      const result = await run(
        id,
        keyed(key, undefined, {
          [OPTION_MODE]: "ecb",
          ...(set ? { [OPTION_PARAM_SET]: set } : {}),
        }),
        Uint8Array.from(plaintext.match(/../g)!.map((p) => parseInt(p, 16))),
      );
      expect(
        encodeHex(result.bytes!).slice(0, expected.length),
        `${id}${set ? "/" + set : ""}`,
      ).toBe(expected);
    }
    expect(cases).toHaveLength(6);
  });

  it("keeps RECTANGLE's block at 64 bits across both sets, and moves only the key", async () => {
    const tool = requireCipherTool("rectangle");
    for (const set of tool.paramSets!) {
      expect(set.blockSize, set.id).toBe(8);
      const result = await run(
        "rectangle",
        keyed("11".repeat(set.keyLength), "22".repeat(8), {
          [OPTION_MODE]: "cbc",
          [OPTION_PARAM_SET]: set.id,
        }),
        ascii("a message of some length"),
      );
      expect(result.bytes, set.id).toBeDefined();
    }
    // And the two sets are different ciphers, not one taking a longer key.
    const names = new Set<string>();
    for (const set of tool.paramSets!) {
      const result = await run(
        "rectangle",
        keyed("11".repeat(set.keyLength), undefined, {
          [OPTION_MODE]: "ecb",
          [OPTION_PARAM_SET]: set.id,
        }),
        ascii("x"),
      );
      names.add(encodeHex(result.bytes!));
    }
    expect(names.size).toBe(2);
  });

  it("round-trips every mode each one advertises", async () => {
    for (const id of ["prince", "lblock", "pride", "piccolo", "rectangle"] as const) {
      const tool = requireCipherTool(id);
      for (const modeId of tool.block!.modes) {
        const mode = getAesMode(modeId);
        const options = keyed(
          "11".repeat(seedKeyLength(id)),
          requiredNonceLength(id, mode) > 0
            ? "22".repeat(requiredNonceLength(id, mode))
            : undefined,
          { [OPTION_MODE]: modeId },
        );
        const message = ascii("a message of some length");
        const sealed = await run(id, options, message);
        const opened = await run(
          id,
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          sealed.bytes!,
        );
        expect(encodeHex(opened.bytes!), `${id}/${modeId}`).toBe(encodeHex(message));
      }
    }
  });
});

describe("SPARX, Chaskey-LTS, TWINE and LED", () => {
  /**
   * `tests/algos-lightweight-block2.test.ts` owns the byte-level question. What is checked here is that
   * each one's single published vector survives the option catalogue, the key rules, the resolver and
   * compute -- which is the layer this file exists for, and the only layer a one-vector cipher has left
   * to get wrong once the algorithm is verified.
   *
   * The values are written out here rather than imported, and that is a deliberate exception: these four
   * have no fixture file, because one vector apiece does not earn one. They are the same five rows the
   * algorithm test asserts, and a test asserts the two lists agree in count so a future divergence
   * shows up.
   */
  const cases: readonly { id: string; key: string; plaintext: string; expected: string }[] = [
    {
      id: "sparx",
      key: "00".repeat(16),
      plaintext: "00".repeat(8),
      expected: "b423aeb5d405a70d",
    },
    {
      id: "sparx",
      key: "ff".repeat(16),
      plaintext: "00".repeat(8),
      expected: "be25d728346929ab",
    },
    {
      id: "chaskeylts",
      key: "5609e9685f58e32940ecec98c522982f",
      plaintext: "b8232826fd5e405e69a301a978ea7ad8",
      expected: "d5608d4da2bf347babf8772fdfedde07",
    },
    {
      id: "twine",
      key: "00112233445566778899",
      plaintext: "1032547698badcfe",
      expected: "c7f1f0081bfdc982",
    },
    {
      id: "led",
      key: "0123456789abcdeffedc",
      plaintext: "0123456789abcdef",
      expected: "a9625a9c59fcb942",
    },
  ];

  it("reproduces each published vector through the tool", async () => {
    for (const { id, key, plaintext, expected } of cases) {
      const result = await run(
        id,
        keyed(key, undefined, { [OPTION_MODE]: "ecb" }),
        Uint8Array.from(plaintext.match(/../g)!.map((p) => parseInt(p, 16))),
      );
      expect(encodeHex(result.bytes!).slice(0, expected.length), id).toBe(expected);
    }
    expect(cases).toHaveLength(5);
    expect(new Set(cases.map((c) => c.id)).size).toBe(4);
  });

  it("round-trips every mode each one advertises", async () => {
    /**
     * The four have three different block sizes between them -- 8, 16 and 8 -- so this is also what says
     * the IV length each mode asks for came from the right tool rather than from a neighbour.
     */
    for (const id of ["sparx", "chaskeylts", "twine", "led"] as const) {
      const tool = requireCipherTool(id);
      for (const modeId of tool.block!.modes) {
        const mode = getAesMode(modeId);
        const options = keyed(
          "11".repeat(seedKeyLength(id)),
          requiredNonceLength(id, mode) > 0
            ? "22".repeat(requiredNonceLength(id, mode))
            : undefined,
          { [OPTION_MODE]: modeId },
        );
        const message = ascii("a message of some length");
        const sealed = await run(id, options, message);
        const opened = await run(
          id,
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          sealed.bytes!,
        );
        expect(encodeHex(opened.bytes!), `${id}/${modeId}`).toBe(encodeHex(message));
      }
    }
  });
});

describe("CHAM, Simeck and SKINNY", () => {
  /**
   * `tests/algos-lightweight-block.test.ts` owns the byte-level question -- 30 CHAM vectors, 20 Simeck
   * and SKINNY's two plus the cross-check against Romulus's own SKINNY. What is checked here is the
   * family wiring, and for all three the interesting part is the same: **the parameter set decides the
   * block size**, so this is the fourth, fifth and sixth tool where reading `tool.block.size` in a path
   * that holds a spec would be a bug.
   *
   * The vectors are read out of the shared fixture rather than restated here. That is not tidiness --
   * writing one out by hand went wrong on the first attempt, which is the third time in this repo, so
   * the rule is now that a tool-level test imports the same rows the algorithm-level one asserts.
   */
  const specificationVectors = [
    ...CHAM_VECTORS.map((v) => ({ id: "cham", ...v })),
    ...SIMECK_VECTORS.map((v) => ({ id: "simeck", ...v })),
    ...SKINNY_VECTORS.map((v) => ({ id: "skinny", ...v })),
  ].filter((v) => v.paper);

  it("reproduces every specification vector through the tool", async () => {
    // Three CHAM sets, two Simeck, two SKINNY -- one published value per set that has one.
    expect(specificationVectors).toHaveLength(8);
    for (const v of specificationVectors) {
      const result = await run(
        v.id,
        keyed(v.key, undefined, { [OPTION_MODE]: "ecb", [OPTION_PARAM_SET]: v.variant }),
        Uint8Array.from(v.plaintext.match(/../g)!.map((p) => parseInt(p, 16))),
      );
      expect(
        encodeHex(result.bytes!).slice(0, v.ciphertext.length),
        `${v.id}/${v.variant}`,
      ).toBe(v.ciphertext);
    }
  });

  it("gives every parameter set a distinct construction name", async () => {
    const seen = new Set<string>();
    for (const toolId of ["cham", "simeck", "skinny"] as const) {
      const tool = requireCipherTool(toolId);
      for (const set of tool.paramSets!) {
        const result = await run(
          toolId,
          keyed("11".repeat(set.keyLength), undefined, {
            [OPTION_MODE]: "ecb",
            [OPTION_PARAM_SET]: set.id,
          }),
          ascii("x"),
        );
        const name = result.fields?.find((f) => f.label === "Construction")?.value;
        expect(name, `${toolId}/${set.id}`).toBe(`${set.label}-ECB`);
        expect(seen.has(name!), `${name} is a duplicate`).toBe(false);
        seen.add(name!);
      }
    }
    // Three sets for CHAM, two for Simeck, six for SKINNY.
    expect(seen.size).toBe(12);
  });

  it("sizes the IV from the selected set rather than the tool", async () => {
    /**
     * CHAM-64/128 has an eight-byte block and CHAM-128/128 a sixteen-byte one, so a CBC IV taken from
     * `tool.block.size` would be right for the default and wrong for the other -- the exact bug the
     * `paramSets` comment in `tool-meta.ts` exists to prevent, now with three more tools able to hit it.
     */
    for (const [set, ivBytes] of [
      ["64-128", 8],
      ["128-128", 16],
    ] as const) {
      const result = await run(
        "cham",
        keyed("11".repeat(16), "22".repeat(ivBytes), {
          [OPTION_MODE]: "cbc",
          [OPTION_PARAM_SET]: set,
        }),
        ascii("sixteen bytes ok"),
      );
      expect(result.bytes, `${set} with a ${ivBytes}-byte IV`).toBeDefined();
    }

    // And the wrong length is refused, naming the block size the set actually has. Resolved directly
    // rather than through `run`, which asserts success itself.
    const refused = resolveCipher(
      specFor(
        "cham",
        keyed("11".repeat(16), "22".repeat(16), {
          [OPTION_MODE]: "cbc",
          [OPTION_PARAM_SET]: "64-128",
        }),
      ),
    );
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.problem).toMatch(/exactly 8 bytes/);
  });
});

describe("the seven ciphers whose specifications were fetched", () => {
  /**
   * RC2, IDEA, CAST5, SEED, Twofish, Serpent and Kuznyechik, through the tool.
   *
   * `tests/algos-classic.test.ts` owns the byte-level question -- every one of these reproduces its
   * published vectors there, and every table in them was parsed out of a specification by script.
   * What is checked here is the family wiring: that the vector survives the option catalogue, the key
   * rules, the resolver and compute, which is where this family's bugs have always been.
   */
  const cases: readonly {
    readonly id: string;
    readonly key: string;
    readonly plaintext: string;
    readonly expected: string;
  }[] = [
    // RFC 2268's third vector. The effective key length defaults to the key's own 64 bits.
    {
      id: "rc2",
      key: "3000000000000000",
      plaintext: "1000000000000001",
      expected: "30649edf9be7d2c2",
    },
    {
      id: "idea",
      key: "00112233445566778899aabbccddeeff",
      plaintext: "0001020304050607",
      expected: "ed732271a7b39f47",
    },
    // RFC 2144's 128-bit vector, which exercises the sixteen-round path.
    {
      id: "cast5",
      key: "0123456712345678234567893456789a",
      plaintext: "0123456789abcdef",
      expected: "238b4fe5847e44b2",
    },
    {
      id: "seed",
      key: "00000000000000000000000000000000",
      plaintext: "000102030405060708090a0b0c0d0e0f",
      expected: "5ebac6e0054e166819aff1cc6d346cdb",
    },
    {
      id: "twofish",
      key: "000102030405060708090a0b0c0d0e0f",
      plaintext: "000102030405060708090a0b0c0d0e0f",
      expected: "9fb63337151be9c71306d159ea7afaa4",
    },
    {
      id: "serpent",
      key: "d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9",
      plaintext: "d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9",
      expected: "20ea07f19c8e93fda30f6b822ad5d486",
    },
    {
      id: "kuznyechik",
      key: "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
      plaintext: "1122334455667700ffeeddccbbaa9988",
      expected: "7f679d90bebc24305a468d42b9d4edcd",
    },
  ];

  it("reproduces each published vector through the tool", async () => {
    for (const { id, key, plaintext, expected } of cases) {
      const result = await run(
        id,
        keyed(key, undefined, { [OPTION_MODE]: "ecb" }),
        fromHex(plaintext),
      );
      // ECB pads with a whole extra block, so the leading block is the one to compare.
      expect(encodeHex(result.bytes!).slice(0, expected.length), id).toBe(expected);
    }
  });

  it("round-trips each of them through CBC at a partial-block length", async () => {
    const message = ascii("nineteen bytes here");
    expect(message.length).toBe(19);
    for (const { id, key } of cases) {
      const size = requireCipherTool(id).block!.size;
      const options = keyed(key, "77".repeat(size), { [OPTION_MODE]: "cbc" });
      const sealed = await run(id, options, message);
      const opened = await run(
        id,
        { ...options, [OPTION_DIRECTION]: "decrypt" },
        sealed.bytes!,
      );
      expect(encodeHex(opened.bytes!), id).toBe(encodeHex(message));
    }
  });

  it("names each construction after itself, with its key size where that varies", async () => {
    const label = async (id: string, key: string) => {
      const result = await run(id, keyed(key, undefined, { [OPTION_MODE]: "ecb" }), ascii("x"));
      return result.fields?.find((f) => f.label === "Construction")?.value;
    };
    expect(await label("twofish", "11".repeat(24))).toBe("Twofish-192-ECB");
    expect(await label("serpent", "11".repeat(16))).toBe("Serpent-128-ECB");
    // One key size each, so there is nothing to name.
    expect(await label("kuznyechik", "11".repeat(32))).toBe("Kuznyechik-ECB");
    expect(await label("seed", "11".repeat(16))).toBe("SEED-ECB");
    expect(await label("idea", "11".repeat(16))).toBe("IDEA-ECB");
    // CAST5 has twelve key sizes and RC2 a range, so both name theirs.
    expect(await label("cast5", "11".repeat(10))).toBe("CAST5-80-ECB");
    expect(await label("rc2", "11".repeat(8))).toBe("RC2-64-ECB");
  });

  it("offers RC2's effective key length, and gives no other cipher the control", () => {
    /**
     * The only option in this family that belongs to a single cipher. It is not gated with
     * `availableOn` -- the axis is the *tool* rather than a variant of one -- so what has to be true
     * is that RC2's catalogue has it and no other cipher's does.
     */
    expect(cipherCatalogueFor("rc2").options.map((o) => o.id)).toContain(
      OPTION_EFFECTIVE_KEY_BITS,
    );
    for (const meta of CIPHER_TOOLS) {
      if (meta.id === "rc2") continue;
      expect(
        cipherCatalogueFor(meta.id).options.map((o) => o.id),
        meta.id,
      ).not.toContain(OPTION_EFFECTIVE_KEY_BITS);
    }
  });

  it("applies RC2's effective key length, and defaults it the way OpenSSL does", async () => {
    /**
     * RFC 2268's sixth and seventh vectors: one key, two effective lengths, unrelated output. This is
     * the parameter that makes two tools disagree about RC2, so the default matters as much as the
     * control -- an omitted value must mean the key's own length in bits, which is what OpenSSL uses.
     */
    const key = "88bca90e90875a7f0f79c384627bafb2";
    const zeros = fromHex("0000000000000000");
    const at = async (bits?: number) => {
      const options = keyed(key, undefined, {
        [OPTION_MODE]: "ecb",
        ...(bits === undefined ? {} : { [OPTION_EFFECTIVE_KEY_BITS]: bits }),
      });
      const result = await run("rc2", options, zeros);
      return encodeHex(result.bytes!).slice(0, 16);
    };
    expect(await at(64)).toBe("1a807d272bbe5db1");
    expect(await at(128)).toBe("2269552ab0f85ca6");
    expect(await at()).toBe("2269552ab0f85ca6");
    // A value a share link could carry but the cipher would refuse falls back rather than throwing.
    expect(await at(0)).toBe("2269552ab0f85ca6");
  });

  it("accepts RC2's whole key range and CAST5's twelve key sizes", () => {
    for (const bytes of [1, 8, 128]) {
      const result = resolveCipher(
        specFor("rc2", keyed("11".repeat(bytes), "22".repeat(8), { [OPTION_MODE]: "cbc" })),
      );
      expect(result.ok, `rc2 ${bytes} bytes`).toBe(true);
    }
    expect(
      resolveCipher(
        specFor("rc2", keyed("11".repeat(129), "22".repeat(8), { [OPTION_MODE]: "cbc" })),
      ).ok,
    ).toBe(false);

    for (let bytes = 5; bytes <= 16; bytes++) {
      const result = resolveCipher(
        specFor("cast5", keyed("11".repeat(bytes), "22".repeat(8), { [OPTION_MODE]: "cbc" })),
      );
      expect(result.ok, `cast5 ${bytes} bytes`).toBe(true);
    }
    expect(
      resolveCipher(
        specFor("cast5", keyed("11".repeat(4), "22".repeat(8), { [OPTION_MODE]: "cbc" })),
      ).ok,
    ).toBe(false);
  });

  it("says which of them are sound and which are only for reading old data", () => {
    /**
     * The postures are load-bearing: `C004` fires on `broken`, and the sidebar badge shows the rest.
     * Twofish, Serpent and Kuznyechik are unbroken at full rounds and marked `modern`; the four legacy
     * ciphers are `legacy` rather than `broken`, because none of them has a demonstrated break -- RC2
     * included, whose weakness is a deliberately short effective key rather than a flaw in the cipher.
     */
    for (const id of ["twofish", "serpent", "kuznyechik"]) {
      expect(requireCipherTool(id).security, id).toBe("modern");
    }
    for (const id of ["seed", "cast5", "idea", "rc2"]) {
      expect(requireCipherTool(id).security, id).toBe("legacy");
    }
    /**
     * RC2's weakness is its effective key length, which used to be asserted here through its
     * `securityNote`. Nothing replaces the assertion because nothing needs to: "the effective key
     * length" already has a test that reads the catalogue rather than prose -- `OPTION_EFFECTIVE_KEY_BITS`
     * is required to be in RC2's options, and the ciphertext is checked at three values of it.
     */
  });
});

/**
 * The seventh batch: two AES finalists, RC5, Threefish and the three legacy 64-bit ciphers.
 *
 * Every one of these has its arithmetic checked exhaustively in `tests/algos-blockciphers-2.test.ts`
 * -- 13 RC5 vectors across six round counts, 6 for RC6, Threefish at three widths with a non-zero
 * tweak, and both directions everywhere. What this block adds is the *wiring*: that the published
 * value survives the trip through the option catalogue, the resolver and the compute path, which is
 * where a key that is silently truncated, a parameter set that is ignored, or a per-tool option that
 * reaches nothing would show up. Those are not hypothetical -- AEGIS's tag length was inert in the
 * app with a green suite, and the Salsa tools once inherited RC4's key rules.
 *
 * None has an oracle. OpenSSL implemented none of them -- CAST5 is in its legacy provider and
 * CAST-256 never was -- so these came from Bouncy Castle's own test suite, fetched and parsed by
 * script rather than recalled. That distinction has already earned its keep here once: an earlier
 * attempt at IDEA matched a *remembered* vector for five bytes and was abandoned, and it was the
 * remembered vector that turned out to be wrong.
 */
describe("the two AES finalists, RC5, Threefish and the legacy 64-bit ciphers", () => {
  const cases: readonly {
    id: string;
    key: string;
    plaintext: string;
    expected: string;
    options?: Record<string, string | number>;
    note: string;
  }[] = [
    {
      id: "cast6",
      key: "2342bb9efa38542c0af75647f29f615d",
      plaintext: "00000000000000000000000000000000",
      expected: "c842a08972b43d20836c91d1b7530f6b",
      note: "RFC 2612, 128-bit key",
    },
    {
      id: "cast6",
      key: "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
      plaintext: "00000000000000000000000000000000",
      expected: "4f6a2038286897b9c9870136553317fa",
      note: "RFC 2612, 256-bit key -- the schedule zero-pads shorter ones, so both ends matter",
    },
    {
      id: "rc6",
      key: "00000000000000000000000000000000",
      plaintext: "80000000000000000000000000000000",
      expected: "f71f65e7b80c0c6966fee607984b5cdf",
      note: "the AES submission's one-bit plaintext, where a lost multiply precision shows",
    },
    {
      id: "rc6",
      key: "1000000000000000000000000000000000000000000000000000000000000000",
      plaintext: "00000000000000000000000000000000",
      expected: "11395d4bfe4c8258979ee2bf2d24dff4",
      note: "256-bit key",
    },
    {
      /**
       * The round count travelling through the option, which is the whole reason RC5 has one.
       *
       * Twelve and sixteen rounds over the same key and block give completely unrelated ciphertext, so
       * these two cases together prove the control reaches the cipher. A single case at the default
       * would pass with the option wired to nothing.
       */
      id: "rc5",
      key: "01020304",
      plaintext: "ffffffffffffffff",
      expected: "fc586f92f7080934",
      options: { rc5Rounds: 12 },
      note: "RC5-32/12/4",
    },
    {
      id: "rc5",
      key: "01020304",
      plaintext: "ffffffffffffffff",
      expected: "cf270ef9717ff7c4",
      options: { rc5Rounds: 16 },
      note: "RC5-32/16/4 -- same key, same block, different function",
    },
    {
      id: "rc5",
      key: "00",
      plaintext: "0000000000000000",
      expected: "7a7bba4d79111d1e",
      options: { rc5Rounds: 0 },
      note: "zero rounds is legal and has a published value",
    },
    {
      id: "tea",
      key: "0123456712345678234567893456789A",
      plaintext: "0102030405060708",
      expected: "773dc179878a81c0",
      note: "TEA -- one line different from XTEA below, same key and block",
    },
    {
      id: "xtea",
      key: "0123456712345678234567893456789A",
      plaintext: "0102030405060708",
      expected: "8c67155b2ef91ead",
      note: "XTEA -- and the two must not agree",
    },
    {
      id: "skipjack",
      key: "00998877665544332211",
      plaintext: "33221100ddccbbaa",
      expected: "2587cae27a12d300",
      note: "the specification's only published vector",
    },
    {
      id: "threefish",
      key: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
      plaintext: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
      expected: "e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df",
      options: { paramSet: "256-256", tweak: "000102030405060708090a0b0c0d0e0f" },
      note: "Threefish-256 with a non-zero tweak, which is the case that proves the tweak arrives",
    },
    {
      id: "threefish",
      key:
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
      plaintext:
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
        "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0",
      expected:
        "e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779" +
        "272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d",
      options: { paramSet: "512-512", tweak: "000102030405060708090a0b0c0d0e0f" },
      note: "Threefish-512, the default width",
    },
  ];

  it("reproduces each published vector through the tool", async () => {
    for (const { id, key, plaintext, expected, options, note } of cases) {
      const result = await run(
        id,
        keyed(key, undefined, { [OPTION_MODE]: "ecb", ...(options ?? {}) }),
        fromHex(plaintext),
      );
      expect(result.error, `${id} (${note}) reported: ${result.error}`).toBeUndefined();
      // ECB pads, so the first block is the vector and what follows is the padding block.
      expect(encodeHex(result.bytes!).slice(0, expected.length), `${id} (${note})`).toBe(
        expected,
      );
    }
    // Guards the guard: twelve cases over seven tools, and a truncated list would pass silently.
    expect(cases).toHaveLength(12);
    expect(new Set(cases.map((c) => c.id)).size).toBe(7);
  });

  /**
   * Threefish's tweak is an input, so the same key and block under two tweaks must differ.
   *
   * Asserted through the tool rather than only in the algos test, because the failure mode here is a
   * control that renders and reaches nothing -- which is invisible to a typecheck, to the algos test,
   * and to any round trip.
   */
  it("makes Threefish's tweak change the ciphertext", async () => {
    const key = "11".repeat(64);
    const block = fromHex("22".repeat(64));
    const withTweak = await run(
      "threefish",
      keyed(key, undefined, {
        [OPTION_MODE]: "ecb",
        tweak: "000102030405060708090a0b0c0d0e0f",
      }),
      block,
    );
    const without = await run(
      "threefish",
      keyed(key, undefined, { [OPTION_MODE]: "ecb" }),
      block,
    );
    expect(withTweak.error).toBeUndefined();
    expect(without.error).toBeUndefined();
    expect(encodeHex(withTweak.bytes!)).not.toBe(encodeHex(without.bytes!));
  });

  /** A partly filled tweak is refused rather than zero-extended, and the message names the lengths. */
  it("refuses a tweak that is neither empty nor 16 bytes", () => {
    const result = resolveCipher(
      specFor(
        "threefish",
        keyed("11".repeat(64), undefined, { [OPTION_MODE]: "ecb", tweak: "0001020304" }),
      ),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.problem).toMatch(/0 or 16|16 bytes/);
  });

  /**
   * The two per-tool controls belong to one cipher each, and to no other.
   *
   * The same assertion RC2's effective key length already has, extended -- because this family now has
   * three such options, and the failure they guard against is a control appearing on a tool it means
   * nothing for. Read off the catalogue rather than a list of ids.
   */
  it("gives the round count to RC5 alone and the tweak to Threefish alone", () => {
    for (const meta of CIPHER_TOOLS) {
      const ids = new Set(cipherCatalogueFor(meta.id).options.map((o) => o.id));
      expect(ids.has("rc5Rounds"), `${meta.id}/rounds`).toBe(meta.id === "rc5");
      expect(ids.has("tweak"), `${meta.id}/tweak`).toBe(meta.id === "threefish");
    }
  });
});

/**
 * The eighth batch: Noekeon, LEA, SHACAL-2 and GOST 28147-89, through the tool.
 *
 * `tests/algos-phase2-ciphers.test.ts` owns the arithmetic -- thirteen assertions including all three
 * of LEA's key schedules and SHACAL-2's derived round constants. What this adds is the wiring: that the
 * published value survives the option catalogue, the resolver and the compute path.
 *
 * Two of the four needed nothing new in the resolver. The other two are why this block exists: SHACAL-2
 * has a key *range* rather than a list, which is the second cipher here to do that after Blowfish, and
 * GOST 28147-89 has an S-box control that is a genuine parameter of the cipher rather than a preference.
 * A control that renders and reaches nothing is this repo's most-repeated defect, so both are asserted.
 */
/**
 * Phase 2b: the six eSTREAM-era stream ciphers and Kalyna, through the family rather than the algorithm.
 *
 * `tests/algos-phase2-stream.test.ts` and `tests/algos-kalyna.test.ts` already check the implementations
 * against their designers' published values. What is checked here is the *wiring*: that a published
 * vector survives the trip through the option catalogue, the resolver and compute, that the six stream
 * tools got their own key and nonce widths rather than another tool's, and that Kalyna's parameter set
 * reaches the factory -- which is the failure that would look completely normal on screen.
 */
/**
 * The nine NIST lightweight finalists as tools, rather than as algorithms.
 *
 * `tests/algos-lwc.test.ts` already checks the implementations against 61 known-answer records each in
 * both directions. What is checked here is the *wiring*: that a published vector survives options,
 * resolver and compute; that the instance select reaches the binding; that each tool got its own key,
 * nonce and tag widths rather than a neighbour's; and that the AAD field exists exactly where a tag does.
 */
describe("the shaped AEADs", () => {
  /** Every tool that declares a `shape` with a tag length -- which is what makes it an AEAD, not a stream. */
  const LWC_TOOLS = CIPHER_TOOLS.filter((t) => t.shape?.tagLen !== undefined);

  it("covers the nine NIST lightweight finalists, plus the five CAESAR designs", () => {
    /**
     * Derived from the metadata with the expectation written out, as `BLOCK_TOOLS` and `STREAM_TOOLS`
     * are. Ascon is absent because it was already here before this batch and keeps its own hand-written
     * catalogue -- it is the tenth finalist and the one that won.
     *
     * The predicate is a *shape*, not a competition, which is why ACORN-128, Deoxys-II and NORX are in
     * this list: the first two are CAESAR portfolio ciphers and the third a CAESAR candidate, rather
     * than NIST lightweight finalists, and they belong here because their whole form is a key, a nonce,
     * associated data and a tag. Ketje Jr and MORUS are the fourth and fifth CAESAR designs on the same
     * footing -- and MORUS is the one entry here whose posture is `broken`, which `C004` covers. The
     * `describe`
     * was renamed rather than the filter narrowed -- a list that says "the nine finalists" and quietly
     * means "everything with a tagLen" is the kind of drift this file exists to catch.
     */
    expect(LWC_TOOLS.map((t) => t.id).sort()).toEqual([
      "acorn",
      "deoxysii",
      "elephant",
      "giftcofb",
      "grain128aead",
      "isap",
      "ketjejr",
      "morus",
      "norx",
      "photonbeetle",
      "romulus",
      "schwaemm",
      "tinyjambu",
      "xoodyak",
    ]);
    // And Ascon really is registered, so "nine" here is not "nine of ten by accident".
    expect(CIPHER_TOOLS.some((t) => t.id === "ascon")).toBe(true);
  });

  /**
   * One published vector per tool through the whole family path, at the default instance.
   *
   * Every one of these is Count = 1 from the submission's own KAT file: the all-zero-length case with
   * the standard 00..0f key and nonce, so the expected value is the tag alone. That is the input where a
   * wrong initial constant or a missing domain byte has nowhere to hide.
   */
  const cases: readonly {
    id: string;
    key: string;
    nonce: string;
    expected: string;
    note: string;
  }[] = [
    {
      id: "xoodyak",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b0c0d0e0f",
      expected: "4968dc9c714b06a98d1905c6447b4939",
      note: "Cyclist keyed mode, empty message and AD",
    },
    {
      id: "schwaemm",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      expected: "9e3f9f2e8e26e7d00a9eb92730717a51",
      note: "Schwaemm256-128, the default instance -- note the 32-byte nonce",
    },
    {
      id: "giftcofb",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b0c0d0e0f",
      expected: "368965836d36614de2fc24d0f801b9af",
      note: "COFB with an empty message: the offset is tripled four times",
    },
    {
      id: "photonbeetle",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b0c0d0e0f",
      expected: "df4e0bac1162408098fa5cf084d8f464",
      note: "PHOTON-Beetle-AEAD[128], the default rate",
    },
    {
      id: "romulus",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b0c0d0e0f",
      expected: "4f42aed219ecc79f4daf3e3bad52aee7",
      note: "Romulus-N, the default mode",
    },
    {
      id: "elephant",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b",
      expected: "6655b717736adff3",
      note: "Dumbo: a 12-byte nonce and an 8-byte tag",
    },
    {
      id: "isap",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b0c0d0e0f",
      expected: "7b94ef35ae55ab272c9c44d6c1cf0102",
      note: "ISAP-A-128A, the default variant",
    },
    {
      id: "grain128aead",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b",
      expected: "d51fd5d16177b434",
      note: "a 12-byte nonce and an 8-byte tag, bit-serial",
    },
    {
      id: "tinyjambu",
      key: "000102030405060708090a0b0c0d0e0f",
      nonce: "000102030405060708090a0b",
      expected: "ed7b37cc6e9bdc7b",
      note: "TinyJAMBU-128, the default key size",
    },
    {
      // NORX's own KAT row 0 -- the empty message under the generated key and nonce. An empty region is
      // skipped rather than padded in NORX, so this row is the one that pins that behaviour.
      id: "norx",
      key: "7b3af9b87736f5b47332f1b06f2eedac",
      nonce: "7b30e59a4f04b96e23d88d42f7ac6116",
      expected: "4362ce67456b073cbfc8d5852b598200",
      note: "NORX32-4-1, the designers' KAT at length zero",
    },
    {
      // Not a NIST lightweight submission: this is the designers' own test vector 1, from
      // `Deoxys-II-256-128-official-20190608.json`. Empty message and empty associated data, so the
      // expected value is the tag alone -- the same shape as the nine rows above.
      id: "deoxysii",
      key: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
      nonce: "202122232425262728292a2b2c2d2e",
      expected: "2b97bd77712f0cde975309959dfe1d7c",
      note: "Deoxys-II-256-128, the designers' vector 1 -- note the 15-byte nonce",
    },
  ];

  it("reproduces ACORN's published vector through the tool, which needs associated data", async () => {
    /**
     * ACORN cannot join `cases`, and the reason is worth stating rather than working round: every row
     * there runs an empty message with no associated data, and ACORN publishes no vector for that
     * shape. Its own input set 1 is sixteen zero bytes each way, so it needs both an input and an AAD
     * option -- which is a different call, not a different value.
     *
     * The all-zero row is the useful one anyway. ACORN is the only AEAD here with no tables and no key
     * schedule, so an implementation that dropped the key entirely would still produce *something* for
     * a patterned key; a published answer under an all-zero key and nonce is where a missing input has
     * nowhere to hide.
     */
    const result = await run(
      "acorn",
      keyed("00".repeat(16), "00".repeat(16), {
        [OPTION_AAD]: "00".repeat(16),
        aadEncoding: "hex",
      }),
      new Uint8Array(16),
    );
    expect(result.error).toBeUndefined();
    expect(encodeHex(result.bytes!)).toBe(
      "2b584c510628f8b40218105ab57ff350e54895692809bf730fee58de8bb0243a",
    );
  });

  it("reproduces each published tag through the tool, at the default instance", async () => {
    for (const { id, key, nonce, expected, note } of cases) {
      const result = await run(id, keyed(key, nonce), new Uint8Array(0));
      expect(result.error, `${id} (${note}) reported: ${result.error}`).toBeUndefined();
      expect(encodeHex(result.bytes!), `${id} (${note})`).toBe(expected);
    }
    expect(cases).toHaveLength(11);
    expect(new Set(cases.map((c) => c.id)).size).toBe(11);
  });

  /**
   * Every instance of every tool must reach the binding, checked by requiring distinct output.
   *
   * This is the assertion that would have caught the bug the throwing `Record` in `bindings.ts` exists
   * to prevent, and it is the only one that can: a tool wired to the wrong instance encrypts, decrypts
   * and verifies its own tag perfectly. Twenty-two instances across the nine tools.
   */
  it("gives every instance its own output", async () => {
    /**
     * The key and nonce must **not** be a repeated byte, and MORUS is why.
     *
     * MORUS-1280-128 fills its 256-bit register by *repeating* its 128-bit key, so
     * `MORUS-1280-128(K)` is exactly `MORUS-1280-256(K || K)` -- a real property of the design, not a
     * wiring bug. Under the uniform `0x11` key this test used to build, `11 x 16` repeated is `11 x 32`,
     * so those two instances legitimately produced identical output and the assertion failed for the
     * right arithmetic and the wrong reason. A counting byte pattern separates them; the property itself
     * is pinned in `tests/algos-morus.test.ts`.
     */
    const pattern = (length: number): string =>
      Array.from({ length }, (_, i) => ((i * 7 + 3) & 0xff).toString(16).padStart(2, "0")).join(
        "",
      );
    const seen = new Map<string, string>();
    let instances = 0;
    for (const tool of LWC_TOOLS) {
      const list = tool.shape!.instances ?? [
        {
          id: undefined,
          keyLen: tool.shape!.keyLengths[0]!,
          nonceLen: tool.shape!.nonceLengths[0]!,
        },
      ];
      for (const instance of list) {
        instances++;
        const result = await run(
          tool.id,
          keyed(
            pattern(instance.keyLen),
            pattern(instance.nonceLen),
            instance.id === undefined ? {} : { [OPTION_PARAM_SET]: instance.id },
          ),
          ascii("lightweight"),
        );
        expect(
          result.error,
          `${tool.id}/${String(instance.id)} reported: ${result.error}`,
        ).toBeUndefined();
        seen.set(`${tool.id}/${String(instance.id)}`, encodeHex(result.bytes!));
      }
    }
    // Twenty-two named instances across the nine finalists, plus one each for ACORN, Deoxys-II and NORX.
    expect(instances).toBe(29);
    expect(new Set(seen.values()).size, "two instances produced identical output").toBe(
      seen.size,
    );
  });

  /** Round-trip every instance, including the ones whose decrypt path is a different expression. */
  it("round-trips every instance", async () => {
    const message = ascii("Romulus irho and Schwaemm's final block are not rearrangements.");
    for (const tool of LWC_TOOLS) {
      const list = tool.shape!.instances ?? [
        {
          id: undefined,
          keyLen: tool.shape!.keyLengths[0]!,
          nonceLen: tool.shape!.nonceLengths[0]!,
        },
      ];
      for (const instance of list) {
        const options: Record<string, string> =
          instance.id === undefined ? {} : { [OPTION_PARAM_SET]: instance.id };
        const sealed = await run(
          tool.id,
          keyed("33".repeat(instance.keyLen), "44".repeat(instance.nonceLen), options),
          message,
        );
        expect(sealed.error, `${tool.id}/${String(instance.id)} encrypt`).toBeUndefined();
        const opened = await run(
          tool.id,
          keyed("33".repeat(instance.keyLen), "44".repeat(instance.nonceLen), {
            ...options,
            [OPTION_DIRECTION]: "decrypt",
          }),
          sealed.bytes!,
        );
        expect(opened.error, `${tool.id}/${String(instance.id)} decrypt`).toBeUndefined();
        expect(encodeHex(opened.bytes!), `${tool.id}/${String(instance.id)}`).toBe(
          encodeHex(message),
        );
      }
    }
  });

  /** Each tool's declared widths reach the form, and the tag length reaches the resolver. */
  it("gives each tool its own key, nonce and tag widths", () => {
    for (const tool of LWC_TOOLS) {
      const catalogue = cipherCatalogueFor(tool.id);
      expect(catalogue.require(OPTION_KEY).bytesLength?.exact, `${tool.id} key`).toEqual([
        ...tool.shape!.keyLengths,
      ]);
      expect(catalogue.require(OPTION_NONCE).bytesLength?.exact, `${tool.id} nonce`).toEqual([
        ...tool.shape!.nonceLengths,
      ]);
      // The AAD field exists exactly where a tag does -- which is what `shape.tagLen` decides.
      expect(catalogue.get(OPTION_AAD) !== undefined, `${tool.id} AAD`).toBe(true);

      const instance = tool.shape!.instances?.find((i) => i.id === tool.shape!.defaultInstance);
      const resolved = resolveCipher(
        specFor(
          tool.id,
          keyed(
            "11".repeat(instance?.keyLen ?? tool.shape!.keyLengths[0]!),
            "22".repeat(instance?.nonceLen ?? tool.shape!.nonceLengths[0]!),
            instance ? { [OPTION_PARAM_SET]: instance.id } : {},
          ),
        ),
      );
      expect(resolved.ok, tool.id).toBe(true);
      if (resolved.ok) {
        expect(resolved.resolved.aead, `${tool.id} aead`).toBe(true);
        expect(resolved.resolved.tagLen, `${tool.id} tagLen`).toBe(
          instance?.tagLen ?? tool.shape!.tagLen,
        );
      }
    }
  });

  /**
   * Elephant is the only tool here whose instances disagree about the tag length, so it is the one that
   * proves `CipherInstance.tagLen` is read at all.
   */
  it("takes Elephant's tag length from the instance, not the tool", async () => {
    const lengths = new Map<string, number>();
    for (const id of ["dumbo", "jumbo", "delirium"]) {
      const result = await run(
        "elephant",
        keyed("11".repeat(16), "22".repeat(12), { [OPTION_PARAM_SET]: id }),
        new Uint8Array(0),
      );
      expect(result.error, id).toBeUndefined();
      lengths.set(id, result.bytes!.length);
    }
    expect(lengths.get("dumbo")).toBe(8);
    expect(lengths.get("jumbo")).toBe(8);
    expect(lengths.get("delirium")).toBe(16);
  });

  /** And no lightweight tool gets a mode, a drop count or any of the block ciphers' per-tool controls. */
  it("offers a direction, an instance where there is one, a key, a nonce and AAD -- and nothing else", () => {
    for (const tool of LWC_TOOLS) {
      const ids = toolOwnOptionIds(tool.id);
      const wanted = [OPTION_DIRECTION, OPTION_KEY, OPTION_NONCE, OPTION_AAD];
      if (tool.shape!.instances) wanted.push(OPTION_PARAM_SET);
      expect(ids, tool.id).toEqual(wanted.sort());
    }
  });
});

describe("the ten stream ciphers and Kalyna", () => {
  /** Every tool that declares `stream` on its metadata, which is what drives the derived catalogue. */
  /**
   * The eight raw stream ciphers: a shaped tool with no tag length, which is exactly what a raw
   * stream cipher is. The nine NIST lightweight AEADs share `shape` and are filtered out by that test.
   */
  const STREAM_TOOLS = CIPHER_TOOLS.filter(
    (t) => t.shape !== undefined && t.shape.tagLen === undefined,
  );

  it("covers exactly the eight ciphers with a derived stream catalogue", () => {
    /**
     * Derived from the metadata with the expectation written out, exactly as `BLOCK_TOOLS` is -- so a
     * ninth stream cipher fails here once and is then covered by every loop below for free.
     *
     * RC4, the four raw ChaChas and the three Salsas are deliberately absent: each has a control of its
     * own or a key range, so each keeps a hand-written catalogue. See the note on `CipherToolMeta.shape`.
     */
    expect(STREAM_TOOLS.map((t) => t.id).sort()).toEqual([
      "grain128",
      "grainv1",
      "hc128",
      "hc256",
      "rabbit",
      "snow3g",
      "sosemanuk",
      "trivium",
      "zuc128",
      "zuc256",
    ]);
  });

  const streamCases: readonly {
    id: string;
    key: string;
    nonce: string;
    keystream: string;
    note: string;
  }[] = [
    {
      id: "zuc128",
      key: "00".repeat(16),
      nonce: "00".repeat(16),
      keystream: "27bede74018082da",
      note: "GSMA's own all-zero vector, big-endian as ZUC spells it",
    },
    {
      id: "zuc256",
      key: "ff".repeat(32),
      nonce: "ffffffffffffffffffffffffffffffffff3f3f3f3f3f3f3f3f",
      keystream: "3356cbaed1a1c18b",
      note: "a 25-byte IV, and the only tool in the family with one",
    },
    {
      id: "snow3g",
      key: "2bd6459f82c5b300952c49104881ff48",
      nonce: "ea024714ad5c4d84df1f9b251c0bf45f",
      keystream: "abee97047ac31373",
      note: "3GPP TS 35.216 test set 1, which is the whole published value",
    },
    {
      id: "hc128",
      key: "0053a6f94c9ff24598eb3e91e4378add",
      nonce: "0d74db42a91077de45ac137ae148af16",
      keystream: "2e1ed12a8551c05a",
      note: "eSTREAM set 6, vector 0",
    },
    {
      id: "hc256",
      key: "00".repeat(16),
      nonce: "00".repeat(16),
      keystream: "5b078985d8f6f30d",
      note: "the 128-bit form, which expands rather than truncating",
    },
    {
      id: "hc256",
      key: "0053a6f94c9ff24598eb3e91e4378add3083d6297ccf2275c81b6ec11467ba0d",
      nonce: "0d74db42a91077de45ac137ae148af167de44bb21980e74eb51c83ea51b81f86",
      keystream: "23d9e70a45eb0127",
      note: "the 256-bit form the specification actually defines",
    },
    {
      id: "grainv1",
      key: "0123456789abcdef1234",
      nonce: "0123456789abcdef",
      keystream: "7f362bd3f7abae20",
      note: "an 80-bit key and a 64-bit IV, the narrowest pair here",
    },
    {
      id: "grain128",
      key: "00".repeat(16),
      nonce: "00".repeat(12),
      keystream: "4bdb20824c5dce6f",
      note: "a 96-bit IV padded with all ones, not with zeroes",
    },
    {
      id: "rabbit",
      key: "00".repeat(16),
      nonce: "",
      keystream: "b15754f036a5d6ecf56b45261c4af702",
      note: "RFC 4503 A.1 -- no IV setup at all, which an empty nonce field is what asks for",
    },
    {
      id: "rabbit",
      key: "00".repeat(16),
      nonce: "00".repeat(8),
      keystream: "c6a7275ef85495d87ccd5d376705b7ed",
      note: "RFC 4503 A.2 -- an all-zero IV, which is a different keystream from no IV",
    },
    {
      id: "trivium",
      key: "80000000000000000000",
      nonce: "00000000000000000000",
      keystream: "38eb86ff730d7a9caf8df13a4420540d",
      note: "eSTREAM's own set 1 vector 0, at the specification's 80-bit IV",
    },
    {
      id: "trivium",
      key: "0053a6f94c9ff24598eb",
      nonce: "0d74db42",
      keystream: "1ee5830a5321d9123ead6f8374c0c047",
      note: "eSTREAM's set 6 vector 0 at a 32-bit IV, so both the short and long loads are covered",
    },
  ];

  /**
   * The keystream is the vector, so the input is zeroes and the output is the keystream verbatim.
   *
   * That also makes this a test of the *encoding* path: the key and nonce go in as hex through the
   * options form, which is where a tool inheriting another's declared widths would fail.
   */
  it("reproduces each published keystream through the tool", async () => {
    for (const { id, key, nonce, keystream, note } of streamCases) {
      const result = await run(id, keyed(key, nonce), new Uint8Array(keystream.length / 2));
      expect(result.error, `${id} (${note}) reported: ${result.error}`).toBeUndefined();
      expect(encodeHex(result.bytes!), `${id} (${note})`).toBe(keystream);
    }
    // Every one of the eight appears; HC-256 twice for its two key widths, Rabbit twice for its two IV
    // cases and Trivium twice for two of its three IV widths -- the three places a single vector would
    // leave a real branch uncovered. SOSEMANUK is absent because nothing publishes its first bytes
    // under a key length the form offers; it has its own test below instead.
    expect(new Set(streamCases.map((c) => c.id)).size).toBe(9);
    expect(streamCases).toHaveLength(12);
  });

  it("reproduces SOSEMANUK's eSTREAM XOR digest through the tool", async () => {
    /**
     * SOSEMANUK cannot join `streamCases`, and the reason is worth stating rather than working round.
     * The only published keystream *prefix* reachable from this environment is Crypto++'s reference
     * vector, whose key is five bytes -- which the primitive accepts, because Serpent's padding bit
     * makes it well defined, and which the form does not offer, because eight to forty bits of key is
     * not a thing to put in a dropdown. `tests/algos-sosemanuk.test.ts` asserts that prefix directly.
     *
     * What *is* reachable under an offered key length is eSTREAM's own set 6 vector 3: 131,072 bytes
     * folded into a 64-byte XOR digest. So that is what runs here, through the option catalogue, the
     * key rules, the resolver and compute -- which is the layer this file exists to check -- and it
     * happens to be a far stronger check than eight bytes, at 32,768 LFSR steps.
     */
    const result = await run(
      "sosemanuk",
      keyed(
        "0f62b5085bae0154a7fa4da0f34699ec3f92e5388bde3184d72a7dd02376c91c",
        "288ff65dc42b92f960c72e95fc63ca31",
      ),
      new Uint8Array(131072),
    );
    expect(result.error).toBeUndefined();
    const digest = new Uint8Array(64);
    for (let i = 0; i < 131072; i++) digest[i % 64] = digest[i % 64]! ^ result.bytes![i]!;
    expect(encodeHex(digest)).toBe(
      "cc09fb7405dd54bbf09407b1d2033fbbac53f388dd387a46f2b8fcff692a7838" +
        "353523a621a55d08da0ca5348ae96d8b0d6a028f309982ef6628054d01b9a368",
    );
  });

  /**
   * Each of the six declares its own key and nonce widths, and no two of them are alike.
   *
   * This is the assertion that would have caught the bug the throwing `Record` in `bindings.ts` exists to
   * prevent -- a stream tool wired to the wrong arm encrypts and decrypts perfectly and matches nothing,
   * so the only visible symptom is a form asking for the wrong number of bytes.
   */
  it("gives each stream cipher its own declared key and nonce widths", () => {
    const shapes = STREAM_TOOLS.map((tool) => {
      const catalogue = cipherCatalogueFor(tool.id);
      return {
        id: tool.id,
        key: catalogue.require(OPTION_KEY).bytesLength?.exact,
        nonce: catalogue.require(OPTION_NONCE).bytesLength?.exact,
      };
    });
    for (const shape of shapes) {
      const tool = requireCipherTool(shape.id);
      expect(shape.key, `${shape.id} key`).toEqual([...tool.shape!.keyLengths]);
      expect(shape.nonce, `${shape.id} nonce`).toEqual([...tool.shape!.nonceLengths]);
    }
    /**
     * Eight distinct shapes across ten tools, and both collisions are real rather than bugs.
     *
     * ZUC-128, HC-128 and SNOW 3G all take a 16-byte key and a 16-byte IV. That is a fact about the
     * three ciphers, so the assertion is on the *shape* count rather than the tool count -- pinning ten
     * would be pinning something false, which is worse than pinning nothing. What actually rules out a
     * tool reading another's widths is the loop above, which compares each against its own metadata.
     *
     * Rabbit adds the only shape here whose nonce list includes zero: its IV is genuinely optional, and
     * an empty one is a different keystream from an all-zero one rather than a special case of it.
     * Trivium adds the only one with three nonce widths, all of them published rather than padded.
     * SOSEMANUK adds the only one with three *key* widths, which are Serpent's, since its schedule is.
     */
    expect(new Set(shapes.map((s) => `${String(s.key)}/${String(s.nonce)}`)).size).toBe(8);
  });

  /** No stream tool gets a mode, an AAD field or any of the per-cipher block controls. */
  it("offers a stream cipher nothing but a direction, a key and a nonce", () => {
    for (const tool of STREAM_TOOLS) {
      // Key derivation excluded; see `toolOwnOptionIds`.
      expect(toolOwnOptionIds(tool.id), tool.id).toEqual(
        [OPTION_DIRECTION, OPTION_KEY, OPTION_NONCE].sort(),
      );
    }
  });

  const KALYNA_VECTORS: readonly {
    set: string;
    key: string;
    plaintext: string;
    expected: string;
  }[] = [
    {
      set: "128-128",
      key: "000102030405060708090a0b0c0d0e0f",
      plaintext: "101112131415161718191a1b1c1d1e1f",
      expected: "81bf1c7d779bac20e1c9ea39b4d2ad06",
    },
    {
      set: "128-256",
      key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      plaintext: "202122232425262728292a2b2c2d2e2f",
      expected: "58ec3e091000158a1148f7166f334f14",
    },
    {
      set: "256-256",
      key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      plaintext: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      expected: "f66e3d570ec92135aedae323dcbd2a8ca03963ec206a0d5a88385c24617fd92c",
    },
    {
      set: "256-512",
      key:
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      plaintext: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
      expected: "606990e9e6b7b67a4bd6d893d72268b78e02c83c3cd7e102fd2e74a8fdfe5dd9",
    },
    {
      set: "512-512",
      key:
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      plaintext:
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
      expected:
        "4a26e31b811c356aa61dd6ca0596231a67ba8354aa47f3a13e1deec320eb56b8" +
        "95d0f417175bab662fd6f134bb15c86ccb906a26856efeb7c5bc6472940dd9d9",
    },
  ];

  /**
   * All five pairings through the tool, which is what checks the parameter set reaches the factory.
   *
   * The two 32-byte-key sets are the case that matters: Kalyna-128/256 and Kalyna-256/256 take the same
   * key and are different ciphers with different block sizes, so a binding that inferred the block from
   * the key would produce a plausible answer for one of them and a wrong one for the other -- with the
   * *right* number of output bytes in both, since ECB pads to the block it thinks it has.
   */
  it("reproduces every Kalyna vector through the tool, at all five pairings", async () => {
    for (const v of KALYNA_VECTORS) {
      const result = await run(
        "kalyna",
        keyed(v.key, undefined, { [OPTION_MODE]: "ecb", [OPTION_PARAM_SET]: v.set }),
        fromHex(v.plaintext),
      );
      expect(result.error, `Kalyna-${v.set} reported: ${result.error}`).toBeUndefined();
      expect(encodeHex(result.bytes!).slice(0, v.expected.length), `Kalyna-${v.set}`).toBe(
        v.expected,
      );
    }
    expect(KALYNA_VECTORS).toHaveLength(requireCipherTool("kalyna").paramSets!.length);
  });

  /**
   * The two sets that share a key length are different functions, asserted directly.
   *
   * Written as its own test rather than left implied by the vectors above, because this is the one
   * property that says the parameter set -- and not the key -- decides the block size.
   */
  it("treats Kalyna-128/256 and Kalyna-256/256 as different ciphers", async () => {
    const key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const message = fromHex("202122232425262728292a2b2c2d2e2f");
    const narrow = await run(
      "kalyna",
      keyed(key, undefined, { [OPTION_MODE]: "ecb", [OPTION_PARAM_SET]: "128-256" }),
      message,
    );
    const wide = await run(
      "kalyna",
      keyed(key, undefined, { [OPTION_MODE]: "ecb", [OPTION_PARAM_SET]: "256-256" }),
      message,
    );
    expect(narrow.error).toBeUndefined();
    expect(wide.error).toBeUndefined();
    // A 16-byte input under a 32-byte block is one padded block, so the lengths differ too.
    expect(narrow.bytes!.length).toBe(32);
    expect(wide.bytes!.length).toBe(32);
    expect(encodeHex(narrow.bytes!)).not.toBe(encodeHex(wide.bytes!));
  });

  /**
   * Kalyna's IV length follows the *set*, not the tool -- which is the hazard the Speck merge introduced
   * and the reason `ResolvedCipher.blockSize` exists.
   */
  it("takes an IV of the selected set's block size", () => {
    for (const set of requireCipherTool("kalyna").paramSets!) {
      expect(requiredNonceLength("kalyna", getAesMode("cbc"), set.id), set.id).toBe(
        set.blockSize,
      );
    }
    // And the tool asked about in the abstract answers for its declared default.
    expect(requiredNonceLength("kalyna", getAesMode("cbc"))).toBe(16);
  });
});

describe("KASUMI, Khazad and Trivium", () => {
  /**
   * The published vectors through the tool rather than the primitive.
   * `tests/algos-phase8.test.ts` covers the implementations, including Khazad's iterated values and
   * Trivium's far-offset keystream windows; Trivium's own tool-level check is in the streaming section
   * above, since its vector *is* a keystream.
   */
  it("reproduces Botan's KASUMI vector through the tool", async () => {
    const result = await run(
      "kasumi",
      keyed("2bd6459f82c5b300952c49104881ff48", undefined, { [OPTION_MODE]: "ecb" }),
      fromHex("ea024714ad5c4d84"),
    );
    expect(encodeHex(result.bytes!).slice(0, 16)).toBe("df1f9b251c0bf45f");
  });

  it("reproduces a NESSIE Khazad vector through the tool", async () => {
    const result = await run(
      "khazad",
      keyed("80000000000000000000000000000000", undefined, { [OPTION_MODE]: "ecb" }),
      fromHex("0000000000000000"),
    );
    expect(encodeHex(result.bytes!).slice(0, 16)).toBe("49a4ce32ac190e3f");
  });

  it("keeps KASUMI, Khazad and MISTY1 apart", async () => {
    /**
     * All three are 64-bit blocks under 128-bit keys, so a factory wired to the wrong one produces a
     * plausible answer at the right length -- and KASUMI is *derived* from MISTY1, which makes that
     * mistake more likely here than anywhere else in the family.
     */
    const key = "00112233445566778899aabbccddeeff";
    const block = fromHex("0123456789abcdef");
    const outputs = [];
    for (const id of ["kasumi", "khazad", "misty1"]) {
      const result = await run(id, keyed(key, undefined, { [OPTION_MODE]: "ecb" }), block);
      outputs.push(encodeHex(result.bytes!).slice(0, 16));
    }
    expect(new Set(outputs).size).toBe(3);
  });

  it("consumes a Trivium IV from its last byte, so a short one right-aligns", async () => {
    /**
     * The non-obvious consequence of the loading order, and the first draft of this test asserted the
     * opposite.
     *
     * The bit that becomes `s[94]` is the *most significant bit of the last IV byte*, so the register
     * fills from the end of the field backwards. A four-byte IV therefore matches the same four bytes
     * **right-aligned** in a ten-byte field -- and differs from those bytes followed by six zeros,
     * which is the padding somebody would reach for. Getting this backwards produces a plausible
     * keystream matching nothing, and eSTREAM publishes vectors at three widths precisely because it is
     * a place to go wrong.
     */
    const key = "0053a6f94c9ff24598eb";
    const short = await run("trivium", keyed(key, "0d74db42"), new Uint8Array(16));
    // eSTREAM's set 6 vector 0 at a 32-bit IV, so the left side of each comparison is pinned.
    expect(encodeHex(short.bytes!)).toBe("1ee5830a5321d9123ead6f8374c0c047");

    const rightAligned = await run(
      "trivium",
      keyed(key, "0000000000000d74db42"),
      new Uint8Array(16),
    );
    expect(encodeHex(rightAligned.bytes!)).toBe(encodeHex(short.bytes!));

    const zeroPadded = await run(
      "trivium",
      keyed(key, "0d74db42000000000000"),
      new Uint8Array(16),
    );
    expect(encodeHex(zeroPadded.bytes!)).not.toBe(encodeHex(short.bytes!));

    // An all-zero IV coincides at every width, which follows and is worth stating rather than implying.
    const zeroShort = await run("trivium", keyed(key, "00000000"), new Uint8Array(16));
    const zeroLong = await run("trivium", keyed(key, "00".repeat(10)), new Uint8Array(16));
    expect(encodeHex(zeroShort.bytes!)).toBe(encodeHex(zeroLong.bytes!));
  });
});

describe("CLEFIA, MARS and Rabbit", () => {
  /**
   * The published vectors again, but through the tool -- options, resolver, compute and the mode layer.
   * `tests/algos-phase6b.test.ts` covers the implementations; what is left for here is that the value
   * survives the trip, which is where a key length rule or a mode default could lose it.
   *
   * Rabbit is covered by the streaming section above instead, since its vector *is* a keystream.
   */
  const cases: readonly {
    id: string;
    key: string;
    plaintext: string;
    expected: string;
    note: string;
  }[] = [
    {
      id: "clefia",
      key: "ffeeddccbbaa99887766554433221100",
      plaintext: "000102030405060708090a0b0c0d0e0f",
      expected: "de2bf2fd9b74aacdf1298555459494fd",
      note: "RFC 6114 Appendix A, 128-bit key",
    },
    {
      id: "clefia",
      key: "ffeeddccbbaa99887766554433221100f0e0d0c0b0a090807060504030201000",
      plaintext: "000102030405060708090a0b0c0d0e0f",
      expected: "a1397814289de80c10da46d1fa48b38a",
      note: "the 256-bit key, which runs 26 rounds rather than 18",
    },
    {
      id: "mars",
      key: "00".repeat(16),
      plaintext: "00".repeat(16),
      expected: "dcc07b8dfb0738d6e30a22dfcf27e886",
      note: "Crypto++'s first MARS vector",
    },
    {
      id: "mars",
      key: "000000000000000000000000000000000000000000000000",
      plaintext: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      expected: "97778747d60e425c2b4202599db856fb",
      note: "a 24-byte key, which no other cipher in this batch accepts",
    },
  ];

  it("reproduces each published vector through the tool", async () => {
    for (const { id, key, plaintext, expected, note } of cases) {
      const result = await run(
        id,
        keyed(key, undefined, { [OPTION_MODE]: "ecb" }),
        fromHex(plaintext),
      );
      // ECB pads, so the tool returns the vector's block plus a padding block.
      expect(encodeHex(result.bytes!).slice(0, expected.length), `${id} (${note})`).toBe(
        expected,
      );
    }
  });

  it("makes CLEFIA's key length change the round count, not just the schedule", async () => {
    /**
     * 18, 22 and 26 rounds for 128, 192 and 256 bits. A schedule that ignored the length would still
     * produce sixteen bytes, so the three have to be compared against each other -- and a 192-bit key
     * is completed internally with the complement of its own first words, which makes it a distinct
     * function rather than a zero-padded 256-bit one.
     */
    const pt = fromHex("000102030405060708090a0b0c0d0e0f");
    const base = "ffeeddccbbaa99887766554433221100";
    const outputs = [];
    for (const key of [base, base + "00".repeat(8), base + "00".repeat(16)]) {
      const result = await run("clefia", keyed(key, undefined, { [OPTION_MODE]: "ecb" }), pt);
      outputs.push(encodeHex(result.bytes!));
    }
    expect(new Set(outputs).size).toBe(3);
  });

  it("keeps Rabbit's empty IV distinct from an all-zero one, through the tool", async () => {
    /**
     * The resolver has to pass an empty nonce through rather than substituting eight zero bytes, and
     * this is the assertion that says so. Both values are published in RFC 4503; substituting would
     * produce the second where the first was asked for, with no error anywhere.
     */
    const input = new Uint8Array(16);
    const none = await run("rabbit", keyed("00".repeat(16), ""), input);
    const zeros = await run("rabbit", keyed("00".repeat(16), "00".repeat(8)), input);
    expect(encodeHex(none.bytes!)).toBe("b15754f036a5d6ecf56b45261c4af702");
    expect(encodeHex(zeros.bytes!)).toBe("c6a7275ef85495d87ccd5d376705b7ed");
  });
});

describe("MISTY1 and HIGHT", () => {
  /**
   * The published vectors again, but through the *tool* -- options, resolver, compute and the mode
   * layer -- rather than through the primitive. `tests/algos-phase6-ciphers.test.ts` covers the
   * implementations, including HIGHT's 60 published CBC and CTR cases; what is left for here is that
   * the value survives the trip, which is where a key length rule or a mode default could lose it.
   */
  it("reproduces RFC 2994's MISTY1 example, and its CBC one", async () => {
    const key = "00112233445566778899aabbccddeeff";
    const plaintext = fromHex("0123456789abcdeffedcba9876543210");

    const ecb = await run("misty1", keyed(key, undefined, { [OPTION_MODE]: "ecb" }), plaintext);
    expect(ecb.error).toBeUndefined();
    // ECB pads, so the tool's output is the RFC's two blocks plus a padding block; the RFC's value is
    // the prefix, which is the honest comparison for a tool that pads by default.
    expect(encodeHex(ecb.bytes!).slice(0, 32)).toBe("8b1da5f56ab3d07c04b68240b13be95d");

    const cbc = await run(
      "misty1",
      keyed(key, "0102030405060708", { [OPTION_MODE]: "cbc" }),
      plaintext,
    );
    expect(cbc.error).toBeUndefined();
    expect(encodeHex(cbc.bytes!).slice(0, 32)).toBe("461c1e879c18c27fb9adf2d80c89031f");
  });

  it("reproduces a KISA HIGHT vector through the tool", async () => {
    // The first entry of Crypto++'s `hight.txt`, whose values come from KISA's reference archive.
    const result = await run(
      "hight",
      keyed("88e34f8f081779f1e9f394370ad40589", undefined, { [OPTION_MODE]: "ecb" }),
      fromHex("d76d0d18327ec562"),
    );
    expect(result.error).toBeUndefined();
    expect(encodeHex(result.bytes!).slice(0, 16)).toBe("e4bc2e312277e4dd");
  });

  it("keeps the two apart, though they share a block size and a key size", async () => {
    /**
     * Both are 64-bit blocks under 128-bit keys, so a factory wired to the wrong one would produce a
     * plausible answer at the right length. The family's construction-label test would not catch it
     * either -- both labels are derived from the metadata and would still read correctly.
     */
    const key = "00112233445566778899aabbccddeeff";
    const plaintext = fromHex("0123456789abcdef");
    const a = await run("misty1", keyed(key, undefined, { [OPTION_MODE]: "ecb" }), plaintext);
    const b = await run("hight", keyed(key, undefined, { [OPTION_MODE]: "ecb" }), plaintext);
    expect(a.error).toBeUndefined();
    expect(b.error).toBeUndefined();
    expect(encodeHex(a.bytes!)).not.toBe(encodeHex(b.bytes!));
  });

  it("refuses a key that is not 16 bytes, naming the cipher", async () => {
    // Through `compute` rather than the `run` helper, which asserts the absence of an error.
    for (const [id, label] of [
      ["misty1", "MISTY1"],
      ["hight", "HIGHT"],
    ] as const) {
      const tool = cipherToolDefinition(id);
      const spec = specFor(id, keyed("00".repeat(8), undefined, { [OPTION_MODE]: "ecb" }));
      const result = await tool.compute(spec, fromHex("0011223344556677"));
      expect(result.error, `${id} short key`).toContain(label);
      expect(result.error, `${id} short key`).toContain("16 bytes");
    }
  });
});

describe("Noekeon, LEA, SHACAL-2 and GOST 28147-89", () => {
  const cases: readonly {
    id: string;
    key: string;
    plaintext: string;
    expected: string;
    options?: Record<string, string | number>;
    note: string;
  }[] = [
    {
      id: "noekeon",
      key: "b1656851699e29fa24b70148503d2dfc",
      plaintext: "2a78421b87c7d0924f26113f1d1349b2",
      expected: "e2f687e07b75660ffc372233bc47532c",
      note: "the chained vector, which cannot pass unless the other two already do",
    },
    {
      id: "lea",
      key: "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
      plaintext: "101112131415161718191a1b1c1d1e1f",
      expected: "9fc84e3528c6c6185532c7a704648bfd",
      note: "LEA-128, ISO/IEC 29192-2",
    },
    {
      id: "lea",
      key: "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f",
      plaintext: "303132333435363738393a3b3c3d3e3f",
      expected: "d651aff647b189c13a8900ca27f9e197",
      note: "LEA-256 -- a different key schedule, not the same one with more rounds",
    },
    {
      id: "shacal2",
      key:
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      plaintext: "98bcc10405ab0bfc686bececaad01ac19b452511bceb9cb094f905c51ca45430",
      expected: "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
      note: "a 512-bit key over a 256-bit block, which nothing else here does",
    },
    {
      id: "gost28147",
      key: "546d203368656c326973652073736e62206167796967747473656865202c3d73",
      plaintext: "0000000000000000",
      expected: "1b0bbc32cebcab42",
      options: { gostSbox: "test" },
      note: "the D-Test parameter set, which is what published GOST vectors use",
    },
  ];

  it("reproduces each published vector through the tool", async () => {
    for (const { id, key, plaintext, expected, options, note } of cases) {
      const result = await run(
        id,
        keyed(key, undefined, { [OPTION_MODE]: "ecb", ...(options ?? {}) }),
        fromHex(plaintext),
      );
      expect(result.error, `${id} (${note}) reported: ${result.error}`).toBeUndefined();
      expect(encodeHex(result.bytes!).slice(0, expected.length), `${id} (${note})`).toBe(
        expected,
      );
    }
    expect(cases).toHaveLength(5);
    expect(new Set(cases.map((c) => c.id)).size).toBe(4);
  });

  /**
   * GOST's S-box control has to reach the cipher, and this is the assertion that says so.
   *
   * The whole interoperability problem with GOST is that the tables are a parameter: a tool offering the
   * choice and ignoring it would look right and be useless, and the failure is invisible unless the two
   * settings are compared. Same shape as Threefish's tweak assertion.
   */
  it("makes GOST's S-box set change the ciphertext", async () => {
    const key = "546d203368656c326973652073736e62206167796967747473656865202c3d73";
    const block = fromHex("0000000000000000");
    const test = await run(
      "gost28147",
      keyed(key, undefined, { [OPTION_MODE]: "ecb", gostSbox: "test" }),
      block,
    );
    const crypto = await run(
      "gost28147",
      keyed(key, undefined, { [OPTION_MODE]: "ecb", gostSbox: "crypto" }),
      block,
    );
    expect(test.error).toBeUndefined();
    expect(crypto.error).toBeUndefined();
    expect(encodeHex(test.bytes!)).not.toBe(encodeHex(crypto.bytes!));
  });

  /**
   * SHACAL-2's key range, which is the second in the family after Blowfish's.
   *
   * `block.keyRange` rather than a list, so `decodeBytesOption` enforces the bounds and the resolver's
   * exact-length check has to *skip* it rather than keep a second copy that could drift -- which is the
   * note `keyLengthFor` already carries, now exercised by a second cipher.
   */
  it("accepts SHACAL-2's whole key range and nothing outside it", () => {
    for (const bytes of [16, 32, 64]) {
      const result = resolveCipher(
        specFor(
          "shacal2",
          keyed("11".repeat(bytes), "22".repeat(32), { [OPTION_MODE]: "cbc" }),
        ),
      );
      expect(result.ok, `${bytes} bytes should be accepted`).toBe(true);
    }
    for (const bytes of [8, 65]) {
      const result = resolveCipher(
        specFor(
          "shacal2",
          keyed("11".repeat(bytes), "22".repeat(32), { [OPTION_MODE]: "cbc" }),
        ),
      );
      expect(result.ok, `${bytes} bytes should be refused`).toBe(false);
    }
  });

  /** And the S-box control belongs to GOST alone, like the other three per-tool options. */
  it("gives the S-box control to GOST 28147-89 alone", () => {
    for (const meta of CIPHER_TOOLS) {
      const ids = new Set(cipherCatalogueFor(meta.id).options.map((o) => o.id));
      expect(ids.has("gostSbox"), `${meta.id}/gostSbox`).toBe(meta.id === "gost28147");
    }
  });
});

// ─────────────────── the standards audit: XTS's two keys, GCM-SIV's two sizes ───

/**
 * Three findings from reading every AES mode against its standard, and what now holds each.
 *
 * XTS itself was correct -- `aesXtsOperation` splits the key down the middle into a data cipher and
 * a tweak cipher, and `tests/algos-aead-modes.test.ts` compares both directions against OpenSSL's
 * `aes-128-xts` and `aes-256-xts` at every length. What was missing was everything *around* the two
 * keys: nothing said the halves must differ, one mode offered a key size its RFC does not define,
 * and the key field's own hint described a control that is deliberately absent under three modes.
 */
describe("AES modes against their standards", () => {
  /**
   * RFC 8452 defines AES-GCM-SIV for 128- and 256-bit keys. There is no AES-192-GCM-SIV.
   *
   * Worth a test rather than trusting the metadata line, because the failure was silent in the worst
   * way: `@noble/ciphers` *accepts* a 24-byte key as a documented local extension, so the tool
   * produced a plausible tag that no other implementation would reproduce.
   */
  it("refuses a 192-bit key under GCM-SIV and accepts the two RFC 8452 sizes", () => {
    const at = (bytes: number) =>
      resolveCipher(
        specFor(
          "aes",
          keyed("11".repeat(bytes), "22".repeat(12), { [OPTION_MODE]: "gcm-siv" }),
        ),
      );

    expect(at(16).ok, "AES-128-GCM-SIV is standard and must resolve").toBe(true);
    expect(at(32).ok, "AES-256-GCM-SIV is standard and must resolve").toBe(true);

    const mid = at(24);
    expect(mid.ok, "AES-192-GCM-SIV is not defined by RFC 8452").toBe(false);
    if (!mid.ok) {
      // The message has to name the lengths that *are* allowed; "wrong key length" sends the reader
      // to the standard to find out which three of the four numbers on screen are real.
      expect(mid.problem).toMatch(/16|32/);
    }
  });

  /**
   * Every mode gets a Key size dropdown, and each offers that mode's own names.
   *
   * This replaces a test asserting the opposite -- that the control stood down wherever a mode
   * overrode the key length. That was the behaviour and it was the wrong behaviour: it left the only
   * way to ask for XTS-AES-256 being to know it means 64 bytes and paste them. What holds it now is
   * choice-level `availableOn`, so the assertion is about which choices are *reachable* under each
   * mode rather than about whether the option exists.
   *
   * The labels are asserted, not just the lengths. A 32-byte key string is AES-256 under GCM and
   * XTS-AES-128 under XTS -- the same bytes under a different name -- and the name is the entire
   * reason this is a dropdown instead of a byte count.
   */
  it("offers the Key size choices each mode actually has, under that mode's own names", () => {
    const keySize = cipherCatalogueFor("aes").require(OPTION_KEY_SIZE);
    expect(
      keySize.availableOn,
      "the option itself is available under every mode now; the choices are what vary",
    ).toBeUndefined();

    /** The choices a select would render with this mode selected. */
    const at = (modeId: string) =>
      (withAvailableChoices(keySize, modeId).choices ?? []).map(
        (c) => [c.label, c.value] as const,
      );

    expect(at("gcm")).toEqual([
      ["AES-128", "128"],
      ["AES-192", "192"],
      ["AES-256", "256"],
    ]);
    expect(at("xts"), "two AES keys, so 32 bytes is XTS-AES-128").toEqual([
      ["XTS-AES-128", "256"],
      ["XTS-AES-256", "512"],
    ]);
    expect(at("aessiv"), "RFC 5297 names its sizes after the whole key string").toEqual([
      ["AES-SIV-CMAC-256", "256"],
      ["AES-SIV-CMAC-384", "384"],
      ["AES-SIV-CMAC-512", "512"],
    ]);
    expect(at("gcm-siv"), "RFC 8452 defines no AES-192 variant").toEqual([
      ["AES-128-GCM-SIV", "128"],
      ["AES-256-GCM-SIV", "256"],
    ]);

    /*
     * No mode may be left with nothing to choose, which is the one way choice-level gating can strand
     * a control: a select rendering zero options reads as broken and cannot be recovered from.
     */
    for (const mode of AES_MODES) {
      expect(at(mode.id).length, `${mode.id} has no Key size choices`).toBeGreaterThan(0);
    }
  });

  /**
   * And the choice reaches the resolver, which is the half that makes it a control rather than
   * decoration.
   *
   * A mode's own `keyLengths` used to win outright, so selecting XTS-AES-256 would have left the
   * field still accepting 32 bytes and Generate still producing them -- a dropdown that renders and
   * reaches nothing, introduced by the change that added it.
   */
  it("narrows a splitting mode's key length to the size selected", () => {
    const at = (modeId: string, bits?: string) =>
      [
        ...(cipherAcceptedByteLengths(
          specFor("aes", {
            [OPTION_MODE]: modeId,
            ...(bits === undefined ? {} : { [OPTION_KEY_SIZE]: bits }),
          }),
          OPTION_KEY,
        ) ?? []),
      ].sort((a, b) => a - b);

    /*
     * A mode with its own key lengths is the authority on what is *accepted*; the Key size control
     * decides only what Generate produces. The first version asserted the opposite -- that the
     * selection narrowed acceptance -- and the published XTS vectors caught it: `createSpec` seeds
     * AES-256, XTS offers 32 and 64, so a pasted 64-byte XTS-AES-256 key was refused by a default
     * nobody had chosen.
     */
    expect(at("xts", "256"), "XTS accepts either half-size").toEqual([32, 64]);
    expect(at("xts", "512")).toEqual([32, 64]);
    expect(at("aessiv", "384")).toEqual([32, 48, 64]);
    expect(at("gcm-siv", "128")).toEqual([16, 32]);

    // Generate follows the *selection* even though acceptance does not, which is what keeps the
    // dropdown from being decoration.
    for (const [modeId, bits, want] of [
      ["xts", "256", 32],
      ["xts", "512", 64],
      ["aessiv", "512", 64],
      ["gcm-siv", "128", 16],
    ] as const) {
      const spec = specFor("aes", { [OPTION_MODE]: modeId, [OPTION_KEY_SIZE]: bits });
      expect(cipherGenerateLength(spec, OPTION_KEY), `${modeId} @ ${bits}`).toBe(want);
    }

    /*
     * A size the mode does not offer -- AES-192 left behind by a switch from GCM to XTS -- falls back
     * to the mode's full list rather than to nothing. The form is showing its disabled "(not set)"
     * placeholder at that point, and computing at a length the mode accepts is the honest pairing.
     */
    expect(at("xts", "192")).toEqual([32, 64]);
  });

  /**
   * The reported case: Generate under XTS produced 64 bytes and the field said "needs 16, 24 or 32".
   *
   * Both statements came from one catalogue. `bytesLength.exact` for AES's key is 16/24/32 -- the
   * union across the ordinary modes -- and 64 is not in it, so the form had been calling a valid XTS
   * key invalid all along. The Generate fix only made it visible: before that the button produced 32,
   * which is a legal XTS-AES-128 key and which the form happened to accept.
   *
   * This asserts the invariant that was broken: whatever Generate offers must be something the field
   * accepts *and* something the resolver accepts.
   */
  it("what Generate offers is what the field and the resolver both accept, for every AES mode", () => {
    let checked = 0;
    for (const mode of AES_MODES) {
      const base = specFor("aes", { [OPTION_MODE]: mode.id });
      const offered = cipherGenerateLength(base, OPTION_KEY);
      expect(offered, `${mode.id} must offer a key length`).toBeDefined();

      const accepted = cipherAcceptedByteLengths(base, OPTION_KEY);
      expect(accepted, `${mode.id} must narrow the key length`).toBeDefined();
      expect(
        accepted!.includes(offered!),
        `${mode.id}: Generate offers ${offered} bytes, field accepts ${accepted!.join(", ")}`,
      ).toBe(true);

      const nonceLen = requiredNonceLength("aes", mode, undefined);
      const spec = specFor(
        "aes",
        keyed("ab".repeat(offered!), nonceLen > 0 ? "cd".repeat(nonceLen) : undefined, {
          [OPTION_MODE]: mode.id,
        }),
      );
      expect(
        resolveCipher(spec).ok,
        `${mode.id}: a generated ${offered}-byte key was refused by the resolver`,
      ).toBe(true);
      checked += 1;
    }
    expect(checked, "every AES mode should have been checked").toBe(AES_MODES.length);
  });

  /**
   * And the narrowed set is the mode's own, not the catalogue's union.
   *
   * Spelled out for the three modes that override, because the bug was a union standing in for a
   * mode's answer -- an assertion that only checked "some list came back" would have passed while
   * the list was still 16/24/32.
   */
  it("narrows the key length to the mode's own list", () => {
    const at = (modeId: string, extra: CipherSpec["options"] = {}) => [
      ...(cipherAcceptedByteLengths(
        specFor("aes", { [OPTION_MODE]: modeId, ...extra }),
        OPTION_KEY,
      ) ?? []),
    ];

    expect(at("xts"), "XTS is two AES keys").toEqual([32, 64]);
    expect(at("aessiv"), "RFC 5297 splits the key between a CMAC and a CTR").toEqual([
      32, 48, 64,
    ]);
    expect(at("gcm-siv"), "RFC 8452 defines no AES-192 variant").toEqual([16, 32]);
    // An ordinary mode narrows to the single declared Key size rather than to the union.
    expect(at("gcm")).toEqual([32]);
    expect(at("gcm", { [OPTION_KEY_SIZE]: "128" }), "and follows the Key size control").toEqual(
      [16],
    );
  });

  /**
   * C008: an XTS key whose halves are identical is one key used twice.
   *
   * FIPS 140-3 forbids it and OpenSSL refuses outright with `xts duplicated keys`, so this is the
   * one case where our output exists and OpenSSL's does not -- which is why the rule reports rather
   * than blocks, and why the detail says so.
   */
  it("C008 fires on a duplicated XTS key, and the fix silences it", () => {
    const half = "11".repeat(16);
    const duplicated = specFor(
      "aes",
      keyed(half + half, "33".repeat(16), { [OPTION_MODE]: "xts" }),
    );

    const found = lint(duplicated).diagnostics.find((d) => d.code === "C008");
    expect(found, "C008 should fire when both halves match").toBeDefined();
    expect(found!.level).toBe("insecure");
    expect(found!.detail).toMatch(/duplicated keys/);

    const fixed = applyAllFixes(duplicated);
    expect(
      lint(fixed).diagnostics.some((d) => d.code === "C008"),
      "the fix must leave a key whose halves differ",
    ).toBe(false);
    // The data half is preserved: regenerating both would discard a key the user arrived with.
    expect(String(fixed.options[OPTION_KEY]).slice(0, 32)).toBe(half);
    expect(resolveCipher(fixed).ok, "the fixed spec still resolves").toBe(true);
  });

  it("C008 is silent for distinct halves, and for every mode that is not XTS", () => {
    const distinct = specFor(
      "aes",
      keyed("11".repeat(16) + "22".repeat(16), "33".repeat(16), { [OPTION_MODE]: "xts" }),
    );
    expect(lint(distinct).diagnostics.some((d) => d.code === "C008")).toBe(false);

    /*
     * The same repeating key under every other mode. Nothing else here splits its key in half, so a
     * rule that forgot to check the mode would call an ordinary AES-256 key "one key used twice" --
     * which is the shape of false positive that teaches people to stop reading the panel.
     */
    let checked = 0;
    for (const mode of AES_MODES) {
      if (mode.id === "xts") continue;
      if (!(mode.keyLengths ?? [32]).includes(32)) continue;
      /*
       * The nonce has to be the length this mode actually wants. C008 returns nothing when the spec
       * does not resolve, so a wrong nonce would make every assertion below pass without the rule
       * ever having been consulted -- the vacuous green this repo keeps running into.
       */
      const nonceLen = requiredNonceLength("aes", mode, undefined);
      const spec = specFor(
        "aes",
        keyed("11".repeat(32), nonceLen > 0 ? "22".repeat(nonceLen) : undefined, {
          [OPTION_MODE]: mode.id,
        }),
      );
      expect(
        resolveCipher(spec).ok,
        `${mode.id} should resolve with a ${nonceLen}-byte nonce`,
      ).toBe(true);
      checked += 1;
      expect(
        lint(spec).diagnostics.some((d) => d.code === "C008"),
        `C008 must not fire under ${mode.id}`,
      ).toBe(false);
    }
    expect(checked, "suspiciously few modes reached the rule").toBeGreaterThan(8);
  });
});

// ──────────────────────────────── the Padding control ──────────────────────────

/**
 * Padding, and the two modes that have any.
 *
 * ECB and CBC are the only modes over a block cipher that pad -- everything else either turns the
 * cipher into a keystream, so the ciphertext is the plaintext's length, or defines its own handling:
 * XTS steals ciphertext so a sector encrypts to exactly a sector, and KW/KWP carry RFC 3394/5649's own
 * scheme, which is what "with padding" in KWP's name refers to. The control is therefore gated on
 * `blockAligned`, and this asserts that gate rather than trusting it.
 */
describe("padding", () => {
  const CBC_KEY = { aes: 32, camellia: 32, des: 8 } as const;

  it("offers the control exactly where a mode is block-aligned", () => {
    const padding = cipherCatalogueFor("aes").options.find((o) => o.id === OPTION_PADDING);
    expect(padding, "AES has a Padding control").toBeDefined();
    expect([...(padding!.availableOn ?? [])].sort()).toEqual(["cbc", "ecb"]);
    expect(
      [...AES_MODES.filter((m) => m.blockAligned).map((m) => m.id)].sort(),
      "and those are exactly the block-aligned modes",
    ).toEqual(["cbc", "ecb"]);

    /*
     * The choice values are the scheme ids, so the form cannot offer something `readPadding` will not
     * accept -- which is how an enum control comes to look configured while computing at a fallback.
     */
    expect(padding!.choices?.map((c) => c.value)).toEqual([...PADDING_SCHEMES]);

    // Every block cipher with a block-aligned mode gets it; a stream or shaped cipher does not.
    for (const tool of CIPHER_TOOLS) {
      const has = cipherCatalogueFor(tool.id).options.some((o) => o.id === OPTION_PADDING);
      const wants =
        tool.id === "aes" ||
        (tool.block?.modes ?? []).some((id) => getAesMode(id)?.blockAligned === true);
      expect(has, `${tool.id} padding control`).toBe(wants);
    }
  });

  it("seeds PKCS#7, and the fallback is the same value", () => {
    for (const id of ["aes", "camellia", "des"]) {
      const spec = createSpec({ variant: id });
      expect(spec.options[OPTION_PADDING], `${id} seed`).toBe("pkcs7");
      /*
       * A key is supplied before resolving: `createSpec` deliberately seeds none, so a bare default
       * spec fails with "Enter a key" and `resolved.padding` was never reached. The first version of
       * this asserted `false === "pkcs7"` and said nothing about padding at all.
       */
      /*
       * A key *and* a nonce, because `createSpec` seeds neither: a bare default AES spec fails with
       * "Enter a key", and once given one it fails again on the 12 bytes GCM wants. The first version
       * of this asserted `false === "pkcs7"` and said nothing about padding at all.
       */
      const keyBytes = id === "des" ? 8 : 32;
      const nonceBytes = requiredNonceLength(id, modeForSpec(spec), undefined);
      const withKey = {
        ...spec,
        options: {
          ...spec.options,
          key: "11".repeat(keyBytes),
          keyEncoding: "hex",
          ...(nonceBytes > 0 ? { nonce: "22".repeat(nonceBytes), nonceEncoding: "hex" } : {}),
        },
      };
      const resolved = resolveCipher(withKey);
      expect(resolved.ok && resolved.resolved.padding, `${id} resolved`).toBe("pkcs7");
    }

    /*
     * A spec from before the control existed -- an older share link, saved state -- has to compute
     * exactly as it did, which is what makes seeding a change to what the form *shows* only.
     */
    const bare = createSpec({ variant: "aes" });
    const options = {
      ...bare.options,
      key: "11".repeat(32),
      keyEncoding: "hex",
      nonce: "22".repeat(12),
      nonceEncoding: "hex",
    };
    delete (options as Record<string, unknown>)[OPTION_PADDING];
    const resolved = resolveCipher({ ...bare, options });
    expect(resolved.ok && resolved.resolved.padding).toBe("pkcs7");
  });

  /**
   * The control reaches the cipher, which is the half a catalogue test cannot see.
   *
   * Four schemes over one plaintext give four different ciphertexts; an ignored option gives four
   * identical ones, which is exactly how AEGIS's tag length was inert with a green suite. The input is
   * already block-aligned, since None refuses anything else by design -- and that also makes this the
   * case where PKCS#7 adds a whole block, so the four differ in length as well as in content.
   */
  it("changes the ciphertext, for AES and for the shared mode layer", async () => {
    for (const [variant, block] of [
      ["aes", 16],
      ["camellia", 16],
      ["des", 8],
    ] as const) {
      const plaintext = "ab".repeat(block * 2);
      const seen = new Set<string>();
      const byScheme = new Map<string, string>();
      for (const scheme of PADDING_SCHEMES) {
        const options = keyed("11".repeat(CBC_KEY[variant]), "22".repeat(block), {
          [OPTION_MODE]: "cbc",
          [OPTION_PADDING]: scheme,
        });
        const sealed = await run(variant, options, fromHex(plaintext));
        seen.add(encodeHex(sealed.bytes!));
        byScheme.set(scheme, encodeHex(sealed.bytes!));

        // And back through our own unpadding, which is what says it matches the padding rather than
        // merely differing from its neighbours.
        const back = await run(
          variant,
          { ...options, [OPTION_DIRECTION]: "decrypt" },
          sealed.bytes!,
        );
        expect(encodeHex(back.bytes!), `${variant}/${scheme} round trip`).toBe(plaintext);
      }
      /*
       * Six distinct answers from seven schemes, because PKCS#5 *is* PKCS#7 -- which is the property
       * both are offered for, and is asserted directly rather than hidden inside a count. An ignored
       * option would give one answer for all seven, which is the defect this looks for.
       */
      expect(
        seen.size,
        `${variant}: expected six distinct ciphertexts from seven schemes`,
      ).toBe(PADDING_SCHEMES.length - 1);
      expect(
        byScheme.get("pkcs5"),
        `${variant}: PKCS#5 must be byte-for-byte PKCS#7 -- that is why both are listed`,
      ).toBe(byScheme.get("pkcs7"));
    }
  });

  /**
   * None refuses an unaligned input rather than inventing a rule, and says how to proceed.
   *
   * Refused in `compute` rather than in the resolver, because the resolver never sees the input -- the
   * same place Ascon-PRFShort's length cap is enforced, and the reason `computeCipher` wraps the whole
   * operation in a `try`.
   */
  it("refuses an unaligned input under None, naming the way out", async () => {
    const out = await cipherToolDefinition("aes").compute(
      specFor(
        "aes",
        keyed("11".repeat(32), "22".repeat(16), {
          [OPTION_MODE]: "cbc",
          [OPTION_PADDING]: "none",
        }),
      ),
      new Uint8Array(17),
    );
    expect(out.error, "17 bytes is not whole blocks").toBeDefined();
    expect(out.error).toMatch(/whole number of 16-byte blocks/);
    expect(out.error, "and it says what to do").toMatch(/padding scheme|trim/i);
  });

  /**
   * The failed-decrypt message names the scheme in force.
   *
   * It was fixed at "PKCS#7", written when that was the only scheme -- a sentence that cannot follow a
   * dropdown, which is the defect the deleted `securityNote` field kept producing.
   */
  it("names the selected scheme when decryption fails", async () => {
    const wrongKey = async (scheme: string) =>
      (
        await cipherToolDefinition("aes").compute(
          specFor(
            "aes",
            keyed("99".repeat(32), "22".repeat(16), {
              [OPTION_MODE]: "cbc",
              [OPTION_PADDING]: scheme,
              [OPTION_DIRECTION]: "decrypt",
            }),
          ),
          fromHex("ab".repeat(32)),
        )
      ).error ?? "";

    expect(await wrongKey("pkcs7")).toMatch(/PKCS#7 padding is invalid/);
    expect(await wrongKey("iso7816")).toMatch(/ISO 9797-1 method 2 padding is invalid/);
    expect(await wrongKey("x923")).toMatch(/ANSI X9\.23 padding is invalid/);
  });
});

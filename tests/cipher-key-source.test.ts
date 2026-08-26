import { describe, expect, it } from "vitest";
import {
  AES_MODES,
  CIPHER_TOOLS,
  OPTION_DIRECTION,
  OPTION_MODE,
  type CipherSpec,
} from "@ocs/cipher";
import {
  cipherCatalogueFor,
  cipherToolDefinition,
  createSpec,
  lint,
  resolveCipher,
} from "@ocs/cipher/definition";
import {
  KDF_DERIVES,
  KEY_SOURCES,
  OPTION_KDF_DERIVES,
  OPTION_KEY_SOURCE,
} from "@ocs/kdf/key-source";
import { encodeHex, isAvailableOn } from "@ocs/engine";

/**
 * Deriving a cipher key from a password.
 *
 * The point of the feature is interoperability, so the assertions that matter are against the
 * *installed OpenSSL* rather than against a round trip. A round trip cannot see a key and an IV
 * swapped -- both directions would agree with each other perfectly and with nothing else in existence,
 * which is this repo's most-repeated failure mode.
 *
 * The fixtures below were produced by the commands in each comment, against OpenSSL 3.5.7. Two facts
 * about `openssl enc` are worth recording because they are not obvious and they decide what maps onto
 * what:
 *
 * - **`-S <hex>` uses that salt and writes no `Salted__` header.** So an explicit salt with
 *   `Envelope: None` is the deterministic case, and it is what most of these check.
 * - **Omitting `-S` generates a random salt and *does* write the header.** So `Envelope: OpenSSL` with
 *   an empty salt field is that case, and it is deliberately not reproducible -- `C013` says so.
 *
 * There is no OpenSSL invocation that salts *and* omits the header, so `Envelope: OpenSSL` with an
 * explicit salt is a superset of what the CLI can do rather than a case with a reference value.
 */

const utf8 = (text: string) => new TextEncoder().encode(text);
const fromHex = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));

function specFor(options: Record<string, unknown>, variant = "aes"): CipherSpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } } as CipherSpec;
}

const run = (options: Record<string, unknown>, input: Uint8Array, variant = "aes") =>
  cipherToolDefinition(variant).compute(specFor(options, variant), input);

/** A password and an explicit salt, which is the reproducible shape. */
const PASSWORD = {
  password: "hunter2",
  passwordEncoding: "utf-8",
  kdfSalt: "0011223344556677",
  kdfSaltEncoding: "hex",
};

describe("key source: openssl enc interoperability", () => {
  // printf '123456789' | openssl enc -aes-256-cbc -pbkdf2 -iter 10000 -S 0011223344556677 \
  //   -pass pass:hunter2 | xxd -p
  it("PBKDF2-SHA256 at 10,000 iterations, AES-256-CBC", async () => {
    const out = await run(
      {
        ...PASSWORD,
        [OPTION_MODE]: "cbc",
        [OPTION_KEY_SOURCE]: "pbkdf2",
        pbkdf2Iterations: 10000,
      },
      utf8("123456789"),
    );
    expect(out.error).toBeUndefined();
    expect(encodeHex(out.bytes!)).toBe("2a36645fdc30bcee17351ec19106e5f6");
  });

  // printf '123456789' | openssl enc -aes-256-cbc -k hunter2 -S 0011223344556677 -md sha256 | xxd -p
  it("EvpKDF-SHA256, AES-256-CBC", async () => {
    const out = await run(
      { ...PASSWORD, [OPTION_MODE]: "cbc", [OPTION_KEY_SOURCE]: "evpkdf" },
      utf8("123456789"),
    );
    expect(encodeHex(out.bytes!)).toBe("2da8751e0176daa801427e546d400972");
  });

  /**
   * EvpKDF over MD5 at AES-128, which is the shape CryptoJS's `AES.encrypt(msg, "pass")` uses.
   *
   * Worth its own case rather than folding into the one above: the hash, the key size and the count
   * are all different, and this is the combination people arrive with when they are trying to read
   * something a JavaScript front end wrote.
   */
  // printf '123456789' | openssl enc -aes-128-cbc -k hunter2 -S 0011223344556677 -md md5 | xxd -p
  it("EvpKDF-MD5, AES-128-CBC -- the CryptoJS shape", async () => {
    const out = await run(
      {
        ...PASSWORD,
        [OPTION_MODE]: "cbc",
        [OPTION_KEY_SOURCE]: "evpkdf",
        kdfHash: "md5",
        keySize: "128",
      },
      utf8("123456789"),
    );
    expect(encodeHex(out.bytes!)).toBe("73d3fa49fe6a85d4cc72bb4779fd5cbb");
  });

  // printf 'hello world' | openssl enc -aes-256-cbc -pbkdf2 -iter 10000 -pass pass:hunter2 | xxd -p
  it("decrypts a Salted__ envelope OpenSSL actually produced", async () => {
    const blob = fromHex("53616c7465645f5fbb1d626afdfbd956ae8a2ff9a107fc8f4f4d3c18cee6dc9f");
    const out = await run(
      {
        password: "hunter2",
        passwordEncoding: "utf-8",
        [OPTION_MODE]: "cbc",
        [OPTION_KEY_SOURCE]: "pbkdf2",
        pbkdf2Iterations: 10000,
        kdfEnvelope: "openssl",
        [OPTION_DIRECTION]: "decrypt",
      },
      blob,
    );
    expect(out.error).toBeUndefined();
    expect(new TextDecoder().decode(out.bytes!)).toBe("hello world");
  });

  /**
   * A malformed envelope is refused rather than decrypted as ciphertext.
   *
   * Sixteen bytes of a real ciphertext would otherwise be eaten as a header and the rest decrypted to
   * rubbish -- a wrong answer with no error, which is the outcome this repo spends its effort on.
   */
  it("refuses input that is not an envelope, naming what was expected", async () => {
    const out = await run(
      {
        ...PASSWORD,
        [OPTION_MODE]: "cbc",
        [OPTION_KEY_SOURCE]: "pbkdf2",
        kdfEnvelope: "openssl",
        [OPTION_DIRECTION]: "decrypt",
      },
      fromHex("00".repeat(32)),
    );
    expect(out.error).toMatch(/Salted__/);
  });
});

describe("key source: what is derived", () => {
  /**
   * `Key and IV` versus `Key only`, which is the whole of the first design decision.
   *
   * The two must differ, and `Key only` must actually use the IV field -- a mode that ignored it would
   * produce the `Key and IV` answer while showing a field that did nothing.
   */
  it("Key only uses the entered IV; Key and IV does not", async () => {
    const shared = { ...PASSWORD, [OPTION_MODE]: "cbc", [OPTION_KEY_SOURCE]: "pbkdf2" };
    const derivedBoth = await run({ ...shared, kdfDerives: "key-iv" }, utf8("123456789"));
    const keyOnly = await run(
      { ...shared, kdfDerives: "key", nonce: "22".repeat(16), nonceEncoding: "hex" },
      utf8("123456789"),
    );
    const keyOnlyOther = await run(
      { ...shared, kdfDerives: "key", nonce: "33".repeat(16), nonceEncoding: "hex" },
      utf8("123456789"),
    );

    expect(derivedBoth.error).toBeUndefined();
    expect(keyOnly.error).toBeUndefined();
    expect(encodeHex(keyOnly.bytes!)).not.toBe(encodeHex(derivedBoth.bytes!));
    expect(
      encodeHex(keyOnly.bytes!),
      "changing the IV must change the answer, or the field is inert",
    ).not.toBe(encodeHex(keyOnlyOther.bytes!));
  });

  it("hides the IV field only while it is being derived", () => {
    const tagsFor = (options: Record<string, unknown>) => {
      const spec = specFor(options);
      const tag = cipherToolDefinition("aes").variantTag?.(spec);
      return tag === undefined ? [] : Array.isArray(tag) ? tag : [tag];
    };
    const nonce = cipherCatalogueFor("aes").require("nonce");

    expect(isAvailableOn(nonce, tagsFor({ [OPTION_MODE]: "cbc" })), "Custom").toBe(true);
    expect(
      isAvailableOn(
        nonce,
        tagsFor({ [OPTION_MODE]: "cbc", [OPTION_KEY_SOURCE]: "pbkdf2", kdfDerives: "key" }),
      ),
      "Key only",
    ).toBe(true);
    expect(
      isAvailableOn(
        nonce,
        tagsFor({ [OPTION_MODE]: "cbc", [OPTION_KEY_SOURCE]: "pbkdf2", kdfDerives: "key-iv" }),
      ),
      "Key and IV",
    ).toBe(false);
    // And ECB still has no IV whatever the key source, which is what the conjunction tag preserves.
    expect(isAvailableOn(nonce, tagsFor({ [OPTION_MODE]: "ecb" })), "ECB").toBe(false);
  });

  it("every source derives a usable key, and the result names which", async () => {
    for (const source of KEY_SOURCES) {
      if (source === "custom") continue;
      const options: Record<string, unknown> = {
        ...PASSWORD,
        [OPTION_MODE]: "cbc",
        [OPTION_KEY_SOURCE]: source,
        // Keep the memory-hard ones small: this is a wiring test, not a cost test.
        ...(source === "scrypt" ? { kdfScryptN: 1024 } : {}),
        ...(source === "argon2" ? { kdfArgon2Memory: 64, kdfArgon2Time: 1 } : {}),
        ...(source === "bcryptpbkdf" ? { kdfBcryptRounds: 4 } : {}),
      };
      const sealed = await run(options, utf8("123456789"));
      expect(sealed.error, source).toBeUndefined();

      const derived = sealed.fields?.find((f) => f.label === "Derived key");
      expect(derived, `${source} should report the derived key`).toBeDefined();
      expect(derived!.value).toHaveLength(64);

      const back = await run({ ...options, [OPTION_DIRECTION]: "decrypt" }, sealed.bytes!);
      expect(back.error, `${source} decrypt`).toBeUndefined();
      expect(encodeHex(back.bytes!), `${source} round trip`).toBe(encodeHex(utf8("123456789")));
    }
  }, 120_000);

  /**
   * An empty salt under the OpenSSL envelope is a fresh random one, as `openssl enc` does.
   *
   * So two runs must differ *and* both must decrypt -- the second half is what says the salt was
   * carried rather than lost. This is the only nondeterministic path the cipher family has.
   */
  it("generates a random salt per run under the envelope, and still round-trips", async () => {
    const options = {
      password: "hunter2",
      passwordEncoding: "utf-8",
      [OPTION_MODE]: "cbc",
      [OPTION_KEY_SOURCE]: "pbkdf2",
      pbkdf2Iterations: 10000,
      kdfEnvelope: "openssl",
    };
    const first = await run(options, utf8("123456789"));
    const second = await run(options, utf8("123456789"));
    expect(encodeHex(first.bytes!)).not.toBe(encodeHex(second.bytes!));
    // "Salted__" is the first eight bytes of both.
    expect(encodeHex(first.bytes!).slice(0, 16)).toBe("53616c7465645f5f");

    const back = await run({ ...options, [OPTION_DIRECTION]: "decrypt" }, first.bytes!);
    expect(back.error).toBeUndefined();
    expect(encodeHex(back.bytes!)).toBe(encodeHex(utf8("123456789")));
  });

  it("asks for a password before anything else", () => {
    const result = resolveCipher(
      specFor({ [OPTION_MODE]: "cbc", [OPTION_KEY_SOURCE]: "pbkdf2" }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.optionId).toBe("password");
  });
});

describe("key source: the diagnostics", () => {
  const codes = (options: Record<string, unknown>) =>
    lint(specFor(options)).diagnostics.map((d) => d.code);

  it("C011 marks EvpKDF, and offers PBKDF2 only when encrypting", () => {
    const encrypting = { ...PASSWORD, [OPTION_MODE]: "cbc", [OPTION_KEY_SOURCE]: "evpkdf" };
    expect(codes(encrypting)).toContain("C011");

    const found = lint(specFor(encrypting)).diagnostics.find((d) => d.code === "C011");
    expect(found!.level).toBe("insecure");
    const fixed = found!.fix!.apply(specFor(encrypting));
    expect(fixed.options[OPTION_KEY_SOURCE]).toBe("pbkdf2");

    /*
     * No fix while decrypting: the KDF has to match whatever wrote the data, so offering to change it
     * would be offering to break the task. Same reasoning C009's encrypt-only fix follows.
     */
    const decrypting = lint(
      specFor({ ...encrypting, [OPTION_DIRECTION]: "decrypt" }),
    ).diagnostics.find((d) => d.code === "C011");
    expect(decrypting, "still reported").toBeDefined();
    expect(decrypting!.fix, "but not fixable").toBeUndefined();
  });

  /**
   * C012 fires *below* OpenSSL's own default rather than below OWASP's figure.
   *
   * 10,000 is what `openssl enc -pbkdf2` writes, so warning at it would be warning about the tool's
   * commonest legitimate use -- which is how a checks panel stops being read. `F007` makes the same
   * call about 16 random bytes.
   */
  it("C012 fires below 10,000 iterations and not at it", () => {
    const at = (iterations: number) =>
      codes({
        ...PASSWORD,
        [OPTION_MODE]: "cbc",
        [OPTION_KEY_SOURCE]: "pbkdf2",
        pbkdf2Iterations: iterations,
      });
    expect(at(1000)).toContain("C012");
    expect(at(10000), "OpenSSL's own default must not be scolded").not.toContain("C012");
    expect(at(600000)).not.toContain("C012");
  });

  it("C013 marks the random-salt envelope, and stays quiet with a salt or on decrypt", () => {
    const envelope = {
      password: "hunter2",
      passwordEncoding: "utf-8",
      [OPTION_MODE]: "cbc",
      [OPTION_KEY_SOURCE]: "pbkdf2",
      kdfEnvelope: "openssl",
    };
    expect(codes(envelope)).toContain("C013");
    expect(
      codes({ ...envelope, ...PASSWORD }),
      "an explicit salt is reproducible",
    ).not.toContain("C013");
    expect(
      codes({ ...envelope, [OPTION_DIRECTION]: "decrypt" }),
      "decrypting reads the salt, it does not invent one",
    ).not.toContain("C013");
  });

  /**
   * C006 and C008 read key *bytes*, which do not exist until compute has derived them.
   *
   * Staying quiet is the honest answer, and it is the rule the last three rounds established: a
   * diagnostic may only draw conclusions from values the selected configuration actually uses.
   */
  it("C006 and C008 stand down for a derived key", () => {
    const weak = {
      password: "hunter2",
      passwordEncoding: "utf-8",
      kdfSalt: "0011223344556677",
      kdfSaltEncoding: "hex",
      [OPTION_KEY_SOURCE]: "pbkdf2",
      [OPTION_MODE]: "ecb",
    };
    // A DES key of all-zero parity bytes is one of the four weak keys; typed in, C006 says so.
    expect(
      lint(
        specFor({ key: "0101010101010101", keyEncoding: "hex", [OPTION_MODE]: "ecb" }, "des"),
      ).diagnostics.map((d) => d.code),
    ).toContain("C006");
    expect(lint(specFor(weak, "des")).diagnostics.map((d) => d.code)).not.toContain("C006");

    const xts = {
      ...weak,
      [OPTION_MODE]: "xts",
      nonce: "33".repeat(16),
      nonceEncoding: "hex",
      kdfDerives: "key",
    };
    expect(lint(specFor(xts)).diagnostics.map((d) => d.code)).not.toContain("C008");
  });
});

/**
 * No option may be unreachable in every configuration of its tool.
 *
 * The gate the cipher family did not have, and the reason it now does. `variantTag` returned
 * `undefined` for the 45 tools with no mode -- ChaCha20-Poly1305, XChaCha, Ascon, Salsa, AEGIS and
 * every shaped cipher -- and `isAvailableOn` reads a missing tag as "not available". So gating the Key
 * field on a key-source tag would have deleted the key input for those 45, and it would have
 * typechecked and passed the whole suite, because every other test writes option values straight into
 * a spec rather than through the form. That is the MAC family's four-inert-controls defect, shipped a
 * fourth time.
 *
 * The cross product rather than the default spec, which was the first version of this test and was
 * wrong: `padding` needs ECB or CBC and `tagLen` needs CCM or OCB, so both are correctly hidden on a
 * tool whose default mode is GCM. What is a bug is an option no configuration can reach.
 *
 * Verified by reverting the `variantTag` change: 1,615 of 2,071 options become unreachable, `aes: key`
 * among them.
 */
describe("option reachability", () => {
  it("every cipher option renders in at least one configuration", () => {
    const unreachable: string[] = [];
    let checked = 0;
    for (const tool of CIPHER_TOOLS) {
      const definition = cipherToolDefinition(tool.id);
      const base = createSpec({ variant: tool.id });
      const modes: readonly (string | undefined)[] =
        tool.id === "aes"
          ? AES_MODES.map((m) => m.id)
          : [...(tool.block?.modes ?? [undefined])];

      const reachable = new Set<string>();
      for (const mode of modes) {
        for (const source of KEY_SOURCES) {
          for (const derives of KDF_DERIVES) {
            const spec = {
              ...base,
              options: {
                ...base.options,
                ...(mode ? { [OPTION_MODE]: mode } : {}),
                [OPTION_KEY_SOURCE]: source,
                [OPTION_KDF_DERIVES]: derives,
              },
            } as CipherSpec;
            const tag = definition.variantTag?.(spec);
            const tags = tag === undefined ? [] : Array.isArray(tag) ? tag : [tag];
            for (const option of cipherCatalogueFor(tool.id).options) {
              if (isAvailableOn(option, tags)) reachable.add(option.id);
            }
          }
        }
      }
      for (const option of cipherCatalogueFor(tool.id).options) {
        checked += 1;
        if (!reachable.has(option.id)) unreachable.push(`${tool.id}: ${option.id}`);
      }
    }
    // Guards the guard: a broken sweep would pass by checking almost nothing.
    expect(checked, "suspiciously few options swept").toBeGreaterThan(1500);
    expect(unreachable).toEqual([]);
  }, 120_000);
});

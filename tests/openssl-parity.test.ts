import {
  createHash,
  createHmac,
  getHashes,
  generateKeyPairSync,
  sign,
  verify,
  constants,
} from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { LOREM } from "../apps/web/app/test-inputs";
import { HASH_ALGORITHMS } from "@ocs/hash";
import { hashToolDefinition, prepareHashAlgorithm } from "@ocs/hash/definition";
import { HMAC_HASHES, OPTION_HASH as MAC_OPTION_HASH, OPTION_KEY } from "@ocs/mac";
import { macToolDefinition } from "@ocs/mac/definition";
import {
  OPTION_HASH,
  OPTION_OPERATION,
  OPTION_PRIVATE_KEY,
  OPTION_SCHEME,
  OPTION_SIGNATURE,
  RSA_HASHES,
} from "@ocs/asymmetric";
import { asymmetricToolDefinition } from "@ocs/asymmetric/definition";
import { PKCS1_DIGEST_INFO_PREFIX } from "@ocs/algos";
import { encodeHex } from "@ocs/engine";

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
 * Byte-for-byte parity with OpenSSL, for everything OpenSSL names.
 *
 * Node's `crypto` is OpenSSL, which makes it the one reference that covers exactly the
 * algorithm set someone arriving from `openssl dgst` or `crypto.getHashes()` expects. This
 * file is the gate for the claim that this app matches it: every distinct digest, HMAC over
 * every digest that has a standard HMAC, and RSA signatures under all fourteen hashes OpenSSL
 * will sign with — including the ten `crypto.subtle` refuses.
 *
 * `node:crypto` is banned everywhere else in this repo because it does not exist in a browser
 * and one bundle serves both hosts. A test does not ship; eslint permits the import under
 * `tests/**` only. See the "Test oracles" section of CLAUDE.md.
 *
 * The completeness assertions at the bottom are the part that makes this a gate rather than a
 * spot check: a name OpenSSL grows that nothing here accounts for fails the suite.
 */

const ascii = (text: string) => new TextEncoder().encode(text);

/**
 * Inputs chosen to cross the boundaries digests actually get wrong: nothing, less than one
 * block, exactly one block for both the 64- and 128-byte families, one over, and something
 * long enough to need several.
 */
const INPUTS: readonly { label: string; bytes: Uint8Array }[] = [
  { label: "empty", bytes: new Uint8Array(0) },
  { label: '"abc"', bytes: ascii("abc") },
  { label: "55 bytes", bytes: seq(55) },
  { label: "64 bytes (one 512-bit block)", bytes: seq(64) },
  { label: "65 bytes", bytes: seq(65) },
  { label: "128 bytes (one 1024-bit block)", bytes: seq(128) },
  { label: "1000 bytes", bytes: seq(1000) },
  /**
   * The app's own Lorem test input, 3,824 bytes of prose.
   *
   * Added here rather than in a file of its own because every loop below already walks this array --
   * so one entry buys the nineteen digests, the sixteen HMACs and all fifteen RSA hashes over a
   * multi-kilobyte input, checked against OpenSSL. It is the string the Test input menu offers, so a
   * value somebody compares against this app by hand is the value this asserts.
   *
   * What it adds over `seq(1000)`: 3,824 bytes is fifty-nine and three quarter 64-byte blocks, so the
   * block loop runs dozens of times and the length field spans two bytes; and it is *text*, so a
   * mistake in the ASCII path rather than the byte path has somewhere to show.
   */
  { label: "Lorem ipsum (3,824 bytes)", bytes: ascii(LOREM) },
];

/** A deterministic byte pattern — no randomness, so a failure is always reproducible. */
function seq(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 37 + 11) & 0xff;
  return out;
}

/**
 * Every name OpenSSL exposes, mapped to the tool in this app that must reproduce it.
 *
 * Written out in full rather than matched by digest value, deliberately. Grouping by output
 * would only prove that *something* here happens to agree; naming each alias proves the
 * mapping is understood, and the completeness check below turns a newly-added OpenSSL name
 * into a test failure rather than a silent gap.
 *
 * `outputLength` is set where OpenSSL fixes a length that is not our default — SHAKE is an
 * XOF and has no natural size, so OpenSSL picked 16 and 32 bytes for its two entries.
 */
interface DigestMapping {
  /** This repo's hash tool id. */
  id: string;
  /** Every `crypto.getHashes()` name that must equal it. */
  aliases: readonly string[];
  /** Passed as the tool's `outputLength` option when OpenSSL's size is not our default. */
  outputLength?: number;
}

const DIGEST_MAP: readonly DigestMapping[] = [
  { id: "md5", aliases: ["md5", "RSA-MD5", "md5WithRSAEncryption", "ssl3-md5"] },
  {
    id: "ripemd160",
    aliases: ["ripemd160", "ripemd", "rmd160", "RSA-RIPEMD160", "ripemd160WithRSA"],
  },
  {
    id: "sha1",
    // `RSA-SHA1-2` is OpenSSL's second OID for the same signature algorithm, and `ssl3-sha1`
    // differs from SHA-1 only inside SSLv3's MAC construction, not as a digest.
    aliases: ["sha1", "RSA-SHA1", "RSA-SHA1-2", "sha1WithRSAEncryption", "ssl3-sha1"],
  },
  { id: "sha224", aliases: ["sha224", "RSA-SHA224", "sha224WithRSAEncryption"] },
  { id: "sha256", aliases: ["sha256", "RSA-SHA256", "sha256WithRSAEncryption"] },
  { id: "sha384", aliases: ["sha384", "RSA-SHA384", "sha384WithRSAEncryption"] },
  { id: "sha512", aliases: ["sha512", "RSA-SHA512", "sha512WithRSAEncryption"] },
  {
    id: "sha512-224",
    aliases: ["sha512-224", "RSA-SHA512/224", "sha512-224WithRSAEncryption"],
  },
  {
    id: "sha512-256",
    aliases: ["sha512-256", "RSA-SHA512/256", "sha512-256WithRSAEncryption"],
  },
  {
    id: "sha3-224",
    aliases: ["sha3-224", "RSA-SHA3-224", "id-rsassa-pkcs1-v1_5-with-sha3-224"],
  },
  {
    id: "sha3-256",
    aliases: ["sha3-256", "RSA-SHA3-256", "id-rsassa-pkcs1-v1_5-with-sha3-256"],
  },
  {
    id: "sha3-384",
    aliases: ["sha3-384", "RSA-SHA3-384", "id-rsassa-pkcs1-v1_5-with-sha3-384"],
  },
  {
    id: "sha3-512",
    aliases: ["sha3-512", "RSA-SHA3-512", "id-rsassa-pkcs1-v1_5-with-sha3-512"],
  },
  { id: "sm3", aliases: ["sm3", "RSA-SM3", "sm3WithRSAEncryption"] },
  { id: "blake2b", aliases: ["blake2b512"], outputLength: 64 },
  { id: "blake2s", aliases: ["blake2s256"], outputLength: 32 },
  // OpenSSL exposes SHAKE at one length each; ours is variable, so the length is requested.
  { id: "shake128", aliases: ["shake128"], outputLength: 16 },
  { id: "shake256", aliases: ["shake256"], outputLength: 32 },
  // MD5 ‖ SHA-1: the 36-byte TLS 1.0/1.1 handshake digest.
  { id: "md5-sha1", aliases: ["md5-sha1"] },
];

async function ourDigest(mapping: DigestMapping, input: Uint8Array): Promise<string> {
  const tool = hashToolDefinition(mapping.id);
  const base = tool.createSpec();
  const spec =
    mapping.outputLength === undefined
      ? base
      : { ...base, options: { ...base.options, outputLength: mapping.outputLength } };
  const result = await tool.compute(spec, input);
  expect(result.error, `${mapping.id}: ${result.error}`).toBeUndefined();
  return encodeHex(result.bytes!);
}

describe("digests match OpenSSL", () => {
  for (const mapping of DIGEST_MAP) {
    it(`${mapping.id} equals ${mapping.aliases[0]} on every input`, async () => {
      for (const input of INPUTS) {
        const theirs = createHash(mapping.aliases[0]!).update(input.bytes).digest("hex");
        expect(await ourDigest(mapping, input.bytes), `${mapping.id} over ${input.label}`).toBe(
          theirs,
        );
      }
    });
  }

  it("every alias OpenSSL lists is the same function as the one it is mapped to", () => {
    // One digest each is enough here: this is checking OpenSSL's aliasing, not our arithmetic.
    for (const mapping of DIGEST_MAP) {
      const canonical = createHash(mapping.aliases[0]!).update("abc").digest("hex");
      for (const alias of mapping.aliases) {
        expect(createHash(alias).update("abc").digest("hex"), `${alias} vs ${mapping.id}`).toBe(
          canonical,
        );
      }
    }
  });

  it("accounts for every name in crypto.getHashes()", () => {
    // The gate. An OpenSSL upgrade that adds a digest fails here until someone decides
    // whether this app should offer it — rather than the claim of parity quietly going stale.
    const mapped = new Set(DIGEST_MAP.flatMap((m) => m.aliases));
    const unaccounted = getHashes().filter((name) => !mapped.has(name));
    expect(unaccounted, "OpenSSL digest names this app does not account for").toEqual([]);
  });

  it("maps only to hash tools that actually exist", () => {
    const ours = new Set(HASH_ALGORITHMS.map((a) => a.id));
    for (const mapping of DIGEST_MAP) expect(ours, mapping.id).toContain(mapping.id);
  });
});

// ── HMAC ────────────────────────────────────────────────────────────────────

/**
 * OpenSSL names for the hashes our HMAC tool offers.
 *
 * Not derived from `DIGEST_MAP`, because HMAC is defined only over a hash with a compression
 * block: SHAKE is an extendable-output function with no such structure, and MD5-SHA1 is a
 * concatenation of two hashes rather than one — no standard specifies an HMAC over either, and
 * neither is offered. Everything else is here, which is all sixteen.
 */
const HMAC_OPENSSL_NAME: Readonly<Record<string, string>> = {
  md5: "md5",
  sha1: "sha1",
  ripemd160: "ripemd160",
  sha224: "sha224",
  sha256: "sha256",
  sha384: "sha384",
  sha512: "sha512",
  "sha512-224": "sha512-224",
  "sha512-256": "sha512-256",
  "sha3-224": "sha3-224",
  "sha3-256": "sha3-256",
  "sha3-384": "sha3-384",
  "sha3-512": "sha3-512",
  sm3: "sm3",
  blake2b: "blake2b512",
  blake2s: "blake2s256",
};

/**
 * The hashes HMAC is offered over that this OpenSSL cannot key, with the name it would use if it could.
 *
 * Thirty-two entries, because the HMAC list was widened to everything PHP's `hash_hmac_algos()` offers
 * and OpenSSL keys almost none of them -- MD4 and Whirlpool sit in its legacy provider, RIPEMD-128/256/320
 * were never in it, and Tiger, HAVAL, Snefru, GOST-94 and Streebog need engines or do not exist there at
 * all. Those go through PHP's published HMAC values and the R 50.1.113 vectors in `tests/mac.test.ts`
 * instead.
 *
 * The candidate names are not decoration: the gate below asserts OpenSSL really does *not* know them, so
 * a Node build that gains one fails here rather than quietly losing an oracle it could have had.
 */
const HMAC_NO_OPENSSL: Readonly<Record<string, string>> = {
  md2: "md2",
  md4: "md4",
  ripemd128: "ripemd128",
  ripemd256: "ripemd256",
  ripemd320: "ripemd320",
  whirlpool: "whirlpool",
  snefru: "snefru",
  gost94: "gost",
  "gost94-crypto": "gost-crypto",
  streebog256: "streebog256",
  streebog512: "streebog512",
  "tiger128-3": "tiger128",
  "tiger160-3": "tiger160",
  "tiger192-3": "tiger192",
  "tiger128-4": "tiger128-4",
  "tiger160-4": "tiger160-4",
  "tiger192-4": "tiger192-4",
  "haval128-3": "haval128,3",
  "haval160-3": "haval160,3",
  "haval192-3": "haval192,3",
  "haval224-3": "haval224,3",
  "haval256-3": "haval256,3",
  "haval128-4": "haval128,4",
  "haval160-4": "haval160,4",
  "haval192-4": "haval192,4",
  "haval224-4": "haval224,4",
  "haval256-4": "haval256,4",
  "haval128-5": "haval128,5",
  "haval160-5": "haval160,5",
  "haval192-5": "haval192,5",
  "haval224-5": "haval224,5",
  "haval256-5": "haval256,5",
  // Skein and BLAKE1, which OpenSSL has never carried. They have no published HMAC vector either --
  // see the note on `HMAC_HASHES` for what does stand behind them.
  skein256: "skein256",
  skein512: "skein512",
  skein1024: "skein1024",
  blake224: "blake224",
  blake256: "blake256",
  blake384: "blake384",
  blake512: "blake512",
};

/**
 * Three key lengths, because the block size is what HMAC gets wrong.
 *
 * A key shorter than the block is zero-padded; a key longer than the block is *hashed* first.
 * That second case is the one a wrong `blockLen` in the catalogue breaks — and `blockLen` has
 * no other visible consequence, which is exactly why it needs an oracle. The 200-byte key
 * exceeds every block size here (the largest is SHA-512's 128).
 */
const HMAC_KEYS: readonly { label: string; bytes: Uint8Array }[] = [
  { label: "1 byte", bytes: seq(1) },
  { label: "32 bytes", bytes: seq(32) },
  { label: "200 bytes (longer than every block)", bytes: seq(200) },
];

describe("HMAC matches OpenSSL", () => {
  for (const hash of HMAC_HASHES) {
    const opensslName = HMAC_OPENSSL_NAME[hash.id];
    // The ones OpenSSL cannot key are accounted for by the gate below, not skipped silently.
    if (!opensslName) continue;

    it(`HMAC-${hash.label} equals OpenSSL's, at every key length`, async () => {
      const tool = macToolDefinition("hmac");

      for (const key of HMAC_KEYS) {
        for (const input of INPUTS) {
          const theirs = createHmac(opensslName!, key.bytes).update(input.bytes).digest("hex");
          const base = tool.createSpec();
          const result = await tool.compute(
            {
              ...base,
              options: {
                ...base.options,
                [MAC_OPTION_HASH]: hash.id,
                [OPTION_KEY]: encodeHex(key.bytes),
                keyEncoding: "hex",
              },
            },
            input.bytes,
          );
          expect(result.error, `HMAC-${hash.label}: ${result.error}`).toBeUndefined();
          expect(
            encodeHex(result.bytes!),
            `HMAC-${hash.label}, ${key.label} key, ${input.label}`,
          ).toBe(theirs);
        }
      }
    });
  }

  it("accounts for every hash in the HMAC list, mapped or explicitly unmapped", () => {
    /**
     * Two directions, both of which have to hold.
     *
     * Every entry in `HMAC_HASHES` is either mapped to an OpenSSL digest -- and then checked above at
     * three key lengths -- or listed in `HMAC_NO_OPENSSL`. Nothing may be in neither, which is what
     * stops a newly added hash quietly having no oracle at all.
     */
    const available = new Set(getHashes());
    for (const hash of HMAC_HASHES) {
      const mapped = HMAC_OPENSSL_NAME[hash.id];
      const unmapped = HMAC_NO_OPENSSL[hash.id];
      expect(
        Boolean(mapped) !== Boolean(unmapped),
        `${hash.id} must be either mapped to OpenSSL or listed as unavailable, not both or neither`,
      ).toBe(true);

      if (mapped) expect(available.has(mapped), `OpenSSL lost ${mapped}`).toBe(true);
      if (unmapped) {
        // If this fails, OpenSSL grew a digest this repo could be checking against: move the entry
        // into HMAC_OPENSSL_NAME rather than deleting the assertion.
        expect(
          available.has(unmapped),
          `OpenSSL now knows ${unmapped} — map ${hash.id} to it and get a free oracle`,
        ).toBe(false);
      }
    }
  });

  it("offers HMAC over every OpenSSL digest that has one", () => {
    // The gate for this half: a digest in DIGEST_MAP must either be offered for HMAC or be
    // one of the two the construction does not apply to.
    const noHmac = new Set(["shake128", "shake256", "md5-sha1"]);
    const offered = new Set(HMAC_HASHES.map((h) => h.id));
    const missing = DIGEST_MAP.map((m) => m.id).filter(
      (id) => !offered.has(id) && !noHmac.has(id),
    );
    expect(missing, "OpenSSL digests with no HMAC offered here").toEqual([]);
  });
});

// ── RSA signatures ──────────────────────────────────────────────────────────

/**
 * One 2048-bit key for the whole RSA section, generated by OpenSSL.
 *
 * Exported as PKCS#8 PEM, which is exactly what the tool's private-key field takes — so this
 * also exercises the key-import path against a key this app did not produce.
 */
const rsa = (() => {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicPem: pair.publicKey.export({ type: "spki", format: "pem" }) as string,
    node: pair,
  };
})();

const RSA_MESSAGE = ascii("The quick brown fox jumps over the lazy dog");

async function ourRsaSign(hashId: string, scheme: "pss" | "pkcs1v15"): Promise<Uint8Array> {
  const tool = asymmetricToolDefinition("rsa");
  const base = tool.createSpec();
  const result = await tool.compute(
    {
      ...base,
      options: {
        ...base.options,
        [OPTION_OPERATION]: "sign",
        [OPTION_SCHEME]: scheme,
        [OPTION_HASH]: hashId,
        [OPTION_PRIVATE_KEY]: rsa.privatePem,
      },
    },
    RSA_MESSAGE,
  );
  expect(result.error, `sign ${hashId}/${scheme}: ${result.error}`).toBeUndefined();
  return result.bytes!;
}

async function ourRsaVerify(
  hashId: string,
  scheme: "pss" | "pkcs1v15",
  signature: Uint8Array,
  message: Uint8Array = RSA_MESSAGE,
): Promise<string | undefined> {
  const tool = asymmetricToolDefinition("rsa");
  const base = tool.createSpec();
  const result = await tool.compute(
    {
      ...base,
      options: {
        ...base.options,
        [OPTION_OPERATION]: "verify",
        [OPTION_SCHEME]: scheme,
        [OPTION_HASH]: hashId,
        [OPTION_PRIVATE_KEY]: rsa.privatePem,
        [OPTION_SIGNATURE]: encodeHex(signature),
        signatureEncoding: "hex",
      },
    },
    message,
  );
  expect(result.error, `verify ${hashId}/${scheme}: ${result.error}`).toBeUndefined();
  return result.text;
}

/**
 * Which of `RSA_HASHES` this OpenSSL will actually make an RSA signature with.
 *
 * Not every build will do all fifteen. OpenSSL 3.0 -- which Node 20 ships -- **lists `sm3` in
 * `getHashes()` and then refuses it for signing**, with `error:1C8000AE:Provider routines::digest not
 * allowed`. OpenSSL 3.5, in Node 22 and 24, allows it. So the digest list is not a predictor and the
 * only way to know is to try, which is what the completeness gate at the bottom of this file already
 * does in the other direction.
 *
 * Probed once here so the per-hash tests below can skip the ones this oracle cannot answer, rather
 * than reporting a wrong signature for a hash OpenSSL declined to sign. The pairing matters: this set
 * is used to *skip*, and `completeness` separately asserts that anything OpenSSL **can** sign with is
 * offered by the tool -- so a build that grows a digest fails rather than quietly leaving an oracle
 * unused.
 */
const OPENSSL_SIGNS = new Set(
  RSA_HASHES.filter((hash) => {
    try {
      sign(hash.algosHashId, RSA_MESSAGE, {
        key: rsa.node.privateKey,
        padding: constants.RSA_PKCS1_PADDING,
      });
      return true;
    } catch {
      return false;
    }
  }).map((hash) => hash.algosHashId),
);

/** The reason a hash is skipped, said once so the three call sites below agree. */
const cannotSign = (label: string) =>
  `OpenSSL ${process.versions.openssl} refuses to sign with ${label}. OpenSSL 3.5 -- Node 22 and 24 -- signs with every hash this tool offers.`;

/**
 * And the skip cannot become permanent.
 *
 * OpenSSL 3.5 is what the repo verifies against -- Node 22 and 24 both ship it -- and there every one
 * of the fifteen is signable. Below that it is a known limitation of the provider, and the affected
 * hashes skip with the reason attached rather than failing as though the signatures were wrong.
 */
describe("the OpenSSL signing oracle", () => {
  it("signs every hash the tool offers, on the OpenSSL this repo verifies against", (ctx) => {
    const missing = RSA_HASHES.filter((hash) => !OPENSSL_SIGNS.has(hash.algosHashId)).map(
      (hash) => hash.algosHashId,
    );
    const [major, minor] = process.versions.openssl.split(".").map(Number);
    const modern = (major ?? 0) > 3 || ((major ?? 0) === 3 && (minor ?? 0) >= 5);
    // The note goes on the skip rather than into an assertion message: a vacuous assertion passes and
    // explains nothing, which is the same reasoning the other two oracle guards in this suite record.
    ctx.skip(!modern && missing.length > 0, cannotSign(missing.join(", ")));
    expect(
      missing,
      `OpenSSL ${process.versions.openssl} should sign with every hash the RSA tool offers`,
    ).toEqual([]);
  });
});

describe("RSA signatures match OpenSSL", () => {
  for (const hash of RSA_HASHES) {
    it(`PKCS#1 v1.5 with ${hash.label} is byte-identical to OpenSSL`, async (ctx) => {
      ctx.skip(!OPENSSL_SIGNS.has(hash.algosHashId), cannotSign(hash.label));
      // Deterministic padding, so equality is the strongest statement available — not "each
      // verifies the other's", but "we produce the same bytes".
      const theirs = sign(hash.algosHashId, RSA_MESSAGE, {
        key: rsa.node.privateKey,
        padding: constants.RSA_PKCS1_PADDING,
      });
      const ours = await ourRsaSign(hash.id, "pkcs1v15");
      expect(encodeHex(ours), `${hash.label} signature`).toBe(theirs.toString("hex"));
    });

    it(`PSS with ${hash.label} interoperates with OpenSSL both ways`, async (ctx) => {
      ctx.skip(!OPENSSL_SIGNS.has(hash.algosHashId), cannotSign(hash.label));
      const params = {
        key: rsa.node.privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: hash.outputLen,
      };

      // PSS is randomised, so equality is impossible and mutual verification is the property.
      const ours = await ourRsaSign(hash.id, "pss");
      expect(
        verify(hash.algosHashId, RSA_MESSAGE, { ...params, key: rsa.node.publicKey }, ours),
        `OpenSSL rejected our ${hash.label} PSS signature`,
      ).toBe(true);

      const theirs = sign(hash.algosHashId, RSA_MESSAGE, params);
      expect(await ourRsaVerify(hash.id, "pss", theirs)).toBe("MATCH");
    });

    it(`rejects a tampered ${hash.label} signature under both schemes`, async () => {
      for (const scheme of ["pkcs1v15", "pss"] as const) {
        const signature = await ourRsaSign(hash.id, scheme);
        const tampered = Uint8Array.from(signature);
        tampered[200] = (tampered[200] ?? 0) ^ 0x01;
        expect(await ourRsaVerify(hash.id, scheme, tampered), `${hash.label}/${scheme}`).toBe(
          "NO MATCH",
        );
        // And the untampered one over a different message.
        expect(
          await ourRsaVerify(hash.id, scheme, signature, ascii("a different message")),
          `${hash.label}/${scheme} wrong message`,
        ).toBe("NO MATCH");
      }
    });
  }
});

describe("the PKCS#1 DigestInfo table", () => {
  /**
   * Re-derives every DER prefix from OpenSSL rather than trusting the constant.
   *
   * How the table in `packages/algos/src/rsa.ts` was produced in the first place, run again on
   * every test run: sign with OpenSSL, apply the public operation to recover the padded block,
   * and read off the bytes before the digest. A wrong OID in that table would produce
   * signatures that verify perfectly against themselves and against nothing else — the one
   * failure mode a round-trip test cannot see.
   */
  it("holds the prefix OpenSSL actually emits, for every hash", () => {
    const jwk = rsa.node.publicKey.export({ format: "jwk" }) as { n: string; e: string };
    const nBytes = Buffer.from(jwk.n, "base64url");
    const n = BigInt("0x" + nBytes.toString("hex"));
    const e = BigInt("0x" + Buffer.from(jwk.e, "base64url").toString("hex"));
    const k = nBytes.length;

    const modPowLocal = (base: bigint, exp: bigint, mod: bigint) => {
      let result = 1n;
      let b = base % mod;
      let x = exp;
      while (x > 0n) {
        if (x & 1n) result = (result * b) % mod;
        b = (b * b) % mod;
        x >>= 1n;
      }
      return result;
    };

    /*
     * Filtered rather than skipped whole: this is one test over fifteen hashes, and on an OpenSSL that
     * signs fourteen of them the fourteen are still worth checking. What must not happen is the
     * filter going unmentioned -- the guard above is what says which were left out and why.
     */
    for (const hash of RSA_HASHES.filter((h) => OPENSSL_SIGNS.has(h.algosHashId))) {
      const signature = sign(hash.algosHashId, RSA_MESSAGE, {
        key: rsa.node.privateKey,
        padding: constants.RSA_PKCS1_PADDING,
      });
      const recovered = modPowLocal(BigInt("0x" + signature.toString("hex")), e, n);
      // The leading 0x00 of EM is lost to the integer, so this is k-1 octets.
      const em = Buffer.from(recovered.toString(16).padStart((k - 1) * 2, "0"), "hex");
      // EM is 0x01 || 0xFF… || 0x00 || DigestInfo once that leading zero is gone.
      const t = em.subarray(em.indexOf(0x00, 1) + 1);
      const digest = createHash(hash.algosHashId).update(RSA_MESSAGE).digest();
      const prefix = t.subarray(0, t.length - digest.length);

      expect(
        t.subarray(t.length - digest.length).toString("hex"),
        `${hash.label}: the recovered block does not end in the digest`,
      ).toBe(digest.toString("hex"));
      expect(
        PKCS1_DIGEST_INFO_PREFIX[hash.algosHashId],
        `${hash.label} DigestInfo prefix`,
      ).toBe(prefix.toString("hex"));
    }
  });

  it("covers every hash the RSA tool offers, and nothing it does not", () => {
    expect(Object.keys(PKCS1_DIGEST_INFO_PREFIX).sort()).toEqual(
      RSA_HASHES.map((h) => h.algosHashId).sort(),
    );
  });
});

describe("completeness", () => {
  it("offers every hash OpenSSL will make an RSA signature with", () => {
    // The gate for the RSA half. Any digest OpenSSL can sign with must be in RSA_HASHES;
    // anything it refuses is excluded here for the reason OpenSSL gives.
    const signable = DIGEST_MAP.map((m) => m.id).filter((id) => {
      try {
        sign(id, RSA_MESSAGE, {
          key: rsa.node.privateKey,
          padding: constants.RSA_PKCS1_PADDING,
        });
        return true;
      } catch {
        return false;
      }
    });
    const offered = new Set(RSA_HASHES.map((h) => h.algosHashId));
    expect(
      signable.filter((id) => !offered.has(id)),
      "hashes OpenSSL signs with that the RSA tool does not offer",
    ).toEqual([]);
  });

  it("spells algosHashId the way OpenSSL spells it", () => {
    // Not a coincidence to rely on silently: `algosHashId` is used both as this repo's hash id
    // and, here, as OpenSSL's name. If the two ever diverge for a new hash, this fails rather
    // than the parity tests mysteriously skipping it.
    for (const hash of RSA_HASHES) {
      expect(getHashes(), `${hash.label} -> ${hash.algosHashId}`).toContain(hash.algosHashId);
    }
  });

  it("routes exactly four hashes through WebCrypto and the rest through @ocs/algos", async () => {
    const subtleOk: string[] = [];
    const kp = (await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));

    for (const hash of RSA_HASHES) {
      try {
        await crypto.subtle.importKey(
          "pkcs8",
          pkcs8,
          { name: "RSA-PSS", hash: hash.id },
          true,
          ["sign"],
        );
        subtleOk.push(hash.id);
      } catch {
        /* refused — the pure path is what covers it */
      }
    }

    /**
     * The `webcrypto` flag must reflect what the *browser* supports, not what this host does.
     *
     * Node 24 accepts SHA3-256 and SHA3-384 for RSA and warns that it is experimental; no
     * browser does. Marking those `webcrypto: true` would give a tool that signs on the
     * desktop and fails on the web, which is the exact split the one-bundle-two-hosts rule
     * exists to prevent — so the flag stays false and this asserts only that every hash we
     * *claim* WebCrypto handles really is handled.
     */
    for (const hash of RSA_HASHES.filter((h) => h.webcrypto)) {
      expect(
        subtleOk,
        `${hash.label} is marked webcrypto but crypto.subtle refused it`,
      ).toContain(hash.id);
    }
    expect(
      RSA_HASHES.filter((h) => h.webcrypto)
        .map((h) => h.id)
        .sort(),
    ).toEqual(["SHA-1", "SHA-256", "SHA-384", "SHA-512"]);
  });
});

describe("the in-repo RSA path, checked on hashes WebCrypto also supports", () => {
  /**
   * Exercises `@ocs/algos`'s RSA on SHA-256 — a hash it never handles in the app, because the
   * tool routes SHA-256 to WebCrypto.
   *
   * That is the point. Everywhere else the pure path is tested it is the *only* implementation
   * available, so a systematic error in the padding would have to be caught by OpenSSL alone.
   * Running it against a hash the platform also implements isolates this code: if the padding,
   * the DigestInfo, the MGF1 or the leading-bit clearing were wrong, these two lines would
   * disagree with the platform and with OpenSSL simultaneously.
   */
  it("produces the same PKCS#1 v1.5 signature as OpenSSL for SHA-256", async () => {
    const { rsaPkcs1Sign, rsaPkcs1Verify } = await import("@ocs/algos");
    const { sha256 } = await import("@noble/hashes/sha2.js");
    const key = await pureKeyFromPem();

    const ours = rsaPkcs1Sign(key.priv, "sha256", sha256(RSA_MESSAGE));
    const theirs = sign("sha256", RSA_MESSAGE, {
      key: rsa.node.privateKey,
      padding: constants.RSA_PKCS1_PADDING,
    });
    expect(encodeHex(ours)).toBe(theirs.toString("hex"));
    expect(rsaPkcs1Verify(key.pub, "sha256", sha256(RSA_MESSAGE), new Uint8Array(theirs))).toBe(
      true,
    );
  });

  it("produces a PSS signature for SHA-256 that OpenSSL accepts, and vice versa", async () => {
    const { rsaPssSign, rsaPssVerify } = await import("@ocs/algos");
    const { sha256 } = await import("@noble/hashes/sha2.js");
    const key = await pureKeyFromPem();
    const digest = sha256(RSA_MESSAGE);

    const ours = rsaPssSign(key.priv, digest, seq(32), sha256, 32);
    expect(
      verify(
        "sha256",
        RSA_MESSAGE,
        { key: rsa.node.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        ours,
      ),
      "OpenSSL rejected the in-repo PSS signature",
    ).toBe(true);

    const theirs = sign("sha256", RSA_MESSAGE, {
      key: rsa.node.privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    });
    expect(rsaPssVerify(key.pub, digest, new Uint8Array(theirs), 32, sha256, 32)).toBe(true);
  });

  it("rejects a PSS signature verified with the wrong salt length", async () => {
    const { rsaPssSign, rsaPssVerify } = await import("@ocs/algos");
    const { sha256 } = await import("@noble/hashes/sha2.js");
    const key = await pureKeyFromPem();
    const digest = sha256(RSA_MESSAGE);
    const signature = rsaPssSign(key.priv, digest, seq(32), sha256, 32);
    // A real distinction, not a formality: the salt length is not recoverable from the
    // signature, so both sides have to agree on it independently.
    expect(rsaPssVerify(key.pub, digest, signature, 20, sha256, 32)).toBe(false);
  });
});

/**
 * The test key's numbers, read out of its JWK.
 *
 * The same route the tool takes — `rsaPrivateNumbers` exports a JWK from a `CryptoKey` and
 * parses these eight members — but done here from OpenSSL's own JWK export instead, so the
 * arithmetic is checked against a key representation this repo had no hand in producing.
 */
async function pureKeyFromPem() {
  const jwkPriv = rsa.node.privateKey.export({ format: "jwk" }) as Record<string, string>;
  const int = (member: string) =>
    BigInt("0x" + Buffer.from(jwkPriv[member]!, "base64url").toString("hex"));
  const k = Buffer.from(jwkPriv.n!, "base64url").length;
  const priv = {
    n: int("n"),
    e: int("e"),
    d: int("d"),
    p: int("p"),
    q: int("q"),
    dp: int("dp"),
    dq: int("dq"),
    qi: int("qi"),
    k,
  };
  return { priv, pub: { n: priv.n, e: priv.e, k } };
}

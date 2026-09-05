import { beforeAll, describe, expect, it } from "vitest";
import {
  applyAllFixes,
  createSpec,
  describeSpec,
  DOUBLE_HASH_ITERATIONS,
  HASH_ALGORITHMS,
  HASH_MANIFESTS,
  hasVariableOutput,
  lint,
  maxOutputLen,
  OPTION_HASH_VARIANT,
  OPTION_ITERATIONS,
  OPTION_OUTPUT_LENGTH,
  OPTION_SEED_64,
  OPTION_PASSES,
  OPTION_SEED,
  OPTIONS,
  requireHashAlgorithm,
  resolveOutputLen,
  withIterations,
  withOutputLength,
  withSeed,
  type HashSpec,
  usesInputPanel,
  variantTags,
  OPTION_BLOCK_SIZE,
  OPTION_CUSTOMIZATION,
  OPTION_TUPLE,
} from "@ocs/hash";
import { hashToolDefinition, prepareHashAlgorithm, requireHashBinding } from "@ocs/hash/definition";
import {
  encodeHex,
  isAvailableOn,
  rechunk,
  runStream,
  runStreams,
  validateCatalogue,
} from "@ocs/engine";
import {
  DIGEST_VECTORS,
  DOUBLE_SHA256_VECTORS,
  NO_PUBLISHED_VECTOR,
  SHA3_ADDON_VECTORS,
  XOF_VECTORS,
} from "./vectors";

const ascii = (text: string) => new TextEncoder().encode(text);
const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));

/**
 * Prepare every algorithm before anything else runs, exactly as `loadTool()` does.
 *
 * Only FSB has any setup -- its matrix table is a dynamic import, so the other 138 hash tools are not
 * made to download 266 KB for it. These tests reach `hashToolDefinition` directly and therefore bypass
 * the registry, so they have to do the same thing the registry does.
 */
beforeAll(async () => {
  await Promise.all(HASH_ALGORITHMS.map((meta) => prepareHashAlgorithm(meta.id)));
});

function specFor(algorithm: string, options: HashSpec["options"] = {}): HashSpec {
  return { ...createSpec({ algorithm }), options };
}

describe("published digest vectors", () => {
  for (const vector of DIGEST_VECTORS) {
    const variant = vector.options
      ? ` [${Object.entries(vector.options)
          .map(([k, v]) => `${k}=${v}`)
          .join(" ")}]`
      : "";
    it(`${vector.algorithm}${variant}("${vector.input}") matches ${vector.source}`, async () => {
      const tool = hashToolDefinition(vector.algorithm);
      // `inputHex` wins when present: the input is bytes the standard gave in hex, and `input` is
      // then a description of them rather than the bytes themselves.
      const message =
        vector.inputHex === undefined ? ascii(vector.input) : fromHex(vector.inputHex);
      const result = await tool.compute(
        specFor(vector.algorithm, vector.options ?? {}),
        message,
      );
      expect(result.error).toBeUndefined();
      expect(encodeHex(result.bytes!)).toBe(vector.hex);
    });
  }
});

describe("published XOF vectors", () => {
  for (const vector of XOF_VECTORS) {
    it(`${vector.algorithm}("${vector.input}") at ${vector.outputLen} bytes matches ${vector.source}`, async () => {
      const tool = hashToolDefinition(vector.algorithm);
      const spec = specFor(vector.algorithm, withOutputLength({}, vector.outputLen));
      const result = await tool.compute(spec, ascii(vector.input));
      expect(result.bytes).toHaveLength(vector.outputLen);
      expect(encodeHex(result.bytes!)).toBe(vector.hex);
    });
  }

  it("Keccak is not silently wired to SHA-3", async () => {
    /**
     * The one bug that would make the Keccak entries worthless while every digest
     * still looked plausible: binding `keccak-256` to `sha3_256`. The two differ only
     * in a padding byte, so the output is a well-formed 32-byte value either way and
     * nothing about it looks wrong.
     *
     * This check does not depend on the Keccak vectors above — it pairs each Keccak
     * entry against its SHA-3 twin, whose values are transcribed from FIPS 202, and
     * requires them to disagree. That makes it independent evidence for the two
     * Keccak lengths (224, 384) whose own vectors come from the reference
     * implementation rather than a separate standards document.
     */
    const pairs: [string, string][] = [
      ["keccak-224", "sha3-224"],
      ["keccak-256", "sha3-256"],
      ["keccak-384", "sha3-384"],
      ["keccak-512", "sha3-512"],
    ];

    for (const [keccak, sha3] of pairs) {
      const k = await hashToolDefinition(keccak).compute(specFor(keccak), ascii("abc"));
      const s = await hashToolDefinition(sha3).compute(specFor(sha3), ascii("abc"));
      expect(k.bytes!.length, `${keccak} length`).toBe(s.bytes!.length);
      expect(encodeHex(k.bytes!), `${keccak} must differ from ${sha3}`).not.toBe(
        encodeHex(s.bytes!),
      );
    }
  });

  it("every algorithm ships at least one published vector", () => {
    // The rule this repo holds itself to: a tool does not get registered until it
    // reproduces a value from the document that defines it.
    const covered = new Set([
      ...DIGEST_VECTORS.map((v) => v.algorithm),
      ...XOF_VECTORS.map((v) => v.algorithm),
      ...SHA3_ADDON_VECTORS.map((v) => v.algorithm),
      // Four algorithms NIST publishes no sample values for. Justified in writing where that
      // list is defined, and covered by property tests instead -- not silently skipped.
      ...NO_PUBLISHED_VECTOR,
    ]);
    const uncovered = HASH_ALGORITHMS.map((a) => a.id).filter((id) => !covered.has(id));
    expect(uncovered, "algorithms with no published test vector").toEqual([]);
  });
});

describe("output modes", () => {
  it("an XOF's shorter output is a prefix of its longer one", async () => {
    for (const meta of HASH_ALGORITHMS.filter((a) => a.outputMode === "xof")) {
      const tool = hashToolDefinition(meta.id);
      const long = await tool.compute(specFor(meta.id, withOutputLength({}, 48)), ascii("abc"));
      const short = await tool.compute(
        specFor(meta.id, withOutputLength({}, 16)),
        ascii("abc"),
      );
      expect(encodeHex(short.bytes!), `${meta.id} prefix property`).toBe(
        encodeHex(long.bytes!.subarray(0, 16)),
      );
    }
  });

  it("a parameterized algorithm's shorter output is NOT a prefix", async () => {
    // The distinction H004 exists to explain. If this ever starts passing as a
    // prefix, either the binding stopped passing dkLen into initialisation or the
    // algorithm was misclassified — both produce digests that match nothing.
    //
    // `truncation: true` is the declared exception: Tiger-128 genuinely IS the first 16 bytes of
    // Tiger-192, and the next test pins that from the other side. An algorithm that declared
    // neither would be untested, so the two together have to cover the whole parameterized set.
    for (const meta of HASH_ALGORITHMS.filter(
      (a) => a.outputMode === "parameterized" && a.truncation !== true,
    )) {
      const tool = hashToolDefinition(meta.id);
      const longLen = maxOutputLen(meta);
      // The smallest length the algorithm declares, or 16 for one whose lengths are a range. This was
      // a hardcoded 16 until CityHash, SpookyHash, MetroHash and t1ha arrived topping out *at* 16 --
      // at which point the two lengths coincided and the assertion compared a digest with itself.
      const shortLen = meta.outputLengths ? meta.outputLengths[0]! : 16;
      expect(shortLen, `${meta.id} needs two distinct lengths to compare`).toBeLessThan(longLen);
      const long = await tool.compute(
        specFor(meta.id, withOutputLength({}, longLen)),
        ascii("abc"),
      );
      const short = await tool.compute(
        specFor(meta.id, withOutputLength({}, shortLen)),
        ascii("abc"),
      );
      expect(encodeHex(short.bytes!), `${meta.id} must not be a prefix`).not.toBe(
        encodeHex(long.bytes!.subarray(0, shortLen)),
      );
    }
  });

  it("a truncating algorithm's shorter output IS a prefix", async () => {
    /**
     * The other half of the rule above, and the reason `truncation` is on the metadata at all.
     *
     * Both kinds look identical in the form -- one select, a few lengths -- and someone truncating
     * a digest by hand gets a right answer for Tiger and a wrong one for HAVAL. If this ever fails,
     * Tiger's binding stopped truncating and started re-initialising.
     */
    const truncating = HASH_ALGORITHMS.filter((a) => a.truncation === true);
    expect(truncating.length, "at least one truncating algorithm").toBeGreaterThan(0);
    for (const meta of truncating) {
      const lengths = meta.outputLengths!;
      const longest = lengths[lengths.length - 1]!;
      const tool = hashToolDefinition(meta.id);
      const long = await tool.compute(
        specFor(meta.id, { outputLength: String(longest) }),
        ascii("abc"),
      );
      for (const shorter of lengths.slice(0, -1)) {
        const short = await tool.compute(
          specFor(meta.id, { outputLength: String(shorter) }),
          ascii("abc"),
        );
        expect(encodeHex(short.bytes!), `${meta.id} at ${shorter} must be a prefix`).toBe(
          encodeHex(long.bytes!.subarray(0, shorter)),
        );
      }
    }
  });

  it("snaps an off-list output length to the default instead of rounding it", async () => {
    /**
     * A range is clamped; a list is snapped. Rounding 17 up to 20 for HAVAL would invent a
     * function -- there is no 136-bit HAVAL -- and a stale `outputLength` of 5000 left over from
     * SHAKE has to land somewhere defensible rather than on the largest legal value by accident.
     */
    const listed = HASH_ALGORITHMS.filter((a) => a.outputLengths);
    expect(listed.length, "at least one choice-set algorithm").toBeGreaterThan(0);
    for (const meta of listed) {
      const tool = hashToolDefinition(meta.id);
      for (const off of ["17", "5000", "0", "not a number"]) {
        const result = await tool.compute(
          specFor(meta.id, { outputLength: off }),
          ascii("abc"),
        );
        expect(result.bytes, `${meta.id} given ${off}`).toHaveLength(meta.outputLen);
      }
      // And every value that IS on the list is honoured.
      for (const legal of meta.outputLengths!) {
        const result = await tool.compute(
          specFor(meta.id, { outputLength: String(legal) }),
          ascii("abc"),
        );
        expect(result.bytes, `${meta.id} given ${legal}`).toHaveLength(legal);
      }
    }
  });

  it("a fixed-output algorithm ignores a stale outputLength option", async () => {
    // Switching from SHAKE256 to SHA-256 leaves `outputLength` behind in the spec.
    // It must not be able to change SHA-256's answer.
    const tool = hashToolDefinition("sha256");
    const withStale = await tool.compute(
      specFor("sha256", withOutputLength({}, 7)),
      ascii("abc"),
    );
    const clean = await tool.compute(specFor("sha256"), ascii("abc"));
    expect(withStale.bytes).toHaveLength(32);
    expect(encodeHex(withStale.bytes!)).toBe(encodeHex(clean.bytes!));
  });

  it("clamps a request above the algorithm's ceiling rather than failing", async () => {
    // Ranges only. A choice set snaps instead, which the test above covers -- clamping there would
    // silently promote an illegal length to the largest legal one.
    for (const meta of HASH_ALGORITHMS.filter(
      (a) => hasVariableOutput(a) && !a.outputLengths,
    )) {
      const tool = hashToolDefinition(meta.id);
      const result = await tool.compute(
        specFor(meta.id, withOutputLength({}, 5000)),
        ascii("abc"),
      );
      expect(result.bytes, `${meta.id} clamped length`).toHaveLength(maxOutputLen(meta));
    }
  });

  it("resolveOutputLen agrees with what compute actually produces", async () => {
    for (const meta of HASH_ALGORITHMS) {
      for (const requested of [undefined, 1, 16, 64, 5000]) {
        const tool = hashToolDefinition(meta.id);
        const options = requested === undefined ? {} : withOutputLength({}, requested);
        const result = await tool.compute(specFor(meta.id, options), ascii("abc"));
        const predicted = resolveOutputLen(
          meta,
          hasVariableOutput(meta) ? requested : undefined,
        );
        expect(result.bytes, `${meta.id} @ ${requested}`).toHaveLength(predicted);
      }
    }
  });

  /**
   * The same agreement, under *every* variant rather than only the default.
   *
   * The loop above passes no variant, so for Quark it predicts the default's 17 bytes and compute
   * produces exactly that -- which means it would stay green with `variantOutputLen` returning
   * undefined for everything. That is not a hypothetical: the width the *bytes* have comes from the
   * binding, which reads the variant directly, while `resolveOutputLen` is what the tool header and
   * `describeSpec` report. So the two can disagree, and this is the assertion that says they must not.
   *
   * Verified by making `variantOutputLen` return undefined and watching this fail with
   * `quark @ c-quark: expected length 48 to be 17`. The packaged probe does *not* catch it -- it reads
   * the rendered digest, which is the binding's answer and stays correct.
   */
  it("resolveOutputLen agrees with compute under every named variant", async () => {
    for (const meta of HASH_ALGORITHMS.filter((a) => a.variants)) {
      const tool = hashToolDefinition(meta.id);
      for (const variant of meta.variants!) {
        const result = await tool.compute(
          specFor(meta.id, { [OPTION_HASH_VARIANT]: variant.id }),
          ascii("abc"),
        );
        const predicted = resolveOutputLen(meta, undefined, variant.id);
        expect(result.bytes, `${meta.id} @ ${variant.id}`).toHaveLength(predicted);
        // And where the variant declares a width, that is the width -- not the algorithm's default.
        if (variant.outputLen !== undefined) {
          expect(result.bytes, `${meta.id} @ ${variant.id} declared`).toHaveLength(variant.outputLen);
        }
      }
    }
  });
});

describe("iterations", () => {
  for (const vector of DOUBLE_SHA256_VECTORS) {
    it(`double SHA-256 of "${vector.input}" matches ${vector.source}`, async () => {
      const tool = hashToolDefinition("sha256");
      const spec = specFor("sha256", withIterations({}, 2));
      const result = await tool.compute(spec, ascii(vector.input));
      expect(encodeHex(result.bytes!)).toBe(vector.hex);
    });
  }

  it("one iteration is identical to no iterations option at all", async () => {
    const tool = hashToolDefinition("sha256");
    const bare = await tool.compute(specFor("sha256"), ascii("abc"));
    const explicit = await tool.compute(specFor("sha256", withIterations({}, 1)), ascii("abc"));
    expect(encodeHex(explicit.bytes!)).toBe(encodeHex(bare.bytes!));
  });

  it("clamps a nonsense count rather than hanging", async () => {
    const tool = hashToolDefinition("sha256");
    // 1e9 passes would freeze the tab; `readIterations` caps at MAX_ITERATIONS.
    const result = await tool.compute(specFor("sha256", withIterations({}, 1e9)), ascii("abc"));
    expect(result.bytes).toHaveLength(32);
  });
});

describe("streaming equals one-shot", () => {
  // The invariant every streaming tool must satisfy. Chunk sizes are chosen to
  // straddle the compression block size in both directions (SHA-256 blocks at
  // 64 bytes, SHA-512 at 128) plus a deliberately awkward prime, because a
  // buffering bug that survives 1-byte and 1024-byte chunks will not survive 7.
  const CHUNK_SIZES = [1, 7, 63, 64, 65, 128, 1000];

  async function* single(bytes: Uint8Array) {
    yield bytes;
  }

  /**
   * Only the algorithms that *claim* to stream, which is all of them but the TupleHash set.
   *
   * TupleHash's `update()` appends one tuple element rather than more of a message, so chunking a
   * message through it produces a tuple of chunks -- a different value, by design. Its manifest
   * says `streaming: false`, and the test below asserts that claim is honoured rather than
   * skipping it silently.
   */
  const STREAMING = HASH_ALGORITHMS.filter((a) => usesInputPanel(a)).map((a) => a.id);

  it("only the TupleHash set declines to stream", () => {
    const declining = HASH_ALGORITHMS.filter((a) => !usesInputPanel(a)).map((a) => a.id);
    expect(declining.sort()).toEqual(
      ["tuplehash128", "tuplehash128xof", "tuplehash256", "tuplehash256xof"].sort(),
    );
    // And the manifest has to agree, since that is what the app actually reads.
    for (const id of declining) {
      const manifest = HASH_MANIFESTS.find((m) => m.id === id)!;
      expect(manifest.streaming, id).toBe(false);
      expect(manifest.supportsFile, id).toBe(false);
      expect(manifest.readsInput, id).toBe(false);
      expect(hashToolDefinition(id).createStream, id).toBeUndefined();
    }
  });

  /**
   * TupleHash's tuple belongs beside the message, not in the Settings rail.
   *
   * `readsInput: false` removes the text box these four cannot read, which leaves the tuple as the
   * only place their input comes from -- so it has to be in the Input panel. It was in `transform`,
   * and therefore in the right-hand rail: the one thing you change on every computation, filed under
   * decisions made once, next to an empty box that did nothing. The placement is what fixes that, and
   * it is a *group* field, so this asserts the group rather than the option.
   */
  it("puts the tuple in the Input panel rather than the Settings rail", () => {
    const tool = hashToolDefinition("tuplehash128");
    const option = tool.catalogue.options.find((o) => o.id === OPTION_TUPLE);
    expect(option, "tuplehash128 does not expose the tuple option").toBeDefined();
    expect(tool.groups[option!.group]?.placement, "the tuple group's placement").toBe("input");
    // And the rest of the family's options stay in the rail, which is the half a blanket move breaks.
    for (const other of tool.catalogue.options) {
      if (other.id === OPTION_TUPLE) continue;
      expect(tool.groups[other.group]?.placement, other.id).toBeUndefined();
    }
  });

  for (const algorithm of STREAMING) {
    for (const chunkSize of CHUNK_SIZES) {
      it(`${algorithm} in ${chunkSize}-byte chunks`, async () => {
        const tool = hashToolDefinition(algorithm);
        const spec = specFor(algorithm);
        // 500 bytes: several full blocks plus a partial one, for every algorithm here.
        const input = new Uint8Array(500);
        for (let i = 0; i < input.length; i++) input[i] = (i * 31 + 7) & 0xff;

        const oneShot = await tool.compute(spec, input);
        const streamed = await runStream(
          tool.createStream!(spec),
          rechunk(single(input), chunkSize),
        );

        expect(encodeHex(streamed.bytes!)).toBe(encodeHex(oneShot.bytes!));
      });
    }
  }

  it("holds for an iterated digest too", async () => {
    const tool = hashToolDefinition("sha256");
    const spec = specFor("sha256", withIterations({}, 3));
    const input = ascii("the quick brown fox jumps over the lazy dog");

    const oneShot = await tool.compute(spec, input);
    const streamed = await runStream(tool.createStream!(spec), rechunk(single(input), 5));
    expect(encodeHex(streamed.bytes!)).toBe(encodeHex(oneShot.bytes!));
  });

  it("reports progress and finishes at the exact byte count", async () => {
    const tool = hashToolDefinition("sha256");
    const spec = specFor("sha256");
    const input = new Uint8Array(10_000);
    const reports: number[] = [];

    await runStream(tool.createStream!(spec), rechunk(single(input), 1000), {
      totalBytes: input.length,
      progressInterval: 2000,
      onProgress: (p) => reports.push(p.bytesProcessed),
    });

    expect(reports[0]).toBe(0);
    // The final report must be the true total even though 10000 is not a clean
    // multiple of the 2000-byte throttle window — otherwise progress bars stick.
    expect(reports.at(-1)).toBe(10_000);
  });

  it("refuses to be reused after finish()", () => {
    const tool = hashToolDefinition("sha256");
    const stream = tool.createStream!(specFor("sha256"));
    stream.update(ascii("a"));
    stream.finish();
    expect(() => stream.update(ascii("b"))).toThrow(/after finish/);
    expect(() => stream.finish()).toThrow(/twice/);
  });
});

/**
 * BLAKE2's and BLAKE3's own parameters, driven through the tool rather than the binding.
 *
 * Every value below was checked against one recalled independently of this implementation before
 * being written down -- the official BLAKE3 `test_vectors.json` entries for input length 0, and the
 * first keyed entry of BLAKE2's `blake2-kat.json`. That matters more here than usual: OpenSSL exposes
 * BLAKE2b-512 and BLAKE2s-256 but not their keyed, salted or personalised forms, and it has no
 * BLAKE3 at all, so `openssl-parity.test.ts` cannot reach any of this.
 */
describe("keyed and parameterised BLAKE", () => {
  const seq = (n: number) => Uint8Array.from({ length: n }, (_, i) => i);
  const hex = (bytes: Uint8Array) => encodeHex(bytes);

  /** The BLAKE3 test vectors' own key and context strings, verbatim from the file. */
  const B3_KEY = "whats the Elvish word for friend";
  const B3_CONTEXT = "BLAKE3 2019-12-27 16:29:52 test vectors context";

  const compute = async (
    algorithm: string,
    options: HashSpec["options"],
    input: Uint8Array,
  ) => {
    const result = await hashToolDefinition(algorithm).compute(
      specFor(algorithm, options),
      input,
    );
    expect(result.error, `${algorithm}: ${result.error}`).toBeUndefined();
    return hex(result.bytes!);
  };

  it("BLAKE2b keyed with 00..3f matches the first keyed KAT entry", async () => {
    expect(
      await compute(
        "blake2b",
        { blakeKey: hex(seq(64)), blakeKeyEncoding: "hex" },
        new Uint8Array(0),
      ),
    ).toBe(
      "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
    );
  });

  it("BLAKE2s keyed with 00..1f matches the first keyed KAT entry", async () => {
    expect(
      await compute(
        "blake2s",
        { blakeKey: hex(seq(32)), blakeKeyEncoding: "hex" },
        new Uint8Array(0),
      ),
    ).toBe("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");
  });

  it("BLAKE3's three modes match its official vectors for the empty input", async () => {
    // hash, keyed_hash and derive_key: three different functions of the same bytes, which is the
    // whole reason the key and the context cannot be combined.
    expect(await compute("blake3", {}, new Uint8Array(0))).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
    expect(
      await compute(
        "blake3",
        { blakeKey: B3_KEY, blakeKeyEncoding: "utf-8" },
        new Uint8Array(0),
      ),
    ).toBe("92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26");
    expect(
      await compute(
        "blake3",
        { blakeContext: B3_CONTEXT, blakeContextEncoding: "utf-8" },
        new Uint8Array(0),
      ),
    ).toBe("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d");
  });

  it("a key changes the digest, and an empty key is not a key", async () => {
    // RFC 7693 encodes the key length into the parameter block, so keying with zero bytes would still
    // change the initial state -- which is why the binding omits an empty key rather than passing it.
    const plain = await compute("blake2b", {}, ascii("abc"));
    const emptyKey = await compute(
      "blake2b",
      { blakeKey: "", blakeKeyEncoding: "hex" },
      ascii("abc"),
    );
    const keyed = await compute(
      "blake2b",
      { blakeKey: hex(seq(32)), blakeKeyEncoding: "hex" },
      ascii("abc"),
    );
    expect(emptyKey).toBe(plain);
    expect(keyed).not.toBe(plain);
  });

  it("salt and personalisation are distinct fields, not one field twice", async () => {
    // No published vector for these -- OpenSSL cannot produce them and the RFC's KAT file does not
    // cover them -- so the property is asserted instead: the same 16 bytes in the two fields give
    // different digests, which a parameter block that wrote one over the other would not.
    const salted = await compute(
      "blake2b",
      { blakeSalt: hex(seq(16)), blakeSaltEncoding: "hex" },
      ascii("abc"),
    );
    const personalised = await compute(
      "blake2b",
      { blakePersonal: hex(seq(16)), blakePersonalEncoding: "hex" },
      ascii("abc"),
    );
    const plain = await compute("blake2b", {}, ascii("abc"));
    expect(new Set([plain, salted, personalised]).size).toBe(3);
  });

  it("refuses the lengths each algorithm does not accept, naming it", async () => {
    const refuse = async (algorithm: string, options: HashSpec["options"], match: RegExp) => {
      const result = await hashToolDefinition(algorithm).compute(
        specFor(algorithm, options),
        ascii("abc"),
      );
      expect(result.error, `${algorithm} accepted what it should not`).toMatch(match);
    };

    // BLAKE2s takes 32 bytes of key at most; BLAKE2b takes 64.
    await refuse("blake2s", { blakeKey: hex(seq(48)), blakeKeyEncoding: "hex" }, /at most 32/);
    await refuse("blake2b", { blakeKey: hex(seq(80)), blakeKeyEncoding: "hex" }, /at most 64/);
    // BLAKE3's keyed mode is exactly 32, not "up to".
    await refuse("blake3", { blakeKey: hex(seq(16)), blakeKeyEncoding: "hex" }, /exactly 32/);
    // The salt and personalisation fields are fixed-width: 16 for 2b, 8 for 2s.
    await refuse("blake2b", { blakeSalt: hex(seq(8)), blakeSaltEncoding: "hex" }, /exactly 16/);
    await refuse("blake2s", { blakeSalt: hex(seq(16)), blakeSaltEncoding: "hex" }, /exactly 8/);
    // And BLAKE3 has no mode taking both a key and a context.
    await refuse(
      "blake3",
      {
        blakeKey: B3_KEY,
        blakeKeyEncoding: "utf-8",
        blakeContext: B3_CONTEXT,
        blakeContextEncoding: "utf-8",
      },
      /either a key or a derive-key context/,
    );
  });

  it("ignores a stale key left behind after switching algorithm", async () => {
    // Options survive a tool switch by design, so SHA-256 must not change its answer because a BLAKE
    // key is still in the spec. `resolveSpec` reads each parameter only when the metadata declares it.
    const withStale = await compute(
      "sha256",
      { blakeKey: hex(seq(32)), blakeKeyEncoding: "hex", blakeSalt: hex(seq(16)) },
      ascii("abc"),
    );
    expect(withStale).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("streams identically to one shot with every parameter set", async () => {
    // Its own generator: the one in the streaming describe below is scoped to that block.
    async function* single(bytes: Uint8Array) {
      yield bytes;
    }

    // The bug this guards is the one `HashParams` was introduced for: a parameter read on the
    // one-shot path and dropped on the streaming one.
    for (const [algorithm, options] of [
      ["blake2b", { blakeKey: hex(seq(64)), blakeKeyEncoding: "hex" }],
      ["blake2b", { blakeSalt: hex(seq(16)), blakeSaltEncoding: "hex" }],
      ["blake2s", { blakePersonal: hex(seq(8)), blakePersonalEncoding: "hex" }],
      ["blake3", { blakeKey: B3_KEY, blakeKeyEncoding: "utf-8" }],
      ["blake3", { blakeContext: B3_CONTEXT, blakeContextEncoding: "utf-8" }],
    ] as const) {
      const tool = hashToolDefinition(algorithm);
      const spec = specFor(algorithm, options);
      const input = ascii("the quick brown fox jumps over the lazy dog");
      const oneShot = await tool.compute(spec, input);
      const streamed = await runStream(tool.createStream!(spec), rechunk(single(input), 7));
      expect(encodeHex(streamed.bytes!), `${algorithm} ${JSON.stringify(options)}`).toBe(
        encodeHex(oneShot.bytes!),
      );
    }
  });
});

describe("metadata and bindings agree", () => {
  // The manifest/definition split duplicates outputLen and blockLen so the
  // sidebar can render without loading @noble. This is the guard that keeps the
  // two copies honest.
  for (const meta of HASH_ALGORITHMS) {
    it(`${meta.id} declares its real output length`, () => {
      // `passes` is part of what an algorithm needs to be constructed at all, so it goes in
      // alongside the length -- the binding requires it rather than defaulting, on purpose.
      const hasher = requireHashBinding(meta.id).create({
        outputLen: meta.outputLen,
        ...(meta.passes ? { passes: meta.defaultPasses ?? meta.passes[0]! } : {}),
      });
      hasher.update(new Uint8Array(0));
      expect(hasher.digest()).toHaveLength(meta.outputLen);
    });
  }

  it("no two BLAKE variants agree on the same input", async () => {
    /**
     * The check that stands in for BLAKE-224 and BLAKE-384's missing vectors.
     *
     * Those two are the same cores as 256 and 512 with different initial values, and a wrong IV is
     * exactly the mistake a shared-core implementation makes invisibly -- the round function, the
     * schedule and the counter would all still be right, and the digest would still be the declared
     * length. Two variants colliding, or a truncation matching its longer sibling, is what that looks
     * like from outside. See NO_PUBLISHED_VECTOR in `vectors.ts`.
     */
    const ids = ["blake224", "blake256", "blake384", "blake512"];
    const digests = new Map<string, string>();
    for (const id of ids) {
      const meta = HASH_ALGORITHMS.find((m) => m.id === id)!;
      const hasher = requireHashBinding(id).create({ outputLen: meta.outputLen });
      hasher.update(ascii("abc"));
      digests.set(id, encodeHex(hasher.digest()));
    }
    expect(new Set(digests.values()).size, "two BLAKE variants produced the same digest").toBe(
      4,
    );
    // And a shorter variant is not merely its sibling cut short, which is what sharing an IV
    // would produce.
    expect(digests.get("blake256")!.startsWith(digests.get("blake224")!)).toBe(false);
    expect(digests.get("blake512")!.startsWith(digests.get("blake384")!)).toBe(false);
  });

  it("declares the real block size — HMAC and the key-length rules depend on it", async () => {
    // `blockLen` is the one metadata field with no visible consequence inside this
    // family: a wrong value here changes nothing about a digest and would go
    // unnoticed until the MAC family used it to pad an HMAC key. So it is checked
    // against the implementation, which the test reaches independently.
    //
    // Only the noble-backed entries are covered — the `@ocs/algos` ones do not expose a
    // `blockLen` to compare against, and the xxHash pair have a stripe rather than a
    // compression block. Those are asserted by hand below.
    const actual = await nobleBlockLens();
    for (const meta of HASH_ALGORITHMS) {
      const expected = actual.get(meta.id);
      if (expected === undefined) continue;
      expect(expected, `${meta.id} blockLen`).toBe(meta.blockLen);
    }
    // Every algorithm is either covered by the cross-check or listed here, so a new one
    // cannot slip in with an unverified block size.
    const covered = new Set(actual.keys());
    // The @ocs/algos-backed entries, which expose no `blockLen` to compare against. Asserted by
    // hand in the test below.
    const byHand = new Set([
      "md2",
      "md4",
      "md6",
      "sm3",
      "whirlpool",
      "xxh32",
      "xxh64",
      "ripemd128",
      "ripemd256",
      "ripemd320",
      "xxh3",
      "xxh128",
      "streebog512",
      "streebog256",
      "asconhash256",
      "asconxof128",
      "skein256",
      "skein512",
      "skein1024",
      "tiger",
      "tiger2",
      "groestl224",
      "groestl256",
      "groestl384",
      "groestl512",
      "jh224",
      "jh256",
      "jh384",
      "jh512",
      "cubehash224",
      "cubehash256",
      "cubehash384",
      "cubehash512",
      "luffa224",
      "luffa256",
      "luffa384",
      "luffa512",
      "fugue224",
      "fugue256",
      "fugue384",
      "fugue512",
      "shavite224",
      "shavite256",
      "shavite384",
      "shavite512",
      "shabal192",
      "shabal224",
      "shabal256",
      "shabal384",
      "shabal512",
      "belt-hash",
      "haval",
      "snefru",
      "gost94",
      "gost94-crypto",
      "fnv132",
      "fnv1a32",
      "fnv164",
      "fnv1a64",
      "joaat",
      "murmur3a",
      "murmur3c",
      "murmur3f",
      /**
       * The five NIST lightweight hashes. Their `blockLen` is a sponge *rate*, not a compression block,
       * and none is offered under HMAC -- so nothing reads these numbers for padding. They are here for
       * the same reason xxHash's stripe widths are: the field is not optional and a plausible lie would
       * be worse than a documented rate.
       */
      /**
       * RadioGatun's `blockLen` is its 156- or 312-byte rate, and Panama's its 32. Neither is a
       * compression block and neither is offered under HMAC. Kupyna's and HAS-160's *are* real block
       * sizes -- 64 or 128 and 64 -- and are asserted below rather than waived.
       */
      "radiogatun32",
      "radiogatun64",
      "panama",
      "kupyna256",
      "kupyna384",
      "kupyna512",
      "has160",
      "lsh224",
      "lsh256",
      "lsh384",
      "lsh512",
      "xoodyak-hash",
      "esch256",
      "esch384",
      "photonbeetle-hash",
      "romulus-h",
      /**
       * ECHO, Hamsi and SIMD. All three have genuine compression blocks -- unlike the sponge rates
       * above -- but none is offered under HMAC, so nothing pads to these numbers. Two are worth
       * naming because they look wrong: ECHO's block is *larger* at the shorter digest lengths (192
       * against 128), since the wide variants spend more of the grid on chaining value; and Hamsi's
       * is 4 bytes, the smallest here by a factor of eight, because it expands four bytes into eight
       * words through a linear code. HMAC is not offered over any of the three -- none of the three
       * submissions specifies a keyed construction, and no HMAC value for them exists to check.
       */
      "echo224",
      "echo256",
      "echo384",
      "echo512",
      "hamsi224",
      "hamsi256",
      "hamsi384",
      "hamsi512",
      "simd224",
      "simd256",
      "simd384",
      "simd512",
      /**
       * The five non-cryptographic families. None is offered under HMAC and none has a compression
       * block in the Merkle-Damgard sense, so these numbers describe a *stride*: CityHash's 64-byte
       * long-path block (its 32-bit form steps 20 bytes and has no block at all), SpookyHash's twelve
       * 64-bit words, MetroHash's and t1ha's four-lane 32-byte loops. Reported because the field is
       * not optional, and a plausible lie would be worse than a documented stride -- the same
       * arrangement xxHash's entries already have.
       */
      "cityhash",
      "spookyhash",
      "metrohash",
      "t1ha",
      /**
       * The three lightweight sponges. Same waiver as the NIST lightweight five and for a sharper
       * reason: these are sponge *rates*, and Quark's is one byte and PHOTON's two, so neither could
       * carry an HMAC key even if a value existed to check one against. None of the three is offered
       * under HMAC -- see `HMAC_HASHES`.
       */
      "gimli",
      "quark",
      "photon",
      /**
       * The wyhash pair. Neither number is a compression block: wyhash's 48 is its three-lane body's
       * stride and rapidhash's 112 its seven-lane one, and both read from the end of the message, so
       * neither streams and neither is offered under HMAC. Same arrangement as xxHash's stripe widths.
       */
      "wyhash",
      "rapidhash",
      // FarmHash's 64 is its main-loop stride, not a compression block. Not offered under HMAC.
      "farmhash",
      /**
       * The two CRC-mixed variants. CityHashCrc's 240 is the minimum its loop accepts -- shorter inputs
       * are zero-padded up to it -- and MetroHash128CRC's 32 is its four-lane stride. Neither is a
       * compression block and neither is offered under HMAC.
       */
      "cityhashcrc",
      "metrohash128crc",
      /**
       * FSB's is a real compression block -- unusually for this list -- but it *varies with the digest
       * length*: 60 bytes at 160 bits, 96 at 256, 155 at 512, because `inputsize = w * bpc - r`. A single
       * number cannot describe it, the entry carries the default size's, and HMAC is not offered.
       */
      "fsb",
      "poseidon",
      "rescueprime",
      "haraka256",
      "haraka512",
      "meowhash",
      "komihash",
      "nhash",
      "monolith",
      "neptune",
      "reinforced-concrete",
      "anemoi",
      "griffin",
      "poseidon2",
      "mimc",
      "tip5",
      "pearson",
      "murmur1",
      "murmur2",
      "jenkins-lookup3",
    ]);
    for (const meta of HASH_ALGORITHMS) {
      expect(
        covered.has(meta.id) || byHand.has(meta.id),
        `${meta.id} blockLen unverified`,
      ).toBe(true);
    }
  });

  it("declares the documented block size for the locally implemented algorithms", () => {
    const expected: Record<string, number> = {
      // MD2 is byte-oriented: 16-byte blocks, per RFC 1319.
      md2: 16,
      // MD4 and SM3 share SHA-256's 512-bit block.
      md4: 64,
      /**
       * MD6's is a *tree leaf*, not a compression block, and it is the only entry here where the
       * distinction matters. A leaf takes 512 bytes of message and compresses to 128; nothing about
       * Merkle-Damgard applies. HMAC is deliberately not offered over it, so no padding reads this.
       */
      md6: 512,
      // DSTU 7564: eight or sixteen 64-bit columns, so 64 bytes at 256 bits and 128 above it.
      kupyna256: 64,
      kupyna384: 128,
      kupyna512: 128,
      // TTAS.KO-12.0011 uses SHA-1's 512-bit block.
      has160: 64,
      // KS X 3262: 128 bytes for the 256-bit family and 256 for the 512-bit one.
      lsh224: 128,
      lsh256: 128,
      lsh384: 256,
      lsh512: 256,
      sm3: 64,
      whirlpool: 64,
      // Not compression blocks — xxHash's stripe widths.
      xxh32: 16,
      xxh64: 32,
      // All four RIPEMD widths share MD4's 512-bit block; only the state and round count differ.
      ripemd128: 64,
      ripemd256: 64,
      ripemd320: 64,
      // XXH3's long path consumes 64-byte stripes; that is the nearest thing it has to a block.
      xxh3: 64,
      xxh128: 64,
      // Streebog compresses 512 bits at a time at both output lengths -- GOST R 34.11-2012 changes
      // the initialising value between the two, not the block.
      streebog512: 64,
      streebog256: 64,
      // Ascon's sponge rate, which is the nearest thing it has to a block: 8 bytes absorbed between
      // permutations, for both the hash and the XOF.
      asconhash256: 8,
      asconxof128: 8,
      // Skein's block is its state, which is what its name counts.
      skein256: 32,
      skein512: 64,
      skein1024: 128,
      // Tiger compresses 512 bits at a time, like MD4 and the SHA-2 family below 384 bits, whatever
      // its pass count or output width.
      tiger: 64,
      tiger2: 64,
      /**
       * The SHA-3 competition designs. Groestl's block is its state -- 512 bits for the short
       * variants and 1024 for the long ones -- JH's is 512 bits at every output length, and
       * CubeHash's is the 32 bytes its name's second number gives.
       */
      groestl224: 64,
      groestl256: 64,
      groestl384: 128,
      groestl512: 128,
      jh224: 64,
      jh256: 64,
      jh384: 64,
      jh512: 64,
      cubehash224: 32,
      cubehash256: 32,
      cubehash384: 32,
      cubehash512: 32,
      // Luffa absorbs 32 bytes at a time whatever its lane count.
      luffa224: 32,
      luffa256: 32,
      luffa384: 32,
      luffa512: 32,
      /**
       * Fugue has no block: it absorbs one 32-bit word per round, so four bytes is the honest
       * answer here rather than a block size it does not have.
       */
      fugue224: 4,
      fugue256: 4,
      fugue384: 4,
      fugue512: 4,
      /**
       * Shabal's block is 64 bytes at every output length -- unusually for this family, the length
       * changes only the initial values and how much of B is read out at the end.
       */
      shabal192: 64,
      shabal224: 64,
      shabal256: 64,
      shabal384: 64,
      shabal512: 64,
      // STB 34.101.31 compresses 32 bytes at a time -- half of what most of this list uses.
      "belt-hash": 32,
      // SHAvite-3's block is the message that keys its cipher: 64 bytes short, 128 long.
      shavite224: 64,
      shavite256: 64,
      shavite384: 128,
      shavite512: 128,
      // HAVAL's block is 1024 bits -- twice everything else here.
      // All fifteen HAVAL functions share the 128-byte block; only the state folding differs.
      haval: 128,
      // Snefru and GOST both compress 256 bits at a time.
      snefru: 32,
      gost94: 32,
      "gost94-crypto": 32,
      // FNV and joaat consume one byte at a time; there is no block, and 1 says so rather than
      // pretending otherwise.
      fnv132: 1,
      fnv1a32: 1,
      fnv164: 1,
      fnv1a64: 1,
      joaat: 1,
      // MurmurHash3's blocks: 4 bytes for the 32-bit variant, 16 for both 128-bit ones.
      murmur3a: 4,
      murmur3c: 16,
      murmur3f: 16,
    };
    for (const [id, blockLen] of Object.entries(expected)) {
      expect(requireHashAlgorithm(id).blockLen, id).toBe(blockLen);
    }
  });

  it("every algorithm has a manifest and every manifest an algorithm", () => {
    expect(HASH_MANIFESTS.map((m) => m.id).sort()).toEqual(
      HASH_ALGORITHMS.map((a) => a.id).sort(),
    );
  });

  it("declares itself forward-only — a digest has no inverse", () => {
    for (const manifest of HASH_MANIFESTS) {
      expect(manifest.directions).toEqual(["forward"]);
    }
  });

  it("streams and takes files for every algorithm whose input is a message", () => {
    // Split from the assertion above because these two stopped being universal: TupleHash reads a
    // tuple from an option, so it has no message to stream. `usesInputPanel` is the single source
    // of that distinction and the manifest has to follow it.
    for (const meta of HASH_ALGORITHMS) {
      const manifest = HASH_MANIFESTS.find((m) => m.id === meta.id)!;
      expect(manifest.streaming, meta.id).toBe(usesInputPanel(meta));
      expect(manifest.supportsFile, meta.id).toBe(usesInputPanel(meta));
    }
  });

  it("offers no decimal output encoding for a digest", () => {
    for (const manifest of HASH_MANIFESTS) {
      expect(manifest.outputEncodings).not.toContain("decimal");
    }
  });
});

describe("catalogue", () => {
  it("is internally consistent", () => {
    expect(validateCatalogue(OPTIONS)).toEqual([]);
  });

  it("shows one output control or the other, never both, and seed only where it applies", () => {
    /**
     * Three states, and the middle one is new: a numeric field for a range, a select for a fixed
     * set, and nothing for a fixed-output algorithm. Both write `outputLength`, so rendering both
     * would put two controls on screen fighting over one option -- which is why
     * `hashCatalogueFor` drops the numeric one rather than relying on `availableOn` alone.
     */
    for (const meta of HASH_ALGORITHMS) {
      const tool = hashToolDefinition(meta.id);
      const tags = variantTags(meta);
      const ids = tool.catalogue.options
        .filter((option) => isAvailableOn(option, tags))
        .map((option) => option.id);

      const showsLength = ids.includes(OPTION_OUTPUT_LENGTH);
      expect(showsLength, `${meta.id} output control`).toBe(hasVariableOutput(meta));

      const numeric = tool.catalogue.options.filter(
        (option) => option.id === OPTION_OUTPUT_LENGTH && option.kind === "number",
      );
      const select = tool.catalogue.options.filter(
        (option) => option.id === OPTION_OUTPUT_LENGTH && option.kind === "enum",
      );
      if (meta.outputLengths) {
        expect(select, `${meta.id} should offer a select`).toHaveLength(1);
        expect(numeric, `${meta.id} must not also offer a number field`).toHaveLength(0);
        expect(select[0]!.choices!.map((c) => c.value)).toEqual(meta.outputLengths.map(String));
      } else {
        expect(select, `${meta.id} should not offer a select`).toHaveLength(0);
      }

      expect(ids.includes(OPTION_PASSES), `${meta.id} passes control`).toBe(
        meta.passes !== undefined,
      );
      expect(ids.includes(OPTION_SEED), `${meta.id} seed control`).toBe(meta.seeded === true);
    }
  });

  /**
   * An empty Seed field must mean the algorithm's own default, never zero.
   *
   * This is a general property of the `seeded64` option and it is load-bearing for two families:
   * rapidhash v1.0's default seed is `0xbdd89aa982704029`, and every FarmHash namespace has a separate
   * *unseeded* entry point whose answer differs from seeding with zero (`na`'s seeded form is
   * `HashLen16(Hash64 - k2, seed)`, so a zero seed still folds `k2` in). Reading empty as zero would
   * put the reference's own no-seed value out of reach while showing an empty box -- which is the worst
   * pairing available, because nothing on screen would say why the answer was wrong.
   *
   * `compute.ts` leaves `params.seed64` undefined when `decodeBytesOption` returns no bytes. Verified by
   * removing that guard and watching this fail for both families.
   *
   * SpookyHash and t1ha are exempt because their defaults genuinely *are* zero, so the two agree -- and
   * the test asserts that rather than skipping them, since a future change to either default should
   * show up here.
   */
  it("reads an empty seed field as the algorithm's default, not as zero", async () => {
    const ZERO = { [OPTION_SEED_64]: "00", seed64Encoding: "hex" };
    /**
     * Per (algorithm, variant), whether an empty field must differ from an explicit zero.
     *
     * The variant matters: rapidhash's *default* is v3.0, whose own default seed is zero, so there the
     * two correctly agree -- only v1.0 has a non-zero default. Writing this out per variant rather than
     * per algorithm is what makes the distinction visible instead of looking like an inconsistency.
     */
    const CASES: readonly { id: string; variant?: string; differs: boolean }[] = [
      { id: "spookyhash", differs: false },
      { id: "t1ha", differs: false },
      { id: "wyhash", differs: false },
      { id: "rapidhash", variant: "v3.0", differs: false },
      { id: "rapidhash", variant: "v2.2", differs: false },
      { id: "rapidhash", variant: "v1.0", differs: true },
      { id: "farmhash", variant: "na", differs: true },
      { id: "farmhash", variant: "uo", differs: true },
      { id: "farmhash", variant: "xo", differs: true },
    ];
    // Every seeded64 algorithm must appear, so a new one cannot skip this gate.
    expect([...new Set(CASES.map((c) => c.id))].sort()).toEqual(
      HASH_ALGORITHMS.filter((a) => a.seeded64).map((a) => a.id).sort(),
    );

    for (const testCase of CASES) {
      const label = `${testCase.id}${testCase.variant ? ` ${testCase.variant}` : ""}`;
      const base: Record<string, string> = testCase.variant ? { hashVariant: testCase.variant } : {};
      const tool = hashToolDefinition(testCase.id);
      const empty = await tool.compute(specFor(testCase.id, base), ascii("abc"));
      const zero = await tool.compute(specFor(testCase.id, { ...base, ...ZERO }), ascii("abc"));
      const same = encodeHex(empty.bytes!) === encodeHex(zero.bytes!);
      if (testCase.differs) {
        expect(same, `${label}: an empty seed must not be read as zero`).toBe(false);
      } else {
        expect(same, `${label}: its default seed is zero, so the two must agree`).toBe(true);
      }
    }
  });

  it("gives a 64-bit seed to exactly the five families whose reference vectors need one", () => {
    /**
     * SpookyHash and t1ha, and nothing else. The control is bytes rather than a number because a
     * 64-bit seed does not fit a JavaScript number -- and t1ha's own reference schedule uses
     * `ffffffffffffffff`, so a numeric field would put some of its published values out of reach.
     */
    const seeded64 = HASH_ALGORITHMS.filter((a) => a.seeded64).map((a) => a.id);
    // wyhash's own reference vectors seed with the row index and rapidhash inherits the same
    // 64-bit seed parameter, so both need the bytes control rather than a number field.
    expect(seeded64.sort()).toEqual(["farmhash", "rapidhash", "spookyhash", "t1ha", "wyhash"]);
    // And the two seed flags are exclusive: an algorithm gets one control or the other, never both,
    // since they would render two fields both labelled Seed.
    for (const meta of HASH_ALGORITHMS) {
      expect(meta.seeded === true && meta.seeded64 === true, `${meta.id} seed controls`).toBe(false);
    }
  });

  it("gives a variant select to exactly the six families that have named variants", () => {
    /**
     * MetroHash's two constant sets, t1ha's two versions, Quark's four instances and rapidhash's four
     * *published versions*. None is an output length nor a pass count, which is why `variants` exists.
     *
     * rapidhash is the case that stretched the field furthest: its four variants are four separately
     * published revisions of one algorithm that agree on almost no input, so the variant is not a
     * parameter of a function but a choice of which function. A variant list must still carry a
     * resolvable default, which for rapidhash is the newest.
     */
    const withVariants = HASH_ALGORITHMS.filter((a) => a.variants);
    expect(withVariants.map((a) => a.id).sort()).toEqual([
      "farmhash",
      "metrohash",
      "metrohash128crc",
      "quark",
      "rapidhash",
      "t1ha",
    ]);
    /**
     * A variant-carried output length is all-or-nothing within an algorithm.
     *
     * Quark's four instances each declare one because for Quark the instance *is* the width; MetroHash's
     * and t1ha's declare none, because theirs share a width and the length is a separate control. A
     * list where only some entries carried one would leave `resolveOutputLen` reading the algorithm's
     * default for the rest, which is a silent wrong answer rather than an error.
     */
    for (const meta of withVariants) {
      const declared = meta.variants!.filter((v) => v.outputLen !== undefined).length;
      expect(
        declared === 0 || declared === meta.variants!.length,
        `${meta.id} declares outputLen on ${declared} of ${meta.variants!.length} variants`,
      ).toBe(true);
      if (declared > 0) {
        // Each must actually be produced, and they must differ -- a resolver ignoring the variant
        // would give the default's width for all of them.
        const widths = meta.variants!.map((v) => v.outputLen!);
        expect(new Set(widths).size, `${meta.id} variant widths`).toBe(widths.length);
      }
    }
    for (const meta of withVariants) {
      expect(meta.variants!.length, `${meta.id} variant count`).toBeGreaterThan(1);
      const ids = meta.variants!.map((v) => v.id);
      expect(new Set(ids).size, `${meta.id} duplicate variant ids`).toBe(ids.length);
      if (meta.defaultVariant !== undefined) {
        expect(ids, `${meta.id} default variant`).toContain(meta.defaultVariant);
      }
    }
  });

  it("gives a 32-bit seed to exactly the xxHash family, MetroHashes, Murmur1/2, and Jenkins Lookup3", () => {
    // Pinned rather than derived: `seeded` surfaces a control, and an algorithm gaining one by
    // accident is the sort of change that should have to be written down here.
    const seeded = HASH_ALGORITHMS.filter((a) => a.seeded).map((a) => a.id);
    expect(seeded.sort()).toEqual([
      "jenkins-lookup3",
      "metrohash",
      "metrohash128crc",
      "murmur1",
      "murmur2",
      "xxh128",
      "xxh3",
      "xxh32",
      "xxh64",
    ]);
  });
});

describe("the xxHash seed", () => {
  it("changes the result completely", async () => {
    for (const id of ["xxh32", "xxh64"]) {
      const tool = hashToolDefinition(id);
      const zero = await tool.compute(specFor(id), ascii("abc"));
      const one = await tool.compute(specFor(id, withSeed({}, 1)), ascii("abc"));
      expect(encodeHex(one.bytes!), id).not.toBe(encodeHex(zero.bytes!));
    }
  });

  it("treats an absent seed as zero", async () => {
    const tool = hashToolDefinition("xxh64");
    const absent = await tool.compute(specFor("xxh64"), ascii("abc"));
    const explicit = await tool.compute(specFor("xxh64", withSeed({}, 0)), ascii("abc"));
    expect(encodeHex(explicit.bytes!)).toBe(encodeHex(absent.bytes!));
  });

  it("is ignored by an algorithm that is not seeded", async () => {
    // Switching from XXH64 to SHA-256 leaves `seed` in the spec. It must not be able to
    // change SHA-256's answer.
    const tool = hashToolDefinition("sha256");
    const stale = await tool.compute(specFor("sha256", withSeed({}, 12345)), ascii("abc"));
    expect(encodeHex(stale.bytes!)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("survives the whole 32-bit range without going negative", async () => {
    const tool = hashToolDefinition("xxh32");
    for (const seed of [0, 1, 0x7fffffff, 0x80000000, 0xffffffff]) {
      const result = await tool.compute(specFor("xxh32", withSeed({}, seed)), ascii("abc"));
      expect(result.bytes, `seed ${seed}`).toHaveLength(4);
    }
  });

  it("appears in the description only when non-zero", () => {
    expect(describeSpec(specFor("xxh64"))).not.toContain("seed");
    expect(describeSpec(specFor("xxh64", withSeed({}, 42)))).toContain("seed 42");
  });
});

describe("all variants", () => {
  async function* once(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
    yield bytes;
  }

  const familyOf = (id: string) =>
    HASH_ALGORITHMS.filter(
      (m) => m.category === requireHashAlgorithm(id).category && usesInputPanel(m),
    );

  /**
   * Every row agrees with that algorithm's own compute path, across every family that has one.
   *
   * There is no published table of "all the SHA-2 widths of abc", so the oracle here is the tool
   * itself. That is not circular: the digests are pinned to published vectors elsewhere -- the
   * "every algorithm ships at least one published vector" gate -- and what this adds is that the
   * *row* is the algorithm it claims to be. A table of plausible hex under shifted labels is the
   * failure being ruled out, and it is worse than an empty panel.
   */
  it("agrees with each algorithm's own compute path, in every family", async () => {
    const seen = new Set<string>();
    for (const meta of HASH_ALGORITHMS) {
      if (!usesInputPanel(meta) || seen.has(meta.category)) continue;
      seen.add(meta.category);

      const table = hashToolDefinition(meta.id).variants!(specFor(meta.id));
      if (table.rows.length === 0) continue;

      const results = await runStreams(
        table.rows.map((row) => row.stream()),
        once(ascii("abc")),
      );
      for (const [index, row] of table.rows.entries()) {
        const direct = await hashToolDefinition(row.id).compute(specFor(row.id), ascii("abc"));
        expect(direct.error, row.id).toBeUndefined();
        expect(encodeHex(results[index]!.bytes!, false), row.id).toBe(
          encodeHex(direct.bytes!, false),
        );
      }
    }
  });

  it("lists the algorithm's own family and nothing else", () => {
    /**
     * `category` is the axis, and it is the same grouping the sidebar uses: MD is MD2/MD4/MD5, SHA-1
     * stands alone, SHA-2 is the six widths, and SHA-3, Keccak, SHAKE and TurboSHAKE are four
     * families rather than one. It was briefly all 102 algorithms at once, which answers a rarer
     * question and answers it badly -- MD5 next to MurmurHash3 invites a comparison between things
     * with nothing to do with each other.
     */
    for (const id of ["md5", "sha256", "sha3-256", "blake2b", "shake128"]) {
      const { rows } = hashToolDefinition(id).variants!(specFor(id));
      expect(
        rows.map((r) => r.id),
        id,
      ).toEqual(familyOf(id).map((m) => m.id));
    }
    // The shape of the grouping, spelled out on the two the user named.
    /**
     * Four now, in catalogue order -- which for this family is chronological, and that is the order the
     * sidebar shows because it reads the catalogue directly.
     *
     * MD6 sits in this category because that is what Rivest called it and where anyone would look, even
     * though it shares nothing with the other three beyond the name: they are Merkle-Damgard over
     * 64-byte blocks and it is a Merkle tree over 512-byte leaves. It goes *after* MD5, so the four read
     * 2, 4, 5, 6 -- it was inserted before MD5 first, which put the sidebar out of order and is exactly
     * what this assertion is for.
     */
    expect(hashToolDefinition("md5").variants!(specFor("md5")).rows.map((r) => r.id)).toEqual([
      "md2",
      "md4",
      "md5",
      "md6",
    ]);
    expect(
      hashToolDefinition("sha256").variants!(specFor("sha256")).rows.some(
        (r) => r.id === "sha1",
      ),
    ).toBe(false);
  });

  it("offers nothing for an algorithm with no siblings", () => {
    // A single row would restate the Result panel above it. SHA-1 is its own category.
    for (const id of ["sha1", "whirlpool", "sm3"]) {
      expect(hashToolDefinition(id).variants!(specFor(id)).rows, id).toEqual([]);
    }
  });

  it("leaves TupleHash out, by the flag rather than by name", () => {
    /**
     * Its input is a tuple of elements rather than a byte string, so there is nothing to feed it
     * from a stream and `createHashStream` refuses outright. Filtering on `usesInputPanel` rather
     * than on an id list is what keeps that true for whatever arrives next.
     */
    const tuple = HASH_ALGORITHMS.find((m) => !usesInputPanel(m));
    expect(tuple, "no non-streaming algorithm left to check").toBeDefined();
    const { rows } = hashToolDefinition(tuple!.id).variants!(specFor(tuple!.id));
    expect(rows.map((r) => r.id)).not.toContain(tuple!.id);
  });

  it("states each row's own output length, which is what settles a family", () => {
    // Across SHA-2's six widths the length alone identifies the row a 32-byte digest came from.
    const { columns, rows } = hashToolDefinition("sha256").variants!(specFor("sha256"));
    // No Category column: every row shares one, so it would be the same word repeated downwards.
    expect(columns).toEqual(["Output", "Block"]);
    const output = (id: string) =>
      rows.find((r) => r.id === id)!.cells[columns.indexOf("Output")];
    expect(output("sha224")).toBe("28 bytes");
    expect(output("sha256")).toBe("32 bytes");
    expect(output("sha512")).toBe("64 bytes");
  });

  it("is the same table from whichever member it is viewed", () => {
    /**
     * The output length and customisation string in the form belong to the algorithm above the
     * table and mean nothing to its siblings. Threading them through would make a row read
     * "SHAKE256 with your SHAKE128 settings", which is worse than useless.
     */
    const fromShake128 = hashToolDefinition("shake128").variants!(specFor("shake128"));
    const fromShake256 = hashToolDefinition("shake256").variants!(
      specFor("shake256", { [OPTION_OUTPUT_LENGTH]: "99" }),
    );
    expect(fromShake128.rows.map((r) => [r.id, ...r.cells])).toEqual(
      fromShake256.rows.map((r) => [r.id, ...r.cells]),
    );
  });

  it("marks the algorithm it is being viewed from", () => {
    for (const id of ["md5", "sha512", "blake2s"]) {
      const { rows } = hashToolDefinition(id).variants!(specFor(id));
      expect(
        rows.filter((r) => r.selected).map((r) => r.id),
        id,
      ).toEqual([id]);
    }
  });

  it("names its rows so the count badge reads properly", () => {
    // "6 algorithms", not "6 variants" under a heading that already says All variants.
    expect(hashToolDefinition("sha256").variants!(specFor("sha256")).noun).toBe("algorithm");
  });
});

describe("lint rules", () => {
  it("H001 flags a broken algorithm as insecure", () => {
    const result = lint(specFor("md5"));
    const h001 = result.diagnostics.find((d) => d.code === "H001");
    expect(h001?.level).toBe("insecure");
    expect(result.isInsecure).toBe(true);
  });

  it("H001 stays quiet for a modern algorithm", () => {
    expect(lint(specFor("sha256")).diagnostics.find((d) => d.code === "H001")).toBeUndefined();
  });

  it("H002 fires above one iteration, and its fix silences it", () => {
    const noisy = specFor("sha256", withIterations({}, 50));
    expect(lint(noisy).diagnostics.some((d) => d.code === "H002")).toBe(true);

    const fixed = applyAllFixes(noisy);
    expect(lint(fixed).diagnostics.some((d) => d.code === "H002")).toBe(false);
    expect(fixed.options[OPTION_ITERATIONS]).toBeUndefined();
  });

  it("H002 stays quiet at the double-hash count", () => {
    // 2 is the legitimate case the option exists for -- double-SHA-256 is what
    // Bitcoin does. Warning about a real construction would train people to
    // ignore the panel, which is the one thing it cannot afford.
    const doubled = specFor("sha256", withIterations({}, DOUBLE_HASH_ITERATIONS));
    expect(lint(doubled).diagnostics.some((d) => d.code === "H002")).toBe(false);
  });

  it("H002 fires one step above the double-hash count", () => {
    const tripled = specFor("sha256", withIterations({}, DOUBLE_HASH_ITERATIONS + 1));
    expect(lint(tripled).diagnostics.some((d) => d.code === "H002")).toBe(true);
  });

  it("H003 fires for XOFs only, H004 for parameterized only", () => {
    // The two rules say opposite things about what a shorter output means, so
    // exactly one of them must apply to any given algorithm — never both, never the
    // wrong one.
    for (const meta of HASH_ALGORITHMS) {
      const codes = lint(specFor(meta.id)).diagnostics.map((d) => d.code);
      expect(codes.includes("H003"), `${meta.id} H003`).toBe(meta.outputMode === "xof");
      expect(codes.includes("H004"), `${meta.id} H004`).toBe(
        meta.outputMode === "parameterized",
      );
    }
  });

  it("H005 fires when the requested length exceeds the ceiling, and its fix silences it", () => {
    const overLong = specFor("blake2s", withOutputLength({}, 64));
    const before = lint(overLong);
    const h005 = before.diagnostics.find((d) => d.code === "H005");
    expect(h005?.level).toBe("warning");
    expect(h005?.message).toContain("32");

    const fixed = applyAllFixes(overLong);
    expect(fixed.options[OPTION_OUTPUT_LENGTH]).toBe(32);
    expect(lint(fixed).diagnostics.some((d) => d.code === "H005")).toBe(false);
  });

  it("H005 stays quiet at and below the ceiling", () => {
    for (const length of [1, 16, 32]) {
      const spec = specFor("blake2s", withOutputLength({}, length));
      expect(lint(spec).diagnostics.some((d) => d.code === "H005")).toBe(false);
    }
  });

  it("H005 stays quiet for a fixed-output algorithm carrying a stale length", () => {
    // The option is ignored there (see the output-modes suite), so warning about it
    // would be warning about something with no effect.
    const spec = specFor("sha256", withOutputLength({}, 5000));
    expect(lint(spec).diagnostics.some((d) => d.code === "H005")).toBe(false);
  });

  it("never reports a blocking error for a plain digest", () => {
    for (const meta of HASH_ALGORITHMS) {
      expect(lint(specFor(meta.id)).hasErrors, meta.id).toBe(false);
    }
  });
});

describe("describeSpec", () => {
  it("names the algorithm and its real size", () => {
    expect(describeSpec(specFor("sha256"))).toBe(
      "Computes a SHA-256 digest — 32 bytes (256 bits).",
    );
  });

  it("calls two passes a double digest", () => {
    expect(describeSpec(specFor("sha256", withIterations({}, 2)))).toContain("double SHA-256");
  });

  it("spells out a higher count", () => {
    expect(describeSpec(specFor("sha512", withIterations({}, 5)))).toContain(
      "re-hashed 5 times",
    );
  });
});

describe("createSpec", () => {
  it("defaults to SHA-256", () => {
    expect(createSpec().algorithm).toBe("sha256");
  });

  it("refuses an algorithm with no metadata", () => {
    /**
     * `md6` used to be the fictional id here, and then MD6 was implemented.
     *
     * The same expired premise `crc12` had in `tests/crc-tool.test.ts`. `md7` does not exist and there
     * is no MD7 to implement, which is what makes it a safer choice than the next number up from the
     * newest thing in the family.
     */
    expect(() => createSpec({ algorithm: "md7" })).toThrow(/Unknown hash algorithm/);
  });

  it("round-trips through the zod schema", () => {
    const tool = hashToolDefinition("sha512");
    const spec = specFor("sha512", withIterations({}, 2));
    expect(tool.specSchema.parse(spec)).toEqual(spec);
  });

  it("rejects an unknown algorithm at the trust boundary", () => {
    const tool = hashToolDefinition("sha256");
    expect(() => tool.specSchema.parse({ ...specFor("sha256"), algorithm: "nope" })).toThrow();
  });
});

describe("requireHashAlgorithm", () => {
  it("throws with the offending id in the message", () => {
    expect(() => requireHashAlgorithm("md7")).toThrow(/md7/);
  });
});

/**
 * Block sizes read straight off the `@noble` objects, as an independent source to
 * compare the eager metadata against. Imported here rather than re-exported from the
 * package, because the whole point of `catalogue/algorithm-meta.ts` is that nothing
 * on its side of the split can see these.
 */
async function nobleBlockLens(): Promise<Map<string, number>> {
  const [sha2, legacy, sha3, blake1, blake2, blake3, addons] = await Promise.all([
    import("@noble/hashes/sha2.js"),
    import("@noble/hashes/legacy.js"),
    import("@noble/hashes/sha3.js"),
    import("@noble/hashes/blake1.js"),
    import("@noble/hashes/blake2.js"),
    import("@noble/hashes/blake3.js"),
    import("@noble/hashes/sha3-addons.js"),
  ]);

  /**
   * MD5-SHA1's block size is only meaningful because both halves agree on it. Asserting
   * that here rather than hardcoding 64 keeps the cross-check independent: if noble ever
   * disagreed between the two, this would be the line that noticed.
   */
  if (legacy.md5.blockLen !== legacy.sha1.blockLen) {
    throw new Error(
      `md5-sha1 has no single block size: MD5 is ${legacy.md5.blockLen}, SHA-1 is ${legacy.sha1.blockLen}`,
    );
  }

  return new Map<string, number>([
    // The original BLAKE: two cores, 64-byte blocks for the 32-bit pair and 128 for the 64-bit pair,
    // which is the one thing a wrong IV would not change and so is worth reading off the
    // implementation rather than trusting four hand-copied numbers.
    ["blake224", blake1.blake224.blockLen],
    ["blake256", blake1.blake256.blockLen],
    ["blake384", blake1.blake384.blockLen],
    ["blake512", blake1.blake512.blockLen],
    // The SHA-3 derived functions. Their block length is the sponge rate of the SHAKE they are
    // built on -- 168 for the 128-bit strength, 136 for the 256-bit -- which is worth
    // cross-checking rather than trusting, because it is copied into 14 metadata entries by hand.
    ["cshake128", addons.cshake128.blockLen],
    ["cshake256", addons.cshake256.blockLen],
    ["tuplehash128", addons.tuplehash128.blockLen],
    ["tuplehash256", addons.tuplehash256.blockLen],
    ["tuplehash128xof", addons.tuplehash128xof.blockLen],
    ["tuplehash256xof", addons.tuplehash256xof.blockLen],
    ["parallelhash128", addons.parallelhash128.blockLen],
    ["parallelhash256", addons.parallelhash256.blockLen],
    ["parallelhash128xof", addons.parallelhash128xof.blockLen],
    ["parallelhash256xof", addons.parallelhash256xof.blockLen],
    ["turboshake128", addons.turboshake128.blockLen],
    ["turboshake256", addons.turboshake256.blockLen],
    ["kt128", addons.kt128.blockLen],
    ["kt256", addons.kt256.blockLen],

    ["md5", legacy.md5.blockLen],
    ["sha1", legacy.sha1.blockLen],
    ["md5-sha1", legacy.md5.blockLen],
    ["ripemd160", legacy.ripemd160.blockLen],
    ["sha224", sha2.sha224.blockLen],
    ["sha256", sha2.sha256.blockLen],
    ["sha384", sha2.sha384.blockLen],
    ["sha512", sha2.sha512.blockLen],
    ["sha512-224", sha2.sha512_224.blockLen],
    ["sha512-256", sha2.sha512_256.blockLen],
    ["sha3-224", sha3.sha3_224.blockLen],
    ["sha3-256", sha3.sha3_256.blockLen],
    ["sha3-384", sha3.sha3_384.blockLen],
    ["sha3-512", sha3.sha3_512.blockLen],
    ["keccak-224", sha3.keccak_224.blockLen],
    ["keccak-256", sha3.keccak_256.blockLen],
    ["keccak-384", sha3.keccak_384.blockLen],
    ["keccak-512", sha3.keccak_512.blockLen],
    ["shake128", sha3.shake128.blockLen],
    ["shake256", sha3.shake256.blockLen],
    ["blake2b", blake2.blake2b.blockLen],
    ["blake2s", blake2.blake2s.blockLen],
    ["blake3", blake3.blake3.blockLen],
  ]);
}

// ── SHA-3 derived functions ─────────────────────────────────────────────────

describe("SHA-3 derived functions", () => {
  /**
   * Driven through the tool, not through `@noble` directly.
   *
   * That is the point of putting these here rather than beside the library: the customisation
   * string travels as a `bytes` option and the tuple as a `list` option, so a vector passing
   * proves the option decoding, the `availableOn` gating and the compute path all agree -- which
   * is where the interesting bugs live. Calling noble twice would prove nothing.
   */
  for (const vector of SHA3_ADDON_VECTORS) {
    const label = `${vector.algorithm}${vector.customization ? ` S="${vector.customization}"` : ""}`;
    it(`${label} at ${vector.outputLen} bytes matches ${vector.source}`, async () => {
      const base = createSpec({ algorithm: vector.algorithm });
      const options: HashSpec["options"] = {
        ...base.options,
        [OPTION_OUTPUT_LENGTH]: vector.outputLen,
      };
      if (vector.customization !== undefined) {
        options[OPTION_CUSTOMIZATION] = vector.customization;
        options.customizationEncoding = "utf-8";
      }
      if (vector.blockSize !== undefined) options[OPTION_BLOCK_SIZE] = vector.blockSize;
      if (vector.tuple !== undefined) {
        options[OPTION_TUPLE] = [...vector.tuple];
        options.tupleEncoding = "hex";
      }

      const input =
        vector.inputHex === undefined ? new Uint8Array(0) : fromHex(vector.inputHex);
      const result = await hashToolDefinition(vector.algorithm).compute(
        { ...base, options },
        input,
      );
      expect(result.error, `${label}: ${result.error}`).toBeUndefined();
      expect(encodeHex(result.bytes!)).toBe(vector.hex);
    });
  }
});

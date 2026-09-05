import { describe, expect, it } from "vitest";
import {
  DEFAULT_TOOL_ID,
  FAMILY_ORDER,
  getManifest,
  loadTool,
  manifestsInFamily,
  presentFamilies,
  TOOL_MANIFESTS,
} from "@ocs/registry";
import { isAvailableOn, withAvailableChoices, lint, validateCatalogue } from "@ocs/engine";

describe("TOOL_MANIFESTS", () => {
  it("is not empty", () => {
    expect(TOOL_MANIFESTS.length).toBeGreaterThan(0);
  });

  it("has unique ids", () => {
    const ids = TOOL_MANIFESTS.map((m) => m.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("gives every tool the fields the sidebar and header need", () => {
    for (const manifest of TOOL_MANIFESTS) {
      expect(manifest.label).not.toBe("");
      expect(manifest.summary).not.toBe("");
      expect(manifest.category).not.toBe("");
      expect(manifest.tags.length).toBeGreaterThan(0);
      expect(manifest.directions.length).toBeGreaterThan(0);
      expect(manifest.outputEncodings.length).toBeGreaterThan(0);
      expect(FAMILY_ORDER).toContain(manifest.family);
    }
  });

  /**
   * A tool reading no input cannot support a file either, and the two flags must not be set by hand
   * to agree. This is the implication a family gets wrong by adding `readsInput: false` and leaving
   * `supportsFile: true` behind, which would put a drop zone in front of a generator.
   */
  it("never offers a file to a tool that reads no input", () => {
    for (const manifest of TOOL_MANIFESTS) {
      if (manifest.readsInput) continue;
      expect(manifest.supportsFile, `${manifest.id} reads no input but offers a file`).toBe(
        false,
      );
      expect(manifest.streaming, `${manifest.id} reads no input but claims streaming`).toBe(
        false,
      );
    }
  });

  /**
   * The flag is not decorative: the one thing it must buy is that these tools compute from an empty
   * box. They used to appear to work only because the input happened to hold the check string, which
   * they then ignored -- so the moment the text box stopped being rendered they would have gone dead.
   */
  it("computes with no input at all for every tool that reads none", async () => {
    const readsNothing = TOOL_MANIFESTS.filter((m) => !m.readsInput);
    // Guards the guard: a filter that matched nothing would pass this silently for ever.
    expect(readsNothing.length).toBeGreaterThan(0);
    for (const manifest of readsNothing) {
      const tool = await loadTool(manifest.id);
      const spec = tool.createSpec();
      const result = await tool.compute(spec, new Uint8Array(0));
      const blocked = lint(spec, tool.lintRules).hasErrors;
      // Either it produces something, or it refuses for a reason the checks panel also reports --
      // the same agreement the default-spec test below requires, since a KDF with no password should
      // refuse and pre-filling one would be the worst possible default.
      if (result.error === undefined) {
        expect(result.bytes ?? result.text, `${manifest.id} produced nothing`).toBeDefined();
      } else {
        expect(
          blocked || tool.catalogue.secretIds().length > 0,
          `${manifest.id}: ${result.error}`,
        ).toBe(true);
      }
    }
  });

  /**
   * Verify compares bytes, so a tool with no bytes to compare must not offer it.
   *
   * The implication that always holds, and the only one: `outputEncodings` of just `utf-8` means the
   * result is text -- `VerifyPanel` reads `result.bytes` and finds nothing, so the panel renders a box
   * that can never say anything either way. That is what it did for all eight format tools and for the
   * UART diagram before `supportsVerify` existed.
   *
   * Deliberately *one*-directional. The reverse is not an invariant: a byte-output tool may still have
   * nothing anybody could hold a copy of in advance, which is why this is a manifest field rather than
   * something derived from the encodings.
   */
  /**
   * A text-output tool offers Verify only if it is named here, with the reason.
   *
   * This was a flat implication -- text-only output means no Verify -- and that was a *proxy* rather
   * than the rule. The rule, as `## A Verify panel with nothing to verify` states it, is "is there a
   * value somebody could already have", and the proxy held only while every text-output tool in the app
   * happened to be a document, a diagram or something freshly random. It also predates `verifyText`:
   * the panel could not compare text at all when it was written, so the two claims were the same claim.
   *
   * The Caesar cipher is the first tool where they come apart. Its output is letters, so it offers one
   * encoding and no selector -- and a ciphertext is exactly the kind of value somebody is holding when
   * they open a Verify box. Widening the implication to "text-only tools may verify" would give the
   * whole format family a panel that answers nothing, so it is an allowlist instead: a new tool has to
   * argue for itself here, which is the point.
   */
  const TEXT_VERIFIERS: Readonly<Record<string, string>> = {
    caesar: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    adfgvx: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    "vic-cipher": "a ciphertext is a value somebody already has, and verifyText compares it as text",
    "hill-cipher": "a ciphertext is a value somebody already has, and verifyText compares it as text",
    foursquare: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    chaocipher: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    enigma: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    vigenere: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    playfair: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    bifid: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    trifid: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    bacon: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    railfence: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    m209: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    lorenz: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    solitaire: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    adfgx: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    nihilist: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    "straddling-checkerboard": "a ciphertext is a value somebody already has, and verifyText compares it as text",
    typex: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    sigaba: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    bazeries: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    alberti: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    porta: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    gronsfeld: "a ciphertext is a value somebody already has, and verifyText compares it as text",
    jefferson: "a ciphertext is a value somebody already has, and verifyText compares it as text",
  };

  it("offers Verify to a text-output tool only where a value could exist to compare", () => {
    const unexpected: string[] = [];
    for (const manifest of TOOL_MANIFESTS) {
      const textOnly =
        manifest.outputEncodings.length === 1 && manifest.outputEncodings[0] === "utf-8";
      if (!textOnly || !manifest.supportsVerify) continue;
      if (!(manifest.id in TEXT_VERIFIERS)) unexpected.push(manifest.id);
    }
    expect(
      unexpected,
      "a text-output tool offers Verify without a reason recorded above",
    ).toEqual([]);
    // Guards the guard, twice: a filter matching nothing would pass this silently for ever, and an
    // allowlist entry for a tool that has stopped verifying is a stale claim.
    expect(TOOL_MANIFESTS.filter((m) => !m.supportsVerify).length).toBeGreaterThan(0);
    for (const id of Object.keys(TEXT_VERIFIERS)) {
      const manifest = TOOL_MANIFESTS.find((m) => m.id === id);
      expect(manifest, `${id} is allowlisted but not registered`).toBeDefined();
      expect(manifest!.supportsVerify, `${id} is allowlisted but does not offer Verify`).toBe(
        true,
      );
    }
  });

  /**
   * And the tools that *do* offer it produce bytes from their default spec.
   *
   * The other half of the same claim, made against the compute path rather than the metadata: a tool
   * promising Verify and returning only `text` would render the panel and never answer. Tools that
   * legitimately refuse a default spec are skipped -- a MAC with no key should refuse, and that is
   * covered by its own test above.
   */
  it("produces bytes for every tool that offers Verify", async () => {
    for (const manifest of TOOL_MANIFESTS) {
      if (!manifest.supportsVerify) continue;
      const tool = await loadTool(manifest.id);
      const result = await tool.compute(tool.createSpec(), new TextEncoder().encode("abc"));
      if (result.error !== undefined) continue;
      /**
       * Bytes *or* text, because the panel compares both.
       *
       * The encoding family's forward direction returns a Base64 string rather than bytes, and
       * comparing that as text is exactly what somebody wants -- so `verifyText` exists and this
       * assertion is "there is something to compare" rather than "there are bytes". What it still
       * catches is a tool promising Verify and producing neither.
       */
      expect(
        result.bytes ?? result.text,
        `${manifest.id} offers Verify but produced nothing to compare`,
      ).toBeDefined();
    }
  });

  it("only claims streaming for tools that actually implement it", async () => {
    for (const manifest of TOOL_MANIFESTS) {
      const tool = await loadTool(manifest.id);
      expect(Boolean(tool.createStream), `${manifest.id} streaming claim`).toBe(
        manifest.streaming,
      );
    }
  });
});

describe("loadTool", () => {
  /**
   * Tools whose input is a *document* rather than a byte string.
   *
   * The two assertions below both rest on "arbitrary bytes are valid input", which is true of a
   * digest, a checksum, a cipher and an encoding alphabet -- and false for CBOR, whose encoder takes
   * a JSON document and whose decoder takes hex. `abc` is neither, so it refuses, and that refusal is
   * about the input rather than about the settings: the checks panel is right to stay clean, because
   * nothing is wrong with the configuration.
   *
   * Exempted here rather than smoothed over in the tool. A CBOR encoder that quietly reinterpreted
   * invalid JSON as a byte string would satisfy this test and be worse software. The exemption still
   * has teeth: the tool must refuse with a message that names the format it wanted, and lint must
   * *not* block, which is the opposite assertion and catches the same class of bug from the other
   * side.
   *
   * A pattern per tool rather than one shared regex, so the exemption cannot be widened by accident:
   * each entry states what that tool's refusal has to say. The `format` family's three parsers are
   * here for exactly CBOR's reason -- `abc` is not a JWT, not JSON and not XML, and each says so.
   */
  const STRUCTURED_INPUT: Record<string, RegExp> = {
    cbor: /JSON|hex/i,
    jwt: /three dot-separated parts/i,
    json: /line \d+, column \d+/i,
    xml: /./,
    /**
     * BCH is here for a different reason from the four above, and it is worth distinguishing.
     *
     * Those four want a *format*. BCH wants any bytes at all -- but its data unit is five or six bits,
     * so a byte above 31 does not fit one codeword. `abc` is 0x61 0x62 0x63, all out of range.
     *
     * Masking them down would make every input computable and every answer meaningless: it would be a
     * codeword for a value nobody supplied, in a tool whose whole purpose is reproducing QR's own
     * published tables. The refusal has to name the range, which is what this pattern requires.
     */
    bch: /5 bits|6 bits|0 to (31|63)/i,
  };

  it("loads every registered tool and returns a usable definition", async () => {
    for (const manifest of TOOL_MANIFESTS) {
      const tool = await loadTool(manifest.id);
      expect(tool.id).toBe(manifest.id);
      expect(validateCatalogue(tool.catalogue.options), `${manifest.id} catalogue`).toEqual([]);

      const spec = tool.createSpec();
      expect(() => tool.specSchema.parse(spec)).not.toThrow();
      expect(tool.describe(spec)).not.toBe("");

      /**
       * A default spec either computes, or refuses for a reason the checks panel also
       * reports as blocking. Those two must agree.
       *
       * The original form of this assertion required every tool to compute from its
       * default — true for a digest or a checksum, and wrong the moment a keyed tool
       * appeared: a MAC with no key *should* refuse, and pre-filling one would be the worst
       * possible default. Requiring agreement between `compute` and `lint` is the invariant
       * that actually matters, and it catches the real bug in either direction — a tool
       * that errors with a clean checks panel, or one that computes while lint calls the
       * settings unusable.
       */
      const result = await tool.compute(spec, new TextEncoder().encode("abc"));
      const blocked = lint(spec, tool.lintRules).hasErrors;

      if (result.error === undefined) {
        expect(result.bytes ?? result.text, `${manifest.id} produced nothing`).toBeDefined();
        expect(blocked, `${manifest.id} computed but lint blocks it`).toBe(false);
      } else if (STRUCTURED_INPUT[manifest.id]) {
        expect(result.error, `${manifest.id} refused without saying what it wanted`).toMatch(
          STRUCTURED_INPUT[manifest.id]!,
        );
        expect(blocked, `${manifest.id} blocks its own default settings`).toBe(false);
      } else {
        expect(blocked, `${manifest.id} refused but lint reports no error`).toBe(true);
      }
    }
  });

  it("only refuses its default spec when the tool needs a secret", async () => {
    // Narrows the arm above: a tool with no key has no excuse for failing to compute.
    for (const manifest of TOOL_MANIFESTS) {
      const tool = await loadTool(manifest.id);
      const spec = tool.createSpec();
      const result = await tool.compute(spec, new TextEncoder().encode("abc"));
      if (result.error === undefined) continue;
      // See STRUCTURED_INPUT above: `abc` is not a document, and refusing it is correct.
      if (STRUCTURED_INPUT[manifest.id]) continue;
      expect(
        tool.catalogue.secretIds().length,
        `${manifest.id} refuses its default spec but has no secret option`,
      ).toBeGreaterThan(0);
    }
  });

  /**
   * Samples are an *input*, and an input that does not work is worse than none.
   *
   * Each is computed under its tool's own default spec -- which is the state a fresh box is seeded
   * into -- and required to produce something rather than a parse error. This is the whole reason a
   * format tool may seed the box at all: `123456789` in a JSON formatter shows an error where an
   * answer should be, and a sample that did the same would have solved nothing.
   */
  it("computes every sample a tool offers, under that tool's default spec", async () => {
    let checked = 0;
    for (const manifest of TOOL_MANIFESTS) {
      const tool = await loadTool(manifest.id);
      for (const sample of tool.samples ?? []) {
        expect(sample.label, `${manifest.id}/${sample.id}`).not.toBe("");
        expect(sample.note, `${manifest.id}/${sample.id}`).not.toBe("");
        expect(sample.text, `${manifest.id}/${sample.id}`).not.toBe("");
        const result = await tool.compute(
          tool.createSpec(),
          new TextEncoder().encode(sample.text),
        );
        expect(result.error, `${manifest.id}/${sample.id}: ${result.error}`).toBeUndefined();
        checked++;
      }
      // A sample on a tool with no box would be unreachable.
      if (!manifest.readsInput) expect(tool.samples ?? [], manifest.id).toEqual([]);
      // Ids have to be unique within a tool: the picker keys its options on them.
      const ids = (tool.samples ?? []).map((s) => s.id);
      expect(new Set(ids).size, manifest.id).toBe(ids.length);
    }
    expect(checked).toBeGreaterThan(0);
  });

  it("rejects an unknown id by name", async () => {
    await expect(loadTool("not-a-tool")).rejects.toThrow(/not-a-tool/);
  });
});

describe("families", () => {
  it("reports only families that actually have tools", () => {
    for (const family of presentFamilies()) {
      expect(manifestsInFamily(family).length).toBeGreaterThan(0);
    }
  });

  it("orders present families by FAMILY_ORDER", () => {
    const present = presentFamilies();
    const indices = present.map((f) => FAMILY_ORDER.indexOf(f));
    expect(indices).toEqual([...indices].sort((a, b) => a - b));
  });
});

describe("default specs", () => {
  it("leaves no select reading (not set)", async () => {
    /**
     * Every `enum` control a tool renders on open must have a value in the default spec.
     *
     * The options form renders `<option value="">(not set)</option>` first and selects it whenever
     * the stored value is not a string matching one of the choices -- so an unseeded enum, or one
     * seeded with a *number*, shows a tool that looks unconfigured while quietly computing at the
     * resolver's fallback. That is the worst of both: it reads as broken and it is not. The user
     * reported it on HAVAL's Passes control; this is the whole class.
     *
     * Note the `typeof value === "string"` check rather than a truthiness one. That mirrors the form
     * exactly, and it is the part that catches the number case -- which is how AEGIS's 256-bit tag
     * length was inert in the app for a while with a green suite.
     */
    const unset: string[] = [];
    for (const manifest of TOOL_MANIFESTS) {
      const tool = await loadTool(manifest.id);
      const spec = tool.createSpec();
      const tag = tool.variantTag?.(spec);
      const tags = tag === undefined ? [] : Array.isArray(tag) ? tag : [tag];
      for (const raw of tool.catalogue.options) {
        if (raw.kind !== "enum") continue;
        if (!isAvailableOn(raw, tags)) continue;
        /*
         * Choices are narrowed the way the form narrows them, which matters now that a choice can
         * carry its own `availableOn`: AES's Key size offers AES-128/192/256 under GCM and
         * XTS-AES-128/256 under XTS. Comparing the seed against the *unfiltered* list would call a
         * value seeded for one mode a match under another and miss exactly the "(not set)" this test
         * exists to catch.
         */
        const option = withAvailableChoices(raw, tags);
        if (option.choices?.length === 0) {
          unset.push(
            `${manifest.family}/${manifest.id}: ${option.id} has no reachable choices`,
          );
          continue;
        }
        const value = (spec as { options: Record<string, unknown> }).options[option.id];
        const chosen =
          typeof value === "string" && option.choices?.some((c) => c.value === value);
        if (!chosen) unset.push(`${manifest.family}/${manifest.id}: ${option.id}`);
      }
    }
    expect(unset).toEqual([]);
  });

  it("seeds a value the resolver would have used anyway", async () => {
    /**
     * Seeding must not change what a tool computes -- only what it shows.
     *
     * So a spec with the seeds stripped out has to produce the same bytes as the seeded one. If this
     * fails, someone has seeded a control with something other than the fallback it replaced, and
     * every tool that family covers now opens computing a different value than it used to.
     */
    const input = new TextEncoder().encode("abc");
    for (const manifest of TOOL_MANIFESTS) {
      if (!manifest.supportsFile && manifest.family !== "hash") continue;
      const tool = await loadTool(manifest.id);
      const spec = tool.createSpec();
      const enums = tool.catalogue.options.filter((o) => o.kind === "enum").map((o) => o.id);
      if (enums.length === 0) continue;
      const stripped = { ...(spec as { options: Record<string, unknown> }).options };
      for (const id of enums) delete stripped[id];

      /**
       * Skip anything nondeterministic, detected rather than listed.
       *
       * RSA's default operation generates a keypair, so two runs of the *same* spec disagree and the
       * comparison below means nothing. Probing for that beats keeping a list of ids, which would go
       * stale the first time another family gained a generate operation.
       */
      const seededResult = await tool.compute(spec, input);
      const repeat = await tool.compute(spec, input);
      const deterministic =
        seededResult.error !== undefined
          ? repeat.error === seededResult.error
          : String(repeat.bytes) === String(seededResult.bytes);
      if (!deterministic) continue;

      const strippedResult = await tool.compute(
        { ...spec, options: stripped } as typeof spec,
        input,
      );
      expect(
        strippedResult.error === undefined ? strippedResult.bytes : strippedResult.error,
        manifest.id,
      ).toEqual(seededResult.error === undefined ? seededResult.bytes : seededResult.error);
    }
  });
});

describe("DEFAULT_TOOL_ID", () => {
  it("names a tool that exists", () => {
    expect(getManifest(DEFAULT_TOOL_ID)).toBeDefined();
  });

  it("a fresh session does not open on a broken or superseded algorithm", () => {
    /**
     * The assertion the name always described, rather than the stricter one it used to make.
     *
     * It required `modern`, which was true of `sha256` and is not of `crc8` — a CRC is `not-a-mac`,
     * which is a statement about what the output *is for* and not a weakness. Landing on one is
     * fine, and `CRC001` says so on the first paint, which for a tool whose job is explaining that
     * distinction is arguably the better first impression.
     *
     * What must stay forbidden is opening on something `broken` or `legacy`: a page that greets you
     * with MD5 has recommended MD5, whatever the badge says.
     */
    const security = getManifest(DEFAULT_TOOL_ID)!.security;
    expect(["modern", "not-a-mac", "not-encryption"]).toContain(security);
  });

  it("is CRC-8, by name", () => {
    /**
     * Pinned to the id rather than inferred, because it is a requested default rather than a derived
     * one: CRC-8 is the variant a reader recognises, where declaration order in that family starts at
     * CRC-3 -- two variants of a three-bit field in a ROHC header.
     *
     * It is also now the tool *every* session opens on. The shell used to restore the last one from
     * saved state, which is the obvious behaviour and not the one wanted: which tool you last had
     * open is a position, and being dropped back into it is only right if you were interrupted.
     * `Auto update` is a preference and still persists. That half is not asserted here -- it lives in
     * the renderer and the Electron store, neither of which this suite can reach -- so the reasoning
     * is in `PersistedState` in `app-shell.tsx` and in `KnownState` in the desktop store.
     */
    expect(DEFAULT_TOOL_ID).toBe("crc8");
  });

  it("opens inside the family the sidebar leads with", () => {
    /**
     * The family, not the first tool in it.
     *
     * Declaration order in that family now starts at CRC-3 — two variants of a three-bit field in a
     * ROHC header — and opening there would be technically consistent and useless. CRC-8 is the one
     * a reader recognises. What matters is that the workbench and the top of the sidebar agree on
     * which family a fresh session is in, rather than the page starting four families down the list
     * the reader is looking at.
     */
    expect(getManifest(DEFAULT_TOOL_ID)!.family).toBe(presentFamilies()[0]);
  });
});

/**
 * The Variants panel's Result column opens on upper-case hex, and this is what keeps that a real
 * default rather than a silent fallback.
 *
 * `initialEncoding` in `variants-panel.tsx` picks `hex-upper` when the tool offers it and the tool's
 * own first encoding otherwise -- deliberately, because a tool whose output is text offers only
 * `utf-8` and the parity family opens on `binary` for a reason. That fallback is correct and it is
 * also silent: a family that gained variants while declaring no `hex-upper` would quietly open on
 * something else, and nothing on screen would say the default had not applied.
 *
 * So the assertion is on the tools that actually have a variants table. It is a real question rather
 * than a tautology -- `outputEncodings` is per-tool metadata and nothing forces `hex-upper` into it.
 */
describe("the Variants panel's default encoding", () => {
  it("is offered by every tool that has a variants table", async () => {
    const missing: string[] = [];
    let withVariants = 0;
    for (const manifest of TOOL_MANIFESTS) {
      const tool = await loadTool(manifest.id);
      if (!tool.variants) continue;
      withVariants += 1;
      if (!manifest.outputEncodings.includes("hex-upper")) {
        missing.push(`${manifest.id} offers ${manifest.outputEncodings.join(", ")}`);
      }
    }
    // A guard on the guard: if `variants` stopped being detected this would pass by checking nothing.
    expect(withVariants, "no tool reported a variants table").toBeGreaterThan(20);
    expect(missing, "these tools would open the Variants column on something else").toEqual([]);
  });
});

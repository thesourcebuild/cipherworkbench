import { describe, expect, it } from "vitest";
import {
  CHECKSUM_MANIFESTS,
  CHECKSUM_TOOLS,
  OPTION_BCC_MODE,
  OPTION_BYTE_ORDER,
  OPTION_RESULT,
  OPTION_WIDTH,
  OPTION_WORD_SIZE,
  requireChecksumTool,
  type ChecksumSpec,
} from "@ocs/checksum";
import {
  applyAllFixes,
  ALL_CHECKSUM_OPTIONS,
  checksumToolDefinition,
  createSpec,
  describeSpec,
  lint,
  RULE_CODES,
} from "@ocs/checksum/definition";
import { CHECK_INPUT } from "@ocs/algos";
import { encodeHex, rechunk, runStream, runStreams, validateCatalogue } from "@ocs/engine";

const ascii = (text: string) => new TextEncoder().encode(text);

async function* single(bytes: Uint8Array) {
  yield bytes;
}

function specFor(variant: string, options: ChecksumSpec["options"] = {}): ChecksumSpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } };
}

describe("every tool computes its published check value", () => {
  /**
   * The RevEng convention, borrowed: one agreed value for the ASCII input `123456789`.
   *
   * This is the gate that makes the family safe to extend. The algorithms are verified against
   * published vectors in `algos-checksum.test.ts`; this asserts the tool layer wires them up with
   * the defaults it advertises, which is where a wrong default word size or a missing complement
   * would show up.
   */
  for (const tool of CHECKSUM_TOOLS) {
    it(`${tool.label} → ${tool.check}`, async () => {
      const result = await checksumToolDefinition(tool.id).compute(
        specFor(tool.id),
        CHECK_INPUT,
      );
      expect(result.error).toBeUndefined();
      const expected = tool.check.replace(/^0x/, "").toLowerCase();
      expect(encodeHex(result.bytes!)).toBe(expected);
    });
  }

  it("advertises the check value only while the settings are the ones it describes", () => {
    // On `info`, not on the result: it follows from the settings, so it is there before anything is
    // typed -- and it must disappear the moment a setting moves away from the default it describes.
    const definition = checksumToolDefinition("sum");
    expect(definition.info!(specFor("sum")).some((f) => f.label === "Check value")).toBe(true);
    expect(
      definition.info!(specFor("sum", { [OPTION_WIDTH]: "16" })).some(
        (f) => f.label === "Check value",
      ),
    ).toBe(false);
  });

  it("splits what follows from the settings from what comes out of the digest", () => {
    // The rule for which half a field belongs in: would it still be true with no input.
    const definition = checksumToolDefinition("fletcher32");
    const info = definition.info!(specFor("fletcher32")).map((f) => f.label);
    expect(info).toContain("Grouping");
    expect(info).toContain("Check value");
    expect(info).not.toContain("Simple sum");
  });
});

describe("the options change the answer", () => {
  it("width truncates and word size regroups, independently", async () => {
    const definition = checksumToolDefinition("sum");
    const input = ascii("ab");

    const byte8 = await definition.compute(specFor("sum"), input);
    expect(encodeHex(byte8.bytes!)).toBe("c3"); // 0x61 + 0x62

    const word16 = await definition.compute(
      specFor("sum", { [OPTION_WIDTH]: "16", [OPTION_WORD_SIZE]: "16" }),
      input,
    );
    expect(encodeHex(word16.bytes!)).toBe("6162");

    const wordLe = await definition.compute(
      specFor("sum", {
        [OPTION_WIDTH]: "16",
        [OPTION_WORD_SIZE]: "16",
        [OPTION_BYTE_ORDER]: "little",
      }),
      input,
    );
    expect(encodeHex(wordLe.bytes!)).toBe("6261");
  });

  it("the one's complement sum reports either side of the complement", async () => {
    const definition = checksumToolDefinition("ones-complement");
    const input = new Uint8Array([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]);

    const raw = await definition.compute(
      specFor("ones-complement", { [OPTION_RESULT]: "sum" }),
      input,
    );
    expect(encodeHex(raw.bytes!)).toBe("ddf2");

    const complemented = await definition.compute(specFor("ones-complement"), input);
    expect(encodeHex(complemented.bytes!)).toBe("220d");

    // Both numbers appear in the fields either way round, because someone comparing against a
    // capture needs to see which one they have.
    for (const result of [raw, complemented]) {
      const labels = result.fields!.map((f) => f.label);
      expect(labels).toContain("Folded sum");
      expect(labels).toContain("Complement");
      expect(result.fields!.find((f) => f.label === "Folded sum")!.value).toBe("0xDDF2");
      expect(result.fields!.find((f) => f.label === "Complement")!.value).toBe("0x220D");
    }
  });

  it("BCC computes either convention", async () => {
    const definition = checksumToolDefinition("bcc");
    const input = ascii("ab");
    expect(encodeHex((await definition.compute(specFor("bcc"), input)).bytes!)).toBe("03");
    expect(
      encodeHex(
        (await definition.compute(specFor("bcc", { [OPTION_BCC_MODE]: "sum" }), input)).bytes!,
      ),
    ).toBe("c3");
  });

  it("Fletcher-32 exposes the byte order its published vectors depend on", async () => {
    const definition = checksumToolDefinition("fletcher32");
    const input = ascii("abcdef");
    // Little-endian is the default precisely because this is the published value.
    expect(encodeHex((await definition.compute(specFor("fletcher32"), input)).bytes!)).toBe(
      "56502d2a",
    );
    expect(
      encodeHex(
        (await definition.compute(specFor("fletcher32", { [OPTION_BYTE_ORDER]: "big" }), input))
          .bytes!,
      ),
    ).toBe("50562a2d");
  });

  it("reveals the byte order control exactly when it can matter", () => {
    // A control that provably cannot change the result is worse than no control, so byte order is
    // gated — but Fletcher-32's words are 16-bit by definition and it has no word-size option, so
    // it needs the tag unconditionally or its only control would be permanently hidden.
    const sum = checksumToolDefinition("sum");
    expect(sum.variantTag!(specFor("sum"))).toBeUndefined();
    expect(sum.variantTag!(specFor("sum", { [OPTION_WORD_SIZE]: "16" }))).toBe("words");
    expect(checksumToolDefinition("fletcher32").variantTag!(specFor("fletcher32"))).toBe(
      "words",
    );
  });
});

describe("the tools that coincide say so", () => {
  it("LRC equals the two's complement checksum, and BCC equals the XOR", async () => {
    const input = ascii("a checksum is not an integrity check");
    const pairs: [string, string][] = [
      ["lrc", "twos-complement"],
      ["bcc", "xor"],
    ];
    for (const [a, b] of pairs) {
      const left = await checksumToolDefinition(a).compute(specFor(a), input);
      const right = await checksumToolDefinition(b).compute(specFor(b), input);
      expect(encodeHex(left.bytes!), `${a} vs ${b}`).toBe(encodeHex(right.bytes!));
      // And the panel says the value is expected to be identical, rather than leaving someone who
      // tried both to wonder which one is broken. In `info`, because it is a fact about the two
      // tools rather than about this computation.
      const sameAs = checksumToolDefinition(a).info!(specFor(a)).find(
        (f) => f.label === "Same as",
      );
      expect(sameAs!.value).toBe(requireChecksumTool(b).label);
    }
  });

  it("declares the pairing in both directions", () => {
    for (const tool of CHECKSUM_TOOLS) {
      if (!tool.sameAs) continue;
      const other = requireChecksumTool(tool.sameAs);
      expect(other.sameAs, `${tool.id} claims ${other.id}`).toBeTruthy();
      // Not necessarily symmetric as a pair — two's complement points at LRC and LRC points back —
      // but every claim must land on a tool that makes a claim of its own, so a rename cannot leave
      // a one-way reference behind.
      expect(CHECKSUM_TOOLS.map((t) => t.id)).toContain(other.sameAs!);
    }
  });
});

describe("streaming", () => {
  for (const tool of CHECKSUM_TOOLS) {
    it(`${tool.label} streams identically to one shot`, async () => {
      const definition = checksumToolDefinition(tool.id);
      const spec = specFor(tool.id);
      const input = ascii("the quick brown fox jumps over the lazy dog, twice or so");
      const expected = await definition.compute(spec, input);

      for (const chunkSize of [1, 3, 7, 16]) {
        const streamed = await runStream(
          definition.createStream!(spec),
          rechunk(single(input), chunkSize),
        );
        expect(encodeHex(streamed.bytes!), `${tool.id} at ${chunkSize}`).toBe(
          encodeHex(expected.bytes!),
        );
        // The fields have to match too: they are derived from the digest in both paths precisely so
        // that a streamed file and a pasted string report the same breakdown.
        expect(streamed.fields, `${tool.id} at ${chunkSize}`).toEqual(expected.fields);
      }
    });
  }

  it("refuses reuse after finish", () => {
    for (const tool of CHECKSUM_TOOLS) {
      const stream = checksumToolDefinition(tool.id).createStream!(specFor(tool.id));
      stream.update(ascii("a"));
      stream.finish();
      expect(() => stream.update(ascii("b")), tool.id).toThrow(/after finish/);
      expect(() => stream.finish(), tool.id).toThrow(/twice/);
    }
  });
});

describe("catalogues and manifests", () => {
  it("every tool's option catalogue is internally consistent", () => {
    for (const tool of CHECKSUM_TOOLS) {
      expect(
        validateCatalogue(checksumToolDefinition(tool.id).catalogue.options),
        tool.id,
      ).toEqual([]);
    }
    // The shared list too: a duplicate order between two options that no single tool exposes
    // together would pass every per-tool check and still be a latent collision.
    expect(validateCatalogue(ALL_CHECKSUM_OPTIONS)).toEqual([]);
  });

  it("a tool exposes only options that exist, and its defaults name only options it exposes", () => {
    const known = new Set(ALL_CHECKSUM_OPTIONS.map((o) => o.id));
    for (const tool of CHECKSUM_TOOLS) {
      for (const id of tool.exposes) expect(known, tool.id).toContain(id);
      // A default for an option the tool does not show would be dead data that still ends up in
      // share links and saved state.
      expect(Object.keys(tool.defaults).sort(), tool.id).toEqual([...tool.exposes].sort());
    }
  });

  it("every default is one of the option's own choices", () => {
    for (const tool of CHECKSUM_TOOLS) {
      const catalogue = checksumToolDefinition(tool.id).catalogue;
      for (const [id, value] of Object.entries(tool.defaults)) {
        const choices = catalogue.require(id).choices!.map((c) => c.value);
        expect(choices, `${tool.id}.${id}`).toContain(value);
      }
    }
  });

  it("a manifest exists for every tool and describes it consistently", () => {
    expect(CHECKSUM_MANIFESTS.map((m) => m.id)).toEqual(CHECKSUM_TOOLS.map((t) => t.id));
    for (const manifest of CHECKSUM_MANIFESTS) {
      expect(manifest.family).toBe("checksum");
      // Nothing here is a MAC and nothing here should imply it might be.
      expect(manifest.security).toBe("not-a-mac");
      expect(manifest.streaming).toBe(true);
      expect(manifest.supportsFile).toBe(true);
      expect(manifest.directions).toEqual(["forward"]);
      // `decimal` is offered because these values genuinely are small integers.
      expect(manifest.outputEncodings).toContain("decimal");
    }
  });

  it("describes every tool in one sentence that names the width", async () => {
    for (const tool of CHECKSUM_TOOLS) {
      const sentence = describeSpec(specFor(tool.id));
      expect(sentence, tool.id).toMatch(/\.$/);
      const bytes = tool.width / 8;
      expect(sentence, tool.id).toContain(`${bytes} byte`);
    }
  });
});

describe("all variants", () => {
  /**
   * Nine rows, each reproducing its own published check value over `123456789`.
   *
   * `ChecksumToolMeta.check` is already asserted against `compute` elsewhere in this file, so this
   * is the second, independent route to the same number -- through the variants table's streams
   * rather than through the tool's own compute path. A row landing under the wrong label passes
   * neither.
   */
  it("gives every tool in the family its own published check value", async () => {
    const table = checksumToolDefinition("sum").variants!(specFor("sum"));
    expect(table.rows.map((r) => r.id)).toEqual(CHECKSUM_TOOLS.map((t) => t.id));

    const results = await runStreams(
      table.rows.map((row) => row.stream()),
      single(CHECK_INPUT),
    );
    for (const [index, row] of table.rows.entries()) {
      const tool = requireChecksumTool(row.id);
      // `check` is written the way the panel shows it: 0x, upper case.
      expect("0x" + encodeHex(results[index]!.bytes!, true), row.label).toBe(tool.check);
    }
  });

  it("names the coincidences instead of leaving three rows looking wrong", () => {
    /**
     * The reason this panel matters more here than anywhere. LRC *is* the two's complement sum at
     * eight bits and a BCC in XOR mode *is* the XOR checksum, so three of the nine agree by
     * construction. Someone matching a mystery byte off a serial link needs to know that agreement
     * is expected rather than a sign they have identified the algorithm.
     */
    const { columns, rows } = checksumToolDefinition("lrc").variants!(specFor("lrc"));
    const sameAs = (id: string) =>
      rows.find((r) => r.id === id)!.cells[columns.indexOf("Same as")];

    let coincidences = 0;
    for (const tool of CHECKSUM_TOOLS) {
      if (tool.sameAs === undefined) {
        expect(sameAs(tool.id), tool.id).toBe("—");
        continue;
      }
      coincidences++;
      expect(sameAs(tool.id), tool.id).toBe(requireChecksumTool(tool.sameAs).label);
    }
    expect(coincidences).toBeGreaterThan(0);
  });

  it("runs each row at its own defaults, not the open tool's", async () => {
    /**
     * `width` and `byteOrder` belong to individual tools. Threading the open tool's options through
     * every row would make a 32-bit sum appear under an 8-bit heading -- so the table has to be the
     * same whichever member you happen to be viewing it from.
     */
    const fromSum = checksumToolDefinition("sum").variants!(
      specFor("sum", { [OPTION_WIDTH]: "32" }),
    );
    const fromXor = checksumToolDefinition("xor").variants!(specFor("xor"));
    expect(fromSum.rows.map((r) => r.cells)).toEqual(fromXor.rows.map((r) => r.cells));

    const a = await runStreams(
      fromSum.rows.map((r) => r.stream()),
      single(CHECK_INPUT),
    );
    const b = await runStreams(
      fromXor.rows.map((r) => r.stream()),
      single(CHECK_INPUT),
    );
    expect(a.map((r) => encodeHex(r.bytes!, false))).toEqual(
      b.map((r) => encodeHex(r.bytes!, false)),
    );
  });

  it("marks the tool it is being viewed from", () => {
    for (const id of ["sum", "xor", "adler32"]) {
      const { rows } = checksumToolDefinition(id).variants!(specFor(id));
      expect(
        rows.filter((r) => r.selected).map((r) => r.id),
        id,
      ).toEqual([id]);
    }
  });
});

describe("lint rules", () => {
  it("each rule fires somewhere, and each fix silences the rule that offered it", () => {
    // The pattern used by every family here: a rule nobody can trigger is dead weight, and a fix
    // that does not clear its own diagnostic is worse than no fix.
    const fired = new Set<string>();
    const specs: ChecksumSpec[] = [
      ...CHECKSUM_TOOLS.map((t) => specFor(t.id)),
      specFor("sum", { [OPTION_WIDTH]: "16", [OPTION_WORD_SIZE]: "16" }),
      specFor("ones-complement", { [OPTION_RESULT]: "sum" }),
    ];

    for (const spec of specs) {
      for (const diagnostic of lint(spec).diagnostics) {
        fired.add(diagnostic.code);
        if (!diagnostic.fix) continue;
        const fixed = diagnostic.fix.apply(spec);
        expect(
          lint(fixed).diagnostics.map((d) => d.code),
          `${spec.variant}/${diagnostic.code}`,
        ).not.toContain(diagnostic.code);
      }
    }

    expect([...fired].sort()).toEqual([...RULE_CODES].sort());
  });

  it("applyAllFixes leaves a spec that still computes", async () => {
    // `applyAllFixes` runs every fix in one pass, so two of them can land on the same spec.
    for (const tool of CHECKSUM_TOOLS) {
      const fixed = applyAllFixes(specFor(tool.id));
      const result = await checksumToolDefinition(tool.id).compute(fixed, CHECK_INPUT);
      expect(result.error, tool.id).toBeUndefined();
      expect(
        lint(fixed).diagnostics.filter((d) => d.level === "error"),
        tool.id,
      ).toEqual([]);
    }
  });

  it("tells every tool that a checksum is not an integrity check", () => {
    // S001 is the reason this family carries diagnostics at all, so it is the one rule that must
    // fire on all nine tools rather than on a configuration.
    for (const tool of CHECKSUM_TOOLS) {
      const codes = lint(specFor(tool.id)).diagnostics.map((d) => d.code);
      expect(codes, tool.id).toContain("S001");
    }
  });

  it("warns about order-blindness for the sums and not for Fletcher or Adler", () => {
    for (const tool of CHECKSUM_TOOLS) {
      const codes = lint(specFor(tool.id)).diagnostics.map((d) => d.code);
      const positionSensitive = [
        "fletcher16",
        "fletcher32",
        "adler32",
        "verhoeff",
        "damm",
        "luhn",
        "isbn",
        "iban",
        "aba-routing",
        "cusip-isin",
        "sedol",
      ].includes(tool.kind);
      expect(codes.includes("S002"), tool.id).toBe(!positionSensitive);
    }
  });

  it("offers a wider result only where the width is the user's to choose", () => {
    // An LRC is eight bits because Modbus says so; a diagnostic suggesting otherwise would be
    // advice nobody can take.
    expect(lint(specFor("sum")).diagnostics.map((d) => d.code)).toContain("S003");
    expect(lint(specFor("lrc")).diagnostics.map((d) => d.code)).not.toContain("S003");
    expect(lint(specFor("xor")).diagnostics.map((d) => d.code)).not.toContain("S003");
  });

  it("mentions the padding only where a partial word can occur", () => {
    expect(lint(specFor("sum")).diagnostics.map((d) => d.code)).not.toContain("S006");
    expect(
      lint(specFor("sum", { [OPTION_WORD_SIZE]: "16" })).diagnostics.map((d) => d.code),
    ).toContain("S006");
    expect(lint(specFor("fletcher32")).diagnostics.map((d) => d.code)).toContain("S006");
  });
});

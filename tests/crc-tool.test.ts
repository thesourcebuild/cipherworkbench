import { describe, expect, it } from "vitest";
import {
  CRC_MANIFESTS,
  CRC_TOOLS,
  CUSTOM_MODEL,
  formatHexParam,
  OPTION_INIT,
  OPTION_MODEL,
  OPTION_POLY,
  OPTION_REF_IN,
  OPTION_REF_OUT,
  OPTION_XOR_OUT,
  requireCrcTool,
  type CrcSpec,
} from "@ocs/crc";
import {
  applyAllFixes,
  createSpec,
  crcToolDefinition,
  describeSpec,
  lint,
  matchingCatalogueEntry,
  resolveModel,
} from "@ocs/crc/definition";
import {
  CHECK_INPUT,
  CRC_CATALOGUE,
  crcLookupTable,
  reflect,
  reflectByte,
  requireCrcModel,
} from "@ocs/algos";
import {
  encodeHex,
  encodeOutput,
  identifyAmong,
  rechunk,
  runStream,
  runStreams,
  validateCatalogue,
} from "@ocs/engine";

const ascii = (text: string) => new TextEncoder().encode(text);

function specFor(variant: string, options: CrcSpec["options"] = {}): CrcSpec {
  return {
    ...createSpec({ variant }),
    options: { ...createSpec({ variant }).options, ...options },
  };
}

describe("named models compute their published check value through the tool", () => {
  /**
   * The catalogue's own check values are already verified in `algos-crc.test.ts`
   * against the engine. This asserts the same thing end to end through the tool
   * layer, which is where a wrong default model or a mis-parsed option would show up.
   */
  for (const tool of CRC_TOOLS) {
    it(`${tool.label} — every model reachable from this tool`, async () => {
      const definition = crcToolDefinition(tool.id);
      const models = CRC_CATALOGUE.filter((m) => m.width === tool.width);
      expect(models.length).toBeGreaterThan(0);

      for (const model of models) {
        const result = await definition.compute(
          specFor(tool.id, { [OPTION_MODEL]: model.name }),
          CHECK_INPUT,
        );
        expect(result.error, model.name).toBeUndefined();
        /**
         * Padded to the *byte* length of the output, not to the width's hex digits.
         *
         * The two agree from width 5 up, and diverge below it: a 3-bit CRC still comes out of
         * `digestBytes` as one byte, so CRC-3/GSM's check value 0x4 renders "04" and not "4".
         * `ceil(width / 4)` was right while every width was a multiple of 8.
         */
        const expected = model.check.toString(16).padStart(Math.ceil(model.width / 8) * 2, "0");
        expect(encodeHex(result.bytes!), model.name).toBe(expected);
      }
    });
  }

  it("reports the parameters that produce the value, from the spec alone", () => {
    // Two tools that both say "CRC-16" disagree a third of the time, so a checksum with no
    // statement of which variant produced it is not reproducible.
    //
    // Through `info` rather than `compute`, and the distinction is the point: these seven values
    // follow from the model, so they are available with no input at all and the UI can show them
    // beside the dropdown that chose them.
    const definition = crcToolDefinition("crc16");
    const fields = definition.info!(specFor("crc16", { [OPTION_MODEL]: "CRC-16/MODBUS" }));
    const labels = fields.map((f) => f.label);
    expect(labels).toContain("Model");
    expect(labels).toContain("Polynomial");
    expect(labels).toContain("Init");
    expect(labels).toContain("Reflect in / out");
    expect(labels).toContain("Final xor");
    expect(labels).toContain("Check value");

    expect(fields.find((f) => f.label === "Polynomial")!.value).toBe("0x8005");
  });

  it("carries no fields on the result itself", async () => {
    // A CRC produces one number. Anything else the panel shows about it is a restatement of the
    // settings, and duplicating it under the digest is what put it in two places at once.
    const result = await crcToolDefinition("crc16").compute(
      specFor("crc16", { [OPTION_MODEL]: "CRC-16/MODBUS" }),
      CHECK_INPUT,
    );
    expect(result.fields).toBeUndefined();
  });

  it("has nothing to say about parameters that do not resolve", () => {
    // CRC002 already reports the half-typed polynomial; a table of blanks beside it would say
    // nothing twice.
    const definition = crcToolDefinition("crc32");
    expect(definition.info!(specFor("crc32", { [OPTION_MODEL]: CUSTOM_MODEL }))).toEqual([]);
  });

  it("offers decimal and octal output, which the hash family deliberately does not", () => {
    /**
     * Both are here and absent from digests, for the same reason and by the same rule.
     *
     * `decimal` because a CRC-32 is a number people quote as `3421780262`; `octal` because a short
     * checksum is small enough for a per-byte rendering to stay readable. A 32-byte digest is not,
     * which is why `DIGEST_OUTPUT_ENCODINGS` offers neither -- and why the rule is "wherever
     * `binary` is offered" rather than "everywhere".
     */
    for (const manifest of CRC_MANIFESTS) {
      expect(manifest.outputEncodings).toContain("decimal");
      expect(manifest.outputEncodings).toContain("octal");
      expect(manifest.outputEncodings).toContain("binary");
    }
  });

  it("renders CRC-32 as the decimal integer people quote", async () => {
    const definition = crcToolDefinition("crc32");
    const result = await definition.compute(specFor("crc32"), CHECK_INPUT);
    // 0xcbf43926
    expect(encodeOutput(result.bytes!, "decimal")).toBe("3421780262");
  });
});

describe("the eager tags carry every searchable name", () => {
  /**
   * The sidebar searches `ToolManifest.tags`, and the manifest is eager -- it must not import the
   * model catalogue, which is the whole point of the family's manifest/definition split. So the
   * terms are written into `CRC_TOOLS.tags` as literals and generated offline from the catalogue.
   *
   * This is what keeps the two halves honest, exactly as the hash family's `outputLen` test does.
   * Without it, adding a model would leave it unfindable by name and nothing would say so.
   */
  it("every model name and alias at a width is a tag on that width's tool", () => {
    for (const tool of CRC_TOOLS) {
      const tags = new Set(requireCrcTool(tool.id).tags.map((t) => t.toLowerCase()));
      const models = CRC_CATALOGUE.filter((m) => m.width === tool.width);
      expect(models.length, tool.id).toBeGreaterThan(0);

      for (const model of models) {
        for (const term of [model.name, ...(model.aliases ?? [])]) {
          expect(tags.has(term.toLowerCase()), `${tool.id} is missing tag "${term}"`).toBe(
            true,
          );
          // And the bare form, since nobody types "crc-32/castagnoli".
          if (term.includes("/")) {
            const bare = term.split("/").pop()!.toLowerCase();
            expect(tags.has(bare), `${tool.id} is missing tag "${bare}"`).toBe(true);
          }
        }
      }
    }
  });

  it("finds the terms people actually type", () => {
    // The end the user sees: a search string, and the tool it should land on.
    const find = (query: string) =>
      CRC_TOOLS.filter((t) =>
        requireCrcTool(t.id).tags.some((tag) => tag.toLowerCase().includes(query)),
      ).map((t) => t.id);

    expect(find("castagnoli")).toEqual(["crc32"]);
    expect(find("modbus")).toEqual(["crc16"]);
    expect(find("openpgp")).toEqual(["crc24"]);
    expect(find("zmodem")).toEqual(["crc16"]);
    expect(find("dow-crc")).toEqual(["crc8"]);
    expect(find("go-ecma")).toEqual(["crc64"]);
    expect(find("can-fd")).toEqual(["crc17", "crc21"]);
  });
});

describe("custom parameters", () => {
  const customCrc32 = {
    [OPTION_MODEL]: CUSTOM_MODEL,
    [OPTION_POLY]: "0x04C11DB7",
    [OPTION_INIT]: "0xFFFFFFFF",
    [OPTION_XOR_OUT]: "0xFFFFFFFF",
    [OPTION_REF_IN]: true,
    [OPTION_REF_OUT]: true,
  };

  it("reproduces a named model when given its parameters", async () => {
    const definition = crcToolDefinition("crc32");
    const result = await definition.compute(specFor("crc32", customCrc32), CHECK_INPUT);
    expect(encodeHex(result.bytes!)).toBe("cbf43926");
  });

  it("names the catalogue entry it just rediscovered", () => {
    // The point of custom mode is identifying an unknown checksum. Telling someone they have
    // arrived at CRC-32/ISO-HDLC ends the search.
    const definition = crcToolDefinition("crc32");
    const matches = definition.info!(specFor("crc32", customCrc32)).find(
      (f) => f.label === "Matches",
    );
    expect(matches?.value).toBe("CRC-32/ISO-HDLC");
  });

  it("accepts hex with or without the 0x prefix, in either case", async () => {
    const definition = crcToolDefinition("crc32");
    for (const poly of ["0x04C11DB7", "04c11db7", "04C11DB7", "0x04c11db7"]) {
      const result = await definition.compute(
        specFor("crc32", { ...customCrc32, [OPTION_POLY]: poly }),
        CHECK_INPUT,
      );
      expect(encodeHex(result.bytes!), poly).toBe("cbf43926");
    }
  });

  it("reports a missing polynomial as a result, not an exception", async () => {
    const definition = crcToolDefinition("crc32");
    const result = await definition.compute(
      specFor("crc32", { [OPTION_MODEL]: CUSTOM_MODEL }),
      CHECK_INPUT,
    );
    expect(result.bytes).toBeUndefined();
    expect(result.error).toMatch(/polynomial/i);
  });

  it("refuses a parameter too wide for the tool", async () => {
    const definition = crcToolDefinition("crc8");
    const result = await definition.compute(
      specFor("crc8", { [OPTION_MODEL]: CUSTOM_MODEL, [OPTION_POLY]: "0x1FF" }),
      CHECK_INPUT,
    );
    expect(result.error).toMatch(/does not fit in 8 bits/);
  });

  it("treats a half-typed polynomial as absent rather than as zero", () => {
    // Silently reading "0x" as 0 would show a confident, wrong CRC on every keystroke.
    const resolved = resolveModel(
      specFor("crc32", { [OPTION_MODEL]: CUSTOM_MODEL, [OPTION_POLY]: "0x" }),
    );
    expect(resolved.ok).toBe(false);
  });

  it("defaults init, xorOut and both reflection flags to zero/false", () => {
    const resolved = resolveModel(
      specFor("crc16", { [OPTION_MODEL]: CUSTOM_MODEL, [OPTION_POLY]: "0x8005" }),
    );
    expect(resolved.ok).toBe(true);
    if (resolved.ok) {
      expect(resolved.model.init).toBe(0n);
      expect(resolved.model.xorOut).toBe(0n);
      expect(resolved.model.refIn).toBe(false);
      expect(resolved.model.refOut).toBe(false);
      // Poly 0x8005 unreflected with a zero init and no final xor is UMTS, not ARC.
      expect(matchingCatalogueEntry(resolved.model)?.name).toBe("CRC-16/UMTS");
    }
  });

  it("the reflection flags are what separate ARC from UMTS", () => {
    // Same polynomial, same init, same xor. Two entirely different checksums, and the
    // reason "CRC-16" on its own is not a specification.
    const base = { [OPTION_MODEL]: CUSTOM_MODEL, [OPTION_POLY]: "0x8005" };

    const unreflected = resolveModel(specFor("crc16", base));
    const reflected = resolveModel(
      specFor("crc16", { ...base, [OPTION_REF_IN]: true, [OPTION_REF_OUT]: true }),
    );

    expect(unreflected.ok && matchingCatalogueEntry(unreflected.model)?.name).toBe(
      "CRC-16/UMTS",
    );
    expect(reflected.ok && matchingCatalogueEntry(reflected.model)?.name).toBe("CRC-16/ARC");
  });
});

describe("streaming", () => {
  async function* single(bytes: Uint8Array) {
    yield bytes;
  }

  it("chunked equals one-shot for every tool", async () => {
    const input = ascii(
      "the quick brown fox jumps over the lazy dog, repeatedly and at length",
    );

    for (const tool of CRC_TOOLS) {
      const definition = crcToolDefinition(tool.id);
      const spec = specFor(tool.id);
      const oneShot = await definition.compute(spec, input);

      for (const chunkSize of [1, 7, 64]) {
        const streamed = await runStream(
          definition.createStream!(spec),
          rechunk(single(input), chunkSize),
        );
        expect(encodeHex(streamed.bytes!), `${tool.id} @ ${chunkSize}`).toBe(
          encodeHex(oneShot.bytes!),
        );
      }
    }
  });

  it("a stream with incomplete settings consumes the input and reports the problem", async () => {
    // The caller must not need a second code path for "settings are not ready yet".
    const definition = crcToolDefinition("crc32");
    const spec = specFor("crc32", { [OPTION_MODEL]: CUSTOM_MODEL });
    const result = await runStream(
      definition.createStream!(spec),
      rechunk(single(ascii("anything")), 3),
    );
    expect(result.error).toMatch(/polynomial/i);
  });

  it("refuses reuse after finish", () => {
    for (const variant of CRC_TOOLS.map((t) => t.id)) {
      const stream = crcToolDefinition(variant).createStream!(specFor(variant));
      stream.update(ascii("a"));
      stream.finish();
      expect(() => stream.update(ascii("b")), variant).toThrow(/after finish/);
      expect(() => stream.finish(), variant).toThrow(/twice/);
    }
  });
});

describe("catalogues", () => {
  it("every tool's option catalogue is internally consistent", () => {
    for (const tool of CRC_TOOLS) {
      expect(validateCatalogue(crcToolDefinition(tool.id).catalogue.options), tool.id).toEqual(
        [],
      );
    }
  });

  it("each width's model list contains exactly that width's models, plus Custom", () => {
    for (const tool of CRC_TOOLS) {
      const model = crcToolDefinition(tool.id).catalogue.require(OPTION_MODEL);
      const values = model.choices!.map((c) => c.value);
      const expected = CRC_CATALOGUE.filter((m) => m.width === tool.width).map((m) => m.name);
      expect(values).toEqual([...expected, CUSTOM_MODEL]);
    }
  });

  it("gives the custom parameters their own panel, above the result", () => {
    // Six controls being tuned against a live value: not a setting chosen once, and not part of the
    // message either. The workbench decides where a group renders from this one field.
    const groups = crcToolDefinition("crc32").groups;
    expect(groups.parameters?.placement).toBe("panel");
    // The model dropdown stays in the rail, which is what "no placement" means.
    expect(groups.model?.placement).toBeUndefined();
  });

  it("separates the named models from Custom in the dropdown", () => {
    // A native select cannot hold a rule, so the break comes from an optgroup boundary. Picking
    // Custom does something categorically different from picking a model.
    const model = crcToolDefinition("crc8").catalogue.require(OPTION_MODEL);
    const groups = model.choices!.map((c) => c.group);
    expect(new Set(groups.slice(0, -1))).toEqual(new Set(["Standard Models"]));
    expect(groups[groups.length - 1]).toBe("Customize Model");
    expect(model.choices![model.choices!.length - 1]!.value).toBe(CUSTOM_MODEL);
  });

  it("names the aliases in Info, since the dropdown shows bare names", () => {
    // "ISO-HDLC" means nothing on its own; the alias list is how the variant is recognised. It used
    // to be in the option text, where five aliases cropped every other name in the list.
    // Matched on the first line rather than the whole label: it carries a newline, because the row
    // reads "ALIAS" over "(ALSO KNOWN AS)" in the panel.
    const alsoKnownAs = crcToolDefinition("crc32").info!(specFor("crc32")).find(
      (f) => f.label.split("\n")[0] === "Alias",
    );
    expect(alsoKnownAs?.label).toContain("Also known as");
    expect(alsoKnownAs?.value).toContain("CRC-32");
  });

  it("shows the parameter fields only in Custom mode", () => {
    const definition = crcToolDefinition("crc32");
    expect(definition.variantTag!(specFor("crc32"))).toBeUndefined();
    expect(definition.variantTag!(specFor("crc32", { [OPTION_MODEL]: CUSTOM_MODEL }))).toBe(
      "custom",
    );
    // Selecting a named model must not leave its polynomial editable — that would
    // allow "MODBUS" to be selected while computing something else entirely.
    expect(
      definition.variantTag!(specFor("crc32", { [OPTION_MODEL]: "CRC-32/ISCSI" })),
    ).toBeUndefined();
  });
});

describe("lint rules", () => {
  it("CRC001 always fires, at info level, for every tool", () => {
    // The misuse it describes is the most common cryptographic mistake there is, so
    // it says so every time — but at `info`, because computing a CRC is not an error
    // and crying wolf on the tool's own purpose would teach people to ignore the panel.
    for (const tool of CRC_TOOLS) {
      const found = lint(specFor(tool.id)).diagnostics.find((d) => d.code === "CRC001");
      expect(found?.level, tool.id).toBe("info");
      expect(found?.message, tool.id).toMatch(/not tampering/);
    }
  });

  it("every tool is marked not-a-mac", () => {
    /**
     * The badge, and `CRC001` above is the explanation.
     *
     * This also required a `securityNote` per tool. Those are gone, and this width is the reason
     * the removal was right rather than merely asked for: CRC-8's note said all thirteen of its
     * models were designed for a two-wire bus, which is true of SMBus and false of Bluetooth LE,
     * DVB-S2, LTE, SAE-J1850 and 1-Wire. A sentence written once cannot describe a dropdown.
     */
    for (const manifest of CRC_MANIFESTS) {
      expect(manifest.security).toBe("not-a-mac");
    }
  });

  it("CRC002 blocks on an unusable custom polynomial", () => {
    const spec = specFor("crc32", { [OPTION_MODEL]: CUSTOM_MODEL });
    const result = lint(spec);
    expect(result.hasErrors).toBe(true);
    expect(result.diagnostics.some((d) => d.code === "CRC002")).toBe(true);
  });

  it("CRC003 offers to switch to the catalogue entry, and the fix works", () => {
    const spec = specFor("crc16", {
      [OPTION_MODEL]: CUSTOM_MODEL,
      [OPTION_POLY]: "0x8005",
      [OPTION_REF_IN]: true,
      [OPTION_REF_OUT]: true,
    });
    const before = lint(spec).diagnostics.find((d) => d.code === "CRC003");
    expect(before?.message).toContain("CRC-16/ARC");

    const fixed = applyAllFixes(spec);
    expect(fixed.options[OPTION_MODEL]).toBe("CRC-16/ARC");
    expect(lint(fixed).diagnostics.some((d) => d.code === "CRC003")).toBe(false);
    // And the switch must not change the value it computes.
    expect(fixed.options[OPTION_POLY]).toBe("0x8005");
  });

  it("CRC004 warns that a zero polynomial detects nothing", () => {
    const spec = specFor("crc32", { [OPTION_MODEL]: CUSTOM_MODEL, [OPTION_POLY]: "0x0" });
    expect(lint(spec).diagnostics.some((d) => d.code === "CRC004")).toBe(true);
  });

  it("CRC005 notes a zero init, and stays quiet for a non-zero one", () => {
    const zero = specFor("crc32", {
      [OPTION_MODEL]: CUSTOM_MODEL,
      [OPTION_POLY]: "0x04C11DB7",
    });
    expect(lint(zero).diagnostics.some((d) => d.code === "CRC005")).toBe(true);

    const nonZero = specFor("crc32", {
      [OPTION_MODEL]: CUSTOM_MODEL,
      [OPTION_POLY]: "0x04C11DB7",
      [OPTION_INIT]: "0xFFFFFFFF",
    });
    expect(lint(nonZero).diagnostics.some((d) => d.code === "CRC005")).toBe(false);
  });

  it("the custom-only rules stay quiet for named models", () => {
    for (const spec of CRC_TOOLS.map((t) => specFor(t.id))) {
      const codes = lint(spec).diagnostics.map((d) => d.code);
      expect(codes).not.toContain("CRC002");
      expect(codes).not.toContain("CRC003");
      expect(codes).not.toContain("CRC004");
      expect(codes).not.toContain("CRC005");
    }
  });

  it("never blocks a named model", () => {
    for (const tool of CRC_TOOLS) {
      expect(lint(specFor(tool.id)).hasErrors, tool.id).toBe(false);
    }
  });
});

describe("describeSpec", () => {
  it("names the model and spells out its parameters", () => {
    const text = describeSpec(specFor("crc32", { [OPTION_MODEL]: "CRC-32/ISO-HDLC" }));
    // "CRC-32" alone is ambiguous between twelve variants; the polynomial is not.
    expect(text).toContain("CRC-32/ISO-HDLC");
    expect(text).toContain("0x04C11DB7");
    expect(text).toContain("4 bytes");
  });

  it("describes mixed reflection accurately", () => {
    // MCRF4XX reflects both; a hand-built spec that reflects only the input must not
    // be described as "reflected".
    const mixed = specFor("crc16", {
      [OPTION_MODEL]: CUSTOM_MODEL,
      [OPTION_POLY]: "0x1021",
      [OPTION_REF_IN]: true,
    });
    expect(describeSpec(mixed)).toContain("reflected on input only");
  });

  it("says what is missing when custom parameters are incomplete", () => {
    const text = describeSpec(specFor("crc32", { [OPTION_MODEL]: CUSTOM_MODEL }));
    expect(text).toMatch(/polynomial/i);
  });
});

describe("createSpec", () => {
  it("names a concrete model rather than relying on a fallback", () => {
    // A spec that does not say which of thirty-one CRC-16s it means is not a spec.
    expect(createSpec({ variant: "crc16" }).options[OPTION_MODEL]).toBe("CRC-16/ARC");
    expect(createSpec({ variant: "crc32" }).options[OPTION_MODEL]).toBe("CRC-32/ISO-HDLC");
  });

  it("gives every tool a model, since every tool is a CRC", () => {
    // Adler-32 used to be the exception here. It is a `@ocs/checksum` tool now, so the
    // "a spec might have no model" branch is gone from the family entirely.
    for (const tool of CRC_TOOLS) {
      expect(createSpec({ variant: tool.id }).options[OPTION_MODEL], tool.id).toBe(
        tool.defaultModel,
      );
    }
  });

  it("rejects an unknown variant", () => {
    // `crc9`, because there is no CRC-9 in the RevEng catalogue and so no tool for it. This said
    // `crc12` until width 12 was added, at which point the example stopped being fictional and the
    // test failed -- which is the right way round for a test whose premise has expired.
    expect(() => createSpec({ variant: "crc9" })).toThrow(/Unknown CRC tool/);
    expect(() => requireCrcTool("crc9")).toThrow(/crc9/);
  });

  it("falls back to the default model when a share link names one that does not exist", () => {
    // A link is written by someone else; an unknown model must not blank the page.
    const resolved = resolveModel(specFor("crc32", { [OPTION_MODEL]: "CRC-32/INVENTED" }));
    expect(resolved.ok).toBe(true);
    if (resolved.ok) expect(resolved.model.name).toBe("CRC-32/ISO-HDLC");
  });
});

describe("the lookup table", () => {
  it("is the table the engine actually runs on", () => {
    /**
     * The point of the panel, and the one thing it must not get wrong.
     *
     * A displayed table that disagreed with the engine would be worse than no table at all -- it
     * would be a reference someone copies into their own code, which then fails to match this tool.
     * `crcLookupTable(model, "normal")` returns `buildTable`'s own output rather than rebuilding it,
     * and the way to check that from outside is to run the algorithm *by hand* over the table and
     * require the digest to come out.
     */
    // All 113, including the five widths under a byte. Those run on a left-justified register --
    // `justify` below is the whole of the difference, and it is why they get a panel at all.
    for (const model of CRC_CATALOGUE) {
      const table = crcLookupTable(model, "normal");
      expect(table).toHaveLength(256);

      /**
       * The layout, worked out here rather than imported from the implementation.
       *
       * `registerLayout` is exported and using it would make this test agree with the thing it is
       * checking. Four lines of arithmetic a reader can verify against the sentence "shift the
       * polynomial up into a byte" is the point of a cross-check.
       */
      const regWidth = Math.max(8, model.width);
      const justify = BigInt(regWidth - model.width);
      const init = model.init << justify;

      const m = (1n << BigInt(regWidth)) - 1n;
      const shift = BigInt(regWidth - 8);
      /**
       * The engine's own arrangement, and the reason there is one table rather than two.
       *
       * `init` goes in unreflected, `refIn` reflects each input *byte*, and `refOut` reflects the
       * register at the end. Reflecting the init instead, or gating the output reflection on
       * `refIn !== refOut`, are both plausible and both wrong here -- I wrote each of them first and
       * CRC-8/MAXIM-DOW caught it. Which convention a table belongs to is exactly what this test is
       * for, since a reader copying the grid out needs the loop that goes with it.
       */
      let reg = init & m;
      for (const raw of CHECK_INPUT) {
        const byte = model.refIn ? reflectByte(raw) : raw;
        const index = Number(((reg >> shift) ^ BigInt(byte)) & 0xffn);
        reg = ((reg << 8n) ^ table[index]!) & m;
      }
      // Down out of the register before reflecting or xoring: the low `justify` bits are padding,
      // and folding them into the answer is the one way this arrangement goes wrong.
      let value = reg >> justify;
      if (model.refOut) value = reflect(value, model.width);
      expect(value ^ model.xorOut, model.name).toBe(model.check);
    }
  });

  it("derives the reflected orientation rather than building a second table", () => {
    /**
     * `T_ref[i] === reflect(T_norm[reflectByte(i)])`, for all 256 entries of all 113 models.
     *
     * This is the identity `crcLookupTable` relies on, asserted against a table built the other way
     * -- lsb-first from the reflected polynomial. Worth pinning rather than trusting: a hand-built
     * second table is precisely the thing that comes out self-consistent and disagrees with the
     * engine it claims to describe, which is the bug the sibling project's CRC has.
     *
     * Everything here is at the *register* width, which for the five sub-byte models is 8 rather
     * than their own. That is not a concession to the implementation: the polynomial being tabulated
     * genuinely is an 8-bit one, so its reflection is an 8-bit reflection.
     */
    for (const model of CRC_CATALOGUE) {
      const derived = crcLookupTable(model, "reflected");
      const regWidth = Math.max(8, model.width);
      const m = (1n << BigInt(regWidth)) - 1n;
      const polyReflected = reflect(model.poly << BigInt(regWidth - model.width), regWidth);
      for (let i = 0; i < 256; i++) {
        let direct = BigInt(i);
        for (let bit = 0; bit < 8; bit++) {
          direct = (direct & 1n) !== 0n ? (direct >> 1n) ^ polyReflected : direct >> 1n;
        }
        expect(derived[i], `${model.name} entry ${i}`).toBe(direct & m);
      }
    }
  });

  it("is offered by the tool, formatted to the model's width, in both orientations", () => {
    for (const [toolId, modelName, digits] of [
      // `crc5` is here for the register width: its entries are byte-wide, so two digits and not
      // one, which is the visible half of the justification.
      ["crc5", "CRC-5/USB", 2],
      ["crc8", "CRC-8/SMBUS", 2],
      ["crc16", "CRC-16/ARC", 4],
      ["crc32", "CRC-32/ISO-HDLC", 8],
      ["crc64", "CRC-64/XZ", 16],
    ] as const) {
      const definition = crcToolDefinition(toolId);
      const tables = definition.tables!(specFor(toolId, { [OPTION_MODEL]: modelName }));
      expect(
        tables.map((t) => t.id),
        toolId,
      ).toEqual(["normal", "reflected"]);
      for (const table of tables) {
        expect(table.values, `${toolId}/${table.id}`).toHaveLength(256);
        expect(table.columns).toBe(16);
        // Padded, not trimmed: a table is read in columns and ragged cells make it unreadable.
        for (const value of table.values) {
          expect(value, `${toolId}/${table.id} cell width`).toHaveLength(digits);
          expect(value).toMatch(/^[0-9A-F]+$/);
        }
      }
      // And the two orientations are genuinely different tables, not the same one twice.
      expect(tables[0]!.values).not.toEqual(tables[1]!.values);
    }
  });

  it("tracks a custom polynomial rather than the named model it started from", () => {
    // The table follows the spec, so switching to Custom and changing the polynomial has to move
    // it. A table memoised on the tool id would look right and be stale.
    const definition = crcToolDefinition("crc16");
    const named = definition.tables!(specFor("crc16", { [OPTION_MODEL]: "CRC-16/ARC" }));
    const custom = definition.tables!(
      specFor("crc16", { [OPTION_MODEL]: CUSTOM_MODEL, [OPTION_POLY]: "0x1021" }),
    );
    expect(custom).toHaveLength(2);
    expect(custom[0]!.values).not.toEqual(named[0]!.values);
  });

  it("offers nothing when the spec does not resolve", () => {
    // A half-filled custom form is a normal state, and the panel hides rather than showing a grid
    // of zeros that mean nothing.
    const definition = crcToolDefinition("crc16");
    expect(definition.tables!(specFor("crc16", { [OPTION_MODEL]: CUSTOM_MODEL }))).toEqual([]);
  });
});

describe("all variants", () => {
  /** One chunk, as an async iterable -- the same shape `useVariants` hands the typed path. */
  async function* once(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
    yield bytes;
  }

  /** Feeds one input to every row's stream, exactly as `useVariants` does. */
  async function runAll(
    toolId: string,
    options: Record<string, string> = {},
    input = CHECK_INPUT,
  ) {
    const table = crcToolDefinition(toolId).variants!(specFor(toolId, options));
    const results = await runStreams(
      table.rows.map((row) => row.stream()),
      once(input),
    );
    return {
      table,
      values: table.rows.map((row, index) => ({
        label: row.label,
        hex: encodeHex(results[index]!.bytes!, false),
      })),
    };
  }

  /**
   * The panel crccalc.com is used for: every model of a width, over one input, with its parameters.
   *
   * The assertion is not "twenty rows appeared" but that each row is *that model's published check
   * value*, which over `CHECK_INPUT` is exactly what the catalogue records. That covers all 113
   * models across the 22 tools in one pass, and it fails on a row landing under the wrong name -- an
   * off-by-one in the width filter, a stream list that got out of step with the row list -- which
   * counting rows never would. That failure is worse than an empty panel: someone identifying an
   * unknown checksum comes away with the wrong model *name*.
   */
  it("gives every model of the width its own published check value", async () => {
    for (const tool of CRC_TOOLS) {
      const { values } = await runAll(tool.id);
      const expected = CRC_CATALOGUE.filter((m) => m.width === tool.width);
      expect(
        values.map((v) => v.label),
        tool.id,
      ).toEqual(expected.map((m) => m.name));
      for (const value of values) {
        const model = requireCrcModel(value.label);
        expect(BigInt("0x" + value.hex), value.label).toBe(model.check);
      }
    }
  });

  it("gets the same answers from one pass as from a pass each", async () => {
    /**
     * `runStreams` exists so a hundred gigabytes is read once rather than once per variant, and this
     * is the property that makes that safe: fanning the chunks out to thirty engines has to agree
     * with running thirty separate passes. Chunked deliberately, because a fan-out that forgot to
     * forward every chunk would still be right for a single-chunk input.
     */
    const table = crcToolDefinition("crc16").variants!(specFor("crc16"));
    const together = await runStreams(
      table.rows.map((row) => row.stream()),
      rechunk(once(CHECK_INPUT), 2),
    );
    for (const [index, row] of table.rows.entries()) {
      const alone = await runStream(row.stream(), rechunk(once(CHECK_INPUT), 3));
      expect(encodeHex(together[index]!.bytes!, false), row.label).toBe(
        encodeHex(alone.bytes!, false),
      );
    }
  });

  it("gives every row exactly one cell per declared column", () => {
    /**
     * The invariant that makes the columns worth returning with the rows rather than from a second
     * member. A short `cells` array silently shifts every value one column left, so a polynomial
     * appears under Init and reads as a perfectly plausible number.
     */
    for (const tool of CRC_TOOLS) {
      const table = crcToolDefinition(tool.id).variants!(specFor(tool.id));
      expect(table.columns).toEqual(["Check", "Poly", "Init", "RefIn", "RefOut", "XorOut"]);
      for (const row of table.rows) {
        expect(row.cells.length, `${tool.id}: ${row.label}`).toBe(table.columns.length);
      }
    }
  });

  it("states each model's own parameters, not the selected model's", () => {
    /**
     * The cells have to come from the row's model. Reading them off the resolved spec instead would
     * put the *selected* model's polynomial on all twenty rows -- which looks entirely normal, and is
     * the single most misleading thing this panel could do.
     */
    const { columns, rows } = crcToolDefinition("crc8").variants!(
      specFor("crc8", { [OPTION_MODEL]: "CRC-8/SMBUS" }),
    );
    const cell = (label: string, column: string) =>
      rows.find((r) => r.label === label)!.cells[columns.indexOf(column)];

    expect(cell("CRC-8/SMBUS", "Poly")).toBe("0x07");
    expect(cell("CRC-8/BLUETOOTH", "Poly")).toBe("0xA7");
    expect(cell("CRC-8/MAXIM-DOW", "Poly")).toBe("0x31");
    // Reflection and the final xor differ across the same list, and are the other two people copy.
    expect(cell("CRC-8/SMBUS", "RefIn")).toBe("false");
    expect(cell("CRC-8/MAXIM-DOW", "RefIn")).toBe("true");
    expect(cell("CRC-8/GSM-B", "XorOut")).toBe("0xFF");
    expect(cell("CRC-8/SMBUS", "XorOut")).toBe("0x00");
  });

  it("carries the aliases, which is how a row gets found at all", () => {
    // Nobody looks for "CRC-8/I-432-1"; they look for "CRC-8/ITU".
    const { rows } = crcToolDefinition("crc8").variants!(specFor("crc8"));
    const itu = rows.find((r) => r.label === "CRC-8/I-432-1");
    expect(itu?.aliases?.map((a) => a.toLowerCase())).toContain("crc-8/itu");
  });

  it("hands out a fresh stream every call", async () => {
    /**
     * `stream()` is a factory precisely so the panel can render rows without building engines, and a
     * second Run has to work. A shared instance would throw "finish() called twice" on the second
     * press -- or worse, keep accumulating the first run's bytes.
     */
    const row = crcToolDefinition("crc8").variants!(specFor("crc8")).rows[0]!;
    const first = await runStream(row.stream(), once(CHECK_INPUT));
    const second = await runStream(row.stream(), once(CHECK_INPUT));
    expect(encodeHex(second.bytes!, false)).toBe(encodeHex(first.bytes!, false));
  });

  it("marks the model the tool is set to, and only that one", () => {
    const { rows } = crcToolDefinition("crc16").variants!(
      specFor("crc16", { [OPTION_MODEL]: "CRC-16/MODBUS" }),
    );
    expect(rows.filter((r) => r.selected).map((r) => r.label)).toEqual(["CRC-16/MODBUS"]);
  });

  it("marks nothing in custom mode", () => {
    /**
     * Honest rather than helpful. Hand-entered parameters are not one of the catalogued models until
     * they happen to coincide with one, and "is my custom model actually a standard one" already has
     * its own answer -- the `Matches` row in Info, from `matchingCatalogueEntry`.
     */
    const { rows } = crcToolDefinition("crc16").variants!(
      specFor("crc16", { [OPTION_MODEL]: CUSTOM_MODEL, [OPTION_POLY]: "0x8005" }),
    );
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.some((r) => r.selected)).toBe(false);
  });

  it("tracks the input rather than the settings", async () => {
    // Change the bytes and every Result moves, while the parameter cells beside them do not.
    const nine = await runAll("crc8");
    const abc = await runAll("crc8", {}, new TextEncoder().encode("abc"));
    expect(abc.values.map((v) => v.label)).toEqual(nine.values.map((v) => v.label));
    expect(abc.table.rows.map((r) => r.cells)).toEqual(nine.table.rows.map((r) => r.cells));
    expect(abc.values.map((v) => v.hex)).not.toEqual(nine.values.map((v) => v.hex));
  });

  it("covers every width the family offers", () => {
    // One row per model, 113 of them, with no width contributing zero.
    let total = 0;
    for (const tool of CRC_TOOLS) {
      const { rows } = crcToolDefinition(tool.id).variants!(specFor(tool.id));
      expect(rows.length, tool.id).toBeGreaterThan(0);
      total += rows.length;
    }
    expect(total).toBe(CRC_CATALOGUE.length);
  });
});

describe("identify", () => {
  async function* once(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
    yield bytes;
  }

  /** The rows plus their values, which is what `identifyAmong` takes. */
  async function computed(toolId: string, input = CHECK_INPUT) {
    const table = crcToolDefinition(toolId).variants!(specFor(toolId));
    const results = await runStreams(
      table.rows.map((row) => row.stream()),
      once(input),
    );
    return table.rows.map((row, index) => ({ id: row.id, bytes: results[index]!.bytes! }));
  }

  /**
   * Every one of the 113 models is found from its own published check value.
   *
   * The assertion is `toContain`, not `toEqual`, and that is the whole point: several widths have
   * models that produce the *identical* value over this input, so pinning a single id would be a test
   * that is wrong about the arithmetic. What must hold is that the right model is never missed.
   */
  it("finds every model from its own published check value", async () => {
    for (const tool of CRC_TOOLS) {
      const candidates = await computed(tool.id);
      for (const model of CRC_CATALOGUE.filter((m) => m.width === tool.width)) {
        const own = candidates.find((c) => c.id === model.name);
        expect(own, `${tool.id}: ${model.name} has no row`).toBeDefined();
        const found = identifyAmong(candidates, encodeHex(own!.bytes, false));
        expect(found.ids, `${tool.id}: ${model.name}`).toContain(model.name);
        expect(found.readAs).toBe("hex");
      }
    }
  });

  /**
   * The collisions, named. Over the check string these pairs are indistinguishable, and the panel says
   * so rather than picking one -- so the *count* is asserted here, because a change that silently
   * started returning one id would look like an improvement and be a regression.
   */
  it("returns every model that produces the value, not the first", async () => {
    const candidates = await computed("crc8");
    // CRC-8/I-432-1 (poly 0x07, xorOut 0x55) and CRC-8/MAXIM-DOW (poly 0x31, reflected) both give A1.
    const found = identifyAmong(candidates, "a1");
    expect(found.ids.length).toBeGreaterThan(1);
    expect(found.ids).toContain("CRC-8/I-432-1");
    expect(found.ids).toContain("CRC-8/MAXIM-DOW");
  });

  it("reads the pasted value however it is spelled", async () => {
    /**
     * The reuse that makes this cheap: `identifyAmong` calls `verifyAgainst` per candidate, so it
     * inherits the encoding sniffing and the `.sha256`-line handling for free. If these three ever
     * disagree, something has grown its own parser.
     */
    const candidates = await computed("crc32");
    const bare = identifyAmong(candidates, "cbf43926");
    expect(bare.ids).toContain("CRC-32/ISO-HDLC");

    // Base64 of the same four bytes, and a checksum-file line with a filename after it.
    expect(identifyAmong(candidates, "y/Q5Jg==").ids).toContain("CRC-32/ISO-HDLC");
    expect(identifyAmong(candidates, "cbf43926  archive.tar.gz").ids).toContain(
      "CRC-32/ISO-HDLC",
    );
  });

  it("separates a value that is absent from one that is not a value", async () => {
    /**
     * Two different answers, and the panel words them differently: "no model here produces that" is
     * actionable, "that is not a checksum" is a typo. `anyParsed` is what carries the distinction.
     */
    const candidates = await computed("crc8");
    const absent = identifyAmong(candidates, "ff");
    const nonsense = identifyAmong(candidates, "zzz");

    expect(absent.ids).toEqual([]);
    expect(absent.anyParsed).toBe(true);
    expect(nonsense.ids).toEqual([]);
    expect(nonsense.anyParsed).toBe(false);
  });

  it("does not match across widths on a length collision", async () => {
    // A one-byte value cannot be a CRC-16, and `verifyAgainst` refuses on length before comparing.
    const candidates = await computed("crc16");
    expect(identifyAmong(candidates, "f4").ids).toEqual([]);
  });
});

describe("formatHexParam", () => {
  it("pads to the model's width", () => {
    expect(formatHexParam(0x7n, 8)).toBe("0x07");
    expect(formatHexParam(0x1021n, 16)).toBe("0x1021");
    expect(formatHexParam(0xafn, 32)).toBe("0x000000AF");
    expect(formatHexParam(0x1bn, 64)).toBe("0x000000000000001B");
  });
});

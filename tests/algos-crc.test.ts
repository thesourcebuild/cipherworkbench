import { describe, expect, it } from "vitest";
import {
  CHECK_INPUT,
  CRC_CATALOGUE,
  createCrc,
  crc,
  crcBytes,
  crcHex,
  crcLookupTable,
  crcModelsByWidth,
  getCrcModel,
  mask,
  reflect,
  reflectByte,
  requireCrcModel,
} from "@ocs/algos";
// Reached by path, not through the package's exports: the reference implementation is
// deliberately not part of the public surface (see `packages/algos/src/crc/index.ts`).
// Only the test suite has a reason to touch it.
import { crcReference } from "../packages/algos/src/crc/reference";

const ascii = (text: string) => new TextEncoder().encode(text);

/** Deterministic pseudo-random bytes — no Math.random, so a failure is reproducible. */
function pseudoRandom(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let state = seed >>> 0;
  for (let i = 0; i < length; i++) {
    // xorshift32
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[i] = state & 0xff;
  }
  return out;
}

describe("the catalogue's own check values", () => {
  /**
   * Every entry in the RevEng catalogue publishes the CRC of the ASCII bytes
   * "123456789". This is what makes it safe to transcribe sixty-odd sets of
   * constants by hand: a wrong polynomial digit or a flipped reflection flag cannot
   * produce the right check value, so a transcription error fails here instead of
   * silently disagreeing with gzip.
   */
  for (const model of CRC_CATALOGUE) {
    it(`${model.name} reproduces its published check value`, () => {
      expect(crc(model, CHECK_INPUT).toString(16)).toBe(model.check.toString(16));
    });
  }

  it("covers every width group it claims to", () => {
    const widths = [...crcModelsByWidth().keys()].sort((a, b) => a - b);
    // Every width the RevEng catalogue defines, and nothing else. Written out rather than derived,
    // so a width appearing or vanishing is a failure here instead of a silent change.
    expect(widths).toEqual([
      3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 21, 24, 30, 31, 32, 40, 64, 82,
    ]);
  });

  it("carries every model the RevEng catalogue defines", () => {
    /**
     * 113, which is all of them.
     *
     * A count rather than a list, because the list is the file below and asserting it twice would
     * only test the copy. What this catches is a model being dropped in a refactor -- and if RevEng
     * ever publishes a 114th, this fails and someone goes and looks, which is the intent.
     */
    expect(CRC_CATALOGUE).toHaveLength(113);
  });

  it("has no duplicate names", () => {
    const names = CRC_CATALOGUE.map((m) => m.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it("keeps every constant inside its declared width", () => {
    for (const model of CRC_CATALOGUE) {
      const m = mask(model.width);
      expect(model.poly, `${model.name} poly`).toBeLessThanOrEqual(m);
      expect(model.init, `${model.name} init`).toBeLessThanOrEqual(m);
      expect(model.xorOut, `${model.name} xorOut`).toBeLessThanOrEqual(m);
      expect(model.check, `${model.name} check`).toBeLessThanOrEqual(m);
    }
  });
});

describe("the fast engine agrees with the bit-at-a-time reference", () => {
  /**
   * The check value alone is not enough to trust a table-driven CRC. Its two
   * characteristic bugs — a table built in the wrong bit order, and a reflection
   * applied at the wrong end — can coincidentally satisfy one nine-byte vector while
   * being wrong for everything else.
   *
   * So every model is also run against `crcReference`, which is a direct
   * transcription of the model's definition with no table and no width-dependent fast
   * path. Neither implementation can fake agreement with the other across varied
   * inputs.
   */
  const inputs: readonly Uint8Array[] = [
    new Uint8Array(0),
    ascii("a"),
    ascii("123456789"),
    new Uint8Array([0x00]),
    new Uint8Array([0xff]),
    new Uint8Array([0x00, 0x00, 0x00, 0x00]),
    new Uint8Array([0xff, 0xff, 0xff, 0xff]),
    pseudoRandom(1, 1),
    pseudoRandom(7, 2),
    pseudoRandom(64, 3),
    pseudoRandom(255, 4),
    pseudoRandom(1000, 5),
  ];

  for (const model of CRC_CATALOGUE) {
    it(`${model.name}`, () => {
      for (const input of inputs) {
        expect(crc(model, input), `${model.name} over ${input.length} bytes`).toBe(
          crcReference(model, input),
        );
      }
    });
  }
});

describe("streaming", () => {
  it("chunked updates equal a single update, for every model", () => {
    // The invariant the file-hashing path depends on. Chunk sizes chosen to land
    // mid-byte-run and to be co-prime with the input length.
    const input = pseudoRandom(1000, 42);

    for (const model of CRC_CATALOGUE) {
      const oneShot = crc(model, input);

      for (const chunkSize of [1, 3, 7, 64, 999]) {
        const engine = createCrc(model);
        for (let offset = 0; offset < input.length; offset += chunkSize) {
          engine.update(input.subarray(offset, offset + chunkSize));
        }
        expect(engine.digest(), `${model.name} in ${chunkSize}-byte chunks`).toBe(oneShot);
      }
    }
  });

  it("digest() does not finalise — updates may continue after it", () => {
    const model = requireCrcModel("CRC-32/ISO-HDLC");
    const engine = createCrc(model);
    engine.update(ascii("1234"));
    engine.digest();
    engine.update(ascii("56789"));
    expect(engine.digest()).toBe(model.check);
  });

  it("reset() returns the engine to its initial state", () => {
    const model = requireCrcModel("CRC-16/MODBUS");
    const engine = createCrc(model);
    engine.update(ascii("garbage"));
    engine.reset();
    engine.update(CHECK_INPUT);
    expect(engine.digest()).toBe(model.check);
  });
});

describe("output shapes", () => {
  it("digestBytes is big-endian and the model's width", () => {
    expect(Array.from(crcBytes(requireCrcModel("CRC-32/ISO-HDLC"), CHECK_INPUT))).toEqual([
      0xcb, 0xf4, 0x39, 0x26,
    ]);
    expect(Array.from(crcBytes(requireCrcModel("CRC-8/SMBUS"), CHECK_INPUT))).toEqual([0xf4]);
    expect(crcBytes(requireCrcModel("CRC-24/OPENPGP"), CHECK_INPUT)).toHaveLength(3);
    expect(crcBytes(requireCrcModel("CRC-64/XZ"), CHECK_INPUT)).toHaveLength(8);
  });

  it("crcHex pads to the full width", () => {
    // A CRC-32 that happens to start with a zero nibble must still be 8 characters,
    // or it will not match a value quoted anywhere else.
    expect(crcHex(requireCrcModel("CRC-32/MPEG-2"), CHECK_INPUT)).toBe("0376e6e7");
    expect(crcHex(requireCrcModel("CRC-16/DECT-R"), CHECK_INPUT)).toBe("007e");
    expect(crcHex(requireCrcModel("CRC-64/XZ"), CHECK_INPUT)).toBe("995dc9bbdf1939fa");
  });
});

describe("aliases and residue", () => {
  it("never gives one model another model's canonical name", () => {
    /**
     * The one way an alias list can actually break something.
     *
     * `getCrcModel` looks up canonical names, and the sidebar search matches aliases -- so an alias
     * that collides with a different model's real name makes two entries answer to one string, and
     * whichever the search happens to reach first wins. The merge that pulled these in from two
     * sources had to drop collisions, and this is what keeps that true.
     */
    const canonical = new Set(CRC_CATALOGUE.map((m) => m.name));
    for (const model of CRC_CATALOGUE) {
      for (const alias of model.aliases ?? []) {
        expect(canonical.has(alias), `${model.name} claims "${alias}", a canonical name`).toBe(
          false,
        );
      }
    }
  });

  it("gives no alias to two models at once", () => {
    // Two models answering to the same alias is the same ambiguity from the other direction, and it
    // is legitimate for none of them -- an alias names one algorithm.
    const owner = new Map<string, string>();
    for (const model of CRC_CATALOGUE) {
      for (const alias of model.aliases ?? []) {
        const already = owner.get(alias.toLowerCase());
        expect(already, `"${alias}" is claimed by both ${already} and ${model.name}`).toBeUndefined();
        owner.set(alias.toLowerCase(), model.name);
      }
    }
  });

  it("has no alias that repeats its own model's name, or itself", () => {
    for (const model of CRC_CATALOGUE) {
      const aliases = model.aliases ?? [];
      const lowered = aliases.map((a) => a.toLowerCase());
      expect(new Set(lowered).size, `${model.name} has a duplicate alias`).toBe(aliases.length);
      expect(lowered, model.name).not.toContain(model.name.toLowerCase());
    }
  });

  it("attaches the search terms people actually type", () => {
    // Spot checks on the names nobody would guess the canonical form of. These came from the RevEng
    // catalogue and the sibling project's own alias lists, merged.
    // Lower-cased: the dedupe keeps whichever spelling reads better ("Modbus" over "MODBUS"), and
    // what matters is that the term is present, not how it is cased.
    const aliasesOf = (name: string) =>
      (requireCrcModel(name).aliases ?? []).map((a) => a.toLowerCase());
    expect(aliasesOf("CRC-32/ISO-HDLC")).toContain("pkzip");
    expect(aliasesOf("CRC-32/ISO-HDLC")).toContain("ethernet");
    expect(aliasesOf("CRC-32/ISCSI")).toContain("crc-32c");
    expect(aliasesOf("CRC-32/ISCSI")).toContain("crc-32/castagnoli");
    expect(aliasesOf("CRC-16/KERMIT")).toContain("crc-ccitt");
    expect(aliasesOf("CRC-16/KERMIT")).toContain("crc-16/bluetooth");
    expect(aliasesOf("CRC-16/MODBUS")).toContain("modbus");
    expect(aliasesOf("CRC-16/XMODEM")).toContain("zmodem");
    expect(aliasesOf("CRC-8/TECH-3250")).toContain("crc-8/aes");
    expect(aliasesOf("CRC-64/XZ")).toContain("crc-64/go-ecma");
  });

  it("publishes a residue for every catalogued model", () => {
    // Every RevEng entry has one, so a missing residue means a transcription gap rather than a
    // model that legitimately lacks it. Custom models are the only ones allowed none, and they are
    // built in the resolver rather than living here.
    for (const model of CRC_CATALOGUE) {
      expect(model.residue, `${model.name} residue`).toBeDefined();
      expect(model.residue! & ~mask(model.width), model.name).toBe(0n);
    }
  });

  it("the residue is what a message with its own CRC appended produces", () => {
    /**
     * Not a transcription check -- an arithmetic one.
     *
     * Append the CRC to the message the way a sender does and run the whole thing through again: the
     * result is the published residue. That is the property the number exists for, and computing it
     * here means a mistyped residue fails rather than sitting on screen looking plausible.
     *
     * Reflected models append the CRC little-endian and non-reflected ones big-endian, which is the
     * detail that makes this worth asserting rather than assuming. `xorOut` has to be undone first,
     * because the residue is defined on the register before the final xor.
     */
    const message = ascii("123456789");
    for (const model of CRC_CATALOGUE) {
      const width = model.width;
      // Only whole-byte widths can have a CRC appended as bytes at all.
      if (width % 8 !== 0) continue;

      const bytes = crcBytes(model, message);
      const appended = model.refOut ? [...bytes].reverse() : [...bytes];
      const combined = new Uint8Array([...message, ...appended]);

      const got = crc(model, combined) ^ model.xorOut;
      expect(got, `${model.name} residue`).toBe(model.residue);
    }
  });
});

describe("model lookup", () => {
  it("finds a model by its canonical name", () => {
    expect(getCrcModel("CRC-32/ISCSI")?.poly).toBe(0x1edc6f41n);
  });

  it("returns undefined for an unknown name and throws on require", () => {
    expect(getCrcModel("CRC-32/NOPE")).toBeUndefined();
    expect(() => requireCrcModel("CRC-32/NOPE")).toThrow(/CRC-32\/NOPE/);
  });

  it("attaches the names people actually search for", () => {
    // Nobody looks up "CRC-32/ISO-HDLC". They look up "CRC-32", or gzip, or PNG.
    const iso = requireCrcModel("CRC-32/ISO-HDLC");
    expect(iso.aliases).toContain("CRC-32");
    expect(iso.aliases).toContain("gzip");
    // Against the raw list, so these keep the catalogue's own casing. The broader spot check in
    // "aliases and residue" lowercases both sides instead, because there the point is findability.
    expect(requireCrcModel("CRC-32/ISCSI").aliases).toContain("CRC-32C");
    expect(requireCrcModel("CRC-16/KERMIT").aliases).toContain("CRC-CCITT");
  });
});

describe("width guards", () => {
  it("refuses a width this implementation does not cover", () => {
    const base = requireCrcModel("CRC-8/SMBUS");
    // 3 to 82, which is exactly the catalogue's range. Below 3 there is no register worth the name;
    // above 82 there is no published CRC -- CRC-82/DARC is the widest that exists.
    expect(() => createCrc({ ...base, width: 2 })).toThrow(/width 2/);
    expect(() => createCrc({ ...base, width: 83 })).toThrow(/width 83/);
  });

  it("builds an engine for widths 3 to 7 rather than refusing them", () => {
    // These used to throw, then went through a bit-at-a-time engine, and now go through the same
    // table-driven one as CRC-32 on a left-justified register.
    for (const width of [3, 4, 5, 6, 7]) {
      const model = { ...requireCrcModel("CRC-8/SMBUS"), width, poly: 0x3n, init: 0n, xorOut: 0n };
      expect(() => createCrc(model), `width ${width}`).not.toThrow();
    }
  });

  it("builds a left-justified byte table for a sub-byte width", () => {
    /**
     * The property that makes the table exist at all below 8 bits.
     *
     * Left-justifying the polynomial by `8 - width` leaves every entry a multiple of `2 ** (8 -
     * width)`, because eight left shifts carry the index's own low bits clean out of the byte and
     * what remains is XORs of the shifted polynomial. So an entry is a width-bit CRC sitting at the
     * top of a byte, and `crcTables` says so on the panel -- someone who copies the grid and skips
     * the shift gets a plausible byte and a wrong answer.
     *
     * This test asserted the opposite until the justification went in: `crcLookupTable` threw below
     * 8 bits, on the reasoning that a byte index cannot address a narrower register. True of an
     * unjustified table, and it cost five tools their panel.
     */
    for (const width of [3, 4, 5, 6, 7]) {
      const model = { ...requireCrcModel("CRC-8/SMBUS"), width, poly: 0x05n, init: 0n, xorOut: 0n };
      const padding = (1n << BigInt(8 - width)) - 1n;
      for (const orientation of ["normal", "reflected"] as const) {
        const table = crcLookupTable(model, orientation);
        expect(table, `width ${width}/${orientation}`).toHaveLength(256);
        for (const value of table) {
          expect(value, `width ${width}/${orientation} fits a byte`).toBeLessThanOrEqual(0xffn);
        }
      }
      // Only the normal orientation is justified upwards; reflecting a byte moves the padding to
      // the other end, which is what an lsb-first loop wants.
      for (const value of crcLookupTable(model, "normal")) expect(value & padding).toBe(0n);
    }
  });

  it("refuses constants that do not fit the declared width", () => {
    const base = requireCrcModel("CRC-8/SMBUS");
    expect(() => createCrc({ ...base, poly: 0x1ffn })).toThrow(/polynomial/);
    expect(() => createCrc({ ...base, init: 0x1ffn })).toThrow(/init/);
    expect(() => createCrc({ ...base, xorOut: 0x1ffn })).toThrow(/xorOut/);
  });

  it("handles the width-32 boundary without sign-bit corruption", () => {
    // The single most likely arithmetic bug in the narrow engine: `1 << 32` is 1, and
    // `crc << 8` on a value with the top bit set goes negative.
    for (const model of CRC_CATALOGUE.filter((m) => m.width === 32)) {
      expect(crc(model, CHECK_INPUT)).toBeLessThanOrEqual(0xffffffffn);
      expect(crc(model, CHECK_INPUT)).toBeGreaterThanOrEqual(0n);
      expect(crc(model, CHECK_INPUT)).toBe(model.check);
    }
  });
});

describe("bit helpers", () => {
  it("reflects a byte", () => {
    expect(reflectByte(0b10000000)).toBe(0b00000001);
    expect(reflectByte(0b00000001)).toBe(0b10000000);
    expect(reflectByte(0b10110010)).toBe(0b01001101);
    expect(reflectByte(0x00)).toBe(0x00);
    expect(reflectByte(0xff)).toBe(0xff);
  });

  it("reflects an arbitrary width", () => {
    expect(reflect(0b1n, 8)).toBe(0b10000000n);
    expect(reflect(0x1n, 32)).toBe(0x80000000n);
    expect(reflect(0x1n, 64)).toBe(0x8000000000000000n);
    // Reflecting twice is the identity.
    for (const width of [8, 16, 24, 32, 64]) {
      const value = mask(width) / 3n;
      expect(reflect(reflect(value, width), width)).toBe(value);
    }
  });
});

describe("crcLookupTable", () => {
  /**
   * Two published first rows, from the two tables anyone actually has to hand.
   *
   * Everything else about the table is checked by running the algorithm over it and getting the
   * catalogued check value out -- but that is self-consistency: a table and an engine built from the
   * same wrong formulation would agree with each other. These eight words are from source people
   * quote. zlib's `crc_table` is the reflected one and is probably the most copied array in
   * computing; the normal one is what the Ethernet and MPEG-2 references print.
   */
  const ZLIB_REFLECTED_FIRST = [
    0x00000000n,
    0x77073096n,
    0xee0e612cn,
    0x990951ban,
  ];
  const ETHERNET_NORMAL_FIRST = [
    0x00000000n,
    0x04c11db7n,
    0x09823b6en,
    0x0d4326d9n,
  ];

  it("matches zlib's reflected CRC-32 table", () => {
    const table = crcLookupTable(requireCrcModel("CRC-32/ISO-HDLC"), "reflected");
    expect(table.slice(0, 4)).toEqual(ZLIB_REFLECTED_FIRST);
  });

  it("matches the Ethernet/MPEG normal CRC-32 table", () => {
    // Same polynomial, other bit order. Note the second entry *is* the polynomial: byte 1 lands at
    // bit 24 and reaches the top of the register on the eighth shift with nothing before it.
    const table = crcLookupTable(requireCrcModel("CRC-32/ISO-HDLC"), "normal");
    expect(table.slice(0, 4)).toEqual(ETHERNET_NORMAL_FIRST);
    expect(table[1]).toBe(requireCrcModel("CRC-32/ISO-HDLC").poly);
  });

  it("gives every model a 256-entry table inside its register", () => {
    // Every model, all 113. The register, not the model's width -- below 8 bits the entries are
    // byte-wide, because that is the width the tabulated polynomial was shifted up to.
    for (const model of CRC_CATALOGUE) {
      const m = (1n << BigInt(Math.max(8, model.width))) - 1n;
      for (const orientation of ["normal", "reflected"] as const) {
        const table = crcLookupTable(model, orientation);
        expect(table, `${model.name}/${orientation}`).toHaveLength(256);
        expect(table[0], `${model.name}/${orientation} entry 0`).toBe(0n);
        for (const value of table) expect(value & ~m).toBe(0n);
      }
    }
  });

  it("refuses a width the engine refuses", () => {
    // The table goes through `assertSupported`, so it cannot become a back door to a width the
    // engines will not run. It used to be a back door in the other direction: width 5 threw here
    // while `createCrc` accepted it.
    const base = requireCrcModel("CRC-8/SMBUS");
    expect(() => crcLookupTable({ ...base, width: 2, poly: 0x1n }, "normal")).toThrow(/width 2/);
    expect(() => crcLookupTable({ ...base, width: 83 }, "normal")).toThrow(/width 83/);
  });
});

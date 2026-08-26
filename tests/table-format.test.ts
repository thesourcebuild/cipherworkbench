/**
 * The Table panel's copy formats.
 *
 * `formatTable` lives in the engine rather than in the panel precisely so this file can exist: a C
 * array that does not compile, or a Rust one whose declared length disagrees with its contents, is
 * the kind of defect that looks fine on screen and fails at the far end.
 *
 * The fixture is deliberately zlib's CRC-32 table rather than made-up numbers, so that a paste from
 * any of these formats is checkable against source people have to hand.
 */
import { describe, expect, it } from "vitest";
import { crcLookupTable, requireCrcModel } from "@ocs/algos";
import { formatTable, isSourceFormat, TABLE_COPY_FORMATS, type ToolTable } from "@ocs/engine";

function tableFor(modelName: string, orientation: "normal" | "reflected"): ToolTable {
  const model = requireCrcModel(modelName);
  const digits = Math.ceil(model.width / 4);
  return {
    id: orientation,
    label: orientation,
    columns: 16,
    bitWidth: model.width,
    name: "crc_table",
    values: crcLookupTable(model, orientation).map((v) =>
      v.toString(16).toUpperCase().padStart(digits, "0"),
    ),
  };
}

const CRC32 = tableFor("CRC-32/ISO-HDLC", "reflected");
const CRC8 = tableFor("CRC-8/SMBUS", "normal");
const CRC64 = tableFor("CRC-64/XZ", "normal");

/** The first row of zlib's table, which every format has to reproduce somewhere. */
const FIRST_FOUR = ["00000000", "77073096", "EE0E612C", "990951BA"];

describe("formatTable", () => {
  it("covers every format the dropdown offers", () => {
    // The list and the formatter must not drift: an entry in the dropdown with no branch would
    // silently fall through to whatever the last `if` was.
    for (const entry of TABLE_COPY_FORMATS) {
      const out = formatTable(CRC32, { format: entry.value });
      expect(out.length, entry.value).toBeGreaterThan(0);
      expect(out, entry.value).toContain("77073096");
    }
    expect(TABLE_COPY_FORMATS).toHaveLength(7);
  });

  describe("hex", () => {
    it("groups into rows matching the grid", () => {
      const out = formatTable(CRC32, { format: "hex", delimiter: "space", prefix: true });
      const lines = out.split("\n");
      expect(lines).toHaveLength(16);
      expect(lines[0]!.split(" ")).toHaveLength(16);
      expect(lines[0]!.startsWith("0x00000000 0x77073096")).toBe(true);
    });

    it("honours the comma separator and the prefix toggle", () => {
      const out = formatTable(CRC32, { format: "hex", delimiter: "comma", prefix: false });
      expect(out.split("\n")[0]!.startsWith("00000000, 77073096")).toBe(true);
      // A comma at the end of every row but the last, so the whole thing is one list.
      expect(out.split("\n")[0]!.endsWith(",")).toBe(true);
      expect(out.trimEnd().endsWith(",")).toBe(false);
    });

    it("one per line drops the row grouping entirely", () => {
      const out = formatTable(CRC32, { format: "hex", delimiter: "newline", prefix: true });
      expect(out.split("\n")).toHaveLength(256);
    });
  });

  describe("csv", () => {
    it("indexed pairs each value with its index", () => {
      const lines = formatTable(CRC32, { format: "csv-indexed", prefix: true }).split("\n");
      expect(lines).toHaveLength(256);
      expect(lines[1]).toBe("1,0x77073096");
      expect(lines[255]!.startsWith("255,0x")).toBe(true);
    });

    it("values is one column and nothing else", () => {
      const lines = formatTable(CRC32, { format: "csv-values", prefix: false }).split("\n");
      expect(lines).toHaveLength(256);
      expect(lines.slice(0, 4)).toEqual(FIRST_FOUR);
      // Distinct from hex-with-newlines, which is the same shape but keeps the prefix rules and is
      // reachable from a different control. Worth pinning that they are not accidentally the same.
      expect(lines[1]).not.toContain("0x");
    });
  });

  describe("source formats", () => {
    it("C picks a type from the bit width and suffixes 64-bit literals", () => {
      expect(formatTable(CRC8, { format: "c" }).split("\n")[0]).toBe(
        "static const uint8_t crc_table[256] = {",
      );
      expect(formatTable(CRC32, { format: "c" }).split("\n")[0]).toBe(
        "static const uint32_t crc_table[256] = {",
      );
      const wide = formatTable(CRC64, { format: "c" });
      expect(wide.split("\n")[0]).toBe("static const uint64_t crc_table[256] = {");
      // Without ULL a 64-bit literal is a 32-bit `long` on Windows.
      expect(wide).toContain("ULL");
      expect(wide.trimEnd().endsWith("};")).toBe(true);
    });

    it("C rounds a 24-bit table up to a type that exists", () => {
      // There is no uint24_t. CRC-24/BLE's entries are six hex digits in a uint32_t.
      const out = formatTable(tableFor("CRC-24/BLE", "normal"), { format: "c" });
      expect(out.split("\n")[0]).toBe("static const uint32_t crc_table[256] = {");
    });

    it("Python emits a plain list with no width annotation", () => {
      const lines = formatTable(CRC32, { format: "python" }).split("\n");
      expect(lines[0]).toBe("CRC_TABLE = [");
      expect(lines[1]!.startsWith("    0x00000000, 0x77073096")).toBe(true);
      expect(lines[lines.length - 1]).toBe("]");
      expect(formatTable(CRC64, { format: "python" })).not.toContain("ULL");
    });

    it("Go uses a camelCase identifier, a sized array and tabs", () => {
      const lines = formatTable(CRC32, { format: "go" }).split("\n");
      expect(lines[0]).toBe("var crcTable = [256]uint32{");
      expect(lines[1]!.startsWith("\t0x00000000,")).toBe(true);
      expect(lines[lines.length - 1]).toBe("}");
    });

    it("Rust declares a length that matches the contents", () => {
      const lines = formatTable(CRC32, { format: "rust" }).split("\n");
      expect(lines[0]).toBe("pub const CRC_TABLE: [u32; 256] = [");
      expect(lines[lines.length - 1]).toBe("];");
      // The declared length and the real one agreeing is the one thing a reader will not check.
      const declared = Number(/\[u32; (\d+)\]/.exec(lines[0]!)![1]);
      const emitted = lines
        .slice(1, -1)
        .flatMap((line) => line.split(",").filter((piece) => piece.trim() !== "")).length;
      expect(emitted).toBe(declared);
    });

    it("all four keep the row grouping and every value", () => {
      for (const format of ["c", "python", "go", "rust"] as const) {
        const lines = formatTable(CRC32, { format }).split("\n");
        // 16 rows plus an opening and a closing line.
        expect(lines, format).toHaveLength(18);
        for (const value of FIRST_FOUR) expect(lines[1], format).toContain(`0x${value}`);
      }
    });

    it("always prefixes, whatever the checkbox says", () => {
      /**
       * The reason the panel hides that control for these formats.
       *
       * `77073096` is a decimal literal in C, Python, Go and Rust alike -- a table pasted without
       * `0x` would compile and be wrong, which is the worst available outcome.
       */
      for (const format of ["c", "python", "go", "rust"] as const) {
        expect(isSourceFormat(format)).toBe(true);
        const out = formatTable(CRC32, { format, prefix: false });
        expect(out, format).toContain("0x77073096");
        expect(out, format).not.toMatch(/[ \t]77073096/);
      }
    });
  });

  it("falls back to a safe type and name when the table declares neither", () => {
    // `bitWidth` and `name` are optional on `ToolTable`, so a family that omits them still gets
    // something that compiles rather than `uint undefined_t`.
    const bare: ToolTable = { id: "x", label: "x", columns: 4, values: ["01", "02", "03", "04"] };
    expect(formatTable(bare, { format: "c" }).split("\n")[0]).toBe(
      "static const uint64_t table[4] = {",
    );
    expect(formatTable(bare, { format: "rust" }).split("\n")[0]).toBe(
      "pub const TABLE: [u64; 4] = [",
    );
  });
});

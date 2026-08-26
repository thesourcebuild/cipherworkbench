import type { ToolTable } from "./tool-definition";

/**
 * Rendering a `ToolTable` as something you can paste.
 *
 * In the engine rather than in the panel because it is pure and worth testing: a C array that does
 * not compile, or a Rust one whose length does not match its contents, is exactly the sort of defect
 * that survives a glance at the screen. `tests/table-format.test.ts` covers every format.
 *
 * The four source formats are deliberately not a template each. They share the row grouping, the
 * literal spelling and the identifier derivation, and differ only in a header, a footer and a type
 * name -- so that is how they are written. A fifth language is a row in `LANGUAGES`.
 */
export type TableCopyFormat =
  | "hex"
  | "csv-indexed"
  | "csv-values"
  | "c"
  | "python"
  | "go"
  | "rust";

/** Separator for the plain hex form. Ignored by every other format. */
export type TableCopyDelimiter = "space" | "comma" | "newline";

export interface TableCopyOptions {
  format: TableCopyFormat;
  /** `hex` only. */
  delimiter?: TableCopyDelimiter;
  /**
   * Prefix each value with `0x`. Honoured by `hex` and the two CSV forms.
   *
   * The source formats ignore it and always prefix: a C array of bare hex digits does not compile,
   * and one that reads `77073096` would be a decimal literal in every language here.
   */
  prefix?: boolean;
}

/** True when the format emits source code, and therefore ignores `prefix` and `delimiter`. */
export function isSourceFormat(format: TableCopyFormat): boolean {
  return format === "c" || format === "python" || format === "go" || format === "rust";
}

/** Rounded up to a type a language actually has. */
function storageBits(bitWidth: number | undefined): 8 | 16 | 32 | 64 {
  if (bitWidth === undefined) return 64;
  if (bitWidth <= 8) return 8;
  if (bitWidth <= 16) return 16;
  if (bitWidth <= 32) return 32;
  return 64;
}

const SNAKE = (name: string): string => name;
const SCREAMING = (name: string): string => name.toUpperCase();
const CAMEL = (name: string): string =>
  name.replace(/_([a-z0-9])/g, (_, ch: string) => ch.toUpperCase());

interface Language {
  /** Opens the declaration. `bits` is the storage size, `count` the entry count. */
  open(name: string, bits: number, count: number): string;
  close: string;
  /** Appended to each literal. C needs `ULL` at 64 bits; nothing else needs anything. */
  suffix(bits: number): string;
  indent: string;
}

const LANGUAGES: Record<"c" | "python" | "go" | "rust", Language> = {
  c: {
    open: (name, bits, count) =>
      `static const uint${bits}_t ${SNAKE(name)}[${count}] = {`,
    close: "};",
    // Without it a 64-bit literal is an `unsigned long` on LP64 and overflows on Windows, where
    // `long` is 32 bits -- a warning at best and wrong at worst.
    suffix: (bits) => (bits === 64 ? "ULL" : ""),
    indent: "    ",
  },
  python: {
    open: (name) => `${SCREAMING(name)} = [`,
    close: "]",
    // Python integers have no width, so there is nothing to annotate.
    suffix: () => "",
    indent: "    ",
  },
  go: {
    open: (name, bits, count) => `var ${CAMEL(name)} = [${count}]uint${bits}{`,
    close: "}",
    suffix: () => "",
    indent: "\t",
  },
  rust: {
    open: (name, bits, count) => `pub const ${SCREAMING(name)}: [u${bits}; ${count}] = [`,
    close: "];",
    suffix: () => "",
    indent: "    ",
  },
};

/** Groups `values` into rows of `columns`, joined by `", "`, each row prefixed with `indent`. */
function rows(values: readonly string[], columns: number, indent: string): string[] {
  const out: string[] = [];
  for (let at = 0; at < values.length; at += columns) {
    out.push(indent + values.slice(at, at + columns).join(", ") + ",");
  }
  return out;
}

export function formatTable(table: ToolTable, options: TableCopyOptions): string {
  const { format } = options;
  const prefix = options.prefix ?? true;
  const withPrefix = (value: string): string => `0x${value}`;
  const maybePrefix = (value: string): string => (prefix ? withPrefix(value) : value);

  if (format === "csv-indexed") {
    // Index alongside the value, for something that will look entries up.
    return table.values.map((v, i) => `${i},${maybePrefix(v)}`).join("\n");
  }
  if (format === "csv-values") {
    // One value per line and nothing else, which is what a spreadsheet column or a `while read`
    // loop wants. Not the same thing as the hex form with a newline separator: that one keeps the
    // row grouping, and this one does not.
    return table.values.map(maybePrefix).join("\n");
  }
  if (format === "hex") {
    const joined = table.values.map(maybePrefix);
    if (options.delimiter === "newline") return joined.join("\n");
    // A row per line otherwise, matching the grid, which is what makes a 256-entry paste readable.
    const comma = options.delimiter === "comma";
    const lines: string[] = [];
    for (let at = 0; at < joined.length; at += table.columns) {
      lines.push(joined.slice(at, at + table.columns).join(comma ? ", " : " "));
    }
    return lines.join(comma ? ",\n" : "\n");
  }

  const language = LANGUAGES[format];
  const bits = storageBits(table.bitWidth);
  const name = table.name ?? "table";
  const suffix = language.suffix(bits);
  const literals = table.values.map((v) => `${withPrefix(v)}${suffix}`);

  return [
    language.open(name, bits, table.values.length),
    ...rows(literals, table.columns, language.indent),
    language.close,
  ].join("\n");
}

/** Label for the format dropdown, so the panel does not hold a second copy of the list. */
export const TABLE_COPY_FORMATS: readonly { value: TableCopyFormat; label: string }[] = [
  { value: "hex", label: "Hex" },
  { value: "csv-indexed", label: "CSV (index, value)" },
  { value: "csv-values", label: "CSV (value)" },
  /**
   * Every source label names the container, not just the language.
   *
   * Go and Rust read "Go" and "Rust" alone, next to "C array" and "Python list", which made the pair
   * look like they emitted something else -- a file, a module, anything. All four emit one
   * declaration of a fixed-size array; the difference is only the syntax around it. Keep the four
   * labels parallel, because the reader is choosing what to paste rather than choosing a language.
   */
  { value: "c", label: "C array" },
  { value: "python", label: "Python list" },
  { value: "go", label: "Go array" },
  { value: "rust", label: "Rust array" },
];

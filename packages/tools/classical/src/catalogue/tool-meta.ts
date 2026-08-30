import type { OptionValue } from "@ocs/contracts/options";
import {
  DEFAULT_SHIFT,
  OPTION_DIRECTION,
  OPTION_LETTER_CASE,
  OPTION_SHIFT,
  OPTION_SHOW_ALL,
} from "../pure";

/**
 * The family's tools, as eager metadata. Free of any algorithm import, so listing them costs strings.
 *
 * One tool today. ROT13 is deliberately *not* a second: it is this cipher at a shift of 13, which is
 * "one thing with a knob" by the test `## One tool or many` sets out -- and it is a tag here, so
 * searching the sidebar for it lands on this tool. Atbash, Vigenere and an affine cipher would each be
 * a genuine addition rather than a cell of this one's grid, and each is a metadata entry plus a compute
 * arm away.
 */
export type ClassicalKind =
  | "caesar"
  | "adfgvx"
  | "vic-cipher"
  | "hill-cipher"
  | "foursquare"
  | "chaocipher";

export interface ClassicalToolMeta {
  id: string;
  label: string;
  kind: ClassicalKind;
  /** Sidebar group within the family. */
  category: string;
  exposes: readonly string[];
  /**
   * Option values a fresh spec starts with. Every `enum` a tool renders must be seeded here, or the
   * form shows "(not set)" while the resolver quietly computes at its fallback --
   * `tests/registry.test.ts` walks every tool checking exactly that.
   */
  defaults: Readonly<Record<string, OptionValue>>;
  tags: readonly string[];
  summary: string;
}

export const CLASSICAL_TOOLS: readonly ClassicalToolMeta[] = [
  {
    id: "caesar",
    label: "Caesar cipher",
    kind: "caesar",
    category: "Substitution",
    exposes: [OPTION_DIRECTION, OPTION_SHIFT, OPTION_LETTER_CASE, OPTION_SHOW_ALL],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
      [OPTION_SHIFT]: DEFAULT_SHIFT,
      [OPTION_LETTER_CASE]: "preserve",
      [OPTION_SHOW_ALL]: true,
    },
    tags: [
      "caesar",
      "caesar cipher",
      "rot13",
      "rot-13",
      "rot",
      "shift",
      "shift cipher",
      "substitution",
      "monoalphabetic",
      "classical",
      "julius caesar",
      "cryptogram",
      "puzzle",
      "brute force",
    ],
    summary: "Every letter moved a fixed number of places. Breakable by reading 26 lines.",
  },
  {
    id: "adfgvx",
    label: "ADFGVX cipher",
    kind: "adfgvx",
    category: "Fractionating",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["adfgvx", "adfgx", "ww1", "fractionating", "transposition", "classical"],
    summary: "WWI German field cipher combining Polybius fractionating substitution with columnar transposition.",
  },
  {
    id: "vic-cipher",
    label: "VIC cipher",
    kind: "vic-cipher",
    category: "Straddling Checkerboard",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["vic", "vic-cipher", "cold-war", "spy", "straddling-checkerboard", "classical"],
    summary: "Complex Cold War pencil-and-paper cipher used by Soviet agent Reino Häyhänen.",
  },
  {
    id: "hill-cipher",
    label: "Hill cipher",
    kind: "hill-cipher",
    category: "Polygraphic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["hill", "hill-cipher", "linear-algebra", "matrix", "polygraphic", "classical"],
    summary: "Lester S. Hill's 1929 polygraphic cipher based on linear algebra matrix multiplication modulo 26.",
  },
  {
    id: "foursquare",
    label: "Foursquare cipher",
    kind: "foursquare",
    category: "Polygraphic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["foursquare", "polygraphic", "digram", "playfair-variant", "classical"],
    summary: "Felix Delastelle's polygraphic cipher using four 5x5 matrices to encrypt letter pairs.",
  },
  {
    id: "chaocipher",
    label: "Chaocipher",
    kind: "chaocipher",
    category: "Dynamic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["chaocipher", "john-byrne", "dynamic-substitution", "permuting-alphabet", "classical"],
    summary: "John F. Byrne's 1918 cipher using two rotating, permuting alphabet wheels.",
  },
];

export const CLASSICAL_TOOL_IDS = CLASSICAL_TOOLS.map((tool) => tool.id) as readonly string[];

export function getClassicalTool(id: string): ClassicalToolMeta | undefined {
  return CLASSICAL_TOOLS.find((tool) => tool.id === id);
}

export function requireClassicalTool(id: string): ClassicalToolMeta {
  const tool = getClassicalTool(id);
  if (!tool) throw new Error(`Unknown classical tool: ${id}`);
  return tool;
}

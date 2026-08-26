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
export type ClassicalKind = "caesar";

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
    /**
     * Every name this is looked for under, including the two shifts that have their own.
     *
     * ROT13 is this tool at 13 and ROT47 is *not* this tool at all -- it shifts 94 printable ASCII
     * characters, a different alphabet -- so it is absent rather than listed and disappointing.
     */
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

import type { OptionValue } from "@ocs/contracts/options";
import {
  DEFAULT_SHIFT,
  OPTION_DIRECTION,
  OPTION_DIGITS,
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
  | "chaocipher"
  | "enigma"
  | "vigenere"
  | "playfair"
  | "bifid"
  | "trifid"
  | "bacon"
  | "railfence"
  | "m209"
  | "lorenz"
  | "solitaire"
  | "adfgx"
  | "nihilist"
  | "straddling-checkerboard"
  | "typex"
  | "sigaba"
  | "bazeries"
  | "alberti"
  | "porta"
  | "gronsfeld"
  | "jefferson"
  | "autokey"
  | "beaufort"
  | "columnar"
  | "two-square"
  | "fractionated-morse"
  | "scytale";

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
  {
    id: "enigma",
    label: "Enigma Machine (M3/M4)",
    kind: "enigma",
    category: "Rotor Machine",
    exposes: [OPTION_DIRECTION, OPTION_DIGITS],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
      [OPTION_DIGITS]: "preserve",
    },
    tags: ["enigma", "enigma-m3", "enigma-m4", "wehrmacht", "kriegsmarine", "rotor", "turing", "bletchley", "classical"],
    summary: "WWII German electromechanical cipher with interchangeable rotors, reflector, plugboard, and double-stepping.",
  },
  {
    id: "vigenere",
    label: "Vigenère cipher",
    kind: "vigenere",
    category: "Polyalphabetic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["vigenere", "beaufort", "tabula-recta", "polyalphabetic", "autokey", "classical"],
    summary: "Polyalphabetic substitution cipher using a keyword and the tabula recta.",
  },
  {
    id: "playfair",
    label: "Playfair cipher",
    kind: "playfair",
    category: "Polygraphic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["playfair", "wheatstone", "digraph", "matrix", "5x5", "classical"],
    summary: "First practical digraph substitution cipher using a 5x5 key matrix.",
  },
  {
    id: "bifid",
    label: "Bifid cipher",
    kind: "bifid",
    category: "Fractionating",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["bifid", "delastelle", "fractionating", "polybius", "transposition", "classical"],
    summary: "Delastelle's 2-coordinate fractionating cipher combining Polybius substitution with period transposition.",
  },
  {
    id: "trifid",
    label: "Trifid cipher",
    kind: "trifid",
    category: "Fractionating",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["trifid", "delastelle", "fractionating", "3d", "cube", "transposition", "classical"],
    summary: "Delastelle's 3-coordinate fractionating cipher operating over a 3x3x3 27-symbol cube.",
  },
  {
    id: "bacon",
    label: "Bacon's cipher",
    kind: "bacon",
    category: "Steganographic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["bacon", "baconian", "francis-bacon", "steganography", "binary", "classical"],
    summary: "Sir Francis Bacon's 5-bit steganographic cipher encoding letters into A/B binary sequences.",
  },
  {
    id: "railfence",
    label: "Rail fence cipher",
    kind: "railfence",
    category: "Transposition",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["railfence", "zigzag", "transposition", "geometric", "scytale", "classical"],
    summary: "Geometric zig-zag transposition cipher writing letters along consecutive rails.",
  },
  {
    id: "m209",
    label: "M-209 cipher machine",
    kind: "m209",
    category: "Rotor Machine",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["m209", "hagelin", "c38", "rotor", "pinwheel", "military", "wwii", "classical"],
    summary: "US WWII tactical mechanical cipher machine with 6 pinwheels and 27 drum bars.",
  },
  {
    id: "lorenz",
    label: "Lorenz SZ40/SZ42 machine",
    kind: "lorenz",
    category: "Rotor Machine",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["lorenz", "sz40", "sz42", "tunny", "teleprinter", "baudot", "bletchley", "colossus", "classical"],
    summary: "WWII German High Command 12-wheel teleprinter stream cipher machine broken by Colossus.",
  },
  {
    id: "solitaire",
    label: "Solitaire (Pontifex) cipher",
    kind: "solitaire",
    category: "Playing Card Stream",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["solitaire", "pontifex", "schneier", "cryptonomicon", "playing-cards", "deck", "stream", "classical"],
    summary: "Bruce Schneier's playing card stream cipher designed for field operations with a 54-card deck.",
  },
  {
    id: "adfgx",
    label: "ADFGX cipher",
    kind: "adfgx",
    category: "Polygraphic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["adfgx", "wwi", "polybius", "fractionating", "transposition", "german", "classical"],
    summary: "WWI German 5x5 fractionating field cipher combining Polybius coordinates (ADFGX) with transposition.",
  },
  {
    id: "nihilist",
    label: "Nihilist cipher",
    kind: "nihilist",
    category: "Fractionating",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["nihilist", "russian", "polybius", "additive", "coordinates", "classical"],
    summary: "19th-century Russian Nihilist cipher combining Polybius matrix coordinates with additive keys.",
  },
  {
    id: "straddling-checkerboard",
    label: "Straddling checkerboard",
    kind: "straddling-checkerboard",
    category: "Espionage Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["straddling-checkerboard", "vic", "espionage", "soviet", "digits", "compression", "classical"],
    summary: "Espionage digits-to-letters substitution matrix creating variable-length digit sequences without delimiters.",
  },
  {
    id: "typex",
    label: "Typex machine",
    kind: "typex",
    category: "Rotor Machine",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["typex", "british", "enigma-variant", "rotor", "bletchley", "stator", "wwii", "classical"],
    summary: "British WWII 5-rotor cipher machine based on Enigma with a stationary reversing stator.",
  },
  {
    id: "sigaba",
    label: "SIGABA machine (ECM Mark II)",
    kind: "sigaba",
    category: "Rotor Machine",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["sigaba", "ecm", "mark-ii", "csp-889", "15-rotor", "us-army", "us-navy", "wwii", "classical"],
    summary: "High-security US WWII 15-rotor machine with 3 banks of 5 rotors: cipher, control, and index.",
  },
  {
    id: "bazeries",
    label: "Bazeries cylinder (M-94)",
    kind: "bazeries",
    category: "Cylinder Cipher",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["bazeries", "m94", "m-94", "jefferson", "cylinder", "wheel-cipher", "army", "classical"],
    summary: "Historical 25-disc cylinder cipher invented by Thomas Jefferson and Etienne Bazeries.",
  },
  {
    id: "alberti",
    label: "Alberti cipher disk",
    kind: "alberti",
    category: "Polyalphabetic Disk",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["alberti", "cipher disk", "polyalphabetic", "renaissance", "1467", "classical"],
    summary: "Historic 1467 dual-ring cipher disk by Leon Battista Alberti with rotating index alignments.",
  },
  {
    id: "porta",
    label: "Porta cipher",
    kind: "porta",
    category: "Polyalphabetic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["porta", "polyalphabetic", "reciprocal", "della porta", "1563", "classical"],
    summary: "1563 reciprocal polyalphabetic cipher by Giambattista della Porta with 13 paired alphabets.",
  },
  {
    id: "gronsfeld",
    label: "Gronsfeld cipher",
    kind: "gronsfeld",
    category: "Polyalphabetic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["gronsfeld", "numeric key", "vigenere variant", "digits", "classical"],
    summary: "Polyalphabetic substitution cipher keyed by a decimal digit sequence (0-9).",
  },
  {
    id: "jefferson",
    label: "Jefferson disk (US M-94)",
    kind: "jefferson",
    category: "Cylinder Cipher",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["jefferson", "wheel cipher", "m-94", "m94", "cylinder", "us army", "classical"],
    summary: "Thomas Jefferson's 1795 wheel cipher, standardized as the US Army M-94 25-cylinder cipher.",
  },
  {
    id: "autokey",
    label: "Autokey cipher",
    kind: "autokey",
    category: "Polyalphabetic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["autokey", "vigenere autokey", "polyalphabetic", "blaise de vigenere", "classical"],
    summary: "Blaise de Vigenère's authentic autokey cipher extending the keystream with the message itself.",
  },
  {
    id: "beaufort",
    label: "Beaufort cipher",
    kind: "beaufort",
    category: "Polyalphabetic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["beaufort", "reciprocal", "polyalphabetic", "francis beaufort", "classical"],
    summary: "Reciprocal polyalphabetic cipher where encryption and decryption are identical operations.",
  },
  {
    id: "columnar",
    label: "Columnar transposition",
    kind: "columnar",
    category: "Transposition",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["columnar", "transposition", "permutation", "matrix", "classical"],
    summary: "Military transposition cipher routing text through an alphabetical keyword column matrix.",
  },
  {
    id: "two-square",
    label: "Two-Square cipher",
    kind: "two-square",
    category: "Digraphic Substitution",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["two-square", "double playfair", "digraphic", "substitution", "classical"],
    summary: "Double Playfair digraphic substitution cipher operating across two 5x5 keyword grids.",
  },
  {
    id: "fractionated-morse",
    label: "Fractionated Morse",
    kind: "fractionated-morse",
    category: "Fractionating",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["fractionated morse", "morse", "fractionating", "trigrams", "substitution", "classical"],
    summary: "Fractionating cipher converting text to Morse, grouping into trigrams, and substituting through a keyword.",
  },
  {
    id: "scytale",
    label: "Scytale cipher",
    kind: "scytale",
    category: "Transposition",
    exposes: [OPTION_DIRECTION],
    defaults: {
      [OPTION_DIRECTION]: "encrypt",
    },
    tags: ["scytale", "cylinder", "spartan", "ancient greece", "transposition", "classical"],
    summary: "Ancient Spartan transposition cylinder winding parchment around a rod of fixed diameter.",
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

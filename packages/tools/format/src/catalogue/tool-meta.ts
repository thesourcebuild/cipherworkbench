/**
 * The ten tools this family contributes, as eager metadata.
 *
 * One tool per format rather than one per operation, following `@ocs/encoding`: URL-encode and
 * URL-decode are one thing with an arrow on it, and JSON validate/format/minify are one thing with a
 * verb on it. Nobody looks for "minify JSON" in a sidebar separately from "JSON".
 *
 * Four of the ten take no input at all. `uuid`, `password`, `random` and `randombytes` are
 * *generators*, which is a shape this
 * app already has -- the asymmetric family's generate-keypair operation ignores its input too -- and
 * `usesInput` is what the form and the lint rules read to say so rather than each guessing.
 *
 * Free of any library import, so listing these costs nothing but the strings.
 */
import type { OptionValue } from "@ocs/contracts/options";
import {
  OPTION_ACTION,
  OPTION_CASE_STYLE,
  OPTION_COLLAPSE,
  OPTION_COUNT,
  OPTION_DIRECTION,
  OPTION_ENTITY_FORM,
  OPTION_ENTITY_SCOPE,
  OPTION_EXCLUDE_AMBIGUOUS,
  OPTION_INDENT,
  OPTION_LENGTH,
  OPTION_RANDOM_BYTES,
  OPTION_RANDOM_DISTINCT,
  OPTION_RANDOM_MAX,
  OPTION_RANDOM_MIN,
  OPTION_RANDOM_PLACES,
  OPTION_RANDOM_SHAPE,
  OPTION_RANDOM_SORTED,
  OPTION_SORT_KEYS,
  OPTION_URL_MODE,
  OPTION_UUID_NAME,
  OPTION_UUID_NAMESPACE,
  OPTION_UUID_VERSION,
  PASSWORD_CLASS_OPTIONS,
} from "../pure";

/** Which computation a tool performs. The compute path switches on exactly this. */
export type FormatKind =
  | "url"
  | "htmlentity"
  | "jwt"
  | "json"
  | "xml"
  | "case"
  | "uuid"
  | "password"
  | "random"
  | "randombytes";

export interface FormatToolMeta {
  id: string;
  label: string;
  kind: FormatKind;
  /** Sidebar group. */
  category: string;
  /** Catalogue option ids this tool exposes. */
  exposes: readonly string[];
  /**
   * Option values a fresh spec starts with. Every `enum` a tool renders must be seeded here.
   *
   * `OptionValue` rather than `string`, because a number option seeded as `"20"` is not seeded: the
   * form renders it and `optNumber` reads it as `undefined`, so the tool computes at the resolver's
   * fallback while showing a value -- the exact pairing `tests/registry.test.ts` gates the `enum` case
   * against.
   */
  defaults: Readonly<Record<string, OptionValue>>;
  /**
   * False for a generator. Two consequences the UI reads directly: the Input panel is pointless, and
   * a lint rule says so rather than leaving someone typing into a box nothing consumes.
   */
  usesInput: boolean;
  /**
   * True where the tool goes both ways, which is what puts `inverse` in the manifest's `directions`
   * and the arrow on the header badge.
   */
  bidirectional: boolean;
  /**
   * True for the one tool here whose result is bytes rather than text, which is what gives it the
   * Result panel's encoding menu.
   *
   * This field is the reason `random` and `randombytes` are two tools rather than one with a shape
   * dropdown. `outputEncodings` lives on the *manifest* -- the eager half, resolved once per tool --
   * so a tool producing bytes under one setting and text under another cannot express it: the menu
   * would either be missing where it is wanted or present and inert where it is not, and an inert
   * control is this repo's most-repeated defect. Splitting on the output type is the honest answer,
   * and it happens to match how people ask for these: "random number" and "random hex" are different
   * requests.
   */
  emitsBytes?: boolean;
  tags: readonly string[];
  summary: string;
  /**
   * The library behind it, named in the tool's own Info panel.
   *
   * Worth surfacing rather than burying in a package.json. This family is almost entirely *catalogue*
   * over other people's implementations -- unlike every other family here -- and a reader comparing
   * output against another tool is better served knowing it is `entities` underneath than guessing.
   */
  library: string;
}

export const FORMAT_TOOLS: readonly FormatToolMeta[] = [
  {
    id: "url",
    label: "URL encode",
    kind: "url",
    category: "Web",
    exposes: [OPTION_DIRECTION, OPTION_URL_MODE],
    defaults: { [OPTION_DIRECTION]: "encode", [OPTION_URL_MODE]: "component" },
    usesInput: true,
    bidirectional: true,
    tags: [
      "url",
      "uri",
      "percent",
      "percent-encoding",
      "urlencode",
      "urldecode",
      "escape",
      "unescape",
      "query string",
      "form",
      "rfc 3986",
    ],
    summary: "Percent-encoding, in the three flavours that are not interchangeable.",
    library: "the platform's own encodeURIComponent, encodeURI and URLSearchParams",
  },
  {
    id: "htmlentity",
    label: "HTML entities",
    kind: "htmlentity",
    category: "Web",
    exposes: [OPTION_DIRECTION, OPTION_ENTITY_SCOPE, OPTION_ENTITY_FORM],
    defaults: {
      [OPTION_DIRECTION]: "encode",
      [OPTION_ENTITY_SCOPE]: "markup",
      [OPTION_ENTITY_FORM]: "named",
    },
    usesInput: true,
    bidirectional: true,
    tags: [
      "html",
      "entity",
      "entities",
      "escape",
      "unescape",
      "htmlspecialchars",
      "xml",
      "amp",
      "nbsp",
      "character reference",
    ],
    summary: "Escape and unescape HTML character references, named or numeric.",
    library: "entities (the library htmlparser2 and cheerio use)",
  },
  {
    id: "jwt",
    label: "JWT decode",
    kind: "jwt",
    category: "Web",
    exposes: [],
    defaults: {},
    usesInput: true,
    // Decode only, and deliberately: see `F003` and the note in `compute.ts`.
    bidirectional: false,
    tags: [
      "jwt",
      "json web token",
      "jws",
      "bearer",
      "token",
      "claims",
      "decode",
      "rfc 7519",
      "id token",
      "access token",
    ],
    summary: "Read a token's header and claims. Verifies nothing — see the Checks panel.",
    library: "the platform's own atob, over the token's Base64url segments",
  },
  {
    id: "json",
    label: "JSON",
    kind: "json",
    category: "Documents",
    exposes: [OPTION_ACTION, OPTION_INDENT, OPTION_SORT_KEYS],
    defaults: { [OPTION_ACTION]: "format", [OPTION_INDENT]: "2" },
    usesInput: true,
    bidirectional: false,
    tags: [
      "json",
      "format",
      "pretty",
      "prettify",
      "beautify",
      "minify",
      "validate",
      "lint",
      "indent",
      "sort keys",
      "rfc 8259",
    ],
    summary: "Validate, indent or minify a JSON document, with the line and column of any error.",
    library: "jsonc-parser (Microsoft's, the one VS Code parses its own settings with)",
  },
  {
    id: "xml",
    label: "XML",
    kind: "xml",
    category: "Documents",
    exposes: [OPTION_ACTION, OPTION_INDENT, OPTION_COLLAPSE],
    defaults: { [OPTION_ACTION]: "format", [OPTION_INDENT]: "2" },
    usesInput: true,
    bidirectional: false,
    tags: [
      "xml",
      "format",
      "pretty",
      "prettify",
      "beautify",
      "minify",
      "validate",
      "indent",
      "svg",
      "rss",
      "soap",
      "plist",
    ],
    summary: "Validate, indent or minify XML. Namespaces, comments and CDATA all survive.",
    library: "@xmldom/xmldom (a standards-compliant DOM in pure JavaScript)",
  },
  {
    id: "case",
    label: "Case convert",
    kind: "case",
    category: "Text",
    exposes: [OPTION_CASE_STYLE],
    defaults: { [OPTION_CASE_STYLE]: "camel" },
    usesInput: true,
    bidirectional: false,
    tags: [
      "case",
      "camel",
      "camelcase",
      "pascal",
      "snake",
      "snake_case",
      "kebab",
      "kebab-case",
      "constant",
      "screaming",
      "title",
      "sentence",
      "upper",
      "lower",
      "slug",
    ],
    summary: "camelCase, snake_case, kebab-case and eleven more.",
    library: "change-case",
  },
  {
    id: "uuid",
    label: "UUID",
    kind: "uuid",
    category: "Generate",
    exposes: [OPTION_UUID_VERSION, OPTION_UUID_NAMESPACE, OPTION_UUID_NAME, OPTION_COUNT],
    defaults: { [OPTION_UUID_VERSION]: "v4", [OPTION_UUID_NAMESPACE]: "dns", [OPTION_COUNT]: 1 },
    // A generator: nothing is read from the Input panel. v3 and v5 take their name from an option,
    // because it is a *parameter* of the identifier rather than a message being transformed.
    usesInput: false,
    bidirectional: false,
    tags: [
      "uuid",
      "guid",
      "v1",
      "v3",
      "v4",
      "v5",
      "v6",
      "v7",
      "unique",
      "identifier",
      "nil",
      "max",
      "rfc 9562",
      "rfc 4122",
    ],
    summary: "Generate v1, v3, v4, v5, v6 or v7 identifiers, or the nil and max constants.",
    library: "uuid (the reference JavaScript implementation)",
  },
  {
    id: "password",
    label: "Password",
    kind: "password",
    category: "Generate",
    exposes: [
      OPTION_LENGTH,
      PASSWORD_CLASS_OPTIONS.lower,
      PASSWORD_CLASS_OPTIONS.upper,
      PASSWORD_CLASS_OPTIONS.digit,
      PASSWORD_CLASS_OPTIONS.symbol,
      OPTION_EXCLUDE_AMBIGUOUS,
      OPTION_COUNT,
    ],
    /**
     * All four classes on, and the length at 20.
     *
     * Written out rather than left to the compute path's fallback for the reason the `enum` seeds
     * exist: an unchecked box is a statement, so a generator whose boxes read "off" while it quietly
     * used lower, upper and digits would be showing one thing and doing another.
     */
    defaults: {
      [OPTION_LENGTH]: 20,
      [PASSWORD_CLASS_OPTIONS.lower]: true,
      [PASSWORD_CLASS_OPTIONS.upper]: true,
      [PASSWORD_CLASS_OPTIONS.digit]: true,
      [PASSWORD_CLASS_OPTIONS.symbol]: true,
      [OPTION_COUNT]: 1,
    },
    usesInput: false,
    bidirectional: false,
    tags: [
      "password",
      "passphrase",
      "random",
      "generate",
      "secret",
      "entropy",
      "strong",
      "csprng",
    ],
    summary: "Random passwords from a CSPRNG, with the entropy stated in bits.",
    /**
     * The one tool in this family that is *not* a library, and the reason is recorded rather than
     * implied: `generate-password` needs Node's `crypto`, `generate-password-browser` drags in
     * `buffer` and `randombytes` polyfills that a static bundle under this app's CSP should not
     * carry, and `secure-random-password` adds a dependency for the same job. The correct primitive
     * is already here -- `randomBytes()` in `@ocs/engine`, over `crypto.getRandomValues` -- so what is
     * left is charset selection and unbiased sampling. See `compute.ts` for why that is not a modulo.
     */
    library: "randomBytes() from @ocs/engine, over crypto.getRandomValues",
  },
  {
    id: "random",
    label: "Random numbers",
    kind: "random",
    category: "Generate",
    exposes: [
      OPTION_RANDOM_SHAPE,
      OPTION_RANDOM_MIN,
      OPTION_RANDOM_MAX,
      OPTION_RANDOM_DISTINCT,
      OPTION_RANDOM_SORTED,
      OPTION_RANDOM_PLACES,
      OPTION_COUNT,
    ],
    /**
     * 1 to 100, one value, in draw order.
     *
     * Every one of these is written out rather than left to a fallback, including the two booleans:
     * an unchecked box is a statement, and a generator whose "No repeats" reads off while it quietly
     * de-duplicated would be showing one thing and doing another. `OPTION_RANDOM_SHAPE` in particular
     * *must* be here -- an `enum` a tool renders and does not seed opens on "(not set)", which
     * `tests/registry.test.ts` gates against.
     */
    defaults: {
      [OPTION_RANDOM_SHAPE]: "integer",
      [OPTION_RANDOM_MIN]: 1,
      [OPTION_RANDOM_MAX]: 100,
      [OPTION_RANDOM_DISTINCT]: false,
      [OPTION_RANDOM_SORTED]: false,
      [OPTION_RANDOM_PLACES]: 6,
      [OPTION_COUNT]: 1,
    },
    usesInput: false,
    bidirectional: false,
    tags: [
      "random",
      "rng",
      "csprng",
      "number",
      "integer",
      "decimal",
      "float",
      "dice",
      "lottery",
      "range",
      "uniform",
      "unbiased",
      "getrandomvalues",
      "pick",
      "sample",
      "shuffle",
    ],
    summary: "Uniform integers in a range, or decimals, drawn without modulo bias from a CSPRNG.",
    library: "randomBelow(), randomInt() and randomFloat() from @ocs/engine",
  },
  {
    id: "randombytes",
    label: "Random bytes",
    kind: "randombytes",
    category: "Generate",
    exposes: [OPTION_RANDOM_BYTES, OPTION_COUNT],
    defaults: { [OPTION_RANDOM_BYTES]: 32, [OPTION_COUNT]: 1 },
    usesInput: false,
    bidirectional: false,
    // The only tool in this family whose result is bytes, which is what earns it the encoding menu.
    emitsBytes: true,
    tags: [
      "random",
      "bytes",
      "rng",
      "csprng",
      "key",
      "iv",
      "nonce",
      "salt",
      "entropy",
      "hex",
      "base64",
      "secret",
      "token",
      "getrandomvalues",
      "urandom",
    ],
    summary: "Cryptographic random bytes, spelled in whichever encoding you need.",
    library: "randomBytes() from @ocs/engine, over crypto.getRandomValues",
  },
];

export const FORMAT_TOOL_IDS: readonly string[] = FORMAT_TOOLS.map((t) => t.id);

const BY_ID = new Map(FORMAT_TOOLS.map((t) => [t.id, t]));

export function getFormatTool(id: string): FormatToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireFormatTool(id: string): FormatToolMeta {
  const tool = getFormatTool(id);
  if (!tool) throw new Error(`Unknown format tool: ${id}`);
  return tool;
}

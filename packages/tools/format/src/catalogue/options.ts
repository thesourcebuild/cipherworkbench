import {
  createOptionCatalogue,
  type OptionCatalogue,
  type OptionDef,
} from "@ocs/engine";
import {
  CASE_STYLES,
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
  RANDOM_SHAPES,
  type RandomShape,
  TAG_RANDOM_DECIMAL,
  TAG_RANDOM_INTEGER,
  OPTION_SORT_KEYS,
  OPTION_URL_MODE,
  OPTION_UUID_NAME,
  OPTION_UUID_NAMESPACE,
  OPTION_UUID_VERSION,
  PASSWORD_ALPHABETS,
  PASSWORD_CLASS_OPTIONS,
  PASSWORD_CLASSES,
  TAG_UUID_NAMED,
  type PasswordClass,
} from "../pure";
import type { FormatToolMeta } from "./tool-meta";
import type { FormatOptionGroup } from "./groups";

const DIRECTION: OptionDef<FormatOptionGroup> = {
  id: OPTION_DIRECTION,
  label: "Direction",
  group: "direction",
  kind: "enum",
  choices: [
    { value: "encode", label: "Encode", summary: "Plain text in, escaped text out" },
    { value: "decode", label: "Decode", summary: "Escaped text in, plain text out" },
  ],
  summary: "Which way the text goes.",
  detail:
    "One tool rather than two, because escaping and unescaping are the same thing with an arrow on it. Note that the flavour setting below applies to *both* directions: decoding form-encoded text with the wrong flavour turns every plus sign into a space.",
  order: 10,
};

const URL_MODE: OptionDef<FormatOptionGroup> = {
  id: OPTION_URL_MODE,
  label: "Flavour",
  group: "format",
  kind: "enum",
  choices: [
    {
      value: "component",
      label: "Component",
      summary: "One query value or path segment — encodeURIComponent",
    },
    { value: "uri", label: "Whole URI", summary: "Leaves the delimiters — encodeURI" },
    {
      value: "form",
      label: "Form (application/x-www-form-urlencoded)",
      summary: "Space becomes +, as a form POST sends it",
    },
  ],
  summary: "Which of the three percent-encodings.",
  detail:
    "These are not interchangeable and picking the wrong one produces a URL that looks right and resolves somewhere else. Component escapes every reserved character, so it is what you want around a single value. Whole URI leaves ':', '/', '?' and '#' alone, so a complete URL survives being passed through it. Form is what a browser sends and what URLSearchParams produces: a space becomes '+', and '!', apostrophe, '(' , ')' and '~' are escaped where Component leaves them. A literal plus sign in a form value must arrive as %2B or it decodes to a space.",
  order: 10,
};

const ENTITY_SCOPE: OptionDef<FormatOptionGroup> = {
  id: OPTION_ENTITY_SCOPE,
  label: "Escape",
  group: "format",
  kind: "enum",
  choices: [
    { value: "markup", label: "Markup only", summary: "& < > \" ' — the five that change meaning" },
    {
      value: "non-ascii",
      label: "Everything non-ASCII",
      summary: "Also accents, symbols and emoji",
    },
  ],
  // Encoding only: decoding accepts every reference regardless of what an encoder would have written.
  availableOn: ["encode"],
  summary: "How much to escape.",
  detail:
    "Markup only is almost always what you want: those five characters are the ones that change how a document parses, and escaping anything else makes the source unreadable for no gain in a UTF-8 page. Escaping everything non-ASCII is for the cases where the encoding is out of your hands — an email template, a legacy CMS field, a file that has to survive a Latin-1 round trip.",
  order: 10,
};

const ENTITY_FORM: OptionDef<FormatOptionGroup> = {
  id: OPTION_ENTITY_FORM,
  label: "Reference style",
  group: "format",
  kind: "enum",
  choices: [
    { value: "named", label: "Named where possible", summary: "&amp; &nbsp; &eacute;" },
    { value: "decimal", label: "Decimal", summary: "&#38; &#160;" },
    { value: "hex", label: "Hexadecimal", summary: "&#x26; &#xA0;" },
  ],
  availableOn: ["encode"],
  summary: "How a reference is written.",
  detail:
    "Named references are readable and there are over two thousand of them, but only a fraction are recognised by XML parsers — XML defines five and takes the rest from a DTD. Numeric references work everywhere, which is why they are the safe choice for anything that is not HTML. Decoding accepts all three forms whatever this is set to.",
  order: 20,
};

const ACTION: OptionDef<FormatOptionGroup> = {
  id: OPTION_ACTION,
  label: "Action",
  group: "direction",
  kind: "enum",
  choices: [
    { value: "format", label: "Format", summary: "Indent it for reading" },
    { value: "minify", label: "Minify", summary: "Strip the whitespace out" },
    { value: "validate", label: "Validate", summary: "Report problems, change nothing" },
  ],
  summary: "What to do with the document.",
  detail:
    "All three parse the input first, so all three report a syntax error the same way — with the line and column. Validate then stops, which is what you want when the document is the thing you are checking rather than the thing you are reformatting.",
  order: 10,
};

const INDENT: OptionDef<FormatOptionGroup> = {
  id: OPTION_INDENT,
  label: "Indent",
  group: "document",
  kind: "enum",
  choices: [
    { value: "2", label: "2 spaces" },
    { value: "4", label: "4 spaces" },
    { value: "tab", label: "Tab" },
    { value: "0", label: "None", summary: "Same as minifying" },
  ],
  // Only the Format action lays anything out. Minify has no indent and Validate emits nothing.
  availableOn: ["format"],
  summary: "One level of nesting.",
  detail:
    "Two spaces is the default because it is what most formatters emit and what keeps deeply nested documents inside a readable width. Tabs are here for a codebase that uses them, since a formatter that silently converts them is a diff nobody asked for. 'None' produces the same output as minifying and exists so the control has an answer for every case rather than disappearing.",
  order: 10,
};

const SORT_KEYS: OptionDef<FormatOptionGroup> = {
  id: OPTION_SORT_KEYS,
  label: "Sort keys",
  group: "document",
  kind: "boolean",
  summary: "Order object keys alphabetically, at every level.",
  detail:
    "Off by default, because it is the one setting here that changes what the document *says* rather than how it looks. It is worth having anyway: sorting both sides is what makes two JSON files diffable when a serialiser has emitted the same data in a different order.",
  order: 20,
};

const COLLAPSE: OptionDef<FormatOptionGroup> = {
  id: OPTION_COLLAPSE,
  label: "Collapse whitespace",
  group: "document",
  kind: "boolean",
  summary: "Treat runs of whitespace between elements as insignificant.",
  detail:
    "Off by default, and this is the default that matters most in XML: whitespace is *data* unless a schema says otherwise, so '<a> b </a>' and '<a>b</a>' are different documents. Turning this on is a claim about your document that only you can make. With it off, minifying still removes nothing from inside an element — which is why minified XML can look barely smaller than the original.",
  order: 20,
};

const CASE_STYLE: OptionDef<FormatOptionGroup> = {
  id: OPTION_CASE_STYLE,
  label: "Style",
  group: "format",
  kind: "enum",
  choices: [
    { value: "camel", label: "camelCase", group: "Programming" },
    { value: "pascal", label: "PascalCase", group: "Programming" },
    { value: "snake", label: "snake_case", group: "Programming" },
    { value: "constant", label: "CONSTANT_CASE", group: "Programming" },
    { value: "pascalSnake", label: "Pascal_Snake_Case", group: "Programming" },
    { value: "kebab", label: "kebab-case", group: "Web" },
    { value: "train", label: "Train-Case", group: "Web" },
    { value: "path", label: "path/case", group: "Web" },
    { value: "dot", label: "dot.case", group: "Web" },
    { value: "sentence", label: "Sentence case", group: "Prose" },
    { value: "capital", label: "Capital Case", group: "Prose" },
    { value: "no", label: "no case", group: "Prose", summary: "Words, separated by spaces" },
    { value: "upper", label: "UPPER CASE", group: "Whole string" },
    { value: "lower", label: "lower case", group: "Whole string" },
  ],
  summary: "Which casing convention.",
  detail:
    "Everything above the last group splits the input into words first — on existing separators, and on the boundary between a lower-case letter and an upper-case one — then rejoins them. So 'XMLHttpRequest' becomes 'xml_http_request' rather than 'x_m_l_http_request'. The last two do not split at all: they change the case of the string as it stands, which is what you want for text rather than for an identifier.",
  order: 10,
};

const UUID_VERSION: OptionDef<FormatOptionGroup> = {
  id: OPTION_UUID_VERSION,
  label: "Version",
  group: "generate",
  kind: "enum",
  choices: [
    { value: "v4", label: "v4 — random", group: "Random" },
    {
      value: "v7",
      label: "v7 — time-ordered",
      group: "Random",
      summary: "Sorts chronologically; prefer this for new keys",
    },
    { value: "v1", label: "v1 — timestamp and node", group: "Time-based" },
    { value: "v6", label: "v6 — v1 reordered to sort", group: "Time-based" },
    { value: "v3", label: "v3 — MD5 of a name", group: "Name-based" },
    { value: "v5", label: "v5 — SHA-1 of a name", group: "Name-based" },
    { value: "nil", label: "Nil — all zeroes", group: "Constants" },
    { value: "max", label: "Max — all ones", group: "Constants" },
  ],
  summary: "Which kind of identifier.",
  detail:
    "v4 is 122 random bits and the right default. v7 puts a millisecond timestamp in the high bits, so sorting the strings sorts by creation time — which makes it usable as a database key where v4 fragments an index. v1 encodes the same information in a field order that does not sort, and v6 is v1 with the fields put back in order. v3 and v5 are deterministic: the same namespace and name always produce the same identifier, which is what you want for deriving an id from something you already have. There is no v2 here because there is none in RFC 9562.",
  order: 10,
};

const UUID_NAMESPACE: OptionDef<FormatOptionGroup> = {
  id: OPTION_UUID_NAMESPACE,
  label: "Namespace",
  group: "generate",
  kind: "enum",
  choices: [
    { value: "dns", label: "DNS", summary: "6ba7b810-9dad-11d1-80b4-00c04fd430c8" },
    { value: "url", label: "URL", summary: "6ba7b811-9dad-11d1-80b4-00c04fd430c8" },
    { value: "oid", label: "OID", summary: "6ba7b812-9dad-11d1-80b4-00c04fd430c8" },
    { value: "x500", label: "X.500", summary: "6ba7b814-9dad-11d1-80b4-00c04fd430c8" },
    { value: "custom", label: "Custom", summary: "Enter one below" },
  ],
  // Only v3 and v5 hash a name, so only they have a namespace.
  availableOn: [TAG_UUID_NAMED],
  summary: "Which namespace the name is hashed under.",
  detail:
    "The four constants are from RFC 9562 appendix A. The namespace is part of the input, so the same name under two namespaces gives two unrelated identifiers — which is the whole point: it stops a hostname and a URL that happen to share text from colliding.",
  order: 20,
};

const UUID_NAME: OptionDef<FormatOptionGroup> = {
  id: OPTION_UUID_NAME,
  label: "Name",
  group: "generate",
  kind: "text",
  arg: { placeholder: "www.example.com" },
  availableOn: [TAG_UUID_NAMED],
  summary: "The name to hash, or a custom namespace UUID.",
  detail:
    "For v3 and v5 this is the string that gets hashed with the namespace. Enter it here rather than in the Input panel because it is a *parameter* of the identifier — the tool generates rather than transforms, so there is no message. If the namespace is set to Custom, put the namespace UUID on the first line and the name on the second.",
  order: 30,
};

const COUNT: OptionDef<FormatOptionGroup> = {
  id: OPTION_COUNT,
  label: "How many",
  group: "generate",
  kind: "number",
  arg: { placeholder: "1", min: 1, max: 100 },
  summary: "One per line.",
  detail:
    "Capped at 100. Generating a thousand at a time is a scripting job rather than a workbench one, and a number field that accepts 100000 is a way to hang the page rather than a feature.",
  order: 80,
};

const LENGTH: OptionDef<FormatOptionGroup> = {
  id: OPTION_LENGTH,
  label: "Length",
  group: "generate",
  kind: "number",
  arg: { placeholder: "20", min: 4, max: 256 },
  summary: "Characters.",
  detail:
    "The entropy is reported with the result, in bits, because length alone does not say much: a 20-character password over lower case only is weaker than a 14-character one over all four classes. Below 4 there is nothing to generate; above 256 you are past what any password field will accept.",
  order: 10,
};

/**
 * One option per class, built from the same list the generator draws from.
 *
 * Generated rather than written out four times, so the label *is* the alphabet and cannot drift from
 * the pool `compute.ts` actually uses -- the same reason the CRC family's sidebar tags are generated
 * from its model catalogue. The orders leave gaps between them because `validateCatalogue` refuses two
 * options at the same order in one group, and a fifth class should not mean renumbering the rest.
 */
const CLASS_LABELS: Readonly<Record<PasswordClass, string>> = {
  lower: "Lowercase",
  upper: "Uppercase",
  digit: "Digits",
  symbol: "Symbols",
};

const CLASS_DETAIL: Readonly<Record<PasswordClass, string>> = {
  lower: "Twenty-six characters, about 4.7 bits each.",
  upper:
    "Twenty-six more. Worth having unless the destination is case-insensitive, in which case it buys nothing and the length should go up instead.",
  digit: "Ten characters. Nearly every policy requires at least one, which is why this is on by default.",
  symbol:
    "Seventeen characters, chosen to be the ones that survive a shell, a URL and a CSV field without quoting. Turning them off is the single most common reason a generated password has to be regenerated, so it is one click.",
};

const CLASS_OPTIONS: readonly OptionDef<FormatOptionGroup>[] = PASSWORD_CLASSES.map(
  (id, index) => ({
    id: PASSWORD_CLASS_OPTIONS[id],
    label: CLASS_LABELS[id],
    group: "generate",
    kind: "boolean",
    summary: PASSWORD_ALPHABETS[id],
    detail: `${CLASS_DETAIL[id]} Every class left on is guaranteed to appear at least once, which is what a password policy usually checks -- and the entropy figure reported with the result is stated as an upper bound because that guarantee removes possibilities.`,
    order: 20 + index * 10,
  }),
);

const EXCLUDE_AMBIGUOUS: OptionDef<FormatOptionGroup> = {
  id: OPTION_EXCLUDE_AMBIGUOUS,
  label: "Avoid look-alikes",
  group: "generate",
  kind: "boolean",
  summary: "Leave out I, l, 1, O and 0.",
  detail:
    "For a password somebody has to read off a screen and type on a phone. It costs a little entropy — five characters out of the pool — and the figure reported with the result already accounts for it.",
  order: 70,
};

/**
 * One `Record`, and a miss throws.
 *
 * The fifth time this repo has used this shape rather than a chain ending in a default, and for the
 * reason the earlier four record: a tool added to the metadata without an entry here should fail by
 * name at build time rather than silently inherit whichever option happened to be last.
 */
const RANDOM_SHAPE_LABEL: Readonly<Record<RandomShape, string>> = {
  integer: "Whole numbers",
  decimal: "Decimals",
};

const RANDOM_SHAPE: OptionDef<FormatOptionGroup> = {
  id: OPTION_RANDOM_SHAPE,
  label: "Produce",
  group: "generate",
  kind: "enum",
  // Derived from the enum with a label map, so adding a shape is a compile error until it is named.
  choices: RANDOM_SHAPES.map((value) => ({ value, label: RANDOM_SHAPE_LABEL[value] })),
  summary: "Integers in a range, or decimals in [0, 1).",
  detail:
    "Whole numbers are drawn from an inclusive range you set. Decimals are drawn from [0, 1) with all 53 bits of the mantissa random, which is what makes them uniform over the interval rather than over a coarse grid of it.",
  order: 5,
};

const RANDOM_MIN: OptionDef<FormatOptionGroup> = {
  id: OPTION_RANDOM_MIN,
  label: "From",
  group: "generate",
  kind: "number",
  arg: { placeholder: "1", min: -Number.MAX_SAFE_INTEGER, max: Number.MAX_SAFE_INTEGER },
  availableOn: [TAG_RANDOM_INTEGER],
  summary: "Inclusive.",
  detail:
    "Inclusive at both ends, because that is what 'between 1 and 6' means. Negative bounds are fine. The range may span up to 2^53 - 1 values, which is where a JavaScript integer stops being exact -- past that the tool refuses rather than returning something that looks like a number and is not one.",
  order: 10,
};

const RANDOM_MAX: OptionDef<FormatOptionGroup> = {
  id: OPTION_RANDOM_MAX,
  label: "To",
  group: "generate",
  kind: "number",
  arg: { placeholder: "100", min: -Number.MAX_SAFE_INTEGER, max: Number.MAX_SAFE_INTEGER },
  availableOn: [TAG_RANDOM_INTEGER],
  summary: "Inclusive.",
  detail: "Inclusive, so 'to 6' can roll a 6. Must not be below From.",
  order: 20,
};

const RANDOM_DISTINCT: OptionDef<FormatOptionGroup> = {
  id: OPTION_RANDOM_DISTINCT,
  label: "No repeats",
  group: "generate",
  kind: "boolean",
  availableOn: [TAG_RANDOM_INTEGER],
  summary: "Draw without replacement.",
  detail:
    "Off is a die: every value is independent and 6,6,6 is a legitimate answer. On is a lottery draw: each value appears at most once, which needs the range to hold at least as many values as you asked for.",
  order: 30,
};

const RANDOM_SORTED: OptionDef<FormatOptionGroup> = {
  id: OPTION_RANDOM_SORTED,
  label: "Sorted",
  group: "generate",
  kind: "boolean",
  availableOn: [TAG_RANDOM_INTEGER],
  summary: "Ascending, after drawing.",
  detail:
    "Sorting happens after the draw and changes nothing about which values came up -- a lottery result is the same six numbers in any order. Off keeps draw order, which is what you want if the order is part of the answer.",
  order: 40,
};

const RANDOM_PLACES: OptionDef<FormatOptionGroup> = {
  id: OPTION_RANDOM_PLACES,
  label: "Decimal places",
  group: "generate",
  kind: "number",
  arg: { placeholder: "6", min: 1, max: 17 },
  availableOn: [TAG_RANDOM_DECIMAL],
  summary: "How many digits to print.",
  detail:
    "Rounding for display only: the draw is always the full 53 bits. 17 is the ceiling because that is the most digits a double can carry without inventing precision it does not have.",
  order: 50,
};

const RANDOM_BYTES_LENGTH: OptionDef<FormatOptionGroup> = {
  id: OPTION_RANDOM_BYTES,
  label: "Bytes",
  group: "generate",
  kind: "number",
  arg: { placeholder: "32", min: 1, max: 4096 },
  summary: "How many per value.",
  detail:
    "32 bytes is 256 bits, which is the usual size for a key or a token. The ceiling is 4096 because this is a workbench: generating a megabyte of random data is a scripting job, and the Result panel would be unreadable long before that. What a given length is for is a question about the tool you are pasting it into -- this one deliberately does not guess, having got it wrong once.",
  order: 10,
};

const BY_ID: Record<string, OptionDef<FormatOptionGroup>> = {
  [OPTION_DIRECTION]: DIRECTION,
  [OPTION_URL_MODE]: URL_MODE,
  [OPTION_ENTITY_SCOPE]: ENTITY_SCOPE,
  [OPTION_ENTITY_FORM]: ENTITY_FORM,
  [OPTION_ACTION]: ACTION,
  [OPTION_INDENT]: INDENT,
  [OPTION_SORT_KEYS]: SORT_KEYS,
  [OPTION_COLLAPSE]: COLLAPSE,
  [OPTION_CASE_STYLE]: CASE_STYLE,
  [OPTION_UUID_VERSION]: UUID_VERSION,
  [OPTION_UUID_NAMESPACE]: UUID_NAMESPACE,
  [OPTION_UUID_NAME]: UUID_NAME,
  [OPTION_COUNT]: COUNT,
  [OPTION_LENGTH]: LENGTH,
  ...Object.fromEntries(CLASS_OPTIONS.map((option) => [option.id, option])),
  [OPTION_EXCLUDE_AMBIGUOUS]: EXCLUDE_AMBIGUOUS,
  [OPTION_RANDOM_SHAPE]: RANDOM_SHAPE,
  [OPTION_RANDOM_MIN]: RANDOM_MIN,
  [OPTION_RANDOM_MAX]: RANDOM_MAX,
  [OPTION_RANDOM_DISTINCT]: RANDOM_DISTINCT,
  [OPTION_RANDOM_SORTED]: RANDOM_SORTED,
  [OPTION_RANDOM_PLACES]: RANDOM_PLACES,
  [OPTION_RANDOM_BYTES]: RANDOM_BYTES_LENGTH,
};

const CACHE = new Map<string, OptionCatalogue<FormatOptionGroup>>();

/** Memoised per tool: `ToolDefinition.catalogue` is resolved once, and this never changes. */
export function formatCatalogueFor(meta: FormatToolMeta): OptionCatalogue<FormatOptionGroup> {
  let catalogue = CACHE.get(meta.id);
  if (!catalogue) {
    const options: OptionDef<FormatOptionGroup>[] = [];
    for (const id of meta.exposes) {
      const option = BY_ID[id];
      if (!option) throw new Error(`${meta.id} exposes unknown format option: ${id}`);
      options.push(option);
    }
    catalogue = createOptionCatalogue<FormatOptionGroup>(options);
    CACHE.set(meta.id, catalogue);
  }
  return catalogue;
}

/** Every option definition in the family, for `validateCatalogue`. */
export const ALL_FORMAT_OPTIONS: readonly OptionDef<FormatOptionGroup>[] =
  Object.values(BY_ID);

/** Re-exported so the compute path and the tests agree about the case list. */
export { CASE_STYLES };

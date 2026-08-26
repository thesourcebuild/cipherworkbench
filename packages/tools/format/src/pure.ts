/**
 * Zod-free constants and accessors, same rationale as the other families' `pure.ts`.
 *
 * Nothing here imports a library, so the manifests and the spec schema stay cheap.
 */
import type { OptionValues } from "@ocs/contracts/options";
import { optBool, optEnumOr, optNumber, setOption } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_DIRECTION = "direction";
export const OPTION_ACTION = "action";
export const OPTION_URL_MODE = "urlMode";
export const OPTION_ENTITY_SCOPE = "entityScope";
export const OPTION_ENTITY_FORM = "entityForm";
export const OPTION_INDENT = "indent";
export const OPTION_SORT_KEYS = "sortKeys";
export const OPTION_COLLAPSE = "collapse";
export const OPTION_CASE_STYLE = "caseStyle";
export const OPTION_UUID_VERSION = "uuidVersion";
export const OPTION_UUID_NAMESPACE = "uuidNamespace";
export const OPTION_UUID_NAME = "uuidName";
export const OPTION_COUNT = "count";
export const OPTION_LENGTH = "length";
/**
 * The random tools' own ids.
 *
 * `randomMin`/`randomMax` rather than a reused `min`/`max`: option ids are global to a tool's
 * catalogue and stable forever -- a share link carries them -- so a generic name is a collision
 * waiting for the next tool that needs a bound.
 */
export const OPTION_RANDOM_SHAPE = "randomShape";
export const OPTION_RANDOM_MIN = "randomMin";
export const OPTION_RANDOM_MAX = "randomMax";
export const OPTION_RANDOM_DISTINCT = "randomDistinct";
export const OPTION_RANDOM_SORTED = "randomSorted";
export const OPTION_RANDOM_PLACES = "randomPlaces";
export const OPTION_RANDOM_BYTES = "randomBytes";
export const OPTION_USE_LOWER = "useLower";
export const OPTION_USE_UPPER = "useUpper";
export const OPTION_USE_DIGIT = "useDigit";
export const OPTION_USE_SYMBOL = "useSymbol";
export const OPTION_EXCLUDE_AMBIGUOUS = "excludeAmbiguous";

export const DIRECTIONS = ["encode", "decode"] as const;
export type Direction = (typeof DIRECTIONS)[number];

/**
 * What a document tool does with its input.
 *
 * One list across JSON and XML rather than one each, so `validateCatalogue` has a single set of ids
 * to check and the compute path switches on it once. XML offers no `validate` of its own -- parsing
 * *is* the validation, and `format` reports the same errors -- so it exposes two of the three.
 */
export const ACTIONS = ["validate", "format", "minify"] as const;
export type Action = (typeof ACTIONS)[number];

/**
 * The three things "URL encode" means, and they are not interchangeable.
 *
 * `component` is `encodeURIComponent`: safe as one query value or path segment. `uri` is `encodeURI`:
 * leaves the delimiters, so a whole URL survives. `form` is the URL standard's
 * `application/x-www-form-urlencoded` serialiser, which differs from `component` in three places --
 * a space becomes `+`, `!`/`'`/`(`/`)` are escaped, and `~` is escaped where RFC 3986 calls it
 * unreserved. Picking the wrong one produces a URL that looks right and resolves somewhere else.
 */
export const URL_MODES = ["component", "uri", "form"] as const;
export type UrlMode = (typeof URL_MODES)[number];

/** How much to escape. Markup-only is what you want inside an HTML document; all is for attributes. */
export const ENTITY_SCOPES = ["markup", "non-ascii"] as const;
export type EntityScope = (typeof ENTITY_SCOPES)[number];

export const ENTITY_FORMS = ["named", "decimal", "hex"] as const;
export type EntityForm = (typeof ENTITY_FORMS)[number];

/**
 * Indentation, as an enum of the four things anybody uses.
 *
 * A number control would admit 7, and a formatter that indents by seven spaces is not a feature. The
 * ids carry their own width so the compute path needs no table.
 */
export const INDENTS = ["2", "4", "tab", "0"] as const;
export type Indent = (typeof INDENTS)[number];

/**
 * The cases `change-case` provides, by its own names.
 *
 * Kept to the library's vocabulary deliberately: a reader who wants to know exactly what `capital`
 * does can look it up, where a name invented here would send them nowhere.
 */
export const CASE_STYLES = [
  "camel",
  "capital",
  "constant",
  "dot",
  "kebab",
  "no",
  "pascal",
  "pascalSnake",
  "path",
  "sentence",
  "snake",
  "train",
  "upper",
  "lower",
] as const;
export type CaseStyle = (typeof CASE_STYLES)[number];

/**
 * The UUID versions this offers, plus the two that carry no version at all.
 *
 * v2 is absent because it is absent from RFC 9562: it was defined for DCE Security, never widely
 * implemented, and the RFC that replaced 4122 does not specify it.
 */
export const UUID_VERSIONS = ["v4", "v7", "v1", "v6", "v3", "v5", "nil", "max"] as const;

/**
 * What the random-number tool produces. The tool is one tool with a knob rather than two, because an
 * integer and a decimal are the same request with a different type on the answer -- see
 * `## One tool or many` in CLAUDE.md. Random *bytes* are a separate tool, for a structural reason:
 * `outputEncodings` is eager and per-tool, so a tool cannot return text in one mode and bytes in
 * another without offering an encoding menu that does nothing half the time.
 */
export const RANDOM_SHAPES = ["integer", "decimal"] as const;
export type RandomShape = (typeof RANDOM_SHAPES)[number];
export type UuidVersion = (typeof UUID_VERSIONS)[number];

/** RFC 9562 appendix A's four namespaces, plus a custom one the form supplies. */
export const UUID_NAMESPACE_IDS = ["dns", "url", "oid", "x500", "custom"] as const;
export type UuidNamespaceId = (typeof UUID_NAMESPACE_IDS)[number];

/**
 * Character classes for the password generator: four booleans, not one multi-select.
 *
 * There is no multi-select among the option kinds -- `list` is a list of *byte strings*, each with its
 * own encoding selector, which is right for a set of keys and wrong for four fixed checkboxes. Rather
 * than add a kind for one tool, this is four `boolean` options, which is also what every password
 * generator anybody has used looks like. `symbol` is its own class rather than folded into "special"
 * because the single most common reason a generated password is rejected is a policy that forbids
 * symbols, so turning them off has to be one click.
 *
 * The alphabets live here rather than in the compute path because both halves of the split need them:
 * the option labels *are* the alphabets, and those are rendered from the eager side.
 */
export const PASSWORD_CLASSES = ["lower", "upper", "digit", "symbol"] as const;
export type PasswordClass = (typeof PASSWORD_CLASSES)[number];

export const PASSWORD_ALPHABETS: Readonly<Record<PasswordClass, string>> = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digit: "0123456789",
  symbol: "!#$%&*+-./:=?@^_~",
};

/** Which option turns each class on. One place, so the catalogue and the rules cannot disagree. */
export const PASSWORD_CLASS_OPTIONS: Readonly<Record<PasswordClass, string>> = {
  lower: OPTION_USE_LOWER,
  upper: OPTION_USE_UPPER,
  digit: OPTION_USE_DIGIT,
  symbol: OPTION_USE_SYMBOL,
};

/**
 * The classes actually selected, in catalogue order.
 *
 * Order matters and is deliberately the declared one rather than the order the options happen to sit
 * in the spec: the alphabet is the concatenation of these, and a tool whose reported alphabet size
 * moved with the insertion order of a share link would be reporting on nothing.
 */
export function readClasses(options: OptionValues): PasswordClass[] {
  return PASSWORD_CLASSES.filter((id) => optBool(options, PASSWORD_CLASS_OPTIONS[id]));
}

/** `availableOn` tags, so a control only appears where it applies. */
export const TAG_ENCODE = "encode";
export const TAG_DECODE = "decode";
/** Set for the two UUID versions that hash a name, which are the only ones with a namespace. */
export const TAG_UUID_NAMED = "uuid-named";
/**
 * One per random shape, prefixed rather than bare.
 *
 * `"integer"` alone would sit in the same tag namespace as the JSON/XML action tags, and
 * `isAvailableOn` matches on the string -- so a bare name is one rename away from revealing a control
 * on a tool that has nothing to do with it.
 */
export const TAG_RANDOM_INTEGER = "random-integer";
export const TAG_RANDOM_DECIMAL = "random-decimal";

export function readDirection(options: OptionValues): Direction {
  return optEnumOr(options, OPTION_DIRECTION, DIRECTIONS, "encode");
}

export function readAction(options: OptionValues, fallback: Action): Action {
  return optEnumOr(options, OPTION_ACTION, ACTIONS, fallback);
}

export function readUrlMode(options: OptionValues): UrlMode {
  return optEnumOr(options, OPTION_URL_MODE, URL_MODES, "component");
}

export function readEntityScope(options: OptionValues): EntityScope {
  return optEnumOr(options, OPTION_ENTITY_SCOPE, ENTITY_SCOPES, "markup");
}

export function readEntityForm(options: OptionValues): EntityForm {
  return optEnumOr(options, OPTION_ENTITY_FORM, ENTITY_FORMS, "named");
}

export function readIndent(options: OptionValues): Indent {
  return optEnumOr(options, OPTION_INDENT, INDENTS, "2");
}

/** Spaces per level, or a tab. Zero is the minified case and callers treat it as "no whitespace". */
export function indentText(indent: Indent): string {
  if (indent === "tab") return "\t";
  return " ".repeat(Number(indent));
}

export function readCaseStyle(options: OptionValues): CaseStyle {
  return optEnumOr(options, OPTION_CASE_STYLE, CASE_STYLES, "camel");
}

export function readUuidVersion(options: OptionValues): UuidVersion {
  return optEnumOr(options, OPTION_UUID_VERSION, UUID_VERSIONS, "v4");
}

export function readUuidNamespace(options: OptionValues): UuidNamespaceId {
  return optEnumOr(options, OPTION_UUID_NAMESPACE, UUID_NAMESPACE_IDS, "dns");
}

export function readRandomShape(options: OptionValues): RandomShape {
  return optEnumOr(options, OPTION_RANDOM_SHAPE, RANDOM_SHAPES, "integer");
}

/** The tag `availableOn` matches for the selected shape. */
export function randomShapeTag(shape: RandomShape): string {
  return shape === "integer" ? TAG_RANDOM_INTEGER : TAG_RANDOM_DECIMAL;
}

export function readCount(options: OptionValues): number {
  // Clamped rather than validated: a count of 0 or 5000 is a slider mishap, not a request.
  return Math.min(Math.max(optNumber(options, OPTION_COUNT) ?? 1, 1), 100);
}

export function readLength(options: OptionValues): number {
  return Math.min(Math.max(optNumber(options, OPTION_LENGTH) ?? 20, 4), 256);
}

export function withDirection(options: OptionValues, direction: Direction): OptionValues {
  return setOption(options, OPTION_DIRECTION, direction);
}

export function withAction(options: OptionValues, action: Action): OptionValues {
  return setOption(options, OPTION_ACTION, action);
}

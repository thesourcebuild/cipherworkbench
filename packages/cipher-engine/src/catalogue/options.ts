import type { BytesEncoding } from "@ocs/contracts/encoding";

/**
 * `bytes` and `password` are the two kinds this app adds over a plain settings
 * form, and both exist because cryptographic material is not just a string:
 *
 *  - `bytes` — a key, IV, nonce, salt or AAD. The stored value is the text the
 *    user typed; a *companion* option (id + "Encoding") says how to turn it
 *    into bytes, so "00112233" as hex and "00112233" as UTF-8 stay
 *    distinguishable. `bytesLength` drives both the form's byte counter and the
 *    length lint rules.
 *  - `password` — masked by default with a reveal toggle. Distinct from `text`
 *    only in presentation, but that presentation is the point.
 *  - `list` — an *ordered set* of byte strings, each decoded independently through
 *    the option's companion encoding. Added for TupleHash, whose input genuinely
 *    is a tuple rather than a message: `TupleHash(["ab", "c"])` and
 *    `TupleHash(["abc"])` are different values by design, which is the whole point
 *    of the construction. A newline-delimited `text` option could not express an
 *    element that contains a newline, and would therefore compute a confidently
 *    wrong digest for one; separate values have no delimiter to collide with.
 */
export type OptionKind = "boolean" | "text" | "number" | "enum" | "password" | "bytes" | "list";

export interface OptionEnumChoice {
  value: string;
  label: string;
  summary?: string;
  /**
   * Renders inside an `<optgroup>` with this label, which is the only separator a native `<select>`
   * has: it cannot hold a rule, and a disabled row of dashes is a hack that screen readers read out.
   *
   * Consecutive choices sharing a value share a group, so order in the array is what defines the
   * segments. Used by `@ocs/crc` to hold sixty-seven standard models apart from the Custom entry that
   * reveals the parameter fields -- two things that do very different jobs and sat adjacent with
   * nothing between them. The input panel's 40 character encodings already group this way; this
   * brings the same to any catalogue that wants it.
   */
  group?: string;
  /**
   * Restricts this choice to the listed `variantTag` values, exactly as `OptionDef.availableOn`
   * restricts a whole option.
   *
   * Added because AES's Key size could not otherwise be a dropdown under XTS, SIV and GCM-SIV. A
   * catalogue is resolved once per tool, so one option cannot swap its `choices` when the mode
   * changes -- but it can carry every choice and let each say where it belongs. Under XTS the select
   * then offers XTS-AES-128 and XTS-AES-256; under GCM it offers AES-128/192/256; and it is one
   * option with one id and one stored value throughout.
   *
   * Two choices may share a `value` with different tags and different labels, which is the point
   * rather than an accident: a 32-byte key string is AES-256 under GCM and XTS-AES-128 under XTS --
   * the same bytes, a different name, and the name is what the reader needs. Only one of the two is
   * ever visible, so the select never shows a duplicate.
   *
   * Narrowed in one place, `withAvailableChoices`, which the form applies where it already filters
   * options by tag. Every consumer downstream -- the "(not set)" placeholder included -- then sees
   * only the reachable choices without being told about tags.
   */
  availableOn?: readonly string[];
  /**
   * Marks a choice as cryptographically unsafe so the form can flag it inline
   * rather than waiting for the diagnostics panel — e.g. AES's "ecb" mode.
   * Purely presentational; the actual rule still lives in `lint/`.
   */
  insecure?: boolean;
}

export interface OptionArgSpec {
  placeholder: string;
  /** Shown after the input, e.g. "bits", "iterations". */
  unit?: string;
  min?: number;
  max?: number;
  /** Snap numeric input to a multiple, e.g. 8 for a bit length. */
  step?: number;
  /**
   * Render as a textarea rather than a single-line input.
   *
   * Exists for PEM keys, which are multi-line by construction and unreadable squeezed into
   * one line. Only meaningful for `text` and `password` kinds.
   */
  multiline?: boolean;
  /** Rows for a multiline control. Ignored otherwise. */
  rows?: number;
}

/**
 * Accepted byte lengths for a `bytes` option. `exact` is the common case (AES
 * key: 16/24/32; GCM nonce: 12); `min`/`max` cover the open-ended ones (HMAC
 * key, AAD, PBKDF2 salt).
 */
export interface BytesLengthSpec {
  exact?: readonly number[];
  min?: number;
  max?: number;
  /** Offer a "generate" button that fills this many random bytes. */
  generate?: number;
}

/**
 * One entry in a tool's option catalogue. Generic over the group id type so
 * each `packages/tools/<family>` package can declare its own group taxonomy
 * while still using this same shape.
 *
 * Compared with the command-generator's `FlagDef` this drops `short`/`long`/
 * `preferShort`/`order`/`renders` — there is no argv to spell anything into —
 * and adds `secret`, `bytesLength` and `defaultTextEncoding`.
 */
export interface OptionDef<TGroup extends string = string> {
  /** Key in the tool's option-values record. Stable forever — renaming breaks saved state and share links. */
  id: string;
  label: string;
  group: TGroup;
  kind: OptionKind;
  arg?: OptionArgSpec;
  choices?: OptionEnumChoice[];
  /** Only for `kind: "bytes"` and `kind: "list"` — for a list it constrains each element. */
  bytesLength?: BytesLengthSpec;
  /** Only for `kind: "list"`. Caps how many elements may be added. */
  maxItems?: number;
  /**
   * Which encoding the companion selector starts on, for `bytes` and `list`.
   * Defaults to hex.
   */
  defaultBytesEncoding?: BytesEncoding;
  /** One line, shown next to the control. */
  summary: string;
  /** Paragraph, shown in the reference panel and the tooltip. */
  detail: string;
  /**
   * Never leaves the machine: excluded from share links, and from any exported
   * or persisted spec. Set on every key, password, passphrase and private key.
   * Nonces and IVs are NOT secret (they are transmitted in the clear alongside
   * the ciphertext) and deliberately do not set this — but see `C003`, which is
   * what actually stops one being reused.
   */
  secret?: boolean;
  /** Option ids this one makes redundant, so the form can grey them out. */
  implies?: string[];
  conflictsWith?: string[];
  requires?: string[];
  /**
   * Restricts an option to specific variants of the tool — e.g. an AEAD tag
   * length only applies to GCM, not CBC. Opaque tags whose meaning each tool
   * defines; absent means "available in every variant".
   */
  availableOn?: readonly string[];
  /** Display order within the group. Gaps left for future insertions. */
  order: number;
}

export interface OptionCatalogue<TGroup extends string = string> {
  readonly options: readonly OptionDef<TGroup>[];
  get(id: string): OptionDef<TGroup> | undefined;
  require(id: string): OptionDef<TGroup>;
  inGroup(group: TGroup): OptionDef<TGroup>[];
  /** Every option in stable display order, ignoring groups. */
  inDisplayOrder(): OptionDef<TGroup>[];
  /** Ids of every option marked `secret` — the share-link and export denylist. */
  secretIds(): readonly string[];
}

/**
 * Build a catalogue instance bound to one tool's option list. A module-level
 * singleton does not work once many tool families share this engine, so each
 * one calls this factory with its own `OPTIONS` array instead.
 */
export function createOptionCatalogue<TGroup extends string = string>(
  options: readonly OptionDef<TGroup>[],
): OptionCatalogue<TGroup> {
  const byId = new Map<string, OptionDef<TGroup>>(options.map((o) => [o.id, o]));
  const sorted = [...options].sort((a, b) => a.order - b.order);
  const secrets = options.filter((o) => o.secret).map((o) => o.id);

  return {
    options,
    get: (id) => byId.get(id),
    require(id) {
      const o = byId.get(id);
      if (!o) throw new Error(`Unknown option id: ${id}`);
      return o;
    },
    inGroup: (group) =>
      options.filter((o) => o.group === group).sort((a, b) => a.order - b.order),
    inDisplayOrder: () => sorted,
    secretIds: () => secrets,
  };
}

/**
 * True when an option restricted to specific variants (see `availableOn`) permits these tags.
 *
 * Accepts several tags because a single one stopped being enough: cSHAKE has a variable output
 * length *and* a customisation string *and* a function name, and ParallelHash adds a block size on
 * top. Before this, `variantTag` returned one string and each of those controls would have had to
 * be forced onto the same axis. Existing families still return a single string, which is why the
 * parameter is a union rather than an array everywhere.
 */
export function isAvailableOn(
  /*
   * Structural rather than `OptionDef`, so a choice can be asked the same question. The rule is
   * identical for both -- no list means always, a list means only these tags -- and two copies of it
   * is how one of them ends up treating a missing tag as available.
   */
  option: { readonly availableOn?: readonly string[] },
  tags: string | readonly string[] | undefined,
): boolean {
  if (option.availableOn === undefined) return true;
  if (tags === undefined) return false;
  const list = typeof tags === "string" ? [tags] : tags;
  return list.some((tag) => option.availableOn!.includes(tag));
}

/**
 * The option with its choices narrowed to those reachable under `tags`.
 *
 * Returned unchanged unless it is an `enum` whose choices are gated, so this is free for every option
 * that does not use the feature. Applied where the form already filters options by tag, which is what
 * keeps the knowledge of tags out of every control below it.
 *
 * Note it does **not** drop an option whose every choice is unavailable -- that is a catalogue bug
 * rather than a state to render, and `tests/registry.test.ts` fails on it by name.
 */
export function withAvailableChoices(
  option: OptionDef,
  tags: string | readonly string[] | undefined,
): OptionDef {
  if (option.kind !== "enum" || !option.choices) return option;
  if (!option.choices.some((choice) => choice.availableOn !== undefined)) return option;
  return { ...option, choices: option.choices.filter((choice) => isAvailableOn(choice, tags)) };
}

/**
 * The companion option id holding a `bytes` option's own encoding — `"key"`
 * pairs with `"keyEncoding"`. Centralised here so the form, the compute path
 * and the share-link filter all derive the same name instead of three string
 * concatenations drifting apart.
 */
export function encodingOptionId(bytesOptionId: string): string {
  return `${bytesOptionId}Encoding`;
}

/** True when the byte length satisfies the option's `bytesLength` spec. */
export function isValidByteLength(
  option: OptionDef,
  length: number,
  accepted?: readonly number[],
): boolean {
  /*
   * `accepted` overrides the option's own list, and exists because a catalogue is resolved once per
   * tool while a length can depend on a mode. AES's key option has to declare 16/24/32 for the
   * ordinary modes, and XTS legitimately takes 64 -- so without an override the form calls a valid
   * XTS key invalid. See `ToolDefinition.acceptedByteLengths`.
   */
  if (accepted) return accepted.includes(length);
  const spec = option.bytesLength;
  if (!spec) return true;
  if (spec.exact) return spec.exact.includes(length);
  if (spec.min !== undefined && length < spec.min) return false;
  if (spec.max !== undefined && length > spec.max) return false;
  return true;
}

/** Human-readable form of a `bytesLength` spec, for lint messages and the form's hint text. */
export function describeByteLength(option: OptionDef, accepted?: readonly number[]): string {
  const spec = option.bytesLength;
  const exact = accepted ?? spec?.exact;
  if (exact) {
    const list = [...exact];
    const last = list.pop();
    return list.length === 0 ? `exactly ${last} bytes` : `${list.join(", ")} or ${last} bytes`;
  }
  if (!spec) return "any length";
  if (spec.min !== undefined && spec.max !== undefined) {
    return `${spec.min}–${spec.max} bytes`;
  }
  if (spec.min !== undefined) return `at least ${spec.min} bytes`;
  if (spec.max !== undefined) return `at most ${spec.max} bytes`;
  return "any length";
}

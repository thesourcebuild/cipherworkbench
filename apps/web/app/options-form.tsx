"use client";

import { Fragment, useState, type ReactNode } from "react";
import type { BytesEncoding, OptionValue, OptionValues } from "@ocs/contracts";
import { BYTES_ENCODING_LABEL, optEnumOr } from "@ocs/contracts";
import type {
  OptionCatalogue,
  OptionDef,
  OptionEnumChoice,
  OptionGroupMeta,
} from "@ocs/engine";
import {
  decodeBytesValue,
  describeByteLength,
  encodingOptionId,
  isAvailableOn,
  withAvailableChoices,
  isValidByteLength,
  orderedGroups,
  LOSSLESS_BYTES_ENCODINGS,
  randomValueEntropyBits,
  randomBytesValue,
  redundantOptionIds,
} from "@ocs/engine";
import { Button, SecretField, StringListEditor, Toggle, cn } from "@ocs/ui";

const BYTES_ENCODINGS: readonly BytesEncoding[] = [
  "hex",
  "base64",
  "base64url",
  "utf-8",
  "latin1",
];

/**
 * Which part of a tool's catalogue to render, mirroring `OptionGroupMeta.placement`.
 *
 * `input` is the keys, IVs, nonces and salts the workbench renders beside the message; `panel` is a
 * parameter set that gets its own panel; `settings` is everything left, which is what the right-hand
 * rail shows. `all` keeps them together, for a caller with nowhere else to put them.
 */
export type OptionScope = "input" | "panel" | "settings" | "all";

export interface OptionsFormProps {
  catalogue: OptionCatalogue;
  groups: Record<string, OptionGroupMeta>;
  options: OptionValues;
  /**
   * Restricts which options are shown, via each option's `availableOn`. Omit to show every one.
   *
   * An array when the selected algorithm sits on several axes at once -- cSHAKE is an XOF and
   * takes a customisation string and a function name. See `ToolDefinition.variantTag`.
   */
  tag?: string | readonly string[];
  /** Defaults to `all`. */
  scope?: OptionScope;
  /**
   * Render exactly these groups, in this order, ignoring `scope`.
   *
   * For a group that has a panel of its own: the workbench renders one panel per group and needs
   * each form to show just that one.
   */
  groupIds?: readonly string[];
  /**
   * Set false where the surrounding container already names the group -- a panel titled "Custom
   * parameters" does not need "CUSTOM PARAMETERS" as its first line.
   */
  headings?: boolean;
  onChange: (id: string, value: OptionValue | undefined) => void;
  /**
   * How many bytes this option's Generate button should produce, when the answer depends on the spec.
   *
   * A callback rather than the spec itself, so this component stays ignorant of what a mode or a
   * parameter set is -- it asks by option id and gets a number. The workbench wires it to
   * `ToolDefinition.generateLength`. Undefined, or a family that does not implement it, leaves the
   * catalogue's static `bytesLength.generate` in charge.
   */
  generateLength?: (optionId: string) => number | undefined;
  /**
   * The lengths a `bytes` field will actually accept, from `ToolDefinition.acceptedByteLengths`.
   *
   * Used for the validity check *and* the hint, so a field cannot call a value invalid while
   * describing a different set of lengths -- which is what "64 bytes -- needs 16, 24 or 32" was.
   */
  acceptedByteLengths?: (optionId: string) => readonly number[] | undefined;
}

/**
 * The groups a form would render, after both filters: the scope, and each option's `availableOn`.
 *
 * Exported because the workbench has to know whether a scope is *empty* before it decides to render
 * a container for it — an empty "Key" section under the input, or a Settings tab with nothing in it,
 * are both worse than the absence. Doing that with a second copy of this predicate is how the two
 * would drift: a group is hidden here and still counted there, and a heading appears above nothing.
 */
export function visibleOptionGroups(
  catalogue: OptionCatalogue,
  groups: Record<string, OptionGroupMeta>,
  tag: string | readonly string[] | undefined,
  scope: OptionScope,
  groupIds?: readonly string[],
): { group: OptionGroupMeta; options: OptionDef[] }[] {
  return orderedGroups(groups)
    .filter((group) => {
      if (groupIds) return groupIds.includes(group.id);
      if (scope === "all") return true;
      // `settings` is the absence of a placement rather than a placement of its own, so a family
      // that adds a group and forgets to place it lands in the rail rather than vanishing.
      if (scope === "settings") return group.placement === undefined;
      return group.placement === scope;
    })
    .map((group) => ({
      group,
      /*
       * Choices are narrowed here too, in the one place options are already filtered by tag. Doing it
       * at the source means the controls below -- and the "(not set)" placeholder, which decides
       * whether the stored value matches any choice -- see only what is reachable, without any of
       * them having to know what a tag is.
       */
      options: catalogue
        .inGroup(group.id)
        .filter((o) => isAvailableOn(o, tag))
        .map((o) => withAvailableChoices(o, tag)),
    }))
    .filter((entry) => entry.options.length > 0);
}

/**
 * Renders any tool's catalogue — grouped, one control per `OptionKind` — driven
 * purely by `OptionDef` metadata.
 *
 * This is the single biggest structural win over the command generator this app
 * is modelled on. There, every command needed a hand-written builder component,
 * because a command's *output* is bespoke: rsync has endpoint pickers, tar has a
 * variant selector. Here every tool's output is the same shape — bytes in, bytes
 * out — so one form plus one result panel serves all of them, and adding an
 * algorithm is catalogue data with no React to write at all.
 */
export function OptionsForm({
  catalogue,
  groups,
  options,
  tag,
  scope = "all",
  groupIds,
  headings = true,
  onChange,
  generateLength,
  acceptedByteLengths,
}: OptionsFormProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Redundancy is computed over the *whole* catalogue, not the scope being rendered: an option in
  // the Settings rail can perfectly well make one beside the input redundant, and grey it out.
  const active = catalogue
    .inDisplayOrder()
    .filter((o) => options[o.id] !== undefined)
    .map((o) => o.id);
  const redundant = redundantOptionIds(catalogue, active);

  const visibleGroups = visibleOptionGroups(catalogue, groups, tag, scope, groupIds);

  if (visibleGroups.length === 0) {
    // Nothing to say about an empty section the workbench has already decided not to wrap in a
    // container. "No settings" is a claim about the tool, and only the rail should be making it.
    if (scope !== "settings" && scope !== "all") return null;
    return (
      <p className="text-xs text-slate-500 dark:text-slate-400">
        This tool has no settings — the algorithm is fully determined.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      {visibleGroups.map(({ group, options: groupOptions }) => {
        const isOpen = !group.collapsedByDefault || expanded.has(group.id);

        return (
          <div key={group.id}>
            {!headings ? null : group.collapsedByDefault ? (
              <button
                type="button"
                onClick={() =>
                  setExpanded((prev) => {
                    const next = new Set(prev);
                    if (next.has(group.id)) next.delete(group.id);
                    else next.add(group.id);
                    return next;
                  })
                }
                className="mb-1 flex w-full items-center gap-1.5 text-left text-[11px] font-semibold uppercase tracking-wide text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                aria-expanded={isOpen}
              >
                <ChevronIcon collapsed={!isOpen} />
                {group.label}
              </button>
            ) : (
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                {group.label}
              </p>
            )}
            {isOpen && (
              <div className="flex flex-col gap-3">
                {groupOptions.map((option) => (
                  /**
                   * `data-ocs-option` is a test hook, matching `data-ocs-input` and
                   * `data-ocs-tool`. The packaged-app smoke test has to drive a real
                   * option — an Ed25519 private key — and the controls it needs to
                   * reach are two components deep and sometimes masked, so there is
                   * nothing stable to select on otherwise.
                   */
                  <div key={option.id} data-ocs-option={option.id}>
                    <OptionControl
                      option={option}
                      value={options[option.id]}
                      generateLength={generateLength}
                      acceptedByteLengths={acceptedByteLengths}
                      // A `bytes` option's encoding lives in a synthesised companion
                      // key rather than its own catalogue entry — see `encodingOptionId`.
                      bytesEncoding={optEnumOr(
                        options,
                        encodingOptionId(option.id),
                        BYTES_ENCODINGS,
                        option.defaultBytesEncoding ?? "hex",
                      )}
                      supersededBy={redundant.get(option.id)}
                      catalogue={catalogue}
                      onChange={onChange}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

interface OptionControlProps {
  option: OptionDef;
  value: OptionValue | undefined;
  bytesEncoding: BytesEncoding;
  supersededBy: string | undefined;
  catalogue: OptionCatalogue;
  onChange: (id: string, value: OptionValue | undefined) => void;
  /** Threaded to `BytesControl`; see `OptionsFormProps.generateLength`. */
  generateLength?: (optionId: string) => number | undefined;
  /** Threaded to `BytesControl`; see `OptionsFormProps.acceptedByteLengths`. */
  acceptedByteLengths?: (optionId: string) => readonly number[] | undefined;
}

function OptionControl({
  option,
  value,
  bytesEncoding,
  supersededBy,
  catalogue,
  onChange,
  generateLength,
  acceptedByteLengths,
}: OptionControlProps) {
  const supersededLabel = supersededBy ? catalogue.get(supersededBy)?.label : undefined;

  switch (option.kind) {
    case "boolean":
      // The same switch the input panel's preferences use. A boolean option is closer to a form
      // field than to a preference -- it changes a spec, and nothing recomputes until the debounce
      // fires -- but leaving one lone checkbox in an app whose every other on/off is a switch reads
      // as an oversight rather than as a distinction.
      return (
        <div>
          <Toggle
            id={option.id}
            label={option.label}
            hint={option.detail}
            checked={value === true}
            disabled={Boolean(supersededBy)}
            onCheckedChange={(next) => onChange(option.id, next)}
            labelClassName="text-xs font-medium"
          />
          {/* Indented to sit under the label rather than under the switch: 1.5rem of track
              plus the 0.375rem gap. */}
          <span className="mt-0.5 block pl-[1.875rem] text-[11px] text-slate-500 dark:text-slate-400">
            {supersededLabel ? `Already covered by ${supersededLabel}.` : option.summary}
          </span>
        </div>
      );

    case "enum": {
      const choice = option.choices?.find((c) => c.value === value);
      /**
       * The empty placeholder is a repair, not a choice.
       *
       * It used to render unconditionally, which put "(not set)" in the list of every select in the
       * app -- an entry that, if picked, dropped the option out of the spec and left compute running
       * on a fallback the form no longer showed. Every enum a tool renders is seeded by its
       * `createSpec` (there is a test), so in normal use there is nothing to choose here.
       *
       * It is still rendered when the stored value matches no choice, because that state has to stay
       * visible: a share link carrying a value from another tool, or an option whose choice list
       * changed under a saved spec. Without it the browser would show the first choice as selected
       * while the spec said something else. `disabled` is what stops it becoming a way back.
       */
      const needsPlaceholder = choice === undefined;
      // No `hint` override: the line under the select stays the option's own summary, the way every
      // other control in this form reads. Echoing the selected choice's summary there was an attempt
      // to give the long text somewhere to wrap, and once the dropdown could show it again it was
      // the same words twice, one line apart.
      return (
        <Field option={option} problem={undefined}>
          <select
            value={typeof value === "string" ? value : ""}
            onChange={(event) => onChange(option.id, event.target.value || undefined)}
            className={inputClass(Boolean(choice?.insecure))}
          >
            {needsPlaceholder && (
              <option value="" disabled>
                (not set)
              </option>
            )}
            {choiceSegments(option.choices ?? []).map((segment, index) => {
              const options = segment.choices.map((c) => (
                // `title` carries the summary. Support for it on an option is patchy across
                // platforms, which is why the summary's real home is the Info panel rather than
                // this.
                <option key={c.value} value={c.value} title={choiceTitle(c)}>
                  {choiceLabel(c)}
                </option>
              ));
              // An `<optgroup>` is the only separator a native select has, and the label comes free
              // with it. Ungrouped choices stay at the top level rather than being forced under a
              // heading nobody asked for.
              return segment.group === undefined ? (
                <Fragment key={`plain-${index}`}>{options}</Fragment>
              ) : (
                <optgroup key={segment.group} label={segment.group}>
                  {options}
                </optgroup>
              );
            })}
          </select>
          {/* Flagged inline as well as in the checks panel: by the time someone
              has picked ECB from a dropdown, saying so next to the dropdown is
              more likely to be read than a diagnostic further down the page. */}
          {choice?.insecure && (
            <p className="mt-1 text-[11px] font-medium text-(--color-severity-insecure)">
              {choice.label} is not secure — see Checks.
            </p>
          )}
        </Field>
      );
    }

    case "number": {
      const numeric = typeof value === "number" ? value : "";
      return (
        <Field option={option} problem={undefined} inline>
          <div className="flex items-center gap-2">
            <input
              type="number"
              value={numeric}
              placeholder={option.arg?.placeholder}
              min={option.arg?.min}
              max={option.arg?.max}
              step={option.arg?.step}
              onChange={(event) => {
                const raw = event.target.value;
                onChange(option.id, raw === "" ? undefined : Number(raw));
              }}
              className={inputClass(false)}
            />
            {option.arg?.unit && (
              <span className="shrink-0 text-[11px] text-slate-500 dark:text-slate-400">
                {option.arg.unit}
              </span>
            )}
          </div>
        </Field>
      );
    }

    case "text":
      return (
        // Inline unless it is a textarea: a polynomial is six characters and reads as a row, a PEM
        // key is twenty lines and cannot share one.
        <Field option={option} problem={undefined} inline={!option.arg?.multiline}>
          {option.arg?.multiline ? (
            // PEM keys and certificates. A single-line input for these is unusable.
            <textarea
              value={typeof value === "string" ? value : ""}
              placeholder={option.arg.placeholder}
              rows={option.arg.rows ?? 6}
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              onChange={(event) => onChange(option.id, event.target.value || undefined)}
              className={cn(inputClass(false), "w-full resize-y whitespace-pre font-mono")}
            />
          ) : (
            <input
              type="text"
              value={typeof value === "string" ? value : ""}
              placeholder={option.arg?.placeholder}
              spellCheck={false}
              onChange={(event) => onChange(option.id, event.target.value || undefined)}
              className={inputClass(false)}
            />
          )}
        </Field>
      );

    case "password":
      return (
        <SecretField
          label={option.label}
          hint={option.summary}
          placeholder={option.arg?.placeholder}
          value={typeof value === "string" ? value : ""}
          onValueChange={(next) => onChange(option.id, next || undefined)}
          {...(option.arg?.multiline ? { multiline: true, rows: option.arg.rows ?? 6 } : {})}
        />
      );

    case "bytes":
      return (
        <BytesControl
          option={option}
          value={typeof value === "string" ? value : ""}
          encoding={bytesEncoding}
          onChange={onChange}
          generateLength={generateLength}
          acceptedByteLengths={acceptedByteLengths}
        />
      );

    case "list":
      return (
        <ListControl
          option={option}
          value={Array.isArray(value) ? value : []}
          encoding={bytesEncoding}
          onChange={onChange}
        />
      );
  }
}

/**
 * An ordered list of byte strings -- TupleHash's tuple, and the only option kind whose *order*
 * is part of the value rather than of the presentation.
 *
 * Each element is decoded and counted independently, so a bad element is reported against its own
 * row. That is the payoff for making this a list rather than a newline-delimited text box: the
 * error can say which element, and an element containing a newline is representable at all.
 */
function ListControl({
  option,
  value,
  encoding,
  onChange,
}: {
  option: OptionDef;
  value: readonly string[];
  encoding: BytesEncoding;
  onChange: (id: string, value: OptionValue | undefined) => void;
}) {
  const decoded = value.map((item) => decodeBytesValue(item, encoding));
  const hints = decoded.map((result) =>
    result.ok
      ? `${result.bytes.length} ${result.bytes.length === 1 ? "byte" : "bytes"}`
      : undefined,
  );
  const problems = decoded.map((result) => (result.ok ? undefined : result.error));
  const total = decoded.reduce((sum, r) => sum + (r.ok ? r.bytes.length : 0), 0);

  return (
    <StringListEditor
      label={option.label}
      items={value}
      onChange={(next) => onChange(option.id, next.length === 0 ? undefined : next)}
      placeholder={option.arg?.placeholder}
      itemHints={hints}
      itemProblems={problems}
      {...(option.maxItems === undefined ? {} : { maxItems: option.maxItems })}
      emptyHint="No elements yet. An empty tuple is valid and hashes to a defined value."
      hint={`${option.summary} — ${value.length} element${value.length === 1 ? "" : "s"}, ${total} bytes total`}
      trailing={
        <select
          aria-label={`${option.label} encoding`}
          value={encoding}
          onChange={(event) => onChange(encodingOptionId(option.id), event.target.value)}
          className="h-[26px] shrink-0 rounded-md border border-slate-300 bg-white px-1.5 text-[11px] dark:border-slate-700 dark:bg-slate-950"
        >
          {BYTES_ENCODINGS.map((id) => (
            <option key={id} value={id}>
              {BYTES_ENCODING_LABEL[id]}
            </option>
          ))}
        </select>
      }
    />
  );
}

/**
 * A key, IV, nonce, salt or AAD: the typed value, the encoding it is written in,
 * a live byte count against the accepted lengths, and — where the option declares
 * `bytesLength.generate` — a button that fills it with fresh random bytes.
 *
 * The byte counter is the point. "AES-256 needs a 32-byte key" is useless advice
 * while the field shows 64 hex characters and no indication of how many bytes
 * that is; showing `32 / 32 bytes` as you type turns the most common cipher
 * mistake into something you cannot make by accident.
 */
function BytesControl({
  option,
  value,
  encoding,
  onChange,
  generateLength,
  acceptedByteLengths,
}: {
  option: OptionDef;
  value: string;
  encoding: BytesEncoding;
  onChange: (id: string, value: OptionValue | undefined) => void;
  generateLength?: (optionId: string) => number | undefined;
  acceptedByteLengths?: (optionId: string) => readonly number[] | undefined;
}) {
  const decoded = decodeBytesValue(value, encoding);
  const length = decoded.ok ? decoded.bytes.length : undefined;
  /*
   * The spec-aware set wins where a family supplies one, and it drives the hint as well as the
   * check. Passing it to only one of the two is how a field comes to say "64 bytes -- needs 16, 24
   * or 32" about a key the algorithm accepts.
   */
  const accepted = acceptedByteLengths?.(option.id);
  const lengthOk = length !== undefined && isValidByteLength(option, length, accepted);

  const problem = !decoded.ok
    ? decoded.error
    : value !== "" && !lengthOk
      ? `${length} bytes — needs ${describeByteLength(option, accepted)}.`
      : undefined;

  const counter =
    value === ""
      ? describeByteLength(option, accepted)
      : `${length} bytes · ${describeByteLength(option, accepted)}`;

  const encodingSelect = (
    <select
      aria-label={`${option.label} encoding`}
      value={encoding}
      onChange={(event) => onChange(encodingOptionId(option.id), event.target.value)}
      className="h-[30px] shrink-0 rounded-md border border-slate-300 bg-white px-1.5 text-[11px] dark:border-slate-700 dark:bg-slate-950"
    >
      {BYTES_ENCODINGS.map((id) => (
        <option key={id} value={id}>
          {BYTES_ENCODING_LABEL[id]}
        </option>
      ))}
    </select>
  );

  // The spec-aware length wins where a family supplies one; see `ToolDefinition.generateLength`.
  const generate = generateLength?.(option.id) ?? option.bytesLength?.generate;
  const generateButton = generate ? (
    <Button
      size="sm"
      variant="secondary"
      // Generating always writes hex, and switches the selector to match — the
      // alternative (emitting bytes in whatever encoding happens to be selected)
      // would produce a "random" Latin-1 string full of unprintable characters.
      onClick={() => {
        /*
         * Generated in the encoding the field is already set to.
         *
         * This used to write hex and force the selector to `hex` every time, so choosing Base64 and
         * pressing Generate moved the selector back under you -- reported, and one call site shared by
         * every `bytes` option in the app. `randomBytesValue` returns the encoding it actually used, so
         * the selector is only touched for the two that cannot hold arbitrary bytes.
         */
        const produced = randomBytesValue(generate, encoding);
        if (produced.encoding !== encoding) {
          onChange(encodingOptionId(option.id), produced.encoding);
        }
        onChange(option.id, produced.value);
      }}
      /*
       * The tooltip states what will happen *before* the button is pressed, and the two cases differ in
       * more than wording. A text encoding gets printable characters rather than encoded bytes -- the
       * value is still exactly `generate` bytes once decoded, but each character carries log2(94) bits
       * instead of 8, so the entropy is quoted rather than left to be assumed.
       */
      title={
        LOSSLESS_BYTES_ENCODINGS.includes(encoding)
          ? `Fill with ${generate} fresh random bytes from crypto.getRandomValues, as ${encoding}`
          : `Fill with ${generate} random printable characters — ${generate} bytes as ${encoding}, about ${randomValueEntropyBits(generate, encoding)} bits of entropy`
      }
    >
      Generate
    </Button>
  ) : null;

  // A secret gets the masked control; an IV or nonce is public and gets a plain one.
  if (option.secret) {
    return (
      <SecretField
        label={option.label}
        hint={`${option.summary} — ${counter}`}
        problem={problem}
        value={value}
        onValueChange={(next) => onChange(option.id, next || undefined)}
        trailing={
          <>
            {encodingSelect}
            {generateButton}
          </>
        }
      />
    );
  }

  return (
    <Field option={option} problem={problem} hint={`${option.summary} — ${counter}`}>
      <div className="flex flex-wrap sm:flex-nowrap items-center gap-2">
        <input
          type="text"
          value={value}
          placeholder={option.arg?.placeholder}
          spellCheck={false}
          onChange={(event) => onChange(option.id, event.target.value || undefined)}
          className={inputClass(false, Boolean(problem))}
        />
        {encodingSelect}
        {generateButton}
      </div>
    </Field>
  );
}

/**
 * One labelled control.
 *
 * `inline` puts the label and the control on the same row, which is what a short value wants: a
 * polynomial is six characters and stacking "Polynomial" above a box that holds `0x07` spends three
 * lines saying one thing. Reverse-engineering a CRC means reading five of these at once, so as rows
 * they line up and can be compared down the column.
 *
 * Stacked is still right for the rest. A `select` needs the full width or its options crop; a
 * `bytes` value shares its row with an encoding selector and a Generate button; a PEM key is a
 * textarea. So this is a per-kind decision at the call site rather than a global switch -- see
 * `OptionControl`, where `text` and `number` pass it and nothing else does.
 */
function Field({
  option,
  problem,
  hint,
  inline = false,
  children,
}: {
  option: OptionDef;
  problem: string | undefined;
  hint?: string;
  inline?: boolean;
  children: ReactNode;
}) {
  const note = problem ? (
    <p className="text-[11px] text-(--color-severity-error)">{problem}</p>
  ) : (
    <Hint>{hint ?? option.summary}</Hint>
  );

  if (inline) {
    return (
      <div className="space-y-1">
        <div className="flex flex-wrap sm:flex-nowrap items-center gap-2">
          {/* A fixed column so several rows line up rather than each finding its own width. */}
          <Label option={option} className="w-24 shrink-0" />
          <div className="min-w-0 flex-1">{children}</div>
        </div>
        {note}
      </div>
    );
  }

  return (
    <div className="space-y-1">
      <Label option={option} />
      {children}
      {note}
    </div>
  );
}

function Label({ option, className }: { option: OptionDef; className?: string }) {
  return (
    <span
      className={cn(
        "block cursor-help text-xs font-medium text-slate-700 underline decoration-dotted decoration-slate-300 dark:text-slate-300 dark:decoration-slate-700",
        className,
      )}
      title={option.detail}
    >
      {option.label}
    </span>
  );
}

function Hint({ children }: { children: ReactNode }) {
  return (
    <span className="block text-[11px] text-slate-500 dark:text-slate-400">{children}</span>
  );
}

/**
 * An enum choice's text, with a marker when the choice is unsafe. `<option>` can
 * hold text only, so this has to be a suffix rather than markup.
 */
/**
 * The text of one `<option>`: the choice's name, and an insecure marker where it applies.
 *
 * No summary. Appending one could not be made to work, and every attempt failed the same way: an
 * `<option>` is a single line that no CSS will wrap, a browser sizes the open list to its longest
 * entry, and it will not grow that list past the window edge — which this rail sits against. CRC-8's
 * MAXIM-DOW carries five aliases, so its line widened the popup until every name in it lost its
 * right-hand end; capping the line only moved the damage into an ellipsis two thirds of the way
 * through the text.
 *
 * A dropdown is for picking a thing by name. The description of the thing goes where there is room
 * for it: the option's `title` on hover, and the Info panel under the settings — `@ocs/crc` puts its
 * alias list there as an "Also known as" row, because for a CRC that list is how anyone finds the
 * variant they came for.
 */
function choiceLabel(choice: OptionEnumChoice): string {
  return choice.insecure ? `${choice.label}  ⚠ insecure` : choice.label;
}

/**
 * Splits a choice list into consecutive runs that share a `group`.
 *
 * Consecutive rather than gathered, so the array's order is the display order and a catalogue cannot
 * accidentally have its list reshuffled by grouping. A list with no groups comes back as one
 * ungrouped segment, which is what every family except CRC produces.
 */
function choiceSegments(
  choices: readonly OptionEnumChoice[],
): { group: string | undefined; choices: OptionEnumChoice[] }[] {
  const segments: { group: string | undefined; choices: OptionEnumChoice[] }[] = [];
  for (const choice of choices) {
    const last = segments[segments.length - 1];
    if (last && last.group === choice.group) last.choices.push(choice);
    else segments.push({ group: choice.group, choices: [choice] });
  }
  return segments;
}

/** The same text untrimmed, for the option's tooltip. */
function choiceTitle(choice: OptionEnumChoice): string {
  const base = choice.summary ? `${choice.label} — ${choice.summary}` : choice.label;
  return choice.insecure ? `${base} (insecure)` : base;
}

/**
 * The shared control styling, and note `w-full` next to `flex-1`.
 *
 * Both are needed because these controls appear in two kinds of parent. A number or a `bytes` value
 * sits in a flex row beside its unit, its encoding selector and a Generate button, where `flex-1`
 * makes it take the leftover space. A select or a plain text field is a direct child of `Field`,
 * which is a block - and there `flex-1` does nothing at all, so the control fell back to its
 * intrinsic width: a `<select>` shrinks to its widest option, which left CRC-8's Model dropdown
 * about as wide as the word "SMBUS" inside a panel four times that. `w-full` is what fills the
 * panel, and it is inert in the flex rows because `flex-1` sets `flex-basis: 0`, which wins over
 * `width` when the flex container lays its children out.
 */
function inputClass(insecure: boolean, invalid = false): string {
  return cn(
    "w-full min-w-0 flex-1 rounded-md border px-2 py-1.5 text-xs",
    "border-slate-300 bg-white text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100",
    "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-blue-600",
    insecure && "border-(--color-severity-insecure)",
    invalid && "border-(--color-severity-error)",
  );
}

function ChevronIcon({ collapsed }: { collapsed: boolean }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={cn(
        "shrink-0 text-slate-400 transition-transform",
        collapsed ? "-rotate-90" : "",
      )}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

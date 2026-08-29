"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { OptionValue, OutputEncoding } from "@ocs/contracts";
import { OutputEncoding as OutputEncodingSchema, setOption } from "@ocs/contracts";
import {
  identifyAmong,
  lint,
  type ToolDefinition,
  type ToolSample,
  type ToolSpecBase,
} from "@ocs/engine";
import { loadTool } from "@ocs/registry";
import { platform } from "@ocs/platform";
import { Button, MonoBlock, Panel, cn } from "@ocs/ui";
import { DiagnosticsPanel } from "./diagnostics-panel";
import { InputPanel } from "./input-panel";
import { isInputBlank, type InputState } from "./input-state";
import { OptionsForm, visibleOptionGroups } from "./options-form";
import { ProgressReadout } from "./progress-readout";
import { CHECK_STRING, TEST_INPUTS } from "./test-inputs";
import { FieldTable } from "./field-table";
import { ResultPanel } from "./result-panel";
import { TablePanel } from "./table-panel";
import { VariantsPanel } from "./variants-panel";
import { RightSidebar, type SidebarTab } from "./right-sidebar";
import { buildShareLink, type ParsedShare } from "./share-link";
import { ToolHeader } from "./tool-header";
import { useCompute } from "./use-compute";
import { useVariants } from "./use-variants";
import { VerifyPanel } from "./verify-panel";

export interface ToolWorkbenchProps {
  toolId: string;
  input: InputState;
  onInputChange: (next: InputState) => void;
  /**
   * True while the box still holds what the app put there rather than something typed.
   *
   * The one condition under which this component may replace the input. See `AppShell`, which owns
   * both the flag and the reason it is not inferred from the text itself.
   */
  inputIsSeeded: boolean;
  /** Replaces the input *without* marking it typed, so the next tool's sample can still take over. */
  onSeedInput: (next: InputState) => void;
  autoUpdate: boolean;
  onAutoUpdateChange: (next: boolean) => void;
  /** Settings recovered from a share link, applied once when this tool first loads. */
  restore?: ParsedShare;
  onRestoreConsumed: () => void;
}

/**
 * One workbench for every tool.
 *
 * The command generator this app is modelled on needs a bespoke builder component
 * per command, because each one's *output* has a different shape — rsync has
 * endpoint pickers and a trailing-slash visualiser, tar has a variant selector.
 * Here every tool has the same shape: bytes in, bytes out, plus a catalogue of
 * options. So this component is the entire UI layer for all of them, and adding
 * an algorithm means adding catalogue data with no React to write.
 */
export function ToolWorkbench({
  toolId,
  input,
  onInputChange,
  inputIsSeeded,
  onSeedInput,
  autoUpdate,
  onAutoUpdateChange,
  restore,
  onRestoreConsumed,
}: ToolWorkbenchProps) {
  const [tool, setTool] = useState<ToolDefinition<ToolSpecBase> | undefined>();
  const [spec, setSpec] = useState<ToolSpecBase | undefined>();
  const [outputEncoding, setOutputEncoding] = useState<OutputEncoding>("hex-upper");
  const [expected, setExpected] = useState("");
  const [loadError, setLoadError] = useState<string | undefined>();

  // Load the tool and build its starting spec. Keyed on toolId, so switching tools
  // discards the previous spec rather than trying to carry options across
  // algorithms whose catalogues have nothing in common.
  useEffect(() => {
    let cancelled = false;
    setTool(undefined);
    setSpec(undefined);
    setLoadError(undefined);

    void loadTool(toolId)
      .then((loaded) => {
        if (cancelled) return;
        setTool(loaded);
        setSpec(buildInitialSpec(loaded, restore));
        setOutputEncoding(pickOutputEncoding(loaded, restore));
        if (restore) onRestoreConsumed();
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setLoadError(error instanceof Error ? error.message : String(error));
      });

    return () => {
      cancelled = true;
    };
    // `restore` is read once at load and then consumed; re-running on its identity
    // would re-apply a share link over settings the user has since changed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toolId]);

  /**
   * Seed this tool's own sample, but only over the app's own placeholder.
   *
   * `123456789` is the right thing to open on for a CRC and nonsense for a JSON formatter, so a
   * family may declare `samples` and the first one lands in the box. Switching to a tool with none
   * puts the check string back, which is what keeps "a fresh box holds 123456789" true everywhere
   * else rather than leaving whichever document was seeded last.
   *
   * Three things this deliberately does not do. It does not touch an input that has been typed,
   * pasted, cleared, shared or picked from the menu -- `inputIsSeeded` is false by then, and a box
   * that rewrites itself when you change tool is worse than one holding the wrong document. It does
   * not compute: with `Auto update` off nothing runs until Compute is pressed, seeded or not. And it
   * leaves a generator alone entirely, since there is no box on screen to seed.
   *
   * Runs once per tool -- this component is keyed on `toolId` and remounts -- so `input` is read
   * without being a dependency.
   */
  useEffect(() => {
    if (!tool || !inputIsSeeded || !tool.readsInput) return;
    const sample = tool.samples?.[0];
    const text = sample ? sample.text : CHECK_STRING;
    if (input.mode === "text" && input.text === text) return;
    onSeedInput({ ...input, mode: "text", file: undefined, text });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tool]);

  /**
   * A generator: reads no input and takes no material either, so the whole interaction is the button.
   *
   * `uuid` and `password` today. Deliberately *not* the KDFs or TupleHash, which also read no box but
   * take their message from fields -- they have something to be expensive over and a real reason to
   * respect the auto-update switch, so they keep it.
   *
   * Derived from the tool alone rather than from `hasInputMaterial` below, for two reasons. It has to
   * be known before the hooks run, since it decides what to pass one of them; and it should not be
   * tag-dependent -- whether a tool *is* a generator is a fact about the tool, not something that
   * should flicker as a variant tag changes which fields are visible.
   */
  const generates =
    tool !== undefined &&
    !tool.readsInput &&
    !Object.values(tool.groups).some((group) => group.placement === "input");

  /**
   * Auto-update is forced on for a generator, and its switch is not shown.
   *
   * The switch exists to stop an expensive recomputation running over input you are still typing, and a
   * generator has neither half of that -- no typing, and nothing to be expensive over. Its hint reads
   * "recompute after you stop typing", which is a sentence about a box that is not on screen.
   *
   * Forcing it matters as much as hiding it. A hidden switch still deciding whether a UUID appears is
   * worse than a visible one that reads oddly: the panel would look identical in both states and the
   * only way to find the setting would be to open a different tool. So changing the version always
   * produces a new value, and the Generate button stays on screen for another one.
   */
  const effectiveAutoUpdate = autoUpdate || generates;

  const { state, recompute, canRecompute, inputProblem } = useCompute(
    tool,
    spec,
    input,
    effectiveAutoUpdate,
  );

  /**
   * Its own hook, deliberately: not driven by `autoUpdate`, not by the Result panel's `Compute`, and
   * not by typing. See the note on `useVariants`.
   */
  const variants = useVariants(tool, spec, input);

  /**
   * Which sibling variants produce the value pasted into Verify.
   *
   * Computed here rather than in either panel, because both need the same answer: the Variants table
   * marks the rows, and the Verify panel points at them when its own result was not one. Two panels
   * deriving one verdict is the mirror this repo keeps finding drifted.
   *
   * Suppressed while `stale`, and that is not tidiness. Once the input has moved on, the values belong
   * to text no longer in the box -- so a green row would claim a model produced *your* value on the
   * strength of a computation over something else. A wrong identification is worse than none: it is
   * the one output here anybody writes down.
   */
  const identity = useMemo(() => {
    const { table, values, stale } = variants.state;
    if (stale || expected.trim() === "" || values.size === 0 || !table) return undefined;
    const candidates = table.rows
      .map((row) => ({ id: row.id, bytes: values.get(row.id) }))
      .filter((entry): entry is { id: string; bytes: Uint8Array } => entry.bytes !== undefined);
    return candidates.length === 0 ? undefined : identifyAmong(candidates, expected);
  }, [variants.state, expected]);

  /**
   * Recomputed only when the spec changes, because a CRC-64 table is 256 BigInt divisions and the
   * input changing must not pay for them. `tables()` is a pure function of the spec, which is what
   * makes that safe.
   */
  const tables = useMemo(() => (tool && spec ? (tool.tables?.(spec) ?? []) : []), [tool, spec]);

  const lintResult = useMemo(
    () => (tool && spec ? lint(spec, tool.lintRules) : undefined),
    [tool, spec],
  );

  const setOptionValue = useCallback(
    (id: string, value: OptionValue | undefined) =>
      setSpec((prev) =>
        prev ? { ...prev, options: setOption(prev.options, id, value) } : prev,
      ),
    [],
  );

  if (loadError) {
    return (
      <Panel title="Could not load this tool">
        <p className="text-xs text-(--color-severity-error)">{loadError}</p>
      </Panel>
    );
  }

  if (!tool || !spec || !lintResult) return <WorkbenchSkeleton />;

  const tag = tool.variantTag?.(spec);
  /**
   * How many bytes a Generate button should produce, asked per option.
   *
   * Wired to `ToolDefinition.generateLength`, which exists because the catalogue's static
   * `bytesLength.generate` cannot know the mode: AES-CBC wants a 16-byte IV and AES-GCM wants 12, and
   * the static number was 12 for both -- so Generate filled the field with a value the tool refused,
   * in eleven measured cipher/mode combinations. Passed to every `OptionsForm` here rather than to the
   * one that happens to hold keys today, since a family can place a `bytes` option in any container.
   */
  const generateLength = (optionId: string) => tool.generateLength?.(spec, optionId);
  /**
   * Wired to `ToolDefinition.acceptedByteLengths`: what a `bytes` field will actually take for this
   * spec, which a once-per-tool catalogue cannot say. Both the hint and the validity check read it.
   */
  const acceptedByteLengths = (optionId: string) => tool.acceptedByteLengths?.(spec, optionId);

  /**
   * The catalogue splits in two, and the split decides the layout.
   *
   * Keys, IVs, nonces, salts and signatures — every group a family marked `material` — go beside
   * the message, because that is what they are: things handed to the tool for this one computation.
   * Everything else is a decision made once and goes in the rail. Both lists are checked for
   * emptiness rather than assumed: a hash has no material at all, and Poly1305 has nothing *but*
   * material, so each container has to be able to not exist.
   */
  const hasInputMaterial =
    visibleOptionGroups(tool.catalogue, tool.groups, tag, "input").length > 0;
  const hasSettings =
    visibleOptionGroups(tool.catalogue, tool.groups, tag, "settings").length > 0;
  /**
   * Groups that get a panel of their own, between Input and Result.
   *
   * One panel each, titled by the group, because that is what a group is for. CRC's custom
   * parameters are the case: seven values being tuned against a live result, which wants width and
   * wants to be near the value it produces.
   */
  const ownPanels = visibleOptionGroups(tool.catalogue, tool.groups, tag, "panel");

  /**
   * What the settings amount to: a CRC's seven parameters, a checksum's grouping and check value.
   *
   * From `tool.info(spec)` rather than from the result, which is what makes it always visible. These
   * rows follow from the spec alone, so they are on screen from the moment the tool loads, they do
   * not blink out while a recompute is pending, and they sit under the options that produced them
   * instead of under a digest they do not depend on. A family with nothing spec-derived to say omits
   * `info` and gets no section.
   */
  const info = tool.info?.(spec) ?? [];

  const tabs: SidebarTab[] = [
    /**
     * The tab exists if *any* of its three parts has something to show.
     *
     * Poly1305 has no settings at all and a tool could in principle have nothing but an Info table --
     * and since the Test input menu moved in here, a tool with neither settings nor info but which
     * reads input still needs the tab to exist, or the menu would have nowhere to live.
     */
    ...(hasSettings || info.length > 0 || tool.readsInput
      ? [
          {
            id: "settings",
            label: "Settings",
            content: (
              <>
                {/*
                  First in the rail, and it has now been in three places.

                  It started in the Input panel's controls row, next to Source, Encoding and Clear --
                  four controls did not fit on one line, so the row wrapped and the panel grew a second
                  row of chrome above a box that was still empty. It moved to a Presets tab next, which
                  is gone. It is here because this is where a control you touch once belongs, and it is
                  *above* Settings because it is the one thing in this tab you reach for before doing
                  anything else: it fills the box you are about to compute over. Settings and Info are
                  both about a computation you have already decided to make.

                  It was last, briefly, on the reasoning that loading a canned string is the least of
                  the three things here. That confused "least" with "last": Settings is unbounded --
                  a block cipher contributes a dozen controls -- so anything under it starts below the
                  fold on a short window, which is the wrong place for the thing you want first.
                */}
                {/* Absent for a generator: there is no box to load anything into. */}
                {tool.readsInput && (
                  <Panel
                    title="Test input"
                    description="Load a known string into the box."
                    collapsible
                  >
                    <TestInputPicker
                      input={input}
                      samples={tool.samples}
                      onChange={onInputChange}
                    />
                  </Panel>
                )}
                {hasSettings && (
                  /**
                   * Collapsible, like the two panels around it, and for the same reason each of them
                   * is: this is the tallest thing in the rail on most tools -- AES contributes a mode,
                   * a padding, a key size and a tag length -- so folding it is what lets the Info
                   * table below it be on screen at the same time.
                   *
                   * Open by default. The whole point of the tab is these controls.
                   */
                  <Panel title="Settings" description={`${tool.label} options`} collapsible>
                    <OptionsForm
                      catalogue={tool.catalogue}
                      groups={tool.groups}
                      options={spec.options}
                      tag={tag}
                      scope="settings"
                      generateLength={generateLength}
                      acceptedByteLengths={acceptedByteLengths}
                      onChange={setOptionValue}
                    />
                  </Panel>
                )}
                {info.length > 0 && (
                  /**
                   * Collapsible, and open. It is the longest *fixed* thing in the rail -- a CRC
                   * contributes nine rows -- so being able to fold it away is worth a chevron.
                   *
                   * Open by default, unlike the Table panel. Both are spec-derived reference
                   * material, but these are the parameters the tool is *running with*, and someone
                   * comparing a CRC against another implementation is reading the polynomial and
                   * the init value while they work. A 256-cell grid is something you go and look
                   * for; nine labelled values are something you glance at.
                   */
                  <Panel title="Info" description="What these settings are." collapsible>
                    <FieldTable fields={info} />
                  </Panel>
                )}
              </>
            ),
          },
        ]
      : []),
    {
      id: "checks",
      label: "Checks",
      ...(lintResult.diagnostics.length > 0
        ? {
            badge: {
              text: String(lintResult.diagnostics.length),
              tone: lintResult.hasErrors
                ? ("error" as const)
                : lintResult.isInsecure
                  ? ("insecure" as const)
                  : lintResult.counts.warning > 0
                    ? ("warning" as const)
                    : ("neutral" as const),
            },
          }
        : {}),
      content: (
        <>
          <DiagnosticsPanel spec={spec} result={lintResult} onApplyFix={setSpec} />
          <ShareLinkPanel
            tool={tool}
            spec={spec}
            input={input}
            outputEncoding={outputEncoding}
          />
        </>
      ),
    },
  ];

  return (
    /*
      Two columns in one row, and *neither* scrolls: `<main>` above owns the only scrollbar in the
      content area. `min-w-0` stays because it is what lets this row shrink to the frame -- a flex
      item defaults to `min-width: auto` and refuses to go below its content width, which once left
      the row 102px wider than `<main>` with the difference cropped off the right-hand rail.
    */
    <div className="flex flex-col lg:flex-row min-w-0 gap-6">
      <div className="min-w-0 flex-1 space-y-4 w-full">
        <ToolHeader manifest={tool} description={tool.describe(spec)} />

        <InputPanel
          input={input}
          onChange={onInputChange}
          readsInput={tool.readsInput}
          // Passed rather than inferred from `!readsInput && !material`, so there is one answer to
          // "is this a generator" and it is the one the compute hook was given.
          generates={generates}
          supportsFile={tool.supportsFile}
          buffersWholeFile={tool.supportsFile && !tool.streaming}
          byteLength={state.inputByteLength}
          /**
           * The decode failure first, because it is true earlier.
           *
           * `inputProblem` comes off the decode, which happens whether or not anything computes, so
           * bad hex is reported the moment it is typed rather than when Compute is next pressed.
           * `state.error` stays as the fallback: it also carries a throw from inside the tool, which
           * the decode knows nothing about.
           */
          problem={inputProblem ?? (state.status === "error" ? state.error : undefined)}
          autoUpdate={effectiveAutoUpdate}
          onAutoUpdateChange={onAutoUpdateChange}
          /**
           * Only when auto-update is off, because with it on there is nothing to ask for.
           *
           * The sentence that used to sit beside this button is its tooltip now. It explained the
           * button's own existence -- "nothing recomputes until you ask" -- to someone who had just
           * turned the switch off and could see the button appear, which is a lot of words for a
           * fact already on screen.
           */
          /**
           * How much of the input has been consumed, and the button that consumes it.
           *
           * The readout is here rather than under the result because what it measures is *input* --
           * bytes read of bytes available. Beneath a digest it sat next to "1 byte · 2 characters as
           * shown" and the two were different quantities in the same grey, which is a thing a reader
           * has to stop and work out. It also puts the bar directly above the button that fills it.
           *
           * `ProgressReadout` is unconditional and `Compute` is not, which is why they are wrapped
           * rather than passed as one node: turning auto-update on removes the button and must not
           * take the bar with it.
           */
          footer={
            <div className="space-y-2">
              {/* Bytes read of bytes available, which a generator has neither of. */}
              {!generates && <ProgressReadout state={state} />}
              {(!effectiveAutoUpdate || generates) && (
                <Button
                  data-ocs-compute=""
                  variant="primary"
                  // `sm` and full width: it is the panel's one action, so it reads as a bar across
                  // the bottom of the input rather than a button placed somewhere in it. The height
                  // comes down because a 40px slab under a textarea is the heaviest thing on the
                  // page, and the only control competing with it is a switch in the header.
                  size="sm"
                  className="w-full"
                  disabled={!canRecompute}
                  onClick={recompute}
                  title={
                    generates
                      ? "Produce another value. Nothing here depends on an input, so this is the whole interaction."
                      : "Auto update is off — nothing recomputes until you ask."
                  }
                >
                  {/* "Compute" over a box you filled in; "Generate" where the button is the whole
                      interaction. The KDFs keep "Compute": they read no box either, but their
                      password comes from a field, so there is still an input being processed. */}
                  {generates ? "Generate" : "Compute"}
                </Button>
              )}
            </div>
          }
          material={
            hasInputMaterial ? (
              <OptionsForm
                catalogue={tool.catalogue}
                groups={tool.groups}
                options={spec.options}
                tag={tag}
                scope="input"
                generateLength={generateLength}
                acceptedByteLengths={acceptedByteLengths}
                onChange={setOptionValue}
              />
            ) : undefined
          }
        />

        {ownPanels.map(({ group }) => (
          <Panel key={group.id} title={group.label} description={group.summary}>
            {/* Headings off: the panel title is the group's label already. */}
            <OptionsForm
              catalogue={tool.catalogue}
              groups={tool.groups}
              options={spec.options}
              tag={tag}
              groupIds={[group.id]}
              headings={false}
              generateLength={generateLength}
              acceptedByteLengths={acceptedByteLengths}
              onChange={setOptionValue}
            />
          </Panel>
        ))}

        <ResultPanel
          state={state}
          outputEncodings={tool.outputEncodings}
          outputEncoding={outputEncoding}
          onOutputEncodingChange={setOutputEncoding}
          isInsecure={lintResult.isInsecure}
          onRecompute={recompute}
          canRecompute={canRecompute}
        />

        {/*
          Absent where there is nothing anybody could already have: see `supportsVerify`.

          It read `result.bytes`, so on the format family it rendered a box that could never say
          anything either way -- a control that renders and does nothing, which is this repo's
          most-repeated defect. Gated on the manifest rather than on the result, because inferring it
          from the bytes would make the panel appear and disappear as the direction changes.
        */}
        {tool.supportsVerify && (
          <VerifyPanel
            result={state.result}
            expected={expected}
            onExpectedChange={setExpected}
            /**
             * Only the rows that are *not* this tool's own selection. "NO MATCH" is correct when the
             * value came from a sibling, and pointing at the sibling is the useful half -- but pointing
             * at the row you already have selected would be nonsense, since that row *is* the result
             * this panel just compared against.
             */
            matchedElsewhere={
              identity?.ids
                .filter((id) => !variants.state.table?.rows.find((r) => r.id === id)?.selected)
                .map(
                  (id) => variants.state.table?.rows.find((r) => r.id === id)?.label ?? id,
                ) ?? []
            }
          />
        )}

        {/*
          Last in the column, and only for a tool that has one.
          Reference material rather than an answer, so it sits below the two panels that are: the
          result, and the check against what you expected. `tables` is a pure function of the spec,
          so this survives an empty input and does not flicker while a file streams.
        */}
        {tables.length > 0 && <TablePanel tables={tables} />}

        {/*
          Last, below the Table panel. The column reads answer, check, reference, survey -- Result,
          Verify, Table, this -- which is decreasing specificity to what was actually asked.

          The rows are spec-derived, so the table is populated from the moment the tool loads; only
          the Result column waits for its own Run button. Nothing about it is tied to the digest
          above -- see `useVariants` for why twenty engines over a file is a decision rather than a
          side effect.
        */}
        {tool.variants && (
          <VariantsPanel
            state={variants.state}
            // The list, not the current choice: this panel picks its own, defaulting to upper hex.
            outputEncodings={tool.outputEncodings}
            identity={identity}
            onRun={variants.run}
            onStop={variants.stop}
            canRun={variants.canRun}
          />
        )}
      </div>

      <RightSidebar tabs={tabs} />
    </div>
  );
}

/**
 * Builds the tool's own default spec, then layers a share link's settings on top —
 * never the other way round.
 *
 * A link is the one input to this app written by someone else, so its fields are
 * merged into a spec the tool itself produced and then validated by the tool's own
 * schema. If anything fails to parse, the default spec is used unchanged: a bad
 * link opens the tool, rather than breaking the page or silently computing with
 * half-applied settings.
 */
function buildInitialSpec(
  tool: ToolDefinition<ToolSpecBase>,
  restore: ParsedShare | undefined,
): ToolSpecBase {
  const base = tool.createSpec();
  if (!restore || restore.toolId !== tool.id) return base;

  const candidate = {
    ...base,
    ...restore.specFields,
    // specVersion is ours, not the link's — a link claiming a version we do not
    // implement must not be able to assert it.
    specVersion: base.specVersion,
    options: { ...base.options, ...restore.options },
  };

  const parsed = tool.specSchema.safeParse(candidate);
  return parsed.success ? parsed.data : base;
}

function pickOutputEncoding(
  tool: ToolDefinition<ToolSpecBase>,
  restore: ParsedShare | undefined,
): OutputEncoding {
  const fallback = tool.outputEncodings[0] ?? "hex-upper";
  if (!restore?.outputEncoding) return fallback;
  const parsed = OutputEncodingSchema.safeParse(restore.outputEncoding);
  // Offered by this tool, not merely a valid encoding somewhere — a CRC's
  // `decimal` must not survive into a digest.
  return parsed.success && tool.outputEncodings.includes(parsed.data) ? parsed.data : fallback;
}

/**
 * Loads one of the canned inputs from `./test-inputs`.
 *
 * A menu rather than a setting, which is why its value is always the empty string: picking an entry
 * fills the box and the control goes straight back to its label. There is no such thing as
 * "currently on Lorem ipsum" -- the claim stops being true the moment anyone types a character -- so
 * holding a value would be a lie with a timer on it. The placeholder is `disabled` for the same
 * reason the options form's is: displayable without being a way back into it.
 *
 * It forces the source to Text. Both entries are prose or decimal digits, so leaving the source on
 * Hex would put something in the box that cannot be decoded -- and note that even "123456789" needs
 * this, being nine hex digits, which is an odd number and therefore not hex at all.
 */
function TestInputPicker({
  input,
  samples,
  onChange,
}: {
  input: InputState;
  /** The open tool's own, from `ToolDefinition.samples`. Undefined for most tools. */
  samples: readonly ToolSample[] | undefined;
  onChange: (next: InputState) => void;
}) {
  /**
   * The tool's own samples, or the generic pair -- never both.
   *
   * `123456789` is *the* check string for a CRC or a digest, and `Lorem ipsum` is a multi-kilobyte
   * input that crosses a hash's block boundary sixty times. Neither is anything to a JSON formatter,
   * so offering them there under a heading was just labelling the noise: a tool that declares its own
   * samples has said what its inputs look like, and the two generic entries are then only wrong
   * answers with a group label on top.
   *
   * Which means no `optgroup` either. One list, so the ids need no prefix and stay exactly what the
   * family or `TEST_INPUTS` called them -- which is what the desktop smoke probe drives this menu by.
   */
  const entries = samples && samples.length > 0 ? samples : TEST_INPUTS;

  return (
    <select
      data-ocs-test-input=""
      aria-label="Test input"
      value=""
      onChange={(event) => {
        const chosen = entries.find((entry) => entry.id === event.target.value);
        if (chosen) onChange({ ...input, mode: "text", file: undefined, text: chosen.text });
      }}
      className="w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs dark:border-slate-700 dark:bg-slate-950"
    >
      <option value="" disabled>
        Choose a test input…
      </option>
      {entries.map((entry) => (
        <option key={entry.id} value={entry.id} title={entry.note}>
          {entry.label}
        </option>
      ))}
    </select>
  );
}

function ShareLinkPanel({
  tool,
  spec,
  input,
  outputEncoding,
}: {
  tool: ToolDefinition<ToolSpecBase>;
  spec: ToolSpecBase;
  input: InputState;
  outputEncoding: OutputEncoding;
}) {
  const [built, setBuilt] = useState<ReturnType<typeof buildShareLink> | undefined>();

  const build = () => {
    const result = buildShareLink(
      window.location.href,
      tool.id,
      tool.catalogue,
      spec,
      input,
      outputEncoding,
    );
    setBuilt(result);
    void platform().copyToClipboard(result.url);
  };

  return (
    <Panel title="Share" description="A link that reproduces these settings.">
      <div className="space-y-2">
        <Button size="sm" className="w-full" onClick={build}>
          Copy share link
        </Button>

        {built && (
          <>
            {/* A tighter cap than MonoBlock's own, which is why it stays: a share link is one long
                token and 24 lines of it would be the whole panel. `cn` is tailwind-merge, so this
                wins over the default. The `overflow-y-auto` that used to be here is now the
                default's. */}
            <MonoBlock value={built.url} className="max-h-24 text-[10px]" />
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Copied to the clipboard.
            </p>

            {/*
              Saying what was left out is the whole point. A link that silently
              omitted the key would look like it reproduces the result and would
              not — and the person receiving it would have no way to know which.
            */}
            {built.omittedSecrets.length > 0 && (
              <p className="rounded-r border-l-4 border-l-(--color-severity-info) bg-blue-50/60 px-2.5 py-1.5 text-[11px] dark:bg-blue-950/20">
                Left out of the link: <strong>{built.omittedSecrets.join(", ")}</strong>.
                Secrets do not go in URLs — they end up in history, logs and chat clients.
                Whoever opens this will need to enter it themselves.
              </p>
            )}
            {built.omittedInput && (
              <p className="rounded-r border-l-4 border-l-(--color-severity-info) bg-blue-50/60 px-2.5 py-1.5 text-[11px] dark:bg-blue-950/20">
                {input.mode === "file"
                  ? "A file cannot travel in a link — only the settings did."
                  : "The input was too long for a link, so only the settings travelled. Truncating it would have produced a different, valid-looking result."}
              </p>
            )}
            {!built.omittedInput && !isInputBlank(input) && (
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                The input is included in this link. Anywhere the link goes, it goes.
              </p>
            )}
          </>
        )}
      </div>
    </Panel>
  );
}

/**
 * An empty frame in the shape of the workbench.
 *
 * Every element is an outline, deliberately. The header placeholder used to be a filled
 * `bg-slate-200` block, which made it the one loud thing among four quiet ones -- a grey slab in the
 * top-left corner with nothing else to balance it. Holding the layout is the whole job here, and an
 * outline does that without asking to be looked at.
 *
 * No pulse either: it animated attention onto a placeholder whose only message is "not yet".
 *
 * And shown immediately, with no delay before it appears. A delay was tried, on the reasoning that a
 * placeholder flashing inside a fast load is pure flicker -- which is true, and the wrong trade: a
 * cold start compiles the tool's lazy chunk and can take seconds, and rendering `null` until a timer
 * fires turns that into a blank page where the workbench should be. Once the frame is quiet enough
 * not to draw the eye, showing it early costs nothing; showing nothing costs the only feedback there
 * is that the page is working.
 */
function WorkbenchSkeleton() {
  const box =
    "rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900";
  return (
    <div className="flex gap-6">
      <div className="min-w-0 flex-1 space-y-4">
        <div className={cn("h-9", box)} />
        {[0, 1, 2].map((row) => (
          <div key={row} className={cn("h-32", box)} />
        ))}
      </div>
      <div className={cn("h-64 w-72 shrink-0", box)} />
    </div>
  );
}

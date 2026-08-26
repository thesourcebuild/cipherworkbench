"use client";

import { useMemo } from "react";
import { verifyAgainst, verifyText, type ToolResult, type VerifyOutcome } from "@ocs/engine";
import { Button, ClearButton, MonoBlock, Panel, cn } from "@ocs/ui";
import { platform } from "@ocs/platform";

export interface VerifyPanelProps {
  result: ToolResult | undefined;
  expected: string;
  onExpectedChange: (next: string) => void;
  /**
   * Names of the sibling variants that *did* produce the pasted value, when this tool's own result
   * did not. Empty or absent when there is nothing to point at.
   *
   * Passed in rather than computed here, because the Variants panel is the thing that has the values:
   * this panel compares one result against one string and has no idea the others exist.
   */
  matchedElsewhere?: readonly string[];
}

/**
 * Paste what you expected; find out whether it matches.
 *
 * This is the half of the app the reference online tool has no equivalent for,
 * and it is the half that most of the actual work looks like. Nobody computes a
 * SHA-256 for its own sake — they compute it because a release page published one
 * and they want to know whether the file they downloaded is that file. Doing that
 * by eye across 64 hex characters is exactly the task humans are worst at, and
 * the failure mode is silent: you skim the first six characters, they match, you
 * install it.
 *
 * The encoding is detected rather than asked for, and the value is compared with
 * `timingSafeEqual`. Neither matters for a page like this in any threat model
 * worth naming; both are here because this is the code someone will copy when
 * they need to do the same thing somewhere it does matter.
 */
export function VerifyPanel({
  result,
  expected,
  onExpectedChange,
  matchedElsewhere,
}: VerifyPanelProps) {
  const bytes = result?.bytes;
  const text = result?.text;

  /**
   * Bytes if there are bytes, text if the result is natively text.
   *
   * The encoding family's forward direction returns a Base64 *string*, so before this the panel had
   * nothing to compare and sat inert on half that family -- the same defect `supportsVerify` removed
   * from the format family, which is why it was worth fixing rather than gating away. Bytes first
   * because a tool returning both means the bytes are the result and the text is a rendering of them.
   */
  const outcome: VerifyOutcome | undefined = useMemo(
    () =>
      bytes
        ? verifyAgainst(bytes, expected)
        : text === undefined
          ? undefined
          : verifyText(text, expected),
    [bytes, text, expected],
  );

  /** At most two names, then a count: the pointer is a signpost, not a second table. */
  const elsewhere =
    matchedElsewhere === undefined || matchedElsewhere.length === 0
      ? undefined
      : matchedElsewhere.length <= 2
        ? matchedElsewhere.join(" and ")
        : `${matchedElsewhere.slice(0, 2).join(", ")} and ${matchedElsewhere.length - 2} more`;

  const tone =
    outcome?.status === "match"
      ? "match"
      : outcome?.status === "mismatch"
        ? "mismatch"
        : "default";

  return (
    <Panel
      // Collapsed by default, so the smoke probe has to expand it before the field exists at all.
      data-ocs-verify=""
      title="Verify"
      description="Check the result against a value you already have."
      collapsible
      defaultOpen={false}
      actions={
        /*
          The same pill the Input panel uses, from `@ocs/ui`. It was a `variant="ghost"` "Clear" that
          was plain text until hovered, and it was rendered only while the field was non-empty -- so
          the panel header changed height the moment you started typing. Both objections were settled
          on the Input panel first; sharing the component is what stops them coming back one call site
          at a time.
        */
        <ClearButton
          disabled={expected === ""}
          onClick={() => onExpectedChange("")}
          aria-label="Clear the expected value"
          title="Empty the box below."
        />
      }
    >
      <div className="space-y-2">
        <textarea
          // Driven by the packaged smoke test, which pastes a colliding CRC-8 value and requires both
          // matching rows in the Variants table to be marked.
          data-ocs-verify-expected=""
          value={expected}
          onChange={(event) => onExpectedChange(event.target.value)}
          onPaste={(event) => {
            // Paste replaces rather than appends. The realistic action is
            // "paste the checksum I just copied", and a field that concatenates
            // onto a previous attempt produces a confusing mismatch.
            event.preventDefault();
            onExpectedChange(event.clipboardData.getData("text"));
          }}
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          rows={2}
          /*
            "value" rather than "digest": this panel serves nine families, and what goes in it is as
            often a MAC, a derived key, a CRC or a ciphertext as a hash. The `.sha256` line stays named,
            because stripping the filename off one is a real feature people would not guess at.
          */
          placeholder="Paste an expected value — hex, Base64, Base64url or Base32. A whole .sha256 line works too."
          className={cn(
            "w-full resize-y rounded-md border px-3 py-2 font-mono text-xs",
            "border-slate-300 bg-white text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100",
            "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-blue-600",
          )}
        />

        {!bytes ? (
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            Compute a result first, then paste what it should be.
          </p>
        ) : (
          outcome && (
            <>
              <MonoBlock
                tone={tone}
                value={verdictText(outcome)}
                className="text-center font-semibold"
              />
              <p
                className={cn(
                  "text-[11px]",
                  outcome.status === "match"
                    ? "text-(--color-verify-match)"
                    : outcome.status === "empty"
                      ? "text-slate-500 dark:text-slate-400"
                      : "text-(--color-verify-mismatch)",
                )}
              >
                {outcome.message}
              </p>
              {outcome.status === "mismatch" && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => void copyBoth(result, expected)}
                  title="Copy both values, so you can paste them into a bug report or a diff"
                >
                  Copy both values
                </Button>
              )}
              {/*
                The failure mode this exists to prevent: "NO MATCH" in bold while the answer is two
                panels below, marked green, because the value came from a sibling variant rather than
                the one in the dropdown. The Variants panel knows which -- this only has to say that
                it might, and only when there is something to look at.
              */}
              {outcome.status !== "match" && outcome.status !== "empty" && elsewhere && (
                <p className="rounded-r border-l-4 border-l-(--color-severity-info) bg-blue-50/60 px-3 py-2 text-[11px] dark:bg-blue-950/20">
                  It is not this one — but <strong>All variants</strong> found it. See{" "}
                  <span className="font-semibold">{elsewhere}</span> below.
                </p>
              )}
            </>
          )
        )}
      </div>
    </Panel>
  );
}

function verdictText(outcome: VerifyOutcome): string {
  switch (outcome.status) {
    case "match":
      return "MATCH";
    case "mismatch":
      return "NO MATCH";
    case "wrong-length":
      return "WRONG LENGTH";
    case "unparseable":
      return "UNREADABLE";
    case "empty":
      return "—";
  }
}

async function copyBoth(result: ToolResult | undefined, expected: string): Promise<void> {
  const { encodeHex } = await import("@ocs/engine");
  const actual = result?.bytes ? encodeHex(result.bytes) : "";
  await platform().copyToClipboard(`computed: ${actual}\nexpected: ${expected.trim()}\n`);
}

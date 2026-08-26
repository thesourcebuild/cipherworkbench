import type { ToolSample } from "@ocs/engine";

/**
 * Three, and the first is what a fresh box is seeded with.
 *
 * `HELLO` because it is the example in every description of this cipher, including the one that
 * prompted the tool: at the default shift of 3 it gives `KHOOR`, so the tool demonstrates itself the
 * moment it opens. `KHOOR` is the other direction of the same example, which is what makes switching
 * Direction meaningful without typing anything.
 *
 * The third is a real cryptogram at shift 7, long enough that the brute-force table earns its place --
 * with one line of English among 26, which is the thing the table exists to make obvious. It also
 * carries punctuation and a digit, which is how the "passes through unchanged" rule becomes visible
 * rather than merely stated.
 */
const SAMPLES: readonly ToolSample[] = [
  {
    id: "hello",
    label: "HELLO",
    note: "The classical example. At the default shift of 3 this encrypts to KHOOR.",
    text: "HELLO",
  },
  {
    id: "khoor",
    label: "KHOOR",
    note: "The same example the other way: switch Direction to Decrypt and this gives HELLO back.",
    text: "KHOOR",
  },
  {
    id: "cryptogram",
    label: "A cryptogram to break",
    note: "Encrypted at some shift between 1 and 25. Read the table under the result and pick the line that is English -- that is the whole attack.",
    // "The quick brown fox jumps over 1 lazy dog!" at shift 7, so the plaintext is row 19.
    text: "Aol xbpjr iyvdu mve qbtwz vcly 1 shgf kvn!",
  },
];

export function samplesFor(toolId: string): readonly ToolSample[] | undefined {
  return toolId === "caesar" ? SAMPLES : undefined;
}

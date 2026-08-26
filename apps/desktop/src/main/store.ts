import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { app } from "electron";
import { z } from "zod";

/**
 * UI state — one boolean, whether auto-update is on — lives in a single JSON file in the app's
 * userData directory. Writes go to a temporary file and are then renamed, so a crash
 * mid-write cannot leave a truncated store behind.
 *
 * Note what this schema does *not* have a place for: any input at all, a key, a password, or a file
 * path. It once held the typed input, behind a "Remember input" switch that no longer exists; the
 * fields went with it rather than being left for something to start filling again. `.strict()` means
 * a future change that tried to would fail here rather than quietly writing a secret to disk.
 */
/**
 * The fields, in one place, with two postures over them.
 *
 * `KnownState` strips what it does not recognise and `SavedState` refuses it, and the difference is
 * which direction the file is moving.
 *
 * Reading has to tolerate a key that used to exist. `toolId` lived here until every session started
 * opening on the default tool; with `.strict()` on the read path, a store written by the previous
 * build fails to parse, `readSavedState` reports "no saved state", and the *other* setting in the
 * file silently reverts to its default on first launch after an update. Removing a field should not
 * cost the user the ones they kept.
 *
 * Writing stays strict, and loudly so: `.strict()` is what makes a future change that tried to
 * persist something new fail here rather than quietly putting it on disk. Stripping would achieve
 * the same on-disk result and tell nobody.
 *
 * One field list, so the two cannot drift.
 */
const KnownState = z.object({
  autoUpdate: z.boolean().optional(),
});

export const SavedState = KnownState.strict();

export type SavedState = z.infer<typeof SavedState>;

function storePath(): string {
  return path.join(app.getPath("userData"), "state.json");
}

export async function readSavedState(): Promise<string | null> {
  try {
    const raw = await readFile(storePath(), "utf8");
    /**
     * Validated here so a hand-edited or corrupt file surfaces as "no saved state" rather than
     * reaching the renderer as something it has to defend against -- and re-serialised from the
     * parsed value rather than echoed, so what the renderer receives contains the known fields and
     * nothing else. That is the guarantee `.strict()` used to provide on this path, kept while
     * letting a store written by an older build through. See `KnownState`.
     */
    const parsed = KnownState.safeParse(JSON.parse(raw));
    return parsed.success ? JSON.stringify(parsed.data) : null;
  } catch {
    return null;
  }
}

/**
 * Serialises writes, and gives each one its own temp file.
 *
 * Both halves fix the same bug, found by the smoke test once it started switching tools and
 * encodings quickly enough to overlap two saves. The temp path used to be
 * `state.json.<pid>.tmp` — the same name for every call in the process — so two concurrent
 * writes shared one file, the first `rename` consumed it, and the second failed with `ENOENT`.
 *
 * The counter alone would stop the crash. The queue is here because it also fixes the quieter
 * half: two renames completing out of order leave the *older* state on disk, which is how a
 * setting appears to un-set itself on the next launch. Saves are tiny and infrequent, so a
 * strict chain costs nothing worth measuring.
 */
let writeSequence = 0;
let writeQueue: Promise<void> = Promise.resolve();

export function writeSavedState(json: string): Promise<void> {
  const run = writeQueue.then(() => writeSavedStateNow(json));
  // The queue must survive a failed write, or one bad payload would wedge every later save.
  writeQueue = run.catch(() => undefined);
  return run;
}

async function writeSavedStateNow(json: string): Promise<void> {
  const parsed = SavedState.safeParse(JSON.parse(json));
  if (!parsed.success) {
    throw new Error(`Refusing to write malformed saved state: ${parsed.error.message}`);
  }

  const target = storePath();
  const temp = `${target}.${process.pid}.${++writeSequence}.tmp`;
  await mkdir(path.dirname(target), { recursive: true });
  // Re-serialised from the parsed value, not echoed from the input — `.strict()` has already
  // rejected unknown keys, and writing `parsed.data` means nothing beyond the schema can reach the
  // file even if that changes.
  await writeFile(temp, JSON.stringify(parsed.data, null, 2), "utf8");
  await rename(temp, target);
}

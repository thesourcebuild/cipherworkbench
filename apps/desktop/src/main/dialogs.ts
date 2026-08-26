import { readFile } from "node:fs/promises";
import path from "node:path";
import { dialog } from "electron";
import type { BrowserWindow, OpenDialogOptions } from "electron";

/**
 * Electron has separate overloads for modal and non-modal dialogs, so the parent
 * window is dispatched on rather than cast away.
 */
const open = (parent: BrowserWindow | null, options: OpenDialogOptions) =>
  parent ? dialog.showOpenDialog(parent, options) : dialog.showOpenDialog(options);

const MAX_IMPORT_BYTES = 2 * 1024 * 1024;

/**
 * Reads a small text file the user picks — used for pasting a checksum file's
 * contents into the verify field.
 *
 * Note this is *not* how input files are read. Those go through the renderer's own
 * `File` API so they can be streamed in chunks; routing a multi-gigabyte read
 * through IPC would be strictly worse. See `PlatformApi`'s doc comment.
 */
export async function openTextFile(
  parent: BrowserWindow | null,
  options: { extensions?: string[] } = {},
): Promise<{ name: string; contents: string } | null> {
  const result = await open(parent, {
    title: "Open",
    properties: ["openFile", "dontAddToRecent"],
    filters: options.extensions?.length
      ? [{ name: "Supported", extensions: options.extensions }]
      : undefined,
  });
  const chosen = result.canceled ? undefined : result.filePaths[0];
  if (!chosen) return null;

  const contents = await readFile(chosen, "utf8");
  if (contents.length > MAX_IMPORT_BYTES) {
    throw new Error("That file is too large to read as text. Use File input mode instead.");
  }
  return { name: path.basename(chosen), contents };
}

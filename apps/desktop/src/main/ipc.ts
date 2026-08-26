import { BrowserWindow, app, ipcMain, shell } from "electron";
import { z } from "zod";
import { openTextFile } from "./dialogs";
import { readSavedState, writeSavedState } from "./store";

/**
 * Every channel is validated. The renderer is the least trusted part of an Electron
 * app, so arguments arriving over IPC get the same treatment as arguments arriving
 * over a network boundary — even though nothing here spawns a process, `openTextFile`
 * and `openExternal` are both real capabilities.
 *
 * The whole surface is five channels wide, and it shrank rather than grew: `dialog:saveTextFile` and
 * `dialog:saveBinaryFile` are gone, along with `PlatformApi.saveTextFile`, `saveBinaryFile`,
 * `SaveResult` and `canChooseSaveLocation`. They lost their last caller when the Result panel's Save
 * button was removed, and a *file-write capability* is not a thing to leave exposed to the renderer
 * on the grounds that it might be wanted again. If saving comes back, so can they.
 *
 * That is not minimalism for its own sake: input files are read by the renderer's own `File` API and
 * every algorithm runs in the renderer, so the main process is only needed for the handful of things
 * a sandboxed page genuinely cannot do.
 */

const Extension = z.string().regex(/^[A-Za-z0-9]{1,12}$/);
const OpenTextFileArgs = z
  .object({ extensions: z.array(Extension).max(20).optional() })
  .default({});

/** Only https, and only hosts this app has a reason to link to. */
const EXTERNAL_ALLOWLIST = [
  /^https:\/\/(www\.)?github\.com\//,
  /^https:\/\/datatracker\.ietf\.org\//,
  /^https:\/\/csrc\.nist\.gov\//,
];

const SavedStateJson = z.string().max(1024 * 1024);

function senderWindow(event: Electron.IpcMainInvokeEvent): BrowserWindow | null {
  return BrowserWindow.fromWebContents(event.sender);
}

export function registerIpc(): void {
  ipcMain.handle("app:getVersion", () => app.getVersion());

  ipcMain.handle("dialog:openTextFile", async (event, raw) =>
    openTextFile(senderWindow(event), OpenTextFileArgs.parse(raw ?? {})),
  );

  ipcMain.handle("shell:openExternal", async (_event, raw) => {
    const url = z.string().url().max(2048).parse(raw);
    if (!EXTERNAL_ALLOWLIST.some((re) => re.test(url))) {
      throw new Error(`Refusing to open a URL outside the allowlist: ${url}`);
    }
    await shell.openExternal(url);
  });

  ipcMain.handle("store:readSavedState", () => readSavedState());

  ipcMain.handle("store:writeSavedState", async (_event, raw) => {
    await writeSavedState(SavedStateJson.parse(raw));
  });
}

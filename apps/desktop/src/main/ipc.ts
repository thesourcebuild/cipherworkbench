import { BrowserWindow, app, ipcMain, shell } from "electron";
import { z } from "zod";
import { openTextFile } from "./dialogs";
import { readSavedState, writeSavedState } from "./store";
import { probeTlsEndpoint, queryOcspResponder, queryCtLogs } from "./network";

/**
 * Every channel is validated. The renderer is the least trusted part of an Electron
 * app, so arguments arriving over IPC get the same treatment as arguments arriving
 * over a network boundary — even though nothing here spawns a process, `openTextFile`
 * and `openExternal` are both real capabilities.
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

const HostnameRegex = /^[a-zA-Z0-9.\-_]+$/;
const ProbeTlsArgs = z.object({
  host: z.string().min(1).max(255).regex(HostnameRegex),
  port: z.number().int().min(1).max(65535).optional().default(443),
  servername: z.string().min(1).max(255).regex(HostnameRegex).optional(),
  timeoutMs: z.number().int().min(1000).max(60000).optional().default(20000),
});

const QueryOcspArgs = z.object({
  responderUrl: z.string().url().max(2048),
  requestBase64: z.string().min(1).max(1024 * 1024),
});

const QueryCtLogsArgs = z.string().min(1).max(255).regex(HostnameRegex);

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

  ipcMain.handle("network:probeTls", async (_event, raw) => {
    const args = ProbeTlsArgs.parse(raw);
    return probeTlsEndpoint(args);
  });

  ipcMain.handle("network:queryOcsp", async (_event, raw) => {
    const args = QueryOcspArgs.parse(raw);
    return queryOcspResponder(args.responderUrl, args.requestBase64);
  });

  ipcMain.handle("network:queryCtLogs", async (_event, raw) => {
    const domain = QueryCtLogsArgs.parse(raw);
    return queryCtLogs(domain);
  });
}


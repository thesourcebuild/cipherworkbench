export type HostPlatform = "darwin" | "win32" | "linux" | "browser";

/**
 * A friendlier, flattened "web vs desktop, and on desktop, which OS" view —
 * derived from `PlatformEnvironment`, not a second source of truth. Use this
 * wherever UI code branches on host platform for something user-facing;
 * `HostPlatform` stays as the raw Node-style value ("win32"/"darwin") the
 * Electron bridge/preload boundary legitimately deals in.
 */
export type AppPlatform = "web" | "windows" | "macos" | "linux";

export function toAppPlatform(
  env: Pick<PlatformEnvironment, "isDesktop" | "platform">,
): AppPlatform {
  if (!env.isDesktop) return "web";
  switch (env.platform) {
    case "win32":
      return "windows";
    case "darwin":
      return "macos";
    case "linux":
      return "linux";
    case "browser":
      // Never actually occurs alongside isDesktop: true — kept only so this
      // switch stays exhaustive over the full HostPlatform union.
      return "web";
  }
}

export interface PlatformEnvironment {
  /** True in the Electron shell, false in a browser tab. */
  isDesktop: boolean;
  platform: HostPlatform;
  appVersion: string;
}

export interface OpenedTextFile {
  name: string;
  contents: string;
}

/**
 * The complete set of host capabilities this app needs.
 *
 * Note what is absent, and why the list is this short: reading the *input* file
 * is not here. An Electron renderer is a Chromium renderer, so `<input
 * type="file">`, drag-and-drop and `File.stream()` all work there exactly as
 * they do in a browser tab — routing multi-gigabyte file reads through IPC to
 * the main process would be strictly worse for no gain. The host is only needed
 * for the things a sandboxed page genuinely cannot do: read a small text file the
 * user picked, reach the clipboard and the system browser, and persist state
 * outside `localStorage`.
 *
 * `saveTextFile`, `saveBinaryFile`, `SaveResult` and `canChooseSaveLocation` were
 * here until the Result panel's Save button went. Nothing called them afterwards,
 * and an arbitrary file *write* is not a capability to leave wired up on the
 * chance it is wanted again — the IPC handlers, the preload forwarders and both
 * adapters went with them.
 *
 * There is no `run`/`exec`/`spawn` surface of any kind. This app computes
 * in-process; the eslint config enforces that `child_process` is unreachable
 * from every file in the repo, including the Electron main process.
 */
export interface PlatformApi {
  environment(): Promise<PlatformEnvironment>;

  openTextFile(options?: { extensions?: string[] }): Promise<OpenedTextFile | undefined>;

  copyToClipboard(text: string): Promise<void>;
  openExternal(url: string): Promise<void>;

  /** Raw JSON string so the caller's schema stays the single validator. */
  readSavedState(): Promise<string | undefined>;
  writeSavedState(json: string): Promise<void>;
}

import type { HostPlatform, OpenedTextFile } from "@ocs/contracts";

/** Native menu items the desktop shell can dispatch into the renderer. */
export type MenuAction =
  | "menu:newComputation"
  | "menu:copyResult"
  | "menu:openInput"
  | "menu:saveResult"
  | "menu:about";

/**
 * The exact surface `apps/desktop` exposes on `window` through contextBridge.
 * Declared here so both sides typecheck against one definition, and so the
 * renderer never needs to import anything from electron.
 *
 * Note how little is here. Input files are read by the renderer itself with the
 * ordinary `File` API — an Electron renderer is a Chromium renderer — so this
 * bridge carries no file *reading* at all, only the things a sandboxed page
 * genuinely cannot do. And there is no execute/spawn surface of any kind: this
 * app computes in-process, and eslint makes `child_process` unreachable from
 * every file in the repo, main process included.
 */
export interface DesktopBridge {
  readonly isDesktop: true;
  readonly platform: HostPlatform;
  getVersion(): Promise<string>;
  openTextFile(options?: { extensions?: string[] }): Promise<OpenedTextFile | null>;
  openExternal(url: string): Promise<void>;
  readSavedState(): Promise<string | null>;
  writeSavedState(json: string): Promise<void>;
  /** Returns an unsubscribe function. */
  onMenuAction(handler: (action: MenuAction) => void): () => void;
}

declare global {
  interface Window {
    openCipherSuite?: DesktopBridge;
  }
}

export function getDesktopBridge(): DesktopBridge | undefined {
  if (typeof window === "undefined") return undefined;
  return window.openCipherSuite;
}

export const isDesktopHost = (): boolean => getDesktopBridge() !== undefined;

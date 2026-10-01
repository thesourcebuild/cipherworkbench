import type {
  CtLogEntry,
  HostPlatform,
  OcspQueryOptions,
  OcspQueryResult,
  OpenedTextFile,
  TlsProbeOptions,
  TlsProbeResult,
} from "@ocs/contracts";

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

  probeTls?(options: TlsProbeOptions): Promise<TlsProbeResult>;
  queryOcsp?(options: OcspQueryOptions): Promise<OcspQueryResult>;
  queryCtLogs?(domain: string): Promise<CtLogEntry[]>;
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

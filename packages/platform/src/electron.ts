import type { OpenedTextFile, PlatformApi, PlatformEnvironment } from "@ocs/contracts";
import { getDesktopBridge } from "./bridge";

/**
 * Desktop adapter. Every call goes through the contextBridge surface declared in
 * `./bridge.ts` — this module imports nothing from electron, and neither does
 * any other file the renderer can reach.
 */
function bridge() {
  const api = getDesktopBridge();
  if (!api)
    throw new Error("The desktop bridge is unavailable — this is not the Electron shell.");
  return api;
}

export const electronPlatform: PlatformApi = {
  async environment(): Promise<PlatformEnvironment> {
    const api = bridge();
    return {
      isDesktop: true,
      platform: api.platform,
      appVersion: await api.getVersion(),
    };
  },

  async openTextFile(options): Promise<OpenedTextFile | undefined> {
    // The bridge speaks `null` (an IPC-friendly absence); the shared API speaks
    // `undefined`. Normalising here keeps that detail out of every call site.
    return (await bridge().openTextFile(options)) ?? undefined;
  },

  async copyToClipboard(text: string): Promise<void> {
    // Not routed through IPC: the renderer's own clipboard works, and an
    // Electron window served over a real origin has permission to use it.
    await navigator.clipboard.writeText(text);
  },

  openExternal(url: string): Promise<void> {
    return bridge().openExternal(url);
  },

  async readSavedState(): Promise<string | undefined> {
    return (await bridge().readSavedState()) ?? undefined;
  },

  writeSavedState(json: string): Promise<void> {
    return bridge().writeSavedState(json);
  },
};

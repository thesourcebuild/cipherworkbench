import { contextBridge, ipcRenderer } from "electron";

/**
 * The complete capability surface of the desktop app. Nothing else crosses into the
 * renderer: no ipcRenderer, no node APIs, no `require`.
 *
 * Keep this in sync with `DesktopBridge` in @ocs/platform — that interface is what
 * the shared UI code typechecks against.
 */
const MENU_CHANNELS = [
  "menu:newComputation",
  "menu:copyResult",
  "menu:openInput",
  "menu:saveResult",
  "menu:about",
] as const;

type MenuAction = (typeof MENU_CHANNELS)[number];

contextBridge.exposeInMainWorld("openCipherSuite", {
  isDesktop: true,
  platform: process.platform,

  getVersion: () => ipcRenderer.invoke("app:getVersion"),

  openTextFile: (options?: { extensions?: string[] }) =>
    ipcRenderer.invoke("dialog:openTextFile", options ?? {}),

  openExternal: (url: string) => ipcRenderer.invoke("shell:openExternal", url),

  readSavedState: () => ipcRenderer.invoke("store:readSavedState"),
  writeSavedState: (json: string) => ipcRenderer.invoke("store:writeSavedState", json),

  /**
   * Native menu items dispatch here. Only the fixed channel list above is
   * subscribable, and the listener receives no event object — passing Electron's
   * IpcRendererEvent into the renderer would leak `sender`.
   */
  onMenuAction: (handler: (action: MenuAction) => void) => {
    const wrapped = new Map<MenuAction, () => void>();
    for (const channel of MENU_CHANNELS) {
      const listener = () => handler(channel);
      wrapped.set(channel, listener);
      ipcRenderer.on(channel, listener);
    }
    return () => {
      for (const [channel, listener] of wrapped) ipcRenderer.removeListener(channel, listener);
    };
  },
});

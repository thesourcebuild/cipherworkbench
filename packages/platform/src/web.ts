import type { OpenedTextFile, PlatformApi, PlatformEnvironment } from "@ocs/contracts";

const STATE_KEY = "cipherworkbench:state:v1";

/**
 * Browser adapter.
 *
 * Genuinely equivalent to the desktop implementation, member for member — which is
 * why the web build is the primary target and the Electron shell is a wrapper
 * around the same bundle rather than a richer app.
 *
 * It used to differ in one place: `canChooseSaveLocation` was false here and true
 * there, because a page cannot say where a download lands. That distinction went
 * with the save surface itself, and the two adapters now have nothing to disagree
 * about.
 */
export const webPlatform: PlatformApi = {
  async environment(): Promise<PlatformEnvironment> {
    return {
      isDesktop: false,
      platform: "browser",
      appVersion: process.env.NEXT_PUBLIC_APP_VERSION ?? "dev",
    };
  },

  async openTextFile({ extensions } = {}): Promise<OpenedTextFile | undefined> {
    return new Promise((resolve) => {
      const input = document.createElement("input");
      input.type = "file";
      if (extensions?.length) input.accept = extensions.map((e) => `.${e}`).join(",");
      input.addEventListener("change", () => {
        const file = input.files?.[0];
        if (!file) return resolve(undefined);
        void file.text().then((contents) => resolve({ name: file.name, contents }));
      });
      // A cancelled dialog fires no `change` event in some browsers.
      input.addEventListener("cancel", () => resolve(undefined));
      input.click();
    });
  },

  async copyToClipboard(text: string): Promise<void> {
    await navigator.clipboard.writeText(text);
  },

  async openExternal(url: string): Promise<void> {
    window.open(url, "_blank", "noopener,noreferrer");
  },

  async readSavedState(): Promise<string | undefined> {
    try {
      return window.localStorage.getItem(STATE_KEY) ?? undefined;
    } catch {
      // Private browsing modes can throw on localStorage access.
      return undefined;
    }
  },

  async writeSavedState(json: string): Promise<void> {
    try {
      window.localStorage.setItem(STATE_KEY, json);
    } catch {
      // Saved state is a convenience, not the product.
    }
  },
};

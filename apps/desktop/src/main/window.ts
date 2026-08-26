import { existsSync } from "node:fs";
import path from "node:path";
import { BrowserWindow, app, shell } from "electron";
import { APP_ORIGIN } from "./protocol";

/**
 * Resolve the window icon. Packaged, resources/ sits next to the app bundle;
 * unpackaged, it is in the source tree. Returns undefined rather than a bad path
 * so Electron falls back to its default instead of failing to create a window.
 */
export function appIcon(): string | undefined {
  const name = process.platform === "win32" ? "icon.ico" : "icon.png";
  const candidates = [
    path.join(process.resourcesPath ?? "", name),
    path.join(app.getAppPath(), "resources", name),
    path.join(app.getAppPath(), "..", "..", "resources", name),
  ];
  return candidates.find((p) => p && existsSync(p));
}

/** The only external hosts the app will ever hand to the system browser. */
const EXTERNAL_ALLOWLIST = [
  /^https:\/\/(www\.)?github\.com\//,
  /^https:\/\/datatracker\.ietf\.org\//,
  /^https:\/\/csrc\.nist\.gov\//,
];

export interface CreateWindowOptions {
  /** Set in development to load the Next dev server instead of the bundle. */
  devUrl?: string;
  preloadPath: string;
}

export function createMainWindow({ devUrl, preloadPath }: CreateWindowOptions): BrowserWindow {
  const window = new BrowserWindow({
    width: 1180,
    height: 860,
    minWidth: 940,
    minHeight: 640,
    show: false,
    backgroundColor: "#0f172a",
    title: `Cipher Workbench v${app.getVersion()}`,
    // Without this Windows shows Electron's atom logo in the title bar, taskbar and
    // Alt-Tab, which is the loudest "this is not a real application" signal there is.
    icon: appIcon(),
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    webPreferences: {
      preload: preloadPath,
      // Defaults in modern Electron, but pinned explicitly: these are the
      // difference between a sandboxed renderer and a shell on the user's box.
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      spellcheck: false,
    },
  });

  window.once("ready-to-show", () => window.show());

  // Nothing in this app should ever open a second window.
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (EXTERNAL_ALLOWLIST.some((re) => re.test(url))) void shell.openExternal(url);
    return { action: "deny" };
  });

  // Client-side state changes happen in the renderer; a real navigation away from
  // our own origin is either a bug or an attack.
  window.webContents.on("will-navigate", (event, url) => {
    const permitted = devUrl ? url.startsWith(devUrl) : url.startsWith(APP_ORIGIN);
    if (!permitted) {
      event.preventDefault();
      if (EXTERNAL_ALLOWLIST.some((re) => re.test(url))) void shell.openExternal(url);
    }
  });

  // No WebView tags, no attaching arbitrary preloads.
  window.webContents.on("will-attach-webview", (event) => event.preventDefault());

  /**
   * Refuse every network request the renderer might make. Packaged builds only.
   *
   * The app's central claim is that nothing you type leaves the machine. In the browser that
   * rests on there being no network code at all; here it can be *enforced* at the session level,
   * so a dependency that decided to phone home is stopped by the runtime rather than by our good
   * intentions. That matters more here than in most apps because the things people paste into
   * this one are private keys and passwords.
   *
   * It is deliberately a **backstop**, not the primary control. `buildCsp` in `protocol.ts`
   * already sends `default-src 'self'` and `connect-src 'self'`, which Chromium enforces on every
   * app:// document -- so in normal operation this handler never fires. What it buys is the case
   * where that header goes missing: a new response path in `protocol.handle`, a refactor, a
   * Content-Type that skips the HTML branch. Two independent mechanisms for one guarantee.
   *
   * Not installed in dev, and that is the point of this comment. The guarantee is about the
   * shipped app; a dev session is a localhost dev server with hot reload and DevTools, where
   * there is nothing to protect and plenty to break. The first version ran it in dev too and
   * blocked Next's HMR websocket -- `ws://localhost:3000/_next/hmr` does not match a
   * `http://localhost:3000` prefix -- so hot reload died, Next retried a dozen times per page,
   * and the terminal filled with warnings. Scoping it to production removes that whole class of
   * problem instead of enumerating exceptions to it.
   */
  if (!devUrl) {
    // One warning per endpoint, query string dropped: anything retrying carries a fresh id, and
    // a flood is how a real finding gets lost. This firing at all is a genuine finding.
    const warned = new Set<string>();
    window.webContents.session.webRequest.onBeforeRequest((details, callback) => {
      const allowed =
        details.url.startsWith(APP_ORIGIN) ||
        details.url.startsWith("devtools:") ||
        details.url.startsWith("blob:") ||
        details.url.startsWith("data:");

      if (!allowed) {
        const key = details.url.split("?")[0] ?? details.url;
        if (!warned.has(key)) {
          warned.add(key);
          console.warn(`Blocked an outbound request from the renderer: ${key}`);
        }
      }
      callback({ cancel: !allowed });
    });
  }

  void window.loadURL(devUrl ? devUrl : `${APP_ORIGIN}/index.html`);

  // DevTools is opt-in: opening it automatically makes the app read as a browser
  // window rather than an application. Set OCS_DEVTOOLS=1, or press F12.
  if (process.env.OCS_DEVTOOLS === "1") {
    window.webContents.openDevTools({ mode: "detach" });
  }

  return window;
}

export const rendererRoot = (appPath: string): string => path.join(appPath, "renderer");

import { rmSync } from "node:fs";
import path from "node:path";
import { BrowserWindow, app } from "electron";
import { registerIpc } from "./ipc";
import { buildMenu } from "./menu";
import { registerScheme, serveRenderer } from "./protocol";
import { runSmokeTest } from "./smoke";
import { createMainWindow } from "./window";

function createWindow(devUrl: string | undefined) {
  const window = createMainWindow({
    devUrl,
    preloadPath: path.join(__dirname, "../preload/index.cjs"),
  });
  buildMenu(window, { isDev: Boolean(devUrl) });
  return window;
}

// Must happen before the app is ready.
registerScheme();

// package.json's name is "@ocs/desktop", which would surface in the About box and
// in native dialogs. Set the real product name instead.
app.setName("Cipher Workbench");

// Windows groups taskbar buttons, pins and notifications by AppUserModelId. Without
// it, an unpackaged run shows up as "Electron" and pinning misbehaves. Matches the
// electron-builder `appId` in electron-builder.config.cjs.
if (process.platform === "win32") {
  app.setAppUserModelId("com.cipherworkbench.app");
}

const devUrl = process.env.OCS_DEV_URL;
const isSmoke = process.env.OCS_SMOKE === "1";

/**
 * The smoke test gets its own userData directory, wiped on every run.
 *
 * The app persists which tool was open, and that turned out to matter twice. A smoke
 * run left `crc32` in the saved state, so the next launch opened on CRC-32 — which made
 * the test non-idempotent (it asserts SHA-256 and got a CRC-32 value) and, before the
 * redirect, meant a headless test silently changed what a person saw when they next
 * opened the app.
 *
 * Redirecting fixes the pollution; deleting fixes the idempotency. Both are needed —
 * redirecting alone just moves the stale state somewhere else and the second run still
 * fails.
 */
if (isSmoke) {
  const smokeData = path.join(app.getPath("temp"), "cipherworkbench-smoke");
  rmSync(smokeData, { recursive: true, force: true });
  app.setPath("userData", smokeData);
}

// One instance only: saved state is a single JSON file and two writers would race.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    const existing = BrowserWindow.getAllWindows()[0];
    if (existing) {
      if (existing.isMinimized()) existing.restore();
      existing.focus();
    }
  });

  app.whenReady().then(() => {
    // In production the renderer sits next to the bundled main process output.
    // In dev it comes from the Next dev server, so nothing needs serving.
    if (!devUrl) {
      serveRenderer(path.join(app.getAppPath(), "renderer"));
    }

    registerIpc();

    const window = createWindow(devUrl);

    if (isSmoke) runSmokeTest(window);

    app.on("activate", () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow(devUrl);
    });
  });

  app.on("window-all-closed", () => {
    if (process.platform !== "darwin") app.quit();
  });
}

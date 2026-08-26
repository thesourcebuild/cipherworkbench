/* eslint-disable no-restricted-imports */
import { spawn } from "node:child_process";
import electronPath from "electron";

/**
 * Launches Electron with a sanitised environment.
 *
 * VS Code's extension host exports ELECTRON_RUN_AS_NODE=1, and it leaks into the
 * integrated terminal. With it set, `electron .` silently runs as plain Node:
 * `require("electron")` returns a stub, so `protocol` and `BrowserWindow` are
 * undefined and the app dies before showing a window. Unsetting it here means
 * `pnpm dev` behaves the same inside and outside the editor.
 *
 * This is the one file in the repository that spawns a process, and it is a dev
 * launcher rather than application code — which is why the eslint ban on
 * `child_process` is disabled here and nowhere else. The app itself computes
 * in-process and never executes anything.
 */
const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;
delete env.VSCODE_ESM_ENTRYPOINT;
delete env.VSCODE_IPC_HOOK;

/**
 * `--dev` means "load the Next dev server". The URL is only defaulted, never
 * forced, so a launcher can point at a different port by exporting OCS_DEV_URL.
 * Production runs never pass --dev and never get a dev URL.
 */
const args = process.argv.slice(2);
const isDev = args.includes("--dev");
if (isDev && !env.OCS_DEV_URL) env.OCS_DEV_URL = "http://localhost:3000";

const child = spawn(electronPath, [".", ...args.filter((a) => a !== "--dev")], {
  stdio: "inherit",
  env,
});

/*
 * "exit", not "close". "close" waits for every inherited stdio stream to actually close, and with
 * `stdio: "inherit"` those streams are shared with whatever Chromium spawns underneath Electron --
 * a GPU process, crashpad, a renderer utility process. On Windows in particular one of those can
 * outlive the main process and keep holding the handle, so "close" never fires and this wrapper
 * hangs forever as an orphaned node process, invisible to whatever called it because Electron itself
 * already reported done. "exit" fires the moment the process we actually spawned terminates, which is
 * the only thing this script needs to know.
 */
child.on("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 0);
});

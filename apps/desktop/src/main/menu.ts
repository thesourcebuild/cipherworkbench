import { Menu, app, type BrowserWindow, type MenuItemConstructorOptions } from "electron";

export interface MenuOptions {
  /** Shows the Developer submenu. Set when running against the dev server. */
  isDev: boolean;
}

/**
 * The application menu.
 *
 * Deliberately not a browser's menu. Reload, zoom and DevTools make a desktop app
 * read as a web page in a frame, so they live under Developer, which only appears
 * in dev — except for a hidden F12 binding, kept because an invisible menu item's
 * accelerator still fires, so a problem can be diagnosed without the app
 * advertising developer tooling.
 */
export function buildMenu(window: BrowserWindow, options: MenuOptions): void {
  const isMac = process.platform === "darwin";

  const send = (channel: string) => () => window.webContents.send(channel);

  const template: MenuItemConstructorOptions[] = [
    ...(isMac ? ([{ role: "appMenu" }] satisfies MenuItemConstructorOptions[]) : []),
    {
      label: "&File",
      submenu: [
        {
          label: "New computation",
          accelerator: "CmdOrCtrl+N",
          click: send("menu:newComputation"),
        },
        {
          label: "Open input file…",
          accelerator: "CmdOrCtrl+O",
          click: send("menu:openInput"),
        },
        { type: "separator" },
        {
          label: "Copy result",
          accelerator: "CmdOrCtrl+Shift+C",
          click: send("menu:copyResult"),
        },
        { label: "Save result…", accelerator: "CmdOrCtrl+S", click: send("menu:saveResult") },
        { type: "separator" },
        isMac ? { role: "close" } : { role: "quit" },
      ],
    },
    {
      label: "&Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
      ],
    },
    {
      label: "&View",
      submenu: [
        { role: "togglefullscreen" },
        {
          label: "Toggle Developer Tools",
          accelerator: "F12",
          visible: false,
          click: () => window.webContents.toggleDevTools(),
        },
      ],
    },
    ...(options.isDev
      ? ([
          {
            label: "&Developer",
            submenu: [
              { role: "reload" },
              { role: "forceReload" },
              { role: "toggleDevTools" },
              { type: "separator" },
              { role: "resetZoom" },
              { role: "zoomIn" },
              { role: "zoomOut" },
            ],
          },
        ] satisfies MenuItemConstructorOptions[])
      : []),
    {
      label: "&Help",
      /**
       * One item, and the two that were here are worth a note.
       *
       * There were links to RFC 6234 and NIST's hash-functions page, opened with
       * `shell.openExternal`. Two reasons they are gone. They were the only part of this app that
       * reached the internet at all -- not a renderer request, so the outbound block never saw them,
       * but a menu that silently launches a browser at a third-party site sits badly beside the
       * Privacy panel's claim that nothing leaves the machine. And they were reference links for the
       * hash family alone, in an app that now spans eight families; the per-algorithm citations
       * belong in each tool's own reference text, where they already are.
       */
      submenu: [{ label: `About ${app.getName()}`, click: send("menu:about") }],
    },
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

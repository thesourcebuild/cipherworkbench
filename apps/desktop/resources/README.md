# Application icons

`icon.svg` is the source of truth. Two raster forms are generated from it and are
what actually ship:

| File | Used by |
|---|---|
| `icon.ico` | The Windows window icon, taskbar, Alt-Tab, and the NSIS installer. |
| `icon.png` | The Linux window icon and the AppImage/deb desktop entry. 512×512. |
| `icon.icns` | macOS, if a signed Mac build is ever produced. |

Generate them with:

```sh
pnpm win:icon          # scripts/make_icon.ps1
```

That redraws the design with `System.Drawing` rather than rasterising the SVG, and the
reason is that it needs nothing installed. Waiting for a real rasteriser is what kept
these files from existing at all, and a missing icon is not cosmetic: `appIcon()` in
`src/main/window.ts` finds nothing, Electron falls back to its own logo, and the atom
in the Windows taskbar is the loudest possible "this is not a real application" signal.

The shapes match `icon.svg` closely enough to read as the same mark -- dark rounded
square, padlock, four hex nibbles on the lock face -- and the glyphs are dropped below
48px, where they would be three pixels tall. If you do have a rasteriser, its output is
strictly better and `icon.svg` remains the source of truth:

```sh
# ImageMagick 7 + librsvg, or any equivalent
magick -background none icon.svg -resize 512x512 icon.png
magick -background none icon.svg -define icon:auto-resize=256,128,64,48,32,16 icon.ico
```

Note that `src/main/smoke.ts` deliberately does **not** assert an icon was found. The
command generator this shell is adapted from does fail its smoke test on a missing
icon, which is right for a shipped app. Now that these files exist and are reproducible
from `pnpm win:icon`, that check is worth reinstating, so a build that loses them cannot
pass silently.

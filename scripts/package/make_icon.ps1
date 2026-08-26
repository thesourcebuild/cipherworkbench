<#
.SYNOPSIS
Generates the application icon set from the design in resources/icon.svg.

.DESCRIPTION
Writes apps/desktop/resources/icon.png (512px, used by Linux and by the window when
running unpackaged) and icon.ico (a multi-size Windows icon, which the title bar,
taskbar, Alt-Tab and the NSIS installer all read).

Redrawn with System.Drawing rather than rasterised from the SVG on purpose: a real
rasteriser means ImageMagick plus librsvg on PATH, which is a dependency this repo
cannot assume and which blocked the icons from existing at all. The shapes here match
icon.svg - dark rounded square, padlock, hex nibbles on the lock face - closely enough
that the two read as the same mark. icon.svg stays the source of truth for the design;
this is the renderer of last resort.

The hex glyphs are dropped below 48px, where they would be two or three pixels tall and
turn into mud. Every size still gets the padlock silhouette, which is what makes the
icon recognisable in a taskbar.

.PARAMETER OutDir
Where to write. Default: apps/desktop/resources.

.EXAMPLE
.\scripts\package\make_icon.ps1
#>
[CmdletBinding()]
param(
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\lib\common.ps1"

Add-Type -AssemblyName System.Drawing

$root = Get-RepoRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'apps\desktop\resources' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Straight out of icon.svg, so the icon and the app's own dark theme agree.
$bg     = [System.Drawing.Color]::FromArgb(255, 11, 18, 32)     # #0b1220
$body   = [System.Drawing.Color]::FromArgb(255, 30, 41, 59)     # slate-800
$edge   = [System.Drawing.Color]::FromArgb(255, 100, 116, 139)  # slate-500
$shackle = [System.Drawing.Color]::FromArgb(255, 148, 163, 184) # slate-400
$accent = [System.Drawing.Color]::FromArgb(255, 56, 189, 248)   # sky-400

function Get-MonoFont {
    param([single]$EmSize)

    foreach ($name in @('Consolas', 'Cascadia Mono', 'Courier New')) {
        $family = $null
        try { $family = New-Object System.Drawing.FontFamily($name) } catch { $family = $null }
        if ($family) {
            return New-Object System.Drawing.Font($family, $EmSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
        }
    }
    # GenericMonospace always resolves, whatever is installed.
    return New-Object System.Drawing.Font([System.Drawing.FontFamily]::GenericMonospace, $EmSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
}

function New-RoundedPath {
    param(
        [System.Drawing.RectangleF]$Box,
        [single]$Radius
    )

    $d = $Radius * 2
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($Box.X, $Box.Y, $d, $d, 180, 90)
    $path.AddArc(($Box.Right - $d), $Box.Y, $d, $d, 270, 90)
    $path.AddArc(($Box.Right - $d), ($Box.Bottom - $d), $d, $d, 0, 90)
    $path.AddArc($Box.X, ($Box.Bottom - $d), $d, $d, 90, 90)
    $path.CloseFigure()
    return $path
}

function New-IconBitmap {
    param([int]$Size)

    $bmp = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::Transparent)

    $s = [single]$Size

    # Background: the rounded square, rx 52/256 in the SVG.
    $bgBox = New-Object System.Drawing.RectangleF(0, 0, $s, $s)
    $bgPath = New-RoundedPath -Box $bgBox -Radius ($s * 0.203)
    $bgBrush = New-Object System.Drawing.SolidBrush($bg)
    $g.FillPath($bgBrush, $bgPath)

    # Shackle: the SVG's arc from (84,112) up over (128,84) and down to (172,112),
    # drawn as the top half of an ellipse so it meets the body at both ends.
    $shackleWidth = [math]::Max(1.0, $s * 0.078)
    $pen = New-Object System.Drawing.Pen($shackle, [single]$shackleWidth)
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $arcX = $s * 0.328
    $arcY = $s * 0.156
    $arcW = $s * 0.344
    $arcH = $s * 0.297
    $g.DrawArc($pen, [single]$arcX, [single]$arcY, [single]$arcW, [single]$arcH, 180, 180)
    $g.DrawLine($pen, [single]$arcX, [single]($arcY + $arcH / 2), [single]$arcX, [single]($s * 0.438))
    $g.DrawLine($pen, [single]($arcX + $arcW), [single]($arcY + $arcH / 2), [single]($arcX + $arcW), [single]($s * 0.438))

    # Body.
    $bodyBox = New-Object System.Drawing.RectangleF(($s * 0.219), ($s * 0.422), ($s * 0.563), ($s * 0.406))
    $bodyPath = New-RoundedPath -Box $bodyBox -Radius ($s * 0.086)
    $bodyBrush = New-Object System.Drawing.SolidBrush($body)
    $g.FillPath($bodyBrush, $bodyPath)
    $edgePen = New-Object System.Drawing.Pen($edge, [single]([math]::Max(1.0, $s * 0.016)))
    $g.DrawPath($edgePen, $bodyPath)

    if ($Size -ge 48) {
        # Four hex nibbles across the lock face - the digest this app exists to produce,
        # drawn as the thing you actually look at when comparing two of them.
        $font = Get-MonoFont -EmSize ([single]($s * 0.117))
        $textBrush = New-Object System.Drawing.SolidBrush($accent)
        $format = New-Object System.Drawing.StringFormat
        $format.Alignment = [System.Drawing.StringAlignment]::Center
        $format.LineAlignment = [System.Drawing.StringAlignment]::Center

        $cells = @(
            @{ Text = 'a'; X = 0.367; Y = 0.539 }
            @{ Text = '7'; X = 0.633; Y = 0.539 }
            @{ Text = 'f'; X = 0.367; Y = 0.703 }
            @{ Text = '3'; X = 0.633; Y = 0.703 }
        )
        foreach ($cell in $cells) {
            $point = New-Object System.Drawing.PointF([single]($s * $cell.X), [single]($s * $cell.Y))
            $g.DrawString($cell.Text, $font, $textBrush, $point, $format)
        }

        $format.Dispose(); $textBrush.Dispose(); $font.Dispose()
    }
    else {
        # Below 48px the glyphs are unreadable, so the face carries a single keyhole
        # instead. The silhouette is what has to survive at 16px.
        $keyhole = New-Object System.Drawing.SolidBrush($accent)
        $r = $s * 0.078
        $g.FillEllipse($keyhole, [single]($s * 0.5 - $r), [single]($s * 0.555 - $r), [single]($r * 2), [single]($r * 2))
        $g.FillRectangle($keyhole, [single]($s * 0.5 - $r * 0.42), [single]($s * 0.555), [single]($r * 0.84), [single]($s * 0.16))
        $keyhole.Dispose()
    }

    $edgePen.Dispose(); $bodyBrush.Dispose(); $bodyPath.Dispose()
    $pen.Dispose(); $bgBrush.Dispose(); $bgPath.Dispose(); $g.Dispose()
    return $bmp
}

Write-Step 'Rendering icon.png (512px)'
$png = Join-Path $OutDir 'icon.png'
$big = New-IconBitmap -Size 512
$big.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)
$big.Dispose()
Write-Note $png

Write-Step 'Rendering icon.ico (multi-size)'
# Each entry is stored as a PNG. Windows Vista and later read PNG-compressed ICO
# entries, and it keeps the 256px entry electron-builder requires small.
$sizes = @(16, 24, 32, 48, 64, 128, 256)
$blobs = @()
foreach ($size in $sizes) {
    $bmp = New-IconBitmap -Size $size
    $stream = New-Object System.IO.MemoryStream
    $bmp.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $blobs += , @{ Size = $size; Bytes = $stream.ToArray() }
    $stream.Dispose(); $bmp.Dispose()
}

$ico = Join-Path $OutDir 'icon.ico'
$fs = [System.IO.File]::Create($ico)
$bw = New-Object System.IO.BinaryWriter($fs)
try {
    $bw.Write([uint16]0)                # reserved
    $bw.Write([uint16]1)                # type: icon
    $bw.Write([uint16]$blobs.Count)

    # Directory entries come first, so image data starts after all of them.
    $offset = 6 + (16 * $blobs.Count)
    foreach ($b in $blobs) {
        # 256 is encoded as 0 in a single byte.
        $dim = if ($b.Size -ge 256) { 0 } else { $b.Size }
        $bw.Write([byte]$dim)           # width
        $bw.Write([byte]$dim)           # height
        $bw.Write([byte]0)              # palette count
        $bw.Write([byte]0)              # reserved
        $bw.Write([uint16]1)            # colour planes
        $bw.Write([uint16]32)           # bits per pixel
        $bw.Write([uint32]$b.Bytes.Length)
        $bw.Write([uint32]$offset)
        $offset += $b.Bytes.Length
    }
    foreach ($b in $blobs) { $bw.Write($b.Bytes) }
}
finally {
    $bw.Dispose(); $fs.Dispose()
}
Write-Note "$ico ($($sizes -join ', ') px)"

Write-Host ''
Write-Host 'Icon set written' -ForegroundColor Green
foreach ($f in @($png, $ico)) {
    Write-Host ('  {0,-30} {1,7} KB' -f (Split-Path $f -Leaf), [math]::Round((Get-Item $f).Length / 1KB, 1))
}
Write-Host ''
Write-Note 'icon.svg remains the source of truth for the design; replace both files with'
Write-Note 'a real rasterisation of it when a rasteriser is available.'

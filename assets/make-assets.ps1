#Requires -Version 5.1
# Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
# Licensed under the MIT License. See LICENSE in the repository root.
#
# The Sarda Cloud name and logo are trademarks of Sarda Cloud Srl and are not
# covered by the MIT License; see README.md.

<#
.SYNOPSIS
    Draws AuthCheck's icon and the README logos from the Sarda Cloud logo.

.DESCRIPTION
    Reads assets\source\sardacloud-logo.png (the white sheep and wordmark on a
    transparent background) and writes:

        AuthCheck.ico                 the executable's icon, 16 to 256 px
        AuthCheck-256.png             the same icon as a picture, for the README
        sardacloud-logo-white.png     the logo for dark backgrounds
        sardacloud-logo-blue.png      the logo for light backgrounds

    The icon is the sheep in white on Sarda Cloud blue, with a green check
    mark badge from 24 px up. Run it again after changing the source logo;
    the output is committed so a build needs nothing but the .NET SDK.

.EXAMPLE
    .\assets\make-assets.ps1
#>

[CmdletBinding()]
param(
    [string] $Source = (Join-Path $PSScriptRoot 'source\sardacloud-logo.png'),
    [string] $Output = $PSScriptRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$Blue  = [System.Drawing.Color]::FromArgb(255, 0x00, 0x66, 0xCC)   # www.sardacloud.com
$Green = [System.Drawing.Color]::FromArgb(255, 0x2E, 0xA0, 0x43)
$White = [System.Drawing.Color]::White

function New-Canvas([int] $Width, [int] $Height) {
    $bmp = New-Object System.Drawing.Bitmap($Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    return @{ Bitmap = $bmp; Graphics = $g }
}

function Get-OpaqueColumns([System.Drawing.Bitmap] $Bitmap) {
    $cols = New-Object 'int[]' $Bitmap.Width
    for ($x = 0; $x -lt $Bitmap.Width; $x++) {
        for ($y = 0; $y -lt $Bitmap.Height; $y += 2) {
            if ($Bitmap.GetPixel($x, $y).A -gt 32) { $cols[$x]++ }
        }
    }
    return $cols
}

# The sheep is everything left of the first wide transparent gap; the
# wordmark is to the right of it.
function Get-SheepBounds([System.Drawing.Bitmap] $Logo) {
    $cols = Get-OpaqueColumns $Logo
    $left = 0
    while ($left -lt $cols.Length -and $cols[$left] -eq 0) { $left++ }
    $right = $left; $gap = 0
    for ($x = $left; $x -lt $cols.Length; $x++) {
        if ($cols[$x] -eq 0) { $gap++; if ($gap -ge 12) { break } }
        else { $gap = 0; $right = $x }
    }
    $top = $Logo.Height; $bottom = 0
    for ($y = 0; $y -lt $Logo.Height; $y++) {
        for ($x = $left; $x -le $right; $x += 2) {
            if ($Logo.GetPixel($x, $y).A -gt 32) {
                if ($y -lt $top) { $top = $y }
                if ($y -gt $bottom) { $bottom = $y }
                break
            }
        }
    }
    return New-Object System.Drawing.Rectangle($left, $top, ($right - $left + 1), ($bottom - $top + 1))
}

function New-RoundedPath([single] $X, [single] $Y, [single] $W, [single] $H, [single] $R) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $R
    $p.AddArc($X, $Y, $d, $d, 180, 90)
    $p.AddArc($X + $W - $d, $Y, $d, $d, 270, 90)
    $p.AddArc($X + $W - $d, $Y + $H - $d, $d, $d, 0, 90)
    $p.AddArc($X, $Y + $H - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

# Recolours every pixel to $Color, keeping the source alpha.
function New-Tinted([System.Drawing.Bitmap] $Image, [System.Drawing.Color] $Color) {
    $out = New-Object System.Drawing.Bitmap($Image.Width, $Image.Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    for ($y = 0; $y -lt $Image.Height; $y++) {
        for ($x = 0; $x -lt $Image.Width; $x++) {
            $a = $Image.GetPixel($x, $y).A
            if ($a -gt 0) { $out.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($a, $Color.R, $Color.G, $Color.B)) }
        }
    }
    return $out
}

function Get-Resized([System.Drawing.Image] $Image, [int] $Width) {
    $h = [int][Math]::Round($Image.Height * $Width / $Image.Width)
    $c = New-Canvas $Width $h
    $c.Graphics.DrawImage($Image, 0, 0, $Width, $h)
    $c.Graphics.Dispose()
    return $c.Bitmap
}

function New-IconImage([System.Drawing.Bitmap] $Sheep, [int] $Size) {
    $c = New-Canvas $Size $Size
    $g = $c.Graphics

    $radius = [single]($Size * 0.2)
    $bg = New-RoundedPath 0 0 $Size $Size $radius
    $brush = New-Object System.Drawing.SolidBrush($Blue)
    $g.FillPath($brush, $bg)

    # The sheep fills most of the tile, nudged up and left to leave the badge
    # its corner.
    $badge = $Size -ge 24
    $box = if ($badge) { $Size * 0.78 } else { $Size * 0.86 }
    $scale = [Math]::Min($box / $Sheep.Width, $box / $Sheep.Height)
    $w = $Sheep.Width * $scale; $h = $Sheep.Height * $scale
    $x = ($Size - $w) / 2; $y = ($Size - $h) / 2
    if ($badge) { $x -= $Size * 0.05; $y -= $Size * 0.06 }
    $g.DrawImage($Sheep, [single]$x, [single]$y, [single]$w, [single]$h)

    if ($badge) {
        $d = $Size * 0.44
        $bx = $Size - $d - $Size * 0.02; $by = $Size - $d - $Size * 0.02
        $ring = New-Object System.Drawing.SolidBrush($White)
        $g.FillEllipse($ring, [single]($bx - $Size * 0.025), [single]($by - $Size * 0.025), [single]($d + $Size * 0.05), [single]($d + $Size * 0.05))
        $fill = New-Object System.Drawing.SolidBrush($Green)
        $g.FillEllipse($fill, [single]$bx, [single]$by, [single]$d, [single]$d)

        $pen = New-Object System.Drawing.Pen($White, [single][Math]::Max(1.5, $d * 0.14))
        $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $tick = [System.Drawing.PointF[]] @(
            (New-Object System.Drawing.PointF([single]($bx + $d * 0.27), [single]($by + $d * 0.53))),
            (New-Object System.Drawing.PointF([single]($bx + $d * 0.44), [single]($by + $d * 0.70))),
            (New-Object System.Drawing.PointF([single]($bx + $d * 0.74), [single]($by + $d * 0.34))))
        $g.DrawLines($pen, $tick)
        $pen.Dispose(); $fill.Dispose(); $ring.Dispose()
    }

    $brush.Dispose(); $bg.Dispose(); $g.Dispose()
    return $c.Bitmap
}

function Get-PngBytes([System.Drawing.Bitmap] $Bitmap) {
    $ms = New-Object System.IO.MemoryStream
    $Bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bytes = $ms.ToArray()
    $ms.Dispose()
    return ,$bytes
}

# An .ico whose images are all PNG-compressed, which Windows has read since
# Vista and the C# compiler embeds as-is.
function Write-Icon([string] $Path, [System.Collections.IList] $Images) {
    $fs = [System.IO.File]::Create($Path)
    $w = New-Object System.IO.BinaryWriter($fs)
    try {
        $w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$Images.Count)
        $offset = 6 + 16 * $Images.Count
        foreach ($img in $Images) {
            $dim = if ($img.Size -ge 256) { 0 } else { $img.Size }
            $w.Write([byte]$dim); $w.Write([byte]$dim)
            $w.Write([byte]0); $w.Write([byte]0)
            $w.Write([uint16]1); $w.Write([uint16]32)
            $w.Write([uint32]$img.Bytes.Length); $w.Write([uint32]$offset)
            $offset += $img.Bytes.Length
        }
        foreach ($img in $Images) { $w.Write($img.Bytes) }
    }
    finally { $w.Dispose(); $fs.Dispose() }
}

$logo = [System.Drawing.Bitmap]::FromFile((Resolve-Path $Source))
try {
    $bounds = Get-SheepBounds $logo
    Write-Verbose "Sheep at $bounds in a $($logo.Width) x $($logo.Height) logo"
    $sheep = $logo.Clone($bounds, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)

    $images = New-Object System.Collections.ArrayList
    foreach ($size in 256, 128, 64, 48, 32, 24, 16) {
        $bmp = New-IconImage $sheep $size
        [void]$images.Add([pscustomobject]@{ Size = $size; Bytes = (Get-PngBytes $bmp) })
        if ($size -eq 256) { $bmp.Save((Join-Path $Output 'AuthCheck-256.png'), [System.Drawing.Imaging.ImageFormat]::Png) }
        $bmp.Dispose()
    }
    Write-Icon (Join-Path $Output 'AuthCheck.ico') $images

    $white = Get-Resized $logo 480
    $white.Save((Join-Path $Output 'sardacloud-logo-white.png'), [System.Drawing.Imaging.ImageFormat]::Png)
    $blue = New-Tinted $white $Blue
    $blue.Save((Join-Path $Output 'sardacloud-logo-blue.png'), [System.Drawing.Imaging.ImageFormat]::Png)
    $white.Dispose(); $blue.Dispose(); $sheep.Dispose()
}
finally { $logo.Dispose() }

Get-ChildItem $Output -File | Where-Object Extension -in '.ico', '.png' |
    ForEach-Object { '{0,-28} {1,8:N0} bytes' -f $_.Name, $_.Length }

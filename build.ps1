#Requires -Version 5.1
# Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
# Licensed under the MIT License. See LICENSE in the repository root.

<#
.SYNOPSIS
    Builds, tests and packages AuthCheck.

.DESCRIPTION
    Publishes AuthCheck.exe as one self-contained file per architecture, so
    it runs on a machine with no .NET installed, and checks that each file is
    built for the processor it claims:

        out\x64\AuthCheck.exe      64-bit Intel and AMD
        out\arm64\AuthCheck.exe    Windows on ARM
        out\x86\AuthCheck.exe      32-bit Windows

    With -Package, each one is zipped with the licence, the README and the
    third-party notices, and SHA256SUMS.txt is written beside the zips.

.PARAMETER Arch
    x64, arm64, x86 or All. Default: the architecture of this machine.

.PARAMETER Configuration
    Release or Debug. Default Release.

.PARAMETER Output
    Where to put the builds. Default .\out.

.PARAMETER Test
    Run the unit tests first, as this machine's architecture.

.PARAMETER Package
    Produce AuthCheck-<version>-win-<arch>.zip and SHA256SUMS.txt.

.PARAMETER Clean
    Empty the output folder first.

.EXAMPLE
    .\build.ps1

.EXAMPLE
    .\build.ps1 -Arch All -Test -Package
#>

[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64', 'x86', 'All')]
    [string[]] $Arch,

    [ValidateSet('Release', 'Debug')]
    [string] $Configuration = 'Release',

    [string] $Output = (Join-Path $PSScriptRoot 'out'),

    [switch] $Test,
    [switch] $Package,
    [switch] $Clean
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$project = Join-Path $root 'src\AuthCheck\AuthCheck.csproj'
$tests = Join-Path $root 'tests\AuthCheck.Tests\AuthCheck.Tests.csproj'
$version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
$machines = @{ x64 = 0x8664; arm64 = 0xAA64; x86 = 0x014C }

function Write-Step([string] $Text) { Write-Host "  [*] $Text" -ForegroundColor Yellow }
function Write-Ok([string] $Text)   { Write-Host "  [+] $Text" -ForegroundColor Green }

function Invoke-Dotnet {
    & dotnet @args
    if ($LASTEXITCODE -ne 0) { throw "dotnet $($args[0]) failed with exit code $LASTEXITCODE." }
}

function Get-HostArch {
    $a = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($a) { 'ARM64' { 'arm64' } 'x86' { 'x86' } default { 'x64' } }
}

function Get-PeMachine([string] $Path) {
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Position = 0x3C
        $fs.Position = $br.ReadInt32() + 4
        return [int]$br.ReadUInt16()
    }
    finally { $fs.Dispose() }
}

if (-not $Arch) { $Arch = @(Get-HostArch) }
if ($Arch -contains 'All') { $Arch = @('x64', 'arm64', 'x86') }

Write-Host ''
Write-Host "  AuthCheck $version - build" -ForegroundColor Cyan
Write-Host '  Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com' -ForegroundColor DarkGray
Write-Host ''

if ($Clean -and (Test-Path $Output)) { Remove-Item $Output -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Output | Out-Null

if ($Test) {
    Write-Step 'Running the unit tests'
    Invoke-Dotnet test $tests -c $Configuration --nologo
    Write-Ok 'Unit tests passed'
}

$zips = @()
foreach ($a in $Arch) {
    $dir = Join-Path $Output $a
    Write-Step "Publishing win-$a"
    Invoke-Dotnet publish $project -c $Configuration -r "win-$a" -o $dir --nologo

    $exe = Join-Path $dir 'AuthCheck.exe'
    if (-not (Test-Path $exe)) { throw "The publish produced no $exe." }
    $machine = Get-PeMachine $exe
    if ($machine -ne $machines[$a]) {
        throw ('{0} is machine 0x{1:X4}, expected 0x{2:X4} for {3}.' -f $exe, $machine, $machines[$a], $a)
    }
    Write-Ok ('win-{0}: AuthCheck.exe, {1:N1} MB, machine 0x{2:X4}' -f $a, ((Get-Item $exe).Length / 1MB), $machine)

    if ($Package) {
        $stage = Join-Path $Output "stage-$a"
        if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
        New-Item -ItemType Directory -Path $stage | Out-Null
        Copy-Item $exe $stage
        foreach ($f in 'LICENSE', 'README.md', 'THIRD-PARTY-NOTICES.md') { Copy-Item (Join-Path $root $f) $stage }

        $zip = Join-Path $Output "AuthCheck-$version-win-$a.zip"
        if (Test-Path $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
        Remove-Item $stage -Recurse -Force
        $zips += Get-Item $zip
        Write-Ok "Packaged $([System.IO.Path]::GetFileName($zip))"
    }
}

if ($Package) {
    # sha256sum format, so "sha256sum -c SHA256SUMS.txt" works as well.
    $all = Get-ChildItem $Output -Filter "AuthCheck-$version-win-*.zip" | Sort-Object Name
    $lines = foreach ($z in $all) { '{0}  {1}' -f (Get-FileHash $z.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $z.Name }
    [System.IO.File]::WriteAllText((Join-Path $Output 'SHA256SUMS.txt'), (($lines -join "`n") + "`n"))
    Write-Ok 'Wrote SHA256SUMS.txt'
}

Write-Host ''

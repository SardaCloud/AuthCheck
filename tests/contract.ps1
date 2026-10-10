#Requires -Version 5.1
# Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
# Licensed under the MIT License. See LICENSE in the repository root.

<#
.SYNOPSIS
    Checks AuthCheck's command-line contract against a built AuthCheck.exe.

.DESCRIPTION
    Runs the executable the way scripts and people will, and fails if any
    promise in the README is broken: help and exit codes, unknown switches,
    the /Json protocol, every action and alias, /Log, and the branding.

    With -SecretProbe it also stores a throw-away generic credential with a
    random password, runs /Credentials, and fails if the password appears
    anywhere in the output. The credential is removed again afterwards. It is
    off by default because it writes to the current user's Credential
    Manager; CI turns it on.

.EXAMPLE
    .\tests\contract.ps1 -Exe .\out\x64\AuthCheck.exe
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Exe,
    [switch] $SecretProbe
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path $Exe).Path
$failures = 0

function Pass([string] $Text) { Write-Host "  [+] $Text" -ForegroundColor Green }
function Fail([string] $Text) {
    $script:failures++
    if ($env:GITHUB_ACTIONS) { Write-Host "::error::$Text" } else { Write-Host "  [x] $Text" -ForegroundColor Red }
}

function Invoke-AuthCheck([string[]] $Arguments) {
    $out = & $Exe @Arguments 2>$null
    return [pscustomobject]@{ Code = $LASTEXITCODE; Lines = @($out) }
}

function Test-JsonRun([string] $Name, [string[]] $Arguments, [string] $ExpectAction) {
    $r = Invoke-AuthCheck ($Arguments + '/Json')
    $objects = @()
    foreach ($line in $r.Lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $objects += ($line | ConvertFrom-Json) }
        catch { Fail "${Name}: stdout line is not JSON: $line"; return }
    }
    if ($objects.Count -lt 2) { Fail "${Name}: expected at least a start and a result line"; return }
    $first = $objects[0]; $last = $objects[-1]
    if ($first.type -ne 'start' -or $first.tool -ne 'AuthCheck') { Fail "${Name}: the first line is not the start line"; return }
    if ($last.type -ne 'result') { Fail "${Name}: the last line is '$($last.type)', not 'result'"; return }
    if ($last.exitCode -ne $r.Code) { Fail "${Name}: result.exitCode $($last.exitCode) differs from the process exit code $($r.Code)"; return }
    if ($r.Code -notin 0, 2) { Fail "${Name}: exit code $($r.Code); a hosted machine should give 0 or 2"; return }
    if ($ExpectAction -and $last.action -ne $ExpectAction) { Fail "${Name}: action '$($last.action)', expected '$ExpectAction'"; return }
    Pass "${Name}: $($objects.Count) JSON lines, result '$($last.action)', exit $($r.Code)"
    return $last
}

Write-Host ''
Write-Host "  AuthCheck contract: $Exe" -ForegroundColor Cyan
Write-Host ''

# --- help and branding -------------------------------------------------------
foreach ($h in '/?', '-?', '/h', '--help', '/Help') {
    $r = Invoke-AuthCheck @($h)
    if ($r.Code -ne 0) { Fail "$h exited $($r.Code)" }
}
$help = (Invoke-AuthCheck @('/?')).Lines -join "`n"
foreach ($must in 'AuthCheck', 'Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com', 'MIT License', 'EXAMPLES', 'EXIT CODES') {
    if ($help -notlike "*$must*") { Fail "/? does not mention '$must'" }
}
Pass 'Help answers /? -? /h --help /Help with exit 0 and carries the copyright'

$info = (Get-Item $Exe).VersionInfo
if ($info.CompanyName -ne 'Sarda Cloud Srl' -or $info.ProductName -ne 'AuthCheck' -or $info.LegalCopyright -notlike '*Sarda Cloud Srl*') {
    Fail "Version resource: company '$($info.CompanyName)', product '$($info.ProductName)', copyright '$($info.LegalCopyright)'"
} else { Pass "Version resource: $($info.ProductName) $($info.ProductVersion), $($info.CompanyName)" }

# --- refusals ------------------------------------------------------------------
foreach ($bad in @(@('/NoSuchSwitch'), @('/Device', '/Mdm'), @('/Action', 'Nope'), @('/Log'), @('stray'), @('/Json:maybe'))) {
    $r = Invoke-AuthCheck $bad
    if ($r.Code -ne 1) { Fail "'$($bad -join ' ')' exited $($r.Code), expected 1" }
}
Pass 'Unknown switches, two actions, bad values and stray words exit 1'

$r = Invoke-AuthCheck @('/NoSuchSwitch', '/Json')
$last = $r.Lines | Where-Object { $_ } | Select-Object -Last 1 | ConvertFrom-Json
if ($last.type -ne 'result' -or $last.exitCode -ne 1) { Fail 'An error under /Json does not end in a result line with exitCode 1' }
else { Pass 'An error under /Json still ends in a result line' }

# However early a run fails, /Json keeps its promise: stdout is JSON only, it
# opens with a start line and closes with a result whose exitCode matches.
function Test-JsonError([string] $Name, [string[]] $Arguments, [int] $Expect) {
    $r = Invoke-AuthCheck $Arguments
    $lines = @($r.Lines | Where-Object { $_ })
    try { $objects = @($lines | ForEach-Object { $_ | ConvertFrom-Json }) }
    catch { Fail "${Name}: stdout is not pure JSON Lines"; return }
    if ($objects.Count -lt 2) { Fail "${Name}: $($objects.Count) JSON line(s) on stdout; expected start and result"; return }
    if ($objects[0].type -ne 'start') { Fail "${Name}: the first line is '$($objects[0].type)', not 'start'"; return }
    if ($objects[-1].type -ne 'result') { Fail "${Name}: the last line is '$($objects[-1].type)', not 'result'"; return }
    if ($objects[-1].exitCode -ne $r.Code -or $r.Code -ne $Expect) {
        Fail "${Name}: exit $($r.Code), result.exitCode $($objects[-1].exitCode); expected $Expect"
        return
    }
    $script:jsonErrorsPassed++
}
$script:jsonErrorsPassed = 0
$badLog = Join-Path ([System.IO.Path]::GetTempPath()) 'bad|name.log'
Test-JsonError '/NoSuchSwitch /Json'     @('/NoSuchSwitch', '/Json') 1
Test-JsonError '/Json /Action Nope'      @('/Json', '/Action', 'Nope') 1
Test-JsonError '/Json /Device /Mdm'      @('/Json', '/Device', '/Mdm') 1
Test-JsonError '/Json stray'             @('/Json', 'stray') 1
Test-JsonError '/Json /Quiet:maybe'      @('/Json', '/Quiet:maybe') 1
Test-JsonError '/Json:maybe'             @('/Json:maybe') 1
Test-JsonError '/Json /Log (no value)'   @('/Json', '/Log') 1
Test-JsonError '/Json /Log <bad path>'   @('/Json', '/Log', $badLog) 1
Test-JsonError '/Json /?'                @('/Json', '/?') 0
if ($script:jsonErrorsPassed -eq 9) { Pass 'Every early failure, and /Json /?, gives a start line, a result line and JSON only' }

# --- every action and alias ------------------------------------------------------
$status = Test-JsonRun 'Status' @() 'Status'
foreach ($pair in @(@('/Device', 'Device'), @('/Dsreg', 'Device'), @('/Mdm', 'Mdm'), @('/Kerberos', 'Kerberos'),
                    @('/Klist', 'Kerberos'), @('/Credentials', 'Credentials'), @('/Cmdkey', 'Credentials'),
                    @('-klist', 'Kerberos'), @('--device', 'Device'))) {
    [void](Test-JsonRun $pair[0] @($pair[0]) $pair[1])
}
[void](Test-JsonRun '/Action Mdm' @('/Action', 'Mdm') 'Mdm')
[void](Test-JsonRun '/Verbose /Quiet /NoLogo' @('/Verbose', '/Quiet', '/NoLogo') 'Status')

if ($status) {
    foreach ($key in 'computer', 'user', 'windows', 'device', 'prt', 'mdm', 'kerberos', 'credentials') {
        if (-not ($status.data.PSObject.Properties.Name -contains $key)) { Fail "Status result has no data.$key" }
    }
    Pass 'Status result carries every section'
}

# --- text mode and /Log ------------------------------------------------------------
$text = (Invoke-AuthCheck @()).Lines -join "`n"
foreach ($must in 'DEVICE REGISTRATION', 'DEVICE MANAGEMENT', 'KERBEROS TICKETS', 'STORED CREDENTIALS', 'Sarda Cloud Srl') {
    if ($text -notlike "*$must*") { Fail "The text report lacks '$must'" }
}
Pass 'The text report has every section and the banner'

$log = Join-Path ([System.IO.Path]::GetTempPath()) ("authcheck-contract-{0}.log" -f [guid]::NewGuid())
try {
    $r = Invoke-AuthCheck @('/Device', '/Quiet', '/Log', $log)
    if (-not (Test-Path $log)) { Fail '/Log wrote no file' }
    elseif ((Get-Content $log -Raw) -notlike '*Copyright (C) 2026 Sarda Cloud Srl*') { Fail '/Log lacks the banner' }
    else { Pass '/Log writes a transcript with the banner, even with /Quiet' }
}
finally { Remove-Item $log -Force -ErrorAction SilentlyContinue }

# --- secrets never reach the output ---------------------------------------------------
if ($SecretProbe) {
    $target = "AuthCheck-contract-$([guid]::NewGuid().ToString('N'))"
    $secret = "Ac$([guid]::NewGuid().ToString('N'))!"
    & cmdkey.exe "/generic:$target" "/user:contract" "/pass:$secret" | Out-Null
    try {
        $r = Invoke-AuthCheck @('/Credentials', '/Json', '/Verbose')
        $all = $r.Lines -join "`n"
        if ($all -like "*$secret*") { Fail 'A stored password appeared in the /Json output' }
        elseif ($all -notlike "*$target*") { Write-Host "  [-] Credential Manager is not available in this session; secret probe skipped" -ForegroundColor DarkGray }
        else {
            $text = (& $Exe /Credentials /Verbose 2>&1) -join "`n"
            if ($text -like "*$secret*") { Fail 'A stored password appeared in the text output' }
            else { Pass 'A stored password is listed by target and never shown' }
        }
    }
    finally { & cmdkey.exe "/delete:$target" | Out-Null }
}

Write-Host ''
if ($failures -gt 0) {
    Write-Host "  [x] $failures contract check(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host '  [+] Every contract check passed.' -ForegroundColor Green
exit 0

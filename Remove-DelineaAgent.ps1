<#
.SYNOPSIS
    Uninstalls the Delinea (Thycotic) Privilege Manager agent from a Windows machine.

.DESCRIPTION
    Dynamically discovers ThycoticAgent MSI files on a specified network share,
    then runs a silent uninstall for each one found. Handles registry-based
    uninstall string extraction and validates exit codes.

    Features:
      - No hardcoded version strings - discovers installed MSIs at runtime
      - Registry-based product discovery with strict mode safe property access
      - Timestamped log file with INFO/WARN/ERROR levels
      - Exit code handling (0, 1605, 1618, 1641, 3010)
      - Post-removal verification via registry check

.PARAMETER SharePath
    UNC path to the folder containing ThycoticAgent_x64_*.msi files.
    Example: \\fileserver\IT-Share\Delinea

.PARAMETER LogFile
    Path for the log file. Defaults to C:\ProgramData\Logs\DelineaAgent_Uninstall.log

.EXAMPLE
    .\Remove-DelineaAgent.ps1 -SharePath "\\fileserver\IT-Share\Delinea"

.EXAMPLE
    .\Remove-DelineaAgent.ps1 -SharePath "\\fileserver\IT-Share\Delinea" -LogFile "D:\Logs\delinea.log"

.NOTES
    IMPORTANT: Delinea agents may have tamper protection enabled in the admin
    console. Disable agent hardening/self-protect in the Delinea portal BEFORE
    running this script, or the msiexec call will be blocked.

    Run as local Administrator or SYSTEM.

    Exit codes:
      0    - Success
      1605 - Product not found (already uninstalled)
      1618 - Another install in progress - retry later
      1641 - Success, reboot initiated
      3010 - Success, reboot required
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SharePath,

    [string]$LogFile = "C:\ProgramData\Logs\DelineaAgent_Uninstall.log"
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

# -- Logging -------------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO'
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $line -Encoding ASCII
    switch ($Level) {
        'INFO'  { Write-Host $line -ForegroundColor Gray }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
    }
}

# -- Ensure log directory exists -----------------------------------------------
$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

Write-Log "Delinea agent uninstall started. User: $($env:USERDOMAIN)\$($env:USERNAME)"
Write-Log "Share path: $SharePath"

# -- Validate share access -----------------------------------------------------
if (-not (Test-Path $SharePath)) {
    Write-Log "Share path not accessible: $SharePath" -Level ERROR
    exit 1
}

# -- Discover MSI files --------------------------------------------------------
$msiFiles = @(Get-ChildItem -Path $SharePath -Filter "ThycoticAgent_x64_*.msi" -ErrorAction SilentlyContinue)
if ($msiFiles.Count -eq 0) {
    Write-Log "No ThycoticAgent_x64_*.msi files found in $SharePath" -Level WARN
    exit 0
}
Write-Log "Found $($msiFiles.Count) MSI file(s):"
foreach ($msi in $msiFiles) { Write-Log "  $($msi.Name)" }

# -- Registry paths to check for installed products ----------------------------
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

function Get-InstalledDelineaProducts {
    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($regPath in $script:regPaths) {
        $entries = @(Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue)
        foreach ($entry in $entries) {
            $nameVal = $entry.PSObject.Properties['DisplayName']
            if ($null -eq $nameVal) { continue }
            if ($nameVal.Value -match 'Thycotic|Delinea|Privilege Manager Agent') {
                $found.Add([PSCustomObject]@{
                    DisplayName     = $nameVal.Value
                    UninstallString = if ($entry.PSObject.Properties['UninstallString']) { $entry.UninstallString } else { '' }
                    Version         = if ($entry.PSObject.Properties['DisplayVersion'])  { $entry.DisplayVersion }  else { '' }
                })
            }
        }
    }
    return $found
}

$installedBefore = @(Get-InstalledDelineaProducts)
if ($installedBefore.Count -eq 0) {
    Write-Log "No Delinea/Thycotic products found in registry. May already be uninstalled." -Level WARN
}
else {
    Write-Log "Found $($installedBefore.Count) installed product(s) to remove:"
    foreach ($p in $installedBefore) { Write-Log "  $($p.DisplayName) $($p.Version)" }
}

# -- Run uninstall for each MSI ------------------------------------------------
$overallSuccess = $true

foreach ($msi in $msiFiles) {
    $msiPath = $msi.FullName
    Write-Log "Processing: $msiPath"

    try {
        $proc = Start-Process -FilePath 'msiexec.exe' `
            -ArgumentList "/uninstall `"$msiPath`" /qn /norestart" `
            -Wait -PassThru -ErrorAction Stop

        $exitCode = $proc.ExitCode
        Write-Log "msiexec exit code: $exitCode"

        switch ($exitCode) {
            0    { Write-Log "Uninstall succeeded: $($msi.Name)" }
            1605 { Write-Log "Product not installed (exit 1605): $($msi.Name)" -Level WARN }
            1618 { Write-Log "Another install in progress (exit 1618). Retry later." -Level WARN; $overallSuccess = $false }
            1641 { Write-Log "Uninstall succeeded, reboot initiated: $($msi.Name)" }
            3010 { Write-Log "Uninstall succeeded, reboot required: $($msi.Name)" -Level WARN }
            default {
                Write-Log "Unexpected exit code $exitCode for $($msi.Name)" -Level WARN
                $overallSuccess = $false
            }
        }
    }
    catch {
        Write-Log "Failed to launch msiexec for $($msi.Name): $_" -Level ERROR
        $overallSuccess = $false
    }
}

# -- Post-removal verification -------------------------------------------------
$installedAfter = @(Get-InstalledDelineaProducts)
if ($installedAfter.Count -eq 0) {
    Write-Log "Verification passed: No Delinea/Thycotic products found in registry."
}
else {
    Write-Log "Verification WARNING: $($installedAfter.Count) product(s) still registered:" -Level WARN
    foreach ($p in $installedAfter) { Write-Log "  Still present: $($p.DisplayName) $($p.Version)" -Level WARN }
    $overallSuccess = $false
}

Write-Log "Delinea agent uninstall script finished. Overall success: $overallSuccess"

if (-not $overallSuccess) { exit 1 }
exit 0

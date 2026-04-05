<#
.SYNOPSIS
    Silently uninstalls the ThreatLocker security agent.

.DESCRIPTION
    Downloads the appropriate ThreatLocker stub installer for the current OS
    architecture (x64 or x86), runs the uninstall command silently, validates
    the result, and cleans up the stub binary.

    Features:
      - Timestamped log file with INFO/WARN/ERROR levels
      - Architecture detection (x64 vs x86)
      - TLS 1.2 enforcement for download
      - Post-download file validation
      - Process timeout with forced kill on expiry
      - Exit code evaluation
      - Cleanup in finally block regardless of outcome

.PARAMETER LogFile
    Path for the log file. Defaults to C:\Temp\ThreatLocker_Uninstall.log

.PARAMETER TimeoutSeconds
    Maximum seconds to wait for uninstall to complete. Default: 300

.EXAMPLE
    .\Remove-ThreatLocker.ps1

.EXAMPLE
    .\Remove-ThreatLocker.ps1 -LogFile "D:\Logs\TL_Remove.log" -TimeoutSeconds 600

.NOTES
    IMPORTANT: If ThreatLocker application control policies are active on the
    endpoint, the stub installer may be blocked from executing. You may need to:
      - Add an exclusion in the ThreatLocker portal before running, OR
      - Request an offline uninstall key from your ThreatLocker portal

    Run as local Administrator or SYSTEM.
#>

[CmdletBinding()]
param(
    [string]$LogFile       = "C:\Temp\ThreatLocker_Uninstall.log",
    [int]   $TimeoutSeconds = 300
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

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

Write-Log "ThreatLocker uninstall started. User: $($env:USERDOMAIN)\$($env:USERNAME)"

$stubPath = $null

try {
    # -- Architecture ----------------------------------------------------------
    $arch = if ([System.Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    Write-Log "Detected architecture: $arch"

    # -- TLS 1.2 ---------------------------------------------------------------
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Log "TLS 1.2 enforced."

    # -- Download stub ----------------------------------------------------------
    $downloadUrl = "https://api.threatlocker.com/updates/threatlockerstub_$arch.exe"
    $stubPath    = Join-Path $env:TEMP "ThreatLockerStub_$arch.exe"

    Write-Log "Downloading stub from: $downloadUrl"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($downloadUrl, $stubPath)

    # -- Validate download ------------------------------------------------------
    if (-not (Test-Path $stubPath)) {
        throw "Stub file not found after download: $stubPath"
    }
    $stubSize = (Get-Item $stubPath).Length
    if ($stubSize -lt 50KB) {
        throw "Stub file appears invalid (size: $stubSize bytes)"
    }
    Write-Log "Stub downloaded successfully ($stubSize bytes): $stubPath"

    # -- Run uninstall ----------------------------------------------------------
    Write-Log "Launching uninstall (timeout: ${TimeoutSeconds}s)..."
    $proc = Start-Process -FilePath $stubPath -ArgumentList '/uninstall','/quiet' -PassThru -ErrorAction Stop

    $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
    if (-not $exited) {
        Write-Log "Uninstall timed out after $TimeoutSeconds seconds. Killing process." -Level WARN
        $proc | Stop-Process -Force -ErrorAction SilentlyContinue
        throw "Uninstall process timed out."
    }

    $exitCode = $proc.ExitCode
    Write-Log "Process exited with code: $exitCode"

    switch ($exitCode) {
        0    { Write-Log "Uninstall completed successfully." }
        1641 { Write-Log "Uninstall succeeded - reboot initiated." }
        3010 { Write-Log "Uninstall succeeded - reboot required." -Level WARN }
        1605 { Write-Log "Product not found (already uninstalled?)." -Level WARN }
        default {
            Write-Log "Uninstall returned non-zero exit code: $exitCode" -Level WARN
        }
    }
}
catch {
    Write-Log "Uninstall failed: $_" -Level ERROR
    exit 1
}
finally {
    if ($stubPath -and (Test-Path $stubPath)) {
        Remove-Item -Path $stubPath -Force -ErrorAction SilentlyContinue
        Write-Log "Stub cleaned up: $stubPath"
    }
    Write-Log "ThreatLocker uninstall script finished."
}

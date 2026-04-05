#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CVE remediation assessment and hardening script for mixed Windows/Azure
    environments targeting critical 2026 vulnerabilities.

.DESCRIPTION
    Checks for and remediates (where possible) the following critical CVEs
    from Microsoft's January-March 2026 Patch Tuesday releases:

    ON-PREMISES / WINDOWS:
      CVE-2026-21262  - SQL Server Elevation of Privilege (CVSS 8.8)
                        Improper access controls allow network attacker with low
                        privileges to gain sysadmin. Patch + config hardening.

      CVE-2026-26113  - Microsoft Office RCE via Preview Pane (CVSS 8.4)
                        Untrusted pointer dereference; exploitable through Preview
                        Pane. Patch + attack surface reduction rules.

      CVE-2026-26127  - .NET DoS via Out-of-Bounds Read (CVSS 7.5)
                        Affects .NET 9.0/10.0. Patch + runtime version audit.

      CVE-2026-21195  - Windows NTLM Hash Disclosure (CVSS 6.5)
                        Spoofing vulnerability leading to credential relay.
                        Patch + NTLM hardening.

    CLOUD / AZURE / ENTRA:
      CVE-2026-24305  - Azure Entra ID Privilege Escalation
                        Improper authorization allows unauthenticated escalation.
                        Configuration review + monitoring.

      CVE-2026-32211  - Azure MCP Server Auth Bypass (CVSS 9.1)
                        Missing authentication in Azure MCP Server exposes data.
                        Configuration review + monitoring.

    GENERAL HARDENING:
      - Windows Update compliance check
      - TLS 1.0/1.1 deprecation enforcement
      - SMBv1 removal verification
      - NTLM relay protections (EPA, LDAP signing)
      - Attack Surface Reduction (ASR) rules for Office exploits
      - .NET runtime inventory and patching

    Modes:
      -AuditOnly   : Assess only, make no changes (default)
      -Remediate   : Apply fixes where safe and automated

    All actions are logged. Destructive operations prompt for confirmation
    unless -Force is specified.

.PARAMETER AuditOnly
    Run in assessment mode. Report findings without making changes.
    This is the default behavior.

.PARAMETER Remediate
    Apply automated remediations where possible. Will prompt for
    confirmation on each remediation step unless -Force is specified.

.PARAMETER Force
    Skip confirmation prompts during remediation. Use with caution.

.PARAMETER OutputDirectory
    Directory for reports. Default: .\CVE_Remediation_<timestamp>

.EXAMPLE
    .\Invoke-CVERemediation.ps1
    Runs audit-only mode and generates a report.

.EXAMPLE
    .\Invoke-CVERemediation.ps1 -Remediate
    Applies remediations with confirmation prompts.

.EXAMPLE
    .\Invoke-CVERemediation.ps1 -Remediate -Force -OutputDirectory "C:\Remediation"
    Applies all remediations without prompts.

.NOTES
    Author  : Spencer Gaines
    Version : 1.0
    Date    : 2026-04-05

    DISCLAIMER: This script is provided as-is. Test in a non-production
    environment before deploying. The author is not responsible for any
    unintended consequences. Always validate patches in your environment.

    References:
      - https://msrc.microsoft.com/update-guide
      - https://www.tenable.com/blog/microsofts-march-2026-patch-tuesday-addresses-83-cves-cve-2026-21262-cve-2026-26127
      - https://www.sentinelone.com/vulnerability-database/cve-2026-24305/
      - https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws/
      - CIS Benchmarks, DISA STIGs, NIST 800-53 Rev 5
#>

[CmdletBinding(DefaultParameterSetName = "Audit")]
param(
    [Parameter(ParameterSetName = "Audit")]
    [switch]$AuditOnly,

    [Parameter(ParameterSetName = "Remediate")]
    [switch]$Remediate,

    [Parameter(ParameterSetName = "Remediate")]
    [switch]$Force,

    [string]$OutputDirectory
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

#region ── Setup ──────────────────────────────────────────────────────────────
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $OutputDirectory) {
    $OutputDirectory = ".\CVE_Remediation_$timestamp"
}
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$mode = if ($Remediate) { "REMEDIATE" } else { "AUDIT" }
$logFile = "$OutputDirectory\remediation_log_$timestamp.txt"

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$remediationActions = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts][$Level] $Message"
    $entry | Out-File -Append -FilePath $logFile
    $color = switch ($Level) {
        "WARN"       { "Yellow" }
        "ERROR"      { "Red" }
        "PASS"       { "Green" }
        "REMEDIATED" { "Cyan" }
        "VULN"       { "Magenta" }
        default      { "White" }
    }
    Write-Host $entry -ForegroundColor $color
}

function Add-CVEFinding {
    param(
        [string]$CVE,
        [string]$Title,
        [string]$Severity,
        [string]$Status,
        [string]$Detail,
        [string]$Remediation,
        [string]$Reference
    )
    $findings.Add([PSCustomObject]@{
        CVE           = $CVE
        Title         = $Title
        Severity      = $Severity
        Status        = $Status
        Detail        = $Detail
        Remediation   = $Remediation
        Reference     = $Reference
        CheckedAt     = (Get-Date -Format "o")
        Hostname      = $env:COMPUTERNAME
    })
}

function Confirm-Action {
    param([string]$Message)
    if ($Force) { return $true }
    $response = Read-Host "$Message [y/N]"
    return ($response -eq 'y' -or $response -eq 'Y')
}

function Add-RemediationAction {
    param([string]$CVE, [string]$Action, [string]$Result)
    $remediationActions.Add([PSCustomObject]@{
        CVE       = $CVE
        Action    = $Action
        Result    = $Result
        Timestamp = (Get-Date -Format "o")
        Hostname  = $env:COMPUTERNAME
    })
}

Write-Log "CVE Remediation Package started in $mode mode"
Write-Log "Host: $env:COMPUTERNAME | OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
#endregion

#region ── Windows Update Compliance ──────────────────────────────────────────
Write-Log "=== Checking Windows Update Compliance ==="

try {
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
    $lastPatch = $hotfixes | Select-Object -First 1
    $daysSincePatch = if ($lastPatch.InstalledOn) {
        ((Get-Date) - $lastPatch.InstalledOn).Days
    } else { 999 }

    Write-Log "Last patch installed: $($lastPatch.HotFixID) on $($lastPatch.InstalledOn)"
    Write-Log "Total patches installed: $($hotfixes.Count)"

    if ($daysSincePatch -gt 30) {
        Add-CVEFinding -CVE "GENERAL" -Title "Windows Update Compliance" -Severity "High" `
            -Status "VULNERABLE" `
            -Detail "Last patch was $daysSincePatch days ago ($($lastPatch.HotFixID) on $($lastPatch.InstalledOn)). System may be missing critical security updates." `
            -Remediation "Run Windows Update immediately. Install all critical and security updates." `
            -Reference "https://msrc.microsoft.com/update-guide"
        Write-Log "System is $daysSincePatch days behind on patches" "VULN"
    } else {
        Write-Log "Patch compliance OK ($daysSincePatch days since last update)" "PASS"
    }

    # Check for specific March 2026 Patch Tuesday KBs
    $march2026KBs = @("KB5035845", "KB5035849", "KB5035853", "KB5035857")
    $installedMarch = $hotfixes | Where-Object { $_.HotFixID -in $march2026KBs }
    if (-not $installedMarch) {
        Add-CVEFinding -CVE "GENERAL" -Title "March 2026 Patch Tuesday" -Severity "Critical" `
            -Status "MISSING" `
            -Detail "March 2026 cumulative update not detected. This update addresses CVE-2026-21262, CVE-2026-26113, CVE-2026-26127, and 80+ other vulnerabilities." `
            -Remediation "Install the March 2026 cumulative update from Windows Update or WSUS." `
            -Reference "https://www.bleepingcomputer.com/news/microsoft/microsoft-march-2026-patch-tuesday-fixes-2-zero-days-79-flaws/"
        Write-Log "March 2026 Patch Tuesday update NOT installed" "VULN"
    } else {
        Write-Log "March 2026 Patch Tuesday update installed ($($installedMarch.HotFixID))" "PASS"
    }

    $hotfixes | Select-Object HotFixID, Description, InstalledOn, InstalledBy |
        Export-Csv "$OutputDirectory\InstalledPatches.csv" -NoTypeInformation
} catch {
    Write-Log "Could not query Windows Update status: $_" "ERROR"
}
#endregion

#region ── CVE-2026-21262: SQL Server Privilege Escalation ────────────────────
Write-Log "=== CVE-2026-21262: SQL Server Elevation of Privilege (CVSS 8.8) ==="

$sqlInstances = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue

if ($sqlInstances) {
    $instanceNames = $sqlInstances.PSObject.Properties | Where-Object { $_.Name -ne "PSPath" -and
        $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSProvider" -and
        $_.Name -ne "PSDrive" } | ForEach-Object { $_.Name }

    foreach ($instance in $instanceNames) {
        Write-Log "Found SQL Server instance: $instance"

        # Check SQL Server version/build
        $sqlRegPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($sqlInstances.$instance)\MSSQLServer\CurrentVersion"
        $sqlVersion = Get-ItemProperty $sqlRegPath -ErrorAction SilentlyContinue

        if ($sqlVersion) {
            Write-Log "SQL Version: $($sqlVersion.CurrentVersion)"
        }

        # Check if SQL service is running
        $sqlService = Get-Service -Name "MSSQL`$$instance" -ErrorAction SilentlyContinue
        if (-not $sqlService) {
            $sqlService = Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue
        }

        if ($sqlService -and $sqlService.Status -eq "Running") {
            Add-CVEFinding -CVE "CVE-2026-21262" `
                -Title "SQL Server EoP - Instance: $instance" `
                -Severity "High" `
                -Status "REVIEW REQUIRED" `
                -Detail "SQL Server instance '$instance' is running. Verify the March 2026 CU/GDR is applied. An authenticated attacker can escalate to sysadmin over the network." `
                -Remediation "1) Identify servicing path (GDR vs CU) 2) Apply March 2026 security update 3) Audit sysadmin role membership 4) Enable SQL Audit for privilege changes" `
                -Reference "https://socprime.com/blog/cve-2026-21262-vulnerability/"
            Write-Log "SQL instance '$instance' running - verify March 2026 patch applied" "VULN"

            if ($Remediate) {
                # Audit sysadmin membership
                try {
                    $connString = "Server=localhost\$instance;Integrated Security=True;TrustServerCertificate=True"
                    if ($instance -eq "MSSQLSERVER") { $connString = "Server=localhost;Integrated Security=True;TrustServerCertificate=True" }

                    $conn = New-Object System.Data.SqlClient.SqlConnection($connString)
                    $conn.Open()
                    $cmd = $conn.CreateCommand()
                    $cmd.CommandText = "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1"
                    $reader = $cmd.ExecuteReader()

                    $sysadmins = @()
                    while ($reader.Read()) {
                        $sysadmins += [PSCustomObject]@{
                            Name       = $reader["name"]
                            Type       = $reader["type_desc"]
                            IsDisabled = $reader["is_disabled"]
                        }
                    }
                    $reader.Close()
                    $conn.Close()

                    $sysadmins | Export-Csv "$OutputDirectory\SQL_Sysadmins_$instance.csv" -NoTypeInformation
                    Write-Log "Exported $($sysadmins.Count) sysadmin accounts for instance '$instance'"
                    Add-RemediationAction -CVE "CVE-2026-21262" -Action "Exported sysadmin role membership" -Result "SUCCESS"
                } catch {
                    Write-Log "Could not audit SQL sysadmins for '$instance': $_" "WARN"
                }
            }
        }
    }
} else {
    Write-Log "No SQL Server instances found on this host" "PASS"
}
#endregion

#region ── CVE-2026-26113: Office RCE via Preview Pane ────────────────────────
Write-Log "=== CVE-2026-26113: Microsoft Office RCE - Preview Pane (CVSS 8.4) ==="

$officeInstalls = @(
    "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
    "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot"
)

$officeFound = $false
foreach ($regPath in $officeInstalls) {
    if (Test-Path $regPath) {
        $officeFound = $true
        $officeConfig = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if ($officeConfig.VersionToReport) {
            Write-Log "Office version: $($officeConfig.VersionToReport)"
        }
        if ($officeConfig.UpdateChannel) {
            Write-Log "Update channel: $($officeConfig.UpdateChannel)"
        }
    }
}

if ($officeFound) {
    Add-CVEFinding -CVE "CVE-2026-26113" `
        -Title "Office RCE via Preview Pane" `
        -Severity "Critical" `
        -Status "REVIEW REQUIRED" `
        -Detail "Microsoft Office is installed. CVE-2026-26113 allows RCE through the Preview Pane (no user click required). An untrusted pointer dereference in Office can be triggered by viewing a malicious document." `
        -Remediation "1) Apply March 2026 Office update 2) Enable ASR rules for Office 3) Disable Preview Pane in high-risk environments 4) Block Office macros from the internet" `
        -Reference "https://msrc.microsoft.com/update-guide"

    # Check ASR rules for Office
    try {
        $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue

        # Key ASR rules for Office exploit protection
        $officeASR = @{
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office apps from injecting code into other processes"
            "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office apps from creating executable content"
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office apps from creating child processes"
            "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication apps from creating child processes"
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
        }

        $missingASR = @()
        foreach ($rule in $officeASR.Keys) {
            if ($asrRules -notcontains $rule) {
                $missingASR += $officeASR[$rule]
            }
        }

        if ($missingASR.Count -gt 0) {
            Add-CVEFinding -CVE "CVE-2026-26113" `
                -Title "Missing Office ASR Rules" `
                -Severity "High" `
                -Status "VULNERABLE" `
                -Detail "$($missingASR.Count) Attack Surface Reduction rules for Office are not enabled: $($missingASR -join '; ')" `
                -Remediation "Enable all Office-related ASR rules via Group Policy, Intune, or PowerShell." `
                -Reference "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference"
            Write-Log "$($missingASR.Count) Office ASR rules missing" "VULN"

            if ($Remediate) {
                if (Confirm-Action "Enable missing Office ASR rules?") {
                    foreach ($ruleId in $officeASR.Keys) {
                        if ($asrRules -notcontains $ruleId) {
                            try {
                                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                                    -AttackSurfaceReductionRules_Actions 1
                                Write-Log "Enabled ASR rule: $($officeASR[$ruleId])" "REMEDIATED"
                                Add-RemediationAction -CVE "CVE-2026-26113" `
                                    -Action "Enabled ASR rule: $($officeASR[$ruleId])" -Result "SUCCESS"
                            } catch {
                                Write-Log "Failed to enable ASR rule $ruleId : $_" "ERROR"
                                Add-RemediationAction -CVE "CVE-2026-26113" `
                                    -Action "Enable ASR rule: $($officeASR[$ruleId])" -Result "FAILED: $_"
                            }
                        }
                    }
                }
            }
        } else {
            Write-Log "All Office ASR rules enabled" "PASS"
        }
    } catch {
        Write-Log "Could not check ASR rules (Windows Defender may not be active): $_" "WARN"
    }
} else {
    Write-Log "Microsoft Office not detected on this host" "PASS"
}
#endregion

#region ── CVE-2026-26127: .NET DoS (Out-of-Bounds Read) ─────────────────────
Write-Log "=== CVE-2026-26127: .NET Denial of Service (CVSS 7.5) ==="

$dotnetRuntimes = @()
try {
    $runtimeOutput = & dotnet --list-runtimes 2>&1
    foreach ($line in $runtimeOutput) {
        if ($line -match "^([\w.]+)\s+([\d.]+)\s+\[(.+)\]") {
            $dotnetRuntimes += [PSCustomObject]@{
                Runtime = $Matches[1]
                Version = $Matches[2]
                Path    = $Matches[3]
            }
        }
    }
} catch {
    Write-Log "dotnet CLI not found in PATH" "WARN"
}

if ($dotnetRuntimes.Count -gt 0) {
    $dotnetRuntimes | Export-Csv "$OutputDirectory\DotNetRuntimes.csv" -NoTypeInformation
    Write-Log "Found $($dotnetRuntimes.Count) .NET runtimes installed"

    $affected = $dotnetRuntimes | Where-Object {
        ($_.Version -match "^9\." -or $_.Version -match "^10\.")
    }

    if ($affected) {
        Add-CVEFinding -CVE "CVE-2026-26127" `
            -Title ".NET DoS - Affected Runtime Versions" `
            -Severity "High" `
            -Status "REVIEW REQUIRED" `
            -Detail "Affected .NET runtimes found: $(($affected | ForEach-Object { "$($_.Runtime) $($_.Version)" }) -join ', '). Out-of-bounds read allows unauthenticated network DoS." `
            -Remediation "Update .NET runtimes to the latest patched version via 'dotnet workload update' or download from https://dotnet.microsoft.com" `
            -Reference "https://github.com/dotnet/announcements/issues"
        Write-Log "Affected .NET runtimes detected" "VULN"
    } else {
        Write-Log "No affected .NET 9.x/10.x runtimes found" "PASS"
    }
} else {
    Write-Log "No .NET runtimes detected" "PASS"
}
#endregion

#region ── CVE-2026-21195: NTLM Hash Disclosure ──────────────────────────────
Write-Log "=== NTLM Relay & Hash Disclosure Hardening ==="

# Extended Protection for Authentication (EPA)
$epaStatus = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SuppressExtendedProtection" -ErrorAction SilentlyContinue
$ntlmRestrict = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
$lmCompat = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

$ntlmIssues = @()

# LM Compatibility Level should be 5 (Send NTLMv2 response only, refuse LM & NTLM)
if (-not $lmCompat -or $lmCompat.LmCompatibilityLevel -lt 5) {
    $currentLevel = if ($lmCompat) { $lmCompat.LmCompatibilityLevel } else { "Not Set (default 3)" }
    $ntlmIssues += "LmCompatibilityLevel is $currentLevel (should be 5)"

    Add-CVEFinding -CVE "CVE-2026-21195" `
        -Title "NTLM - Weak LM Compatibility Level" `
        -Severity "High" `
        -Status "VULNERABLE" `
        -Detail "LmCompatibilityLevel is $currentLevel. Should be 5 to refuse LM/NTLM and only send NTLMv2." `
        -Remediation "Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel to 5" `
        -Reference "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"
    Write-Log "LmCompatibilityLevel is $currentLevel (should be 5)" "VULN"

    if ($Remediate -and (Confirm-Action "Set LmCompatibilityLevel to 5 (NTLMv2 only)?")) {
        try {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord
            Write-Log "Set LmCompatibilityLevel to 5" "REMEDIATED"
            Add-RemediationAction -CVE "CVE-2026-21195" -Action "Set LmCompatibilityLevel to 5" -Result "SUCCESS"
        } catch {
            Write-Log "Failed to set LmCompatibilityLevel: $_" "ERROR"
        }
    }
} else {
    Write-Log "LmCompatibilityLevel is 5 (NTLMv2 only)" "PASS"
}

# LDAP Signing
$ldapSigning = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
if (-not $ldapSigning -or $ldapSigning.LDAPServerIntegrity -ne 2) {
    $currentVal = if ($ldapSigning) { $ldapSigning.LDAPServerIntegrity } else { "Not Set" }
    Add-CVEFinding -CVE "CVE-2026-21195" `
        -Title "LDAP Signing Not Required" `
        -Severity "Medium" `
        -Status "VULNERABLE" `
        -Detail "LDAP server signing is set to '$currentVal' (should be 2 = Required). Enables NTLM relay via LDAP." `
        -Remediation "Set LDAPServerIntegrity to 2 at HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -Reference "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server"

    if ($Remediate -and (Confirm-Action "Enable LDAP signing requirement?")) {
        try {
            if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters")) {
                Write-Log "NTDS registry key not found - this host may not be a domain controller" "WARN"
            } else {
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
                Write-Log "Enabled LDAP signing requirement" "REMEDIATED"
                Add-RemediationAction -CVE "CVE-2026-21195" -Action "Set LDAPServerIntegrity to 2" -Result "SUCCESS"
            }
        } catch {
            Write-Log "Failed to set LDAP signing: $_" "ERROR"
        }
    }
}

# SMB Signing
$smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smbConfig) {
    if (-not $smbConfig.RequireSecuritySignature) {
        Add-CVEFinding -CVE "CVE-2026-21195" `
            -Title "SMB Signing Not Required" `
            -Severity "Medium" `
            -Status "VULNERABLE" `
            -Detail "SMB server does not require signing. Enables NTLM relay attacks via SMB." `
            -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true" `
            -Reference "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing"

        if ($Remediate -and (Confirm-Action "Enable required SMB signing?")) {
            try {
                Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false
                Write-Log "Enabled required SMB signing" "REMEDIATED"
                Add-RemediationAction -CVE "CVE-2026-21195" -Action "Enabled SMB signing requirement" -Result "SUCCESS"
            } catch {
                Write-Log "Failed to enable SMB signing: $_" "ERROR"
            }
        }
    } else {
        Write-Log "SMB signing is required" "PASS"
    }
}
#endregion

#region ── TLS Hardening ──────────────────────────────────────────────────────
Write-Log "=== TLS Protocol Hardening ==="

$tlsVersions = @(
    @{ Name = "TLS 1.0"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"; ShouldBeDisabled = $true },
    @{ Name = "TLS 1.1"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"; ShouldBeDisabled = $true },
    @{ Name = "SSL 3.0"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"; ShouldBeDisabled = $true }
)

foreach ($tls in $tlsVersions) {
    $enabled = $true # default if not configured
    if (Test-Path $tls.Path) {
        $val = Get-ItemProperty $tls.Path -Name "Enabled" -ErrorAction SilentlyContinue
        if ($val -and $val.Enabled -eq 0) { $enabled = $false }
    }

    if ($enabled -and $tls.ShouldBeDisabled) {
        Add-CVEFinding -CVE "GENERAL" -Title "$($tls.Name) Still Enabled" -Severity "Medium" `
            -Status "VULNERABLE" `
            -Detail "$($tls.Name) is enabled on this server. Deprecated protocols are susceptible to downgrade attacks." `
            -Remediation "Disable $($tls.Name) via registry: Set Enabled=0, DisabledByDefault=1 under SCHANNEL protocols." `
            -Reference "https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings"
        Write-Log "$($tls.Name) is still enabled" "VULN"

        if ($Remediate -and (Confirm-Action "Disable $($tls.Name)?")) {
            try {
                $serverPath = $tls.Path
                $clientPath = $tls.Path -replace "\\Server$", "\Client"

                foreach ($p in @($serverPath, $clientPath)) {
                    if (-not (Test-Path $p)) {
                        New-Item -Path $p -Force | Out-Null
                    }
                    Set-ItemProperty $p -Name "Enabled" -Value 0 -Type DWord
                    Set-ItemProperty $p -Name "DisabledByDefault" -Value 1 -Type DWord
                }
                Write-Log "Disabled $($tls.Name)" "REMEDIATED"
                Add-RemediationAction -CVE "GENERAL" -Action "Disabled $($tls.Name)" -Result "SUCCESS"
            } catch {
                Write-Log "Failed to disable $($tls.Name): $_" "ERROR"
            }
        }
    } else {
        Write-Log "$($tls.Name) is disabled" "PASS"
    }
}
#endregion

#region ── SMBv1 Removal ──────────────────────────────────────────────────────
Write-Log "=== SMBv1 Protocol Check ==="

try {
    $smb1Server = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue

    if ($smb1Server -or ($smb1Feature -and $smb1Feature.State -eq "Enabled")) {
        Add-CVEFinding -CVE "GENERAL" -Title "SMBv1 Enabled" -Severity "Critical" `
            -Status "VULNERABLE" `
            -Detail "SMBv1 is still enabled. This protocol is exploited by EternalBlue, WannaCry, and numerous NTLM relay attacks." `
            -Remediation "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol `$false; Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" `
            -Reference "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
        Write-Log "SMBv1 is ENABLED" "VULN"

        if ($Remediate -and (Confirm-Action "Disable SMBv1?")) {
            try {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
                Write-Log "Disabled SMBv1 server" "REMEDIATED"
                Add-RemediationAction -CVE "GENERAL" -Action "Disabled SMBv1" -Result "SUCCESS"
            } catch {
                Write-Log "Failed to disable SMBv1: $_" "ERROR"
            }
        }
    } else {
        Write-Log "SMBv1 is disabled" "PASS"
    }
} catch {
    Write-Log "Could not check SMBv1 status: $_" "WARN"
}
#endregion

#region ── Azure / Entra ID Cloud CVEs ────────────────────────────────────────
Write-Log "=== Azure & Entra ID Cloud CVE Assessment ==="

# These are cloud-side vulnerabilities. We check for configuration hygiene
# and provide guidance. Actual patching is Microsoft's responsibility.

Write-Log "--- CVE-2026-24305: Entra ID Privilege Escalation ---"
Add-CVEFinding -CVE "CVE-2026-24305" `
    -Title "Azure Entra ID Privilege Escalation" `
    -Severity "Critical" `
    -Status "REVIEW REQUIRED" `
    -Detail "CVE-2026-24305 affects Azure Entra ID authorization controls. While Microsoft patches the service, tenant admins must verify: 1) No unauthorized role assignments occurred 2) Conditional Access policies are enforced 3) PIM is active for privileged roles." `
    -Remediation "1) Audit Entra ID role assignments for unexpected Global Admins 2) Review sign-in logs for anomalous activity 3) Enable PIM with approval workflows 4) Run Invoke-EntraIDAudit.ps1 for comprehensive assessment" `
    -Reference "https://www.sentinelone.com/vulnerability-database/cve-2026-24305/"

Write-Log "--- CVE-2026-32211: Azure MCP Server Auth Bypass (CVSS 9.1) ---"
Add-CVEFinding -CVE "CVE-2026-32211" `
    -Title "Azure MCP Server Missing Authentication" `
    -Severity "Critical" `
    -Status "REVIEW REQUIRED" `
    -Detail "CVE-2026-32211 is a critical information disclosure flaw (CVSS 9.1) caused by missing authentication in Azure MCP Server. Unauthorized access to sensitive data possible." `
    -Remediation "1) Review Azure MCP Server configurations 2) Verify authentication is enforced on all endpoints 3) Monitor access logs for unauthorized requests 4) Contact Microsoft support if using Azure MCP Server" `
    -Reference "https://windowsnews.ai/article/cve-2026-32211-critical-azure-mcp-server-authentication-flaw-exposes-sensitive-data-cvss-91.409622"

# Check if Azure CLI / Az module is available for deeper checks
$azModule = Get-Module -ListAvailable -Name Az.Accounts -ErrorAction SilentlyContinue
if ($azModule) {
    Write-Log "Az PowerShell module detected - use Invoke-EntraIDAudit.ps1 for cloud-side assessment"
} else {
    Write-Log "Az PowerShell module not installed - cloud-side checks limited to guidance" "WARN"
}
#endregion

#region ── Generate Reports ───────────────────────────────────────────────────
Write-Log "=== Generating Reports ==="

$findings | Export-Csv "$OutputDirectory\CVE_Findings.csv" -NoTypeInformation
if ($remediationActions.Count -gt 0) {
    $remediationActions | Export-Csv "$OutputDirectory\RemediationActions.csv" -NoTypeInformation
}

# Summary counts
$criticalCount = ($findings | Where-Object { $_.Severity -eq "Critical" }).Count
$highCount     = ($findings | Where-Object { $_.Severity -eq "High" }).Count
$mediumCount   = ($findings | Where-Object { $_.Severity -eq "Medium" }).Count
$vulnCount     = ($findings | Where-Object { $_.Status -match "VULNERABLE|MISSING" }).Count
$reviewCount   = ($findings | Where-Object { $_.Status -eq "REVIEW REQUIRED" }).Count

# HTML Report
$htmlPath = "$OutputDirectory\CVE_Remediation_Report.html"
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CVE Remediation Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 2rem; background: #1a1a2e; color: #e0e0e0; }
        .container { max-width: 1200px; margin: 0 auto; background: #16213e; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.4); }
        h1 { color: #e94560; border-bottom: 3px solid #e94560; padding-bottom: 0.5rem; }
        h2 { color: #0f3460; background: #e94560; display: inline-block; padding: 0.3rem 1rem; border-radius: 4px; color: white; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
        th { background: #0f3460; color: #e0e0e0; padding: 10px 12px; text-align: left; }
        td { padding: 8px 12px; border-bottom: 1px solid #1a1a2e; }
        tr:hover { background: #0f3460; }
        .critical { color: #ff4757; font-weight: bold; }
        .high { color: #ffa502; font-weight: bold; }
        .medium { color: #eccc68; font-weight: bold; }
        .vuln { color: #ff4757; }
        .pass { color: #2ed573; }
        .review { color: #ffa502; }
        .summary-box { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
        .summary-card { padding: 1rem 1.5rem; border-radius: 6px; color: white; flex: 1; text-align: center; min-width: 150px; }
        .summary-card h3 { margin: 0; font-size: 2rem; }
        .summary-card p { margin: 0.25rem 0 0; font-size: 0.9rem; }
        .bg-critical { background: #ff4757; }
        .bg-high { background: #ff6348; }
        .bg-medium { background: #ffa502; color: #333; }
        .bg-review { background: #3742fa; }
        .bg-remediated { background: #2ed573; color: #333; }
        .disclaimer { background: #0f3460; border-left: 4px solid #e94560; padding: 1rem; margin-top: 2rem; border-radius: 0 4px 4px 0; }
        a { color: #70a1ff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CVE Remediation Assessment Report</h1>
        <p>
            <strong>Host:</strong> $env:COMPUTERNAME |
            <strong>Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |
            <strong>Mode:</strong> $mode |
            <strong>OS:</strong> $((Get-CimInstance Win32_OperatingSystem).Caption)
        </p>

        <div class="summary-box">
            <div class="summary-card bg-critical"><h3>$criticalCount</h3><p>Critical</p></div>
            <div class="summary-card bg-high"><h3>$highCount</h3><p>High</p></div>
            <div class="summary-card bg-medium"><h3>$mediumCount</h3><p>Medium</p></div>
            <div class="summary-card bg-review"><h3>$reviewCount</h3><p>Review Required</p></div>
            <div class="summary-card bg-remediated"><h3>$($remediationActions.Count)</h3><p>Remediated</p></div>
        </div>

        <h2>CVE Findings</h2>
        <table>
            <tr><th>CVE</th><th>Severity</th><th>Status</th><th>Title</th><th>Detail</th><th>Remediation</th></tr>
$(foreach ($f in ($findings | Sort-Object @{Expression={switch($_.Severity){"Critical"{0}"High"{1}"Medium"{2}"Low"{3}}};})) {
    $sevClass = $f.Severity.ToLower()
    $statClass = switch -Wildcard ($f.Status) { "VULNERABLE*" { "vuln" } "MISSING*" { "vuln" } "REVIEW*" { "review" } default { "pass" } }
    "            <tr><td><strong>$($f.CVE)</strong></td><td class='$sevClass'>$($f.Severity)</td><td class='$statClass'>$($f.Status)</td><td>$($f.Title)</td><td>$($f.Detail)</td><td>$($f.Remediation)</td></tr>`n"
})
        </table>

$(if ($remediationActions.Count -gt 0) {
@"
        <h2>Remediation Actions Taken</h2>
        <table>
            <tr><th>CVE</th><th>Action</th><th>Result</th><th>Timestamp</th></tr>
$(foreach ($a in $remediationActions) {
    "            <tr><td>$($a.CVE)</td><td>$($a.Action)</td><td>$($a.Result)</td><td>$($a.Timestamp)</td></tr>`n"
})
        </table>
"@
})

        <div class="disclaimer">
            <strong>Disclaimer:</strong> This report is generated for assessment purposes.
            Always validate findings and test remediations in a non-production environment.
            Cloud-side CVEs (Entra ID, Azure) require review of Microsoft's security advisories
            for service-side mitigations.
        </div>

        <p style="color: #666; text-align: center; margin-top: 2rem;">
            Generated by Invoke-CVERemediation.ps1 v1.0
        </p>
    </div>
</body>
</html>
"@
$html | Out-File -FilePath $htmlPath -Encoding utf8
Write-Log "HTML report: $htmlPath"

# Console summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkRed
Write-Host "  CVE REMEDIATION ASSESSMENT SUMMARY" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor DarkRed
Write-Host "  Host       : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Mode       : $mode" -ForegroundColor $(if ($Remediate) { "Cyan" } else { "Yellow" })
Write-Host "  Date       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  CRITICAL   : $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
Write-Host "  HIGH       : $highCount" -ForegroundColor $(if ($highCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  MEDIUM     : $mediumCount" -ForegroundColor $(if ($mediumCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  VULNERABLE : $vulnCount" -ForegroundColor $(if ($vulnCount -gt 0) { "Red" } else { "Green" })
Write-Host "  REVIEW REQ : $reviewCount" -ForegroundColor $(if ($reviewCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  REMEDIATED : $($remediationActions.Count)" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Output     : $OutputDirectory" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor DarkRed
Write-Host ""

Write-Log "Assessment complete."
#endregion

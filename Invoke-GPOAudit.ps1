#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Comprehensive Group Policy Object audit for an Active Directory domain.

.DESCRIPTION
    Performs a multi-phase GPO audit:
      Phase 1 - Security group references in all GPOs
      Phase 2 - GPO settings inventory (scripts, software, preferences, drive maps, etc.)
      Phase 3 - Stale/disabled/empty GPO detection
      Phase 4 - GPO delegation review (non-standard accounts with GPO rights)
      Phase 5 - HTML report generation

    Outputs:
      - GPO_SecurityGroupRefs.csv  - GPOs referencing specific security groups
      - GPO_Settings.csv           - All configured GPO settings
      - GPO_StaleReport.csv        - Disabled, empty, or unlinked GPOs
      - GPO_Delegation.csv         - GPO delegation findings
      - GPO_AuditReport.html       - Full HTML report

    Read-only: Makes no changes to Group Policy or Active Directory.

.PARAMETER SecurityGroupsCSV
    Optional path to security groups CSV from Get-UniqueSecurityGroups.ps1.
    If provided, Phase 1 scans for those specific groups.
    If omitted, Phase 1 is skipped.

.PARAMETER OutputPath
    Directory for output files. Defaults to current directory.

.PARAMETER HTMLReport
    If specified, generates an HTML report.

.PARAMETER StaleThresholdDays
    GPOs not modified within this many days are flagged as potentially stale.
    Default: 180

.EXAMPLE
    .\Invoke-GPOAudit.ps1 -HTMLReport

.EXAMPLE
    .\Invoke-GPOAudit.ps1 -SecurityGroupsCSV ".\UniqueSecurityGroups.csv" -HTMLReport -OutputPath "C:\Audits"

.NOTES
    Requires: ActiveDirectory and GroupPolicy PowerShell modules (RSAT + GPMC)
    Run as domain admin or GPO read-only delegated account.
    Read-only: No changes made.
#>

[CmdletBinding()]
param(
    [string]$SecurityGroupsCSV  = "",
    [string]$OutputPath         = ".",
    [switch]$HTMLReport,
    [int]   $StaleThresholdDays = 180
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

$startTime = Get-Date

foreach ($mod in @('ActiveDirectory','GroupPolicy')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "$mod module not found. Install RSAT."
        exit 1
    }
    Import-Module $mod -ErrorAction Stop
}

$domainName  = (Get-ADDomain).DNSRoot
$domainDN    = (Get-ADDomain).DistinguishedName

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$secGroupRefsFile = Join-Path $OutputPath "GPO_SecurityGroupRefs.csv"
$settingsFile     = Join-Path $OutputPath "GPO_Settings.csv"
$staleFile        = Join-Path $OutputPath "GPO_StaleReport.csv"
$delegationFile   = Join-Path $OutputPath "GPO_Delegation.csv"
$htmlFile         = Join-Path $OutputPath "GPO_AuditReport.html"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Group Policy Object Audit"                            -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Domain: $domainName"
Write-Host "  Output: $OutputPath"
Write-Host ""

# -- Load all GPOs -------------------------------------------------------------
Write-Host "Loading all GPOs..." -ForegroundColor Yellow
try {
    $allGPOs = @(Get-GPO -All -ErrorAction Stop)
    Write-Host "  Found $($allGPOs.Count) GPOs." -ForegroundColor Green
}
catch {
    Write-Error "Failed to load GPOs: $_"
    exit 1
}

$Errors = [System.Collections.Generic.List[string]]::new()

# =============================================================================
# Phase 1 - Security group references
# =============================================================================
$SecurityGroupRefs = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($SecurityGroupsCSV -and (Test-Path $SecurityGroupsCSV)) {
    Write-Host ""
    Write-Host "Phase 1: Security group reference scan..." -ForegroundColor Cyan
    $groups = @(Import-Csv -Path $SecurityGroupsCSV -Encoding ASCII)
    Write-Host "  Loaded $($groups.Count) groups from $SecurityGroupsCSV"

    $i = 0
    foreach ($gpo in $allGPOs) {
        $i++
        Write-Progress -Activity "Phase 1 - Group refs" -Status $gpo.DisplayName -PercentComplete (($i / $allGPOs.Count) * 100)

        # Security filter
        try {
            $perms = @(Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop)
            foreach ($perm in $perms) {
                $matchedGrp = $groups | Where-Object {
                    $_.GroupName -eq $perm.Trustee.Name -or $_.SamAccountName -eq $perm.Trustee.Name
                }
                foreach ($mg in @($matchedGrp)) {
                    $SecurityGroupRefs.Add([PSCustomObject]@{
                        GPOName   = $gpo.DisplayName
                        GPOID     = $gpo.Id
                        MatchType = "SecurityFilter"
                        GroupName = $mg.GroupName
                        Detail    = "Permission: $($perm.Permission)"
                    })
                }
            }
        }
        catch { $Errors.Add("[P1-Perms] $($gpo.DisplayName): $_") }

        # XML content
        try {
            $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
            foreach ($g in $groups) {
                if ($report -match [regex]::Escape($g.GroupName) -or $report -match [regex]::Escape($g.SamAccountName)) {
                    $SecurityGroupRefs.Add([PSCustomObject]@{
                        GPOName   = $gpo.DisplayName
                        GPOID     = $gpo.Id
                        MatchType = "XMLContent"
                        GroupName = $g.GroupName
                        Detail    = "Group found in GPO settings XML"
                    })
                }
            }
        }
        catch { $Errors.Add("[P1-XML] $($gpo.DisplayName): $_") }
    }
    Write-Progress -Activity "Phase 1 - Group refs" -Completed
    $SecurityGroupRefs | Export-Csv -Path $secGroupRefsFile -NoTypeInformation -Encoding ASCII
    Write-Host "  Matches found: $($SecurityGroupRefs.Count)" -ForegroundColor Green
}
else {
    Write-Host "Phase 1: Skipped (no SecurityGroupsCSV provided)" -ForegroundColor Gray
}

# =============================================================================
# Phase 2 - Settings inventory
# =============================================================================
Write-Host ""
Write-Host "Phase 2: Settings inventory..." -ForegroundColor Cyan

$GPOSettings = [System.Collections.Generic.List[PSCustomObject]]::new()

$settingsPatterns = @{
    'LogonScript'     = 'logonscript|scripts.*logon'
    'LogoffScript'    = 'logoffscript|scripts.*logoff'
    'StartupScript'   = 'startupscript|scripts.*startup'
    'ShutdownScript'  = 'shutdownscript|scripts.*shutdown'
    'DriveMapping'    = 'DriveMapSettings|DriveMaps'
    'Shortcut'        = 'ShortcutSettings|Shortcuts'
    'SoftwareInstall' = 'SoftwareInstallation|SoftwareSettings'
    'Registry'        = 'RegistrySettings|RegistryKeys'
    'Printer'         = 'PrinterSettings|Printers'
    'ScheduledTask'   = 'ScheduledTaskSettings|ScheduledTasks'
    'SecuritySetting' = 'SecuritySettings|secedit'
    'FirewallRule'    = 'FirewallSettings|WindowsFirewall'
    'UserRights'      = 'UserRightsAssignment|SeNetworkLogon|SeBatch|SeService'
    'AuditPolicy'     = 'AuditSettings|SuccessOrFailure'
    'RestrictedGroups'= 'RestrictedGroups|GroupMembership'
}

$i = 0
foreach ($gpo in $allGPOs) {
    $i++
    Write-Progress -Activity "Phase 2 - Settings" -Status $gpo.DisplayName -PercentComplete (($i / $allGPOs.Count) * 100)
    try {
        $xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
        foreach ($settingType in $settingsPatterns.Keys) {
            if ($xml -match $settingsPatterns[$settingType]) {
                $GPOSettings.Add([PSCustomObject]@{
                    GPOName     = $gpo.DisplayName
                    GPOID       = $gpo.Id
                    GPOStatus   = $gpo.GpoStatus
                    SettingType = $settingType
                    UserVsComp  = if ($xml -match '<User>') { 'Both' } else { 'Computer' }
                })
            }
        }
    }
    catch { $Errors.Add("[P2] $($gpo.DisplayName): $_") }
}

Write-Progress -Activity "Phase 2 - Settings" -Completed
$GPOSettings | Export-Csv -Path $settingsFile -NoTypeInformation -Encoding ASCII
Write-Host "  Settings found: $($GPOSettings.Count)" -ForegroundColor Green

# =============================================================================
# Phase 3 - Stale / empty / disabled GPOs
# =============================================================================
Write-Host ""
Write-Host "Phase 3: Stale/empty/disabled GPO detection..." -ForegroundColor Cyan

$StaleReport = [System.Collections.Generic.List[PSCustomObject]]::new()
$staleDate   = (Get-Date).AddDays(-$StaleThresholdDays)

# Get all GPO links across domain
$allLinks = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
try {
    $linkedGPOs = @(Get-ADObject -Filter { ObjectClass -eq 'organizationalUnit' -or ObjectClass -eq 'domainDNS' } `
        -Properties gpLink -SearchBase $domainDN -ErrorAction Stop)
    foreach ($obj in $linkedGPOs) {
        if ($obj.gpLink) {
            [regex]::Matches($obj.gpLink, '\{[A-F0-9\-]+\}', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) |
                ForEach-Object { [void]$allLinks.Add($_.Value.ToUpper()) }
        }
    }
}
catch { $Errors.Add("[P3-Links]: $_") }

$i = 0
foreach ($gpo in $allGPOs) {
    $i++
    Write-Progress -Activity "Phase 3 - Stale" -Status $gpo.DisplayName -PercentComplete (($i / $allGPOs.Count) * 100)

    $reasons = [System.Collections.Generic.List[string]]::new()
    $gpoIdUpper = "{$($gpo.Id.ToString().ToUpper())}"

    if ($gpo.GpoStatus -eq 'AllSettingsDisabled')          { $reasons.Add('AllSettingsDisabled') }
    if ($gpo.GpoStatus -eq 'UserSettingsDisabled')         { $reasons.Add('UserSettingsDisabled') }
    if ($gpo.GpoStatus -eq 'ComputerSettingsDisabled')     { $reasons.Add('ComputerSettingsDisabled') }
    if (-not $allLinks.Contains($gpoIdUpper))              { $reasons.Add('NotLinked') }
    if ($gpo.ModificationTime -lt $staleDate)              { $reasons.Add("NotModifiedIn${StaleThresholdDays}Days") }

    # Check for empty GPO (no settings)
    try {
        $xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
        if ($xml -notmatch '<(Computer|User)>[\s\S]*</(Computer|User)>') {
            $reasons.Add('NoSettings')
        }
    }
    catch { $Errors.Add("[P3-Empty] $($gpo.DisplayName): $_") }

    if ($reasons.Count -gt 0) {
        $StaleReport.Add([PSCustomObject]@{
            GPOName      = $gpo.DisplayName
            GPOID        = $gpo.Id
            GpoStatus    = $gpo.GpoStatus
            Created      = $gpo.CreationTime.ToString('yyyy-MM-dd')
            LastModified = $gpo.ModificationTime.ToString('yyyy-MM-dd')
            Reasons      = $reasons -join '; '
        })
    }
}

Write-Progress -Activity "Phase 3 - Stale" -Completed
$StaleReport | Export-Csv -Path $staleFile -NoTypeInformation -Encoding ASCII
Write-Host "  Stale/empty/disabled GPOs: $($StaleReport.Count)" -ForegroundColor Green

# =============================================================================
# Phase 4 - Delegation review
# =============================================================================
Write-Host ""
Write-Host "Phase 4: Delegation review..." -ForegroundColor Cyan

$DelegationFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
$standardPerms      = @('GpoRead','GpoApply')
$expectedTrustees   = @('Domain Admins','Enterprise Admins','CREATOR OWNER','SYSTEM','Authenticated Users','ENTERPRISE DOMAIN CONTROLLERS')

$i = 0
foreach ($gpo in $allGPOs) {
    $i++
    Write-Progress -Activity "Phase 4 - Delegation" -Status $gpo.DisplayName -PercentComplete (($i / $allGPOs.Count) * 100)
    try {
        $perms = @(Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop)
        foreach ($perm in $perms) {
            $isExpected  = $false
            foreach ($et in $expectedTrustees) {
                if ($perm.Trustee.Name -match [regex]::Escape($et)) { $isExpected = $true; break }
            }
            $isElevated = $perm.Permission -notin $standardPerms

            if ($isElevated -and -not $isExpected) {
                $DelegationFindings.Add([PSCustomObject]@{
                    GPOName     = $gpo.DisplayName
                    GPOID       = $gpo.Id
                    Trustee     = $perm.Trustee.Name
                    TrusteeType = $perm.Trustee.SidType
                    Permission  = $perm.Permission
                    IsElevated  = $isElevated
                })
            }
        }
    }
    catch { $Errors.Add("[P4] $($gpo.DisplayName): $_") }
}

Write-Progress -Activity "Phase 4 - Delegation" -Completed
$DelegationFindings | Export-Csv -Path $delegationFile -NoTypeInformation -Encoding ASCII
Write-Host "  Delegation findings: $($DelegationFindings.Count)" -ForegroundColor Green

# =============================================================================
# Phase 5 - HTML Report
# =============================================================================
if ($HTMLReport) {
    Write-Host ""
    Write-Host "Phase 5: Generating HTML report..." -ForegroundColor Cyan

    function ConvertTo-HtmlTable {
        param($Data, [string[]]$Columns)
        if (-not $Data -or $Data.Count -eq 0) { return "<p>No data.</p>" }
        $header = ($Columns | ForEach-Object { "<th>$_</th>" }) -join ''
        $rows = ($Data | ForEach-Object {
            $row = $_
            $cells = ($Columns | ForEach-Object { "<td>$($row.$_)</td>" }) -join ''
            "<tr>$cells</tr>"
        }) -join "`n"
        return "<table><tr>$header</tr>$rows</table>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>GPO Audit Report - $domainName</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; color: #333; }
  h1   { color: #1a1a2e; border-bottom: 2px solid #1a1a2e; padding-bottom: 10px; }
  h2   { color: #1a1a2e; margin-top: 40px; }
  table { border-collapse:collapse; width:100%; margin: 15px 0; font-size:13px; }
  th    { background:#1a1a2e; color:#fff; padding:8px 10px; text-align:left; }
  td    { padding:6px 10px; border-bottom:1px solid #eee; vertical-align:top; }
  tr:hover td { background:#f5f5f5; }
  .summary-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:15px; margin:20px 0; }
  .card { background:#f8f9fa; border:1px solid #dee2e6; border-radius:8px; padding:15px; text-align:center; }
  .card h3 { margin:0; font-size:28px; color:#1a1a2e; }
  .card p  { margin:5px 0 0; font-size:13px; color:#666; }
  .meta    { font-size:12px; color:#888; margin-top: 30px; border-top: 1px solid #eee; padding-top:10px; }
</style>
</head>
<body>
<h1>Group Policy Audit Report</h1>
<div class='meta'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Domain: $domainName | Auditor: $($env:USERDOMAIN)\$($env:USERNAME)</div>

<div class='summary-grid'>
  <div class='card'><h3>$($allGPOs.Count)</h3><p>Total GPOs</p></div>
  <div class='card'><h3>$($StaleReport.Count)</h3><p>Stale/Empty/Disabled</p></div>
  <div class='card'><h3>$($DelegationFindings.Count)</h3><p>Delegation Findings</p></div>
  <div class='card'><h3>$($SecurityGroupRefs.Count)</h3><p>Group References</p></div>
</div>

<h2>Stale / Empty / Disabled GPOs</h2>
$(ConvertTo-HtmlTable $StaleReport @('GPOName','GpoStatus','LastModified','Reasons'))

<h2>Delegation Findings</h2>
$(ConvertTo-HtmlTable $DelegationFindings @('GPOName','Trustee','TrusteeType','Permission'))

<h2>Settings Inventory</h2>
$(ConvertTo-HtmlTable ($GPOSettings | Sort-Object SettingType, GPOName) @('GPOName','SettingType','GPOStatus','UserVsComp'))

$(if ($SecurityGroupRefs.Count -gt 0) {
    "<h2>Security Group References</h2>" + (ConvertTo-HtmlTable $SecurityGroupRefs @('GPOName','MatchType','GroupName','Detail'))
})

$(if ($Errors.Count -gt 0) {
    "<h2>Errors ($($Errors.Count))</h2><pre style='font-size:12px;color:#666'>" + ($Errors -join "`n") + "</pre>"
})

<div class='meta'>Duration: $([int]((Get-Date) - $startTime).TotalSeconds)s | Errors: $($Errors.Count)</div>
</body></html>
"@
    $html | Set-Content -Path $htmlFile -Encoding UTF8
    Write-Host "  HTML report: $htmlFile" -ForegroundColor Green
}

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Summary"                                               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Total GPOs:               $($allGPOs.Count)"         -ForegroundColor White
Write-Host "  Security group refs:      $($SecurityGroupRefs.Count)" -ForegroundColor White
Write-Host "  Settings found:           $($GPOSettings.Count)"     -ForegroundColor White
Write-Host "  Stale/disabled/empty:     $($StaleReport.Count)"     -ForegroundColor $(if ($StaleReport.Count -gt 0) {'Yellow'} else {'White'})
Write-Host "  Delegation findings:      $($DelegationFindings.Count)" -ForegroundColor $(if ($DelegationFindings.Count -gt 0) {'Yellow'} else {'White'})
Write-Host "  Errors:                   $($Errors.Count)"           -ForegroundColor $(if ($Errors.Count -gt 0) {'Yellow'} else {'White'})
Write-Host ""
Write-Host "Output files:" -ForegroundColor Yellow
Write-Host "  $settingsFile"
Write-Host "  $staleFile"
Write-Host "  $delegationFile"
if ($SecurityGroupRefs.Count -gt 0) { Write-Host "  $secGroupRefsFile" }
if ($HTMLReport) { Write-Host "  $htmlFile" }
Write-Host ""
Write-Host "Done. Duration: $([int]((Get-Date) - $startTime).TotalSeconds)s" -ForegroundColor Cyan

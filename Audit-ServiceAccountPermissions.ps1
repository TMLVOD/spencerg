#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audits Active Directory service account permissions and privilege configurations.

.DESCRIPTION
    Enumerates service accounts via MSA/gMSA discovery, naming convention patterns,
    and SPN detection, then evaluates each account across multiple security checks.

    Checks performed:
      Check 1  - Privileged group membership (Domain Admins, Schema Admins, etc.)
      Check 2  - Unconstrained Kerberos delegation (T4A)
      Check 3  - Constrained delegation targets and protocol transition (S4U2Self)
      Check 4  - Resource-Based Constrained Delegation (RBCD)
      Check 5  - SPN enumeration (Kerberoastable attack surface)
      Check 6  - Non-expiring passwords
      Check 7  - Password age threshold
      Check 8  - Reversible encryption enabled
      Check 9  - AdminCount = 1 (orphaned SDHolder)
      Check 10 - Disabled accounts (still configured as service accounts)
      Check 11 - Logon workstation restrictions (or lack thereof)
      Check 12 - AS-REP roastable (no Kerberos preauthentication required)
      Check 13 - Accounts never logged on but still enabled
      Check 14 - Stale accounts (no logon within threshold)
      Check 15 - Excessive AD object-level ACL rights (GenericAll, WriteDACL, etc.)
      Check 16 - Windows service mappings via CIM/WMI
      Check 17 - Local Administrators group membership on remote servers

    Outputs:
      - ServiceAccount_Findings.csv     - Main findings per account
      - AD_ACL_Findings.csv             - Object-level ACL findings (Check 15)
      - Service_Mappings.csv            - Windows service usage (Check 16)
      - LocalAdmin_Findings.csv         - Local admin membership (Check 17)
      - ServiceAccount_Report.html      - Optional HTML summary

    All operations are READ-ONLY. No changes are made to Active Directory.

.PARAMETER SearchBase
    OU Distinguished Name to scope the search (recommended).
    Example: "OU=Service Accounts,DC=corp,DC=local"
    If omitted, searches the entire domain.

.PARAMETER ServiceAccountPattern
    Array of wildcard patterns used to identify service accounts by name.
    Default: "svc_*","svc-*","sa_*","service_*","_svc","_sa"

.PARAMETER MaxPasswordAgeDays
    Password age threshold in days. Accounts older than this are flagged.
    Default: 90

.PARAMETER StaleLogonDays
    Days since last logon before account is considered stale.
    Default: 90

.PARAMETER HTMLReport
    If specified, generates an HTML summary report.

.PARAMETER WriteEventLog
    If specified, writes audit start/finish entries to the Windows Application log.

.PARAMETER IncludeWMIChecks
    If specified, runs service mapping (Check 16) and local admin checks (Check 17).
    Requires WinRM access to domain servers.

.PARAMETER OutputPath
    Directory for output files. Defaults to current directory.

.EXAMPLE
    .\Audit-ServiceAccountPermissions.ps1 -SearchBase "OU=Service Accounts,DC=corp,DC=local"

.EXAMPLE
    .\Audit-ServiceAccountPermissions.ps1 -SearchBase "OU=Service Accounts,DC=corp,DC=local" -HTMLReport -WriteEventLog

.EXAMPLE
    .\Audit-ServiceAccountPermissions.ps1 -ServiceAccountPattern "svc_*","sa_*" -MaxPasswordAgeDays 180 -IncludeWMIChecks

.NOTES
    Version : 2.0
    Requires: ActiveDirectory PowerShell module (RSAT)
              Run as domain admin or delegated read-only auditor.
    Read-only: Makes no changes to Active Directory or any system.
#>

[CmdletBinding()]
param(
    [string]  $SearchBase             = "",
    [string[]]$ServiceAccountPattern  = @("svc_*","svc-*","sa_*","service_*","*_svc","*_sa"),
    [int]     $MaxPasswordAgeDays     = 90,
    [int]     $StaleLogonDays         = 90,
    [switch]  $HTMLReport,
    [switch]  $WriteEventLog,
    [switch]  $IncludeWMIChecks,
    [string]  $OutputPath             = "."
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

$startTime = Get-Date

# -- Module check --------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell"
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$domainName = (Get-ADDomain).DNSRoot

# -- Output paths --------------------------------------------------------------
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$findingsFile    = Join-Path $OutputPath "ServiceAccount_Findings.csv"
$aclFile         = Join-Path $OutputPath "AD_ACL_Findings.csv"
$serviceFile     = Join-Path $OutputPath "Service_Mappings.csv"
$localAdminFile  = Join-Path $OutputPath "LocalAdmin_Findings.csv"
$htmlFile        = Join-Path $OutputPath "ServiceAccount_Report.html"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Service Account Permission Audit v2.0"               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Domain:      $domainName"
Write-Host "  Search base: $(if ($SearchBase) { $SearchBase } else { 'Entire domain' })"
Write-Host "  Pwd age threshold: $MaxPasswordAgeDays days"
Write-Host "  Stale logon:       $StaleLogonDays days"
Write-Host ""

if ($WriteEventLog) {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("ADSecurityAudit")) {
            New-EventLog -LogName Application -Source "ADSecurityAudit" -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source "ADSecurityAudit" -EntryType Information `
            -EventId 1000 -Message "Service account audit started on $domainName by $($env:USERDOMAIN)\$($env:USERNAME)"
    }
    catch { Write-Warning "Could not write to Event Log: $_" }
}

# -- Privileged groups to check ------------------------------------------------
$privilegedGroups = @(
    'Domain Admins','Schema Admins','Enterprise Admins','Group Policy Creator Owners',
    'Administrators','Account Operators','Backup Operators','Server Operators',
    'Print Operators','Remote Desktop Users','DNSAdmins'
)

# -- AD properties needed ------------------------------------------------------
$adProps = @(
    'SamAccountName','Name','DistinguishedName','Enabled','ObjectClass',
    'ServicePrincipalNames','TrustedForDelegation','TrustedToAuthForDelegation',
    'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',
    'PasswordNeverExpires','PasswordLastSet','LastLogonTimestamp','lastLogon',
    'AllowReversiblePasswordEncryption','DoesNotRequirePreAuth',
    'AdminCount','LogonWorkstations','MemberOf','UserAccountControl',
    'Description','Created','Modified'
)

# -- Enumerate service accounts ------------------------------------------------
Write-Host "Enumerating service accounts..." -ForegroundColor Yellow

$searchParams = @{ Properties = $adProps; ErrorAction = 'SilentlyContinue' }
if ($SearchBase) {
    # Validate OU exists
    try { $null = Get-ADOrganizationalUnit -Identity $SearchBase -ErrorAction Stop }
    catch { Write-Error "OU not found: $SearchBase"; exit 1 }
    $searchParams['SearchBase'] = $SearchBase
}

$allAccounts = [System.Collections.Generic.List[object]]::new()

# MSAs and gMSAs
@(Get-ADServiceAccount -Filter * @searchParams) | ForEach-Object { [void]$allAccounts.Add($_) }

# Pattern-matching user accounts
foreach ($pattern in $ServiceAccountPattern) {
    $filter = "SamAccountName -like '$pattern'"
    @(Get-ADUser -Filter $filter @searchParams) | ForEach-Object { [void]$allAccounts.Add($_) }
}

# SPN-bearing user accounts (Kerberoastable) - only if no SearchBase to avoid duplicates
if (-not $SearchBase) {
    @(Get-ADUser -Filter { ServicePrincipalNames -like "*" } @searchParams) |
        Where-Object { $_.SamAccountName -notin ($allAccounts | ForEach-Object { $_.SamAccountName }) } |
        ForEach-Object { [void]$allAccounts.Add($_) }
}

# Deduplicate
$seen     = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$accounts = [System.Collections.Generic.List[object]]::new()
foreach ($acct in $allAccounts) {
    if ($seen.Add($acct.SamAccountName)) { [void]$accounts.Add($acct) }
}

Write-Host "  Found $($accounts.Count) unique service accounts." -ForegroundColor Green
Write-Host ""

# -- Helper: last logon --------------------------------------------------------
function Get-EffectiveLastLogon {
    param($Account)
    $ts  = if ($Account.LastLogonTimestamp -and $Account.LastLogonTimestamp -gt 0) {
        [DateTime]::FromFileTime($Account.LastLogonTimestamp) } else { $null }
    $raw = if ($Account.lastLogon -and $Account.lastLogon -gt 0) {
        [DateTime]::FromFileTime($Account.lastLogon) } else { $null }
    if ($ts -and $raw)  { return if ($ts -gt $raw) { $ts } else { $raw } }
    if ($ts)            { return $ts }
    if ($raw)           { return $raw }
    return $null
}

# -- Main audit loop -----------------------------------------------------------
$Findings   = [System.Collections.Generic.List[PSCustomObject]]::new()
$staleDate  = (Get-Date).AddDays(-$StaleLogonDays)
$pwdDate    = (Get-Date).AddDays(-$MaxPasswordAgeDays)

$i = 0
foreach ($acct in $accounts) {
    $i++
    Write-Progress -Activity "Auditing service accounts" -Status $acct.SamAccountName -PercentComplete (($i / $accounts.Count) * 100)

    $findings     = [System.Collections.Generic.List[string]]::new()
    $severity     = 'Low'
    $isMSA        = $acct.ObjectClass -in @('msDS-ManagedServiceAccount','msDS-GroupManagedServiceAccount')

    $lastLogon    = Get-EffectiveLastLogon $acct
    $spnRaw       = $acct.PSObject.Properties['ServicePrincipalNames']
    $spns         = if ($spnRaw -and $spnRaw.Value) { @($spnRaw.Value) } else { @() }

    $memberOfRaw  = $acct.PSObject.Properties['MemberOf']
    $memberOf     = if ($memberOfRaw -and $memberOfRaw.Value) { @($memberOfRaw.Value) } else { @() }

    # Check 1 - Privileged group membership
    $privMembership = [System.Collections.Generic.List[string]]::new()
    foreach ($dn in $memberOf) {
        $cn = ($dn -split ',')[0] -replace '^CN='
        if ($cn -in $privilegedGroups) { $privMembership.Add($cn) }
    }
    if ($privMembership.Count -gt 0) {
        $findings.Add("Check01-PrivilegedGroup: $($privMembership -join '; ')")
        $severity = 'Critical'
    }

    # Check 2 - Unconstrained delegation
    if ($acct.TrustedForDelegation -and -not $isMSA) {
        $findings.Add("Check02-UnconstrainedDelegation")
        $severity = 'Critical'
    }

    # Check 3 - Constrained delegation
    $delegTo = $acct.PSObject.Properties['msDS-AllowedToDelegateTo']
    if ($delegTo -and $delegTo.Value -and @($delegTo.Value).Count -gt 0) {
        $proto = if ($acct.TrustedToAuthForDelegation) { " (Protocol Transition/S4U2Self)" } else { "" }
        $findings.Add("Check03-ConstrainedDelegation$proto`: $(@($delegTo.Value) -join '; ')")
        if ($acct.TrustedToAuthForDelegation) {
            if ($severity -ne 'Critical') { $severity = 'High' }
        } else {
            if ($severity -notin @('Critical','High')) { $severity = 'Medium' }
        }
    }

    # Check 4 - RBCD
    $rbcd = $acct.PSObject.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity']
    if ($rbcd -and $rbcd.Value) {
        $findings.Add("Check04-RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity set")
        if ($severity -ne 'Critical') { $severity = 'High' }
    }

    # Check 5 - Kerberoastable SPNs
    if ($spns.Count -gt 0 -and -not $isMSA) {
        $findings.Add("Check05-Kerberoastable: $($spns.Count) SPN(s) - $($spns -join '; ')")
        if ($severity -notin @('Critical','High')) { $severity = 'High' }
    }

    # Check 6 - Non-expiring password
    if ($acct.PasswordNeverExpires -and -not $isMSA) {
        $findings.Add("Check06-PasswordNeverExpires")
        if ($severity -notin @('Critical','High')) { $severity = 'Medium' }
    }

    # Check 7 - Password age
    if ($acct.PasswordLastSet -and $acct.PasswordLastSet -lt $pwdDate -and -not $isMSA) {
        $ageDays = [int]((Get-Date) - $acct.PasswordLastSet).TotalDays
        $findings.Add("Check07-OldPassword: $ageDays days old")
        if ($severity -notin @('Critical','High')) { $severity = 'Medium' }
    }

    # Check 8 - Reversible encryption
    if ($acct.AllowReversiblePasswordEncryption) {
        $findings.Add("Check08-ReversibleEncryption")
        if ($severity -ne 'Critical') { $severity = 'High' }
    }

    # Check 9 - AdminCount
    if ($acct.AdminCount -eq 1) {
        $findings.Add("Check09-AdminCount1")
        if ($severity -notin @('Critical','High')) { $severity = 'Medium' }
    }

    # Check 10 - Disabled
    if ($acct.Enabled -eq $false) {
        $findings.Add("Check10-Disabled")
    }

    # Check 11 - No logon workstation restriction
    $lw = $acct.PSObject.Properties['LogonWorkstations']
    if ($null -eq $lw -or [string]::IsNullOrWhiteSpace($lw.Value)) {
        $findings.Add("Check11-NoLogonRestriction: Can log on from any workstation")
        if ($severity -notin @('Critical','High')) { $severity = 'Low' }
    }

    # Check 12 - AS-REP roastable
    if ($acct.DoesNotRequirePreAuth) {
        $findings.Add("Check12-ASREPRoastable")
        if ($severity -ne 'Critical') { $severity = 'High' }
    }

    # Check 13 - Never logged on
    if ($null -eq $lastLogon -and $acct.Enabled) {
        $findings.Add("Check13-NeverLoggedOn")
        if ($severity -notin @('Critical','High','Medium')) { $severity = 'Low' }
    }

    # Check 14 - Stale
    if ($lastLogon -and $lastLogon -lt $staleDate -and $acct.Enabled) {
        $staleDays = [int]((Get-Date) - $lastLogon).TotalDays
        $findings.Add("Check14-StaleAccount: Last logon $staleDays days ago")
        if ($severity -notin @('Critical','High','Medium')) { $severity = 'Low' }
    }

    $pwdAge = if ($acct.PasswordLastSet) { [int]((Get-Date) - $acct.PasswordLastSet).TotalDays } else { $null }

    $Findings.Add([PSCustomObject]@{
        SamAccountName   = $acct.SamAccountName
        AccountType      = if ($isMSA) { $acct.ObjectClass } else { 'User' }
        Enabled          = $acct.Enabled
        Severity         = if ($findings.Count -eq 0) { 'None' } else { $severity }
        FindingCount     = $findings.Count
        Findings         = ($findings | ForEach-Object { $_ }) -join ' | '
        SPNCount         = $spns.Count
        PasswordAgeDays  = if ($null -ne $pwdAge) { $pwdAge } else { '' }
        LastLogon        = if ($lastLogon) { $lastLogon.ToString('yyyy-MM-dd') } else { 'Never' }
        AdminCount       = if ($acct.AdminCount) { $acct.AdminCount } else { 0 }
        DistinguishedName= $acct.DistinguishedName
        Description      = if ($acct.Description) { $acct.Description } else { '' }
    })
}

Write-Progress -Activity "Auditing service accounts" -Completed

# -- Check 15 - AD ACL Analysis ------------------------------------------------
Write-Host "Running Check 15: AD Object ACL analysis..." -ForegroundColor Yellow

$dangerousRights = @(
    'GenericAll','WriteDacl','WriteOwner','GenericWrite',
    'AllExtendedRights','ResetPassword','Self'
)

$ACLFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

$domainDN   = (Get-ADDomain).DistinguishedName
$domainSid  = (Get-ADDomain).DomainSID

$objectsToCheck = [System.Collections.Generic.List[string]]::new()
$objectsToCheck.Add($domainDN)
$objectsToCheck.Add("CN=AdminSDHolder,CN=System,$domainDN")

# Top-level OUs
@(Get-ADOrganizationalUnit -Filter * -SearchScope OneLevel -SearchBase $domainDN -ErrorAction SilentlyContinue) |
    ForEach-Object { $objectsToCheck.Add($_.DistinguishedName) }

# GPO container
$objectsToCheck.Add("CN=Policies,CN=System,$domainDN")

$svcSAMs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($a in $accounts) { [void]$svcSAMs.Add($a.SamAccountName) }

foreach ($objDN in $objectsToCheck) {
    try {
        $acl  = Get-Acl -Path "AD:\$objDN" -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            $trustee = $ace.IdentityReference.Value
            $trusteeSAM = ($trustee -split '\\')[-1]
            if ($svcSAMs.Contains($trusteeSAM)) {
                $rights = $ace.ActiveDirectoryRights.ToString()
                $isDangerous = $false
                foreach ($dr in $dangerousRights) {
                    if ($rights -match $dr) { $isDangerous = $true; break }
                }
                if ($isDangerous) {
                    $ACLFindings.Add([PSCustomObject]@{
                        ServiceAccount   = $trusteeSAM
                        TargetObject     = $objDN
                        Rights           = $rights
                        AccessType       = $ace.AccessControlType.ToString()
                        IsInherited      = $ace.IsInherited
                        InheritanceType  = $ace.InheritanceType.ToString()
                    })
                }
            }
        }
    }
    catch { Write-Warning "ACL check failed on $objDN`: $_" }
}

Write-Host "  ACL findings: $($ACLFindings.Count)" -ForegroundColor Gray

# -- Export all CSVs -----------------------------------------------------------
$Findings    | Export-Csv -Path $findingsFile   -NoTypeInformation -Encoding ASCII
$ACLFindings | Export-Csv -Path $aclFile        -NoTypeInformation -Encoding ASCII

# -- Check 16 + 17 (optional WMI/WinRM) ---------------------------------------
$ServiceMappings = [System.Collections.Generic.List[PSCustomObject]]::new()
$LocalAdminFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($IncludeWMIChecks) {
    Write-Host "Running Checks 16-17: WMI/WinRM service and local admin checks..." -ForegroundColor Yellow
    $servers = @(Get-ADComputer -Filter { OperatingSystem -like "*Server*" } -Properties OperatingSystem -ErrorAction SilentlyContinue)
    Write-Host "  Checking $($servers.Count) servers..." -ForegroundColor Gray

    foreach ($server in $servers) {
        # Check 16 - Windows services
        try {
            $services = @(Get-CimInstance -ClassName Win32_Service -ComputerName $server.Name -ErrorAction Stop |
                Where-Object { $_.StartName -and $svcSAMs.Contains(($_.StartName -split '\\')[-1]) })
            foreach ($svc in $services) {
                $ServiceMappings.Add([PSCustomObject]@{
                    Server       = $server.Name
                    ServiceName  = $svc.Name
                    DisplayName  = $svc.DisplayName
                    StartName    = $svc.StartName
                    State        = $svc.State
                    StartMode    = $svc.StartMode
                })
            }
        }
        catch { Write-Warning "WMI failed on $($server.Name): $_" }

        # Check 17 - Local Admins
        try {
            $localAdmins = Invoke-Command -ComputerName $server.Name -ScriptBlock {
                $members = @(net localgroup Administrators 2>$null)
                $members | Where-Object { $_ -match '\\' }
            } -ErrorAction Stop
            foreach ($member in @($localAdmins)) {
                $memberSAM = ($member -split '\\')[-1].Trim()
                if ($svcSAMs.Contains($memberSAM)) {
                    $LocalAdminFindings.Add([PSCustomObject]@{
                        Server         = $server.Name
                        ServiceAccount = $memberSAM
                        RawEntry       = $member
                    })
                }
            }
        }
        catch { Write-Warning "WinRM failed on $($server.Name): $_" }
    }

    $ServiceMappings    | Export-Csv -Path $serviceFile    -NoTypeInformation -Encoding ASCII
    $LocalAdminFindings | Export-Csv -Path $localAdminFile -NoTypeInformation -Encoding ASCII
    Write-Host "  Service mappings: $($ServiceMappings.Count)" -ForegroundColor Gray
    Write-Host "  Local admin hits: $($LocalAdminFindings.Count)" -ForegroundColor Gray
}

# -- HTML Report ---------------------------------------------------------------
if ($HTMLReport) {
    $critCount = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount  = @($Findings | Where-Object { $_.Severity -eq 'High'     }).Count
    $medCount   = @($Findings | Where-Object { $_.Severity -eq 'Medium'   }).Count
    $lowCount   = @($Findings | Where-Object { $_.Severity -eq 'Low'      }).Count

    $tableRows = ($Findings | Sort-Object Severity, SamAccountName | ForEach-Object {
        $color = switch ($_.Severity) {
            'Critical' { '#f8d7da' }
            'High'     { '#fff3cd' }
            'Medium'   { '#d1ecf1' }
            'Low'      { '#d4edda' }
            default    { '#f8f9fa' }
        }
        "<tr style='background:$color'>
          <td>$($_.SamAccountName)</td>
          <td>$($_.AccountType)</td>
          <td><strong>$($_.Severity)</strong></td>
          <td>$($_.FindingCount)</td>
          <td style='font-size:12px'>$($_.Findings -replace '\|','<br>')</td>
          <td>$($_.LastLogon)</td>
        </tr>"
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>Service Account Audit Report</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; color: #333; }
  h1   { color: #1a1a2e; }
  .summary { display:flex; gap:20px; margin:20px 0; }
  .card { padding:15px 25px; border-radius:8px; text-align:center; }
  .critical { background:#f8d7da; border:1px solid #f5c6cb; }
  .high     { background:#fff3cd; border:1px solid #ffeeba; }
  .medium   { background:#d1ecf1; border:1px solid #bee5eb; }
  .low      { background:#d4edda; border:1px solid #c3e6cb; }
  .card h2  { margin:0; font-size:32px; }
  .card p   { margin:4px 0 0; font-size:13px; }
  table { border-collapse:collapse; width:100%; margin-top:20px; }
  th    { background:#1a1a2e; color:#fff; padding:10px; text-align:left; font-size:13px; }
  td    { padding:8px 10px; border-bottom:1px solid #ddd; font-size:13px; vertical-align:top; }
  .meta { font-size:12px; color:#666; margin-top:30px; }
</style>
</head>
<body>
<h1>Service Account Audit Report</h1>
<div class='meta'>
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') |
  Domain: $domainName |
  Scope: $(if ($SearchBase) { $SearchBase } else { 'Entire Domain' }) |
  Auditor: $($env:USERDOMAIN)\$($env:USERNAME)
</div>
<div class='summary'>
  <div class='card critical'><h2>$critCount</h2><p>Critical</p></div>
  <div class='card high'>    <h2>$highCount</h2><p>High</p></div>
  <div class='card medium'>  <h2>$medCount</h2><p>Medium</p></div>
  <div class='card low'>     <h2>$lowCount</h2><p>Low</p></div>
</div>
<h2>Findings ($($Findings.Count) accounts)</h2>
<table>
  <tr><th>Account</th><th>Type</th><th>Severity</th><th>Issues</th><th>Findings</th><th>Last Logon</th></tr>
  $tableRows
</table>
<div class='meta'>ACL findings: $($ACLFindings.Count) - See AD_ACL_Findings.csv</div>
</body></html>
"@
    $html | Set-Content -Path $htmlFile -Encoding UTF8
    Write-Host "  HTML report: $htmlFile" -ForegroundColor Green
}

# -- Event Log close -----------------------------------------------------------
if ($WriteEventLog) {
    try {
        $duration = [int]((Get-Date) - $startTime).TotalSeconds
        Write-EventLog -LogName Application -Source "ADSecurityAudit" -EntryType Information `
            -EventId 1001 -Message "Service account audit completed. Accounts: $($accounts.Count), Findings: $($Findings.Count), Duration: ${duration}s"
    }
    catch {}
}

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Summary"                                               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Service accounts audited:  $($accounts.Count)"    -ForegroundColor White
Write-Host "  Accounts with findings:    $(@($Findings | Where-Object { $_.FindingCount -gt 0 }).Count)" -ForegroundColor White

$sevGroups = @('Critical','High','Medium','Low') 
foreach ($sev in $sevGroups) {
    $cnt = @($Findings | Where-Object { $_.Severity -eq $sev }).Count
    $color = switch ($sev) { 'Critical' {'Red'} 'High' {'Yellow'} 'Medium' {'Cyan'} default {'Gray'} }
    if ($cnt -gt 0) { Write-Host "    $sev`: $cnt" -ForegroundColor $color }
}

Write-Host "  ACL findings:              $($ACLFindings.Count)"  -ForegroundColor White
Write-Host ""
Write-Host "Output files:" -ForegroundColor Yellow
Write-Host "  $findingsFile"
Write-Host "  $aclFile"
if ($IncludeWMIChecks) {
    Write-Host "  $serviceFile"
    Write-Host "  $localAdminFile"
}
if ($HTMLReport) { Write-Host "  $htmlFile" }

Write-Host ""
Write-Host "Done. Duration: $([int]((Get-Date) - $startTime).TotalSeconds)s" -ForegroundColor Cyan

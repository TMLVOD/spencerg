#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Inventories all Active Directory computer objects with security-relevant data.

.DESCRIPTION
    Enumerates all computer objects in Active Directory and exports a detailed
    inventory CSV. Includes OS details, OU path, group memberships, LAPS coverage,
    staleness indicators, and security flags.

    Security data collected:
      - LAPS coverage (ms-Mcs-AdmPwd attribute presence)
      - Staleness based on most recent of LastLogonTimestamp and lastLogon
      - Password age
      - isCriticalSystemObject flag
      - Enabled/disabled status
      - SPN count
      - Group membership

    Console summary includes:
      - OS distribution breakdown
      - Server vs workstation counts
      - Security warnings for missing LAPS or never-logged-on systems

.PARAMETER OutputFile
    Path for the results CSV. Defaults to .\ADSystems_Inventory.csv

.PARAMETER StaleThresholdDays
    Number of days since last logon before a computer is flagged as stale.
    Default: 90

.EXAMPLE
    .\Get-ADSystems.ps1

.EXAMPLE
    .\Get-ADSystems.ps1 -OutputFile "C:\Audits\computers.csv" -StaleThresholdDays 60

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT)
    Run as a domain user with read access to AD computer objects.
#>

[CmdletBinding()]
param(
    [string]$OutputFile         = ".\ADSystems_Inventory.csv",
    [int]   $StaleThresholdDays = 90
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

# -- Module check --------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell"
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Active Directory Computer Inventory"                  -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

$staleDate = (Get-Date).AddDays(-$StaleThresholdDays)

# -- Properties to retrieve ----------------------------------------------------
$adProps = @(
    'Name','DNSHostName','IPv4Address','OperatingSystem','OperatingSystemVersion',
    'DistinguishedName','Description','Location','SID','ServicePrincipalNames',
    'MemberOf','ManagedBy','Enabled','LastLogonTimestamp','lastLogon',
    'PasswordLastSet','isCriticalSystemObject','ms-Mcs-AdmPwd','AdminCount',
    'Created','Modified','ObjectClass'
)

Write-Host "Querying Active Directory..." -ForegroundColor Yellow
try {
    $computers = @(Get-ADComputer -Filter * -Properties $adProps -ErrorAction Stop)
}
catch {
    Write-Error "Failed to query AD: $_"
    exit 1
}

Write-Host "Found $($computers.Count) computer objects. Processing..." -ForegroundColor Green
Write-Host ""

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

$i = 0
foreach ($computer in $computers) {
    $i++
    Write-Progress -Activity "Processing computers" -Status "$($computer.Name)" -PercentComplete (($i / $computers.Count) * 100)

    # -- Staleness -------------------------------------------------------------
    $lastLogonTS  = if ($null -ne $computer.LastLogonTimestamp -and $computer.LastLogonTimestamp -gt 0) {
        [DateTime]::FromFileTime($computer.LastLogonTimestamp)
    } else { $null }

    $lastLogonRaw = if ($null -ne $computer.lastLogon -and $computer.lastLogon -gt 0) {
        [DateTime]::FromFileTime($computer.lastLogon)
    } else { $null }

    # Most recent of the two logon timestamps
    $effectiveLastLogon = $null
    if ($lastLogonTS -and $lastLogonRaw) {
        $effectiveLastLogon = if ($lastLogonTS -gt $lastLogonRaw) { $lastLogonTS } else { $lastLogonRaw }
    } elseif ($lastLogonTS) {
        $effectiveLastLogon = $lastLogonTS
    } elseif ($lastLogonRaw) {
        $effectiveLastLogon = $lastLogonRaw
    }

    $isStale       = $effectiveLastLogon -eq $null -or $effectiveLastLogon -lt $staleDate
    $neverLoggedOn = $effectiveLastLogon -eq $null

    # -- LAPS ------------------------------------------------------------------
    $lapsValue  = $computer.PSObject.Properties['ms-Mcs-AdmPwd']
    $hasLAPS    = $null -ne $lapsValue -and -not [string]::IsNullOrEmpty($lapsValue.Value)

    # -- Password age ----------------------------------------------------------
    $pwdAge = if ($computer.PasswordLastSet) {
        [int]((Get-Date) - $computer.PasswordLastSet).TotalDays
    } else { $null }

    # -- SPNs ------------------------------------------------------------------
    $spnRaw   = $computer.PSObject.Properties['ServicePrincipalNames']
    $spnCount = if ($spnRaw -and $spnRaw.Value) { @($spnRaw.Value).Count } else { 0 }

    # -- Group memberships -----------------------------------------------------
    $memberOfRaw = $computer.PSObject.Properties['MemberOf']
    $groupCount  = if ($memberOfRaw -and $memberOfRaw.Value) { @($memberOfRaw.Value).Count } else { 0 }
    $groupNames  = if ($memberOfRaw -and $memberOfRaw.Value) {
        (@($memberOfRaw.Value) | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join '; '
    } else { '' }

    # -- OS category -----------------------------------------------------------
    $osName    = if ($computer.OperatingSystem) { $computer.OperatingSystem } else { 'Unknown' }
    $isServer  = $osName -match 'Server'

    # -- Managed by ------------------------------------------------------------
    $managedBy = if ($computer.ManagedBy) { ($computer.ManagedBy -split ',')[0] -replace '^CN=' } else { '' }

    $Results.Add([PSCustomObject]@{
        Name                = $computer.Name
        DNSHostName         = if ($computer.DNSHostName)           { $computer.DNSHostName }           else { '' }
        IPv4Address         = if ($computer.IPv4Address)            { $computer.IPv4Address }            else { '' }
        OperatingSystem     = $osName
        OSVersion           = if ($computer.OperatingSystemVersion) { $computer.OperatingSystemVersion } else { '' }
        IsServer            = $isServer
        Enabled             = $computer.Enabled
        OU                  = ($computer.DistinguishedName -replace '^CN=[^,]+,')
        Description         = if ($computer.Description)            { $computer.Description }            else { '' }
        Location            = if ($computer.Location)               { $computer.Location }               else { '' }
        SID                 = $computer.SID.Value
        SPNCount            = $spnCount
        GroupCount          = $groupCount
        Groups              = $groupNames
        ManagedBy           = $managedBy
        HasLAPS             = $hasLAPS
        IsStale             = $isStale
        NeverLoggedOn       = $neverLoggedOn
        LastLogon           = if ($effectiveLastLogon) { $effectiveLastLogon.ToString('yyyy-MM-dd') } else { 'Never' }
        PasswordLastSet     = if ($computer.PasswordLastSet)        { $computer.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
        PasswordAgeDays     = if ($null -ne $pwdAge)                { $pwdAge }                          else { '' }
        IsCriticalObject    = if ($computer.isCriticalSystemObject) { $computer.isCriticalSystemObject } else { $false }
        AdminCount          = if ($computer.AdminCount)             { $computer.AdminCount }             else { 0 }
        Created             = if ($computer.Created)                { $computer.Created.ToString('yyyy-MM-dd') } else { '' }
        Modified            = if ($computer.Modified)               { $computer.Modified.ToString('yyyy-MM-dd') } else { '' }
    })
}

Write-Progress -Activity "Processing computers" -Completed

# -- Export --------------------------------------------------------------------
try {
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding ASCII -ErrorAction Stop
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export CSV: $_"
    exit 1
}

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Summary"                                               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

$totalComputers  = $Results.Count
$enabledCount    = @($Results | Where-Object { $_.Enabled -eq $true }).Count
$serverCount     = @($Results | Where-Object { $_.IsServer -eq $true }).Count
$workstationCount= $totalComputers - $serverCount
$staleCount      = @($Results | Where-Object { $_.IsStale -eq $true }).Count
$neverCount      = @($Results | Where-Object { $_.NeverLoggedOn -eq $true }).Count
$noLAPSCount     = @($Results | Where-Object { $_.HasLAPS -eq $false -and $_.Enabled -eq $true }).Count

Write-Host "  Total computer objects:     $totalComputers"   -ForegroundColor White
Write-Host "  Enabled:                    $enabledCount"      -ForegroundColor White
Write-Host "  Servers:                    $serverCount"       -ForegroundColor White
Write-Host "  Workstations:               $workstationCount"  -ForegroundColor White
Write-Host ""

Write-Host "OS Distribution:" -ForegroundColor Yellow
$Results | Group-Object OperatingSystem | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("  {0,-45} {1}" -f $_.Name, $_.Count) -ForegroundColor Gray
}

Write-Host ""
Write-Host "Security Warnings:" -ForegroundColor Yellow

if ($staleCount -gt 0) {
    Write-Host "  [WARN] Stale computers (no logon in $StaleThresholdDays days): $staleCount" -ForegroundColor Yellow
}
if ($neverCount -gt 0) {
    Write-Host "  [WARN] Never logged on (enabled):  $neverCount" -ForegroundColor Yellow
}
if ($noLAPSCount -gt 0) {
    Write-Host "  [WARN] Enabled computers missing LAPS: $noLAPSCount" -ForegroundColor Red
}
if ($staleCount -eq 0 -and $neverCount -eq 0 -and $noLAPSCount -eq 0) {
    Write-Host "  No security warnings found." -ForegroundColor Green
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan

#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Enumerates unique security groups from AD user objects within a specified OU.

.DESCRIPTION
    Queries all user objects in a target OU, collects every group membership,
    deduplicates the list, and exports a CSV for use with downstream audit scripts
    such as Search-GPOsBySecurityGroup.ps1 and Search-SharePermissions.ps1.

.PARAMETER SearchBase
    Distinguished name of the OU to search. Required.

.PARAMETER OutputFile
    Path for the output CSV. Defaults to .\UniqueSecurityGroups.csv

.EXAMPLE
    .\Get-UniqueSecurityGroups.ps1 -SearchBase "OU=Users,DC=corp,DC=local"

.EXAMPLE
    .\Get-UniqueSecurityGroups.ps1 -SearchBase "OU=Users,DC=corp,DC=local" -OutputFile "C:\Audits\groups.csv"

.NOTES
    Requires: ActiveDirectory PowerShell module (RSAT)
    This is step 1 of 3 in the share permissions audit workflow.
    Output feeds Search-GPOsBySecurityGroup.ps1 and Search-SharePermissions.ps1.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SearchBase,

    [string]$OutputFile = ".\UniqueSecurityGroups.csv"
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell"
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Unique Security Group Enumeration"                    -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Search base: $SearchBase"
Write-Host ""

# -- Validate OU ---------------------------------------------------------------
try {
    $null = Get-ADOrganizationalUnit -Identity $SearchBase -ErrorAction Stop
}
catch {
    Write-Error "OU not found or inaccessible: $SearchBase`n$_"
    exit 1
}

# -- Query users ---------------------------------------------------------------
Write-Host "Querying user objects..." -ForegroundColor Yellow
try {
    $users = @(Get-ADUser -Filter * -SearchBase $SearchBase -Properties MemberOf -ErrorAction Stop)
}
catch {
    Write-Error "Failed to query users: $_"
    exit 1
}
Write-Host "  Found $($users.Count) user objects." -ForegroundColor Green

# -- Collect group DNs ---------------------------------------------------------
$groupDNs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

foreach ($user in $users) {
    $memberOfRaw = $user.PSObject.Properties['MemberOf']
    if ($memberOfRaw -and $memberOfRaw.Value) {
        foreach ($dn in @($memberOfRaw.Value)) {
            [void]$groupDNs.Add($dn)
        }
    }
}

Write-Host "  Found $($groupDNs.Count) unique group DNs. Resolving..." -ForegroundColor Yellow

# -- Resolve group objects -----------------------------------------------------
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$Errors  = [System.Collections.Generic.List[string]]::new()

$j = 0
foreach ($dn in $groupDNs) {
    $j++
    Write-Progress -Activity "Resolving groups" -Status $dn -PercentComplete (($j / $groupDNs.Count) * 100)

    try {
        $grp = Get-ADGroup -Identity $dn -Properties Description,GroupScope,GroupCategory -ErrorAction Stop
        $Results.Add([PSCustomObject]@{
            GroupName      = $grp.Name
            SamAccountName = $grp.SamAccountName
            DistinguishedName = $grp.DistinguishedName
            GroupScope     = $grp.GroupScope
            GroupCategory  = $grp.GroupCategory
            Description    = if ($grp.Description) { $grp.Description } else { '' }
        })
    }
    catch {
        $Errors.Add("Could not resolve: $dn - $_")
    }
}

Write-Progress -Activity "Resolving groups" -Completed

# -- Export --------------------------------------------------------------------
$sorted = $Results | Sort-Object GroupName
$sorted | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding ASCII

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Summary"                                               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Users scanned:          $($users.Count)"             -ForegroundColor White
Write-Host "  Unique groups found:    $($Results.Count)"           -ForegroundColor White
Write-Host "  Resolution errors:      $($Errors.Count)"            -ForegroundColor $(if ($Errors.Count -gt 0) {'Yellow'} else {'White'})
Write-Host "  Output file:            $OutputFile"                  -ForegroundColor White

if ($Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors:" -ForegroundColor Yellow
    $Errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

Write-Host ""
Write-Host "Done. Pass $OutputFile to Search-GPOsBySecurityGroup.ps1 or Search-SharePermissions.ps1." -ForegroundColor Cyan

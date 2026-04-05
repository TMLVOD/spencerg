#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Scans all domain GPOs for references to specified security groups.

.DESCRIPTION
    Reads a security groups CSV (from Get-UniqueSecurityGroups.ps1) and searches
    every GPO in the domain for references to those groups. Checks:
      - GPO security filtering (who the GPO applies to)
      - GPO delegation entries
      - GPO XML settings content (preferences, restricted groups, etc.)

    Exports all matches to CSV and prints a summary.

.PARAMETER InputFile
    Path to the CSV from Get-UniqueSecurityGroups.ps1.
    Default: .\UniqueSecurityGroups.csv

.PARAMETER OutputFile
    Path for the results CSV.
    Default: .\GPO_SecurityGroup_References.csv

.EXAMPLE
    .\Search-GPOsBySecurityGroup.ps1

.EXAMPLE
    .\Search-GPOsBySecurityGroup.ps1 -InputFile "C:\Audits\groups.csv" -OutputFile "C:\Audits\gpo_refs.csv"

.NOTES
    Requires: ActiveDirectory and GroupPolicy PowerShell modules (RSAT + GPMC)
    This is step 2 of 3 in the share permissions audit workflow.
#>

[CmdletBinding()]
param(
    [string]$InputFile  = ".\UniqueSecurityGroups.csv",
    [string]$OutputFile = ".\GPO_SecurityGroup_References.csv"
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

foreach ($mod in @('ActiveDirectory','GroupPolicy')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "$mod module not found. Install RSAT."
        exit 1
    }
    Import-Module $mod -ErrorAction Stop
}

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " GPO Security Group Reference Scanner"                 -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

# -- Load groups CSV -----------------------------------------------------------
if (-not (Test-Path $InputFile)) {
    Write-Error "Input file not found: $InputFile"
    exit 1
}
$groups = @(Import-Csv -Path $InputFile -Encoding ASCII)
Write-Host "  Loaded $($groups.Count) security groups from $InputFile" -ForegroundColor Green

# Build lookup sets for fast matching
$groupNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$groupSAMs  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($g in $groups) {
    [void]$groupNames.Add($g.GroupName)
    [void]$groupSAMs.Add($g.SamAccountName)
}

# -- Load all GPOs -------------------------------------------------------------
Write-Host "  Loading GPOs..." -ForegroundColor Yellow
try {
    $allGPOs = @(Get-GPO -All -ErrorAction Stop)
}
catch {
    Write-Error "Failed to retrieve GPOs: $_"
    exit 1
}
Write-Host "  Found $($allGPOs.Count) GPOs." -ForegroundColor Green

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$Errors  = [System.Collections.Generic.List[string]]::new()

function Add-Match {
    param($GPO, $MatchType, $GroupName, $Detail)
    $script:Results.Add([PSCustomObject]@{
        GPOName    = $GPO.DisplayName
        GPOID      = $GPO.Id
        GPOStatus  = $GPO.GpoStatus
        MatchType  = $MatchType
        GroupName  = $GroupName
        Detail     = $Detail
    })
}

$i = 0
foreach ($gpo in $allGPOs) {
    $i++
    Write-Progress -Activity "Scanning GPOs" -Status $gpo.DisplayName -PercentComplete (($i / $allGPOs.Count) * 100)

    # -- Security filtering ----------------------------------------------------
    try {
        $perms = @(Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop)
        foreach ($perm in $perms) {
            if ($groupNames.Contains($perm.Trustee.Name) -or $groupSAMs.Contains($perm.Trustee.Name)) {
                Add-Match $gpo "SecurityFilter" $perm.Trustee.Name "Permission: $($perm.Permission)"
            }
        }
    }
    catch {
        $Errors.Add("[Permissions] $($gpo.DisplayName): $_")
    }

    # -- GPO XML content --------------------------------------------------------
    try {
        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
        foreach ($g in $groups) {
            if ($gpoReport -match [regex]::Escape($g.GroupName) -or
                $gpoReport -match [regex]::Escape($g.SamAccountName)) {
                Add-Match $gpo "XMLContent" $g.GroupName "Group referenced in GPO settings XML"
            }
        }
    }
    catch {
        $Errors.Add("[XMLReport] $($gpo.DisplayName): $_")
    }
}

Write-Progress -Activity "Scanning GPOs" -Completed

# -- Export --------------------------------------------------------------------
$Results | Sort-Object GPOName | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding ASCII

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Summary"                                               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  GPOs scanned:       $($allGPOs.Count)"  -ForegroundColor White
Write-Host "  Matches found:      $($Results.Count)"  -ForegroundColor White
Write-Host "  Errors:             $($Errors.Count)"   -ForegroundColor $(if ($Errors.Count -gt 0) {'Yellow'} else {'White'})
Write-Host "  Output file:        $OutputFile"         -ForegroundColor White

$grouped = $Results | Group-Object MatchType
foreach ($grp in $grouped) {
    Write-Host "    $($grp.Name): $($grp.Count)" -ForegroundColor Gray
}

if ($Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors:" -ForegroundColor Yellow
    $Errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan

#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audits NTFS and share-level permissions on a file server against a list of
    target security groups.

.DESCRIPTION
    Prompts for a file server name, enumerates its SMB shares (excluding admin
    shares), lets you select which shares to scan, then checks both share-level
    and NTFS ACLs for references to groups from the input CSV.

    Uses .NET DirectorySecurity for reliable UNC ACL reads on remote paths.

    Outputs:
      - CSV of all ACE matches with path, permission type, access level, and
        inheritance information
      - Error log for inaccessible paths

.PARAMETER InputFile
    Path to the CSV from Get-UniqueSecurityGroups.ps1.
    Default: .\UniqueSecurityGroups.csv

.PARAMETER OutputFile
    Path for the results CSV.
    Default: .\SharePermissions_Results.csv

.EXAMPLE
    .\Search-SharePermissions.ps1

.EXAMPLE
    .\Search-SharePermissions.ps1 -InputFile "C:\Audits\groups.csv"

.NOTES
    Requires: ActiveDirectory module, SMB access to target server, read rights on share ACLs.
    Run as a domain admin or user with share/NTFS read permission.
    This is step 3 of 3 in the share permissions audit workflow.
#>

[CmdletBinding()]
param(
    [string]$InputFile  = ".\UniqueSecurityGroups.csv",
    [string]$OutputFile = ".\SharePermissions_Results.csv"
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

$ErrorLogFile = ".\SharePermissions_Errors.log"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Share Permission Audit - Security Groups"             -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

# -- Load groups CSV -----------------------------------------------------------
if (-not (Test-Path $InputFile)) {
    Write-Error "Input file not found: $InputFile"
    exit 1
}
$groups = @(Import-Csv -Path $InputFile -Encoding ASCII)
Write-Host "  Loaded $($groups.Count) groups from $InputFile" -ForegroundColor Green

$groupLookup = @{}
foreach ($g in $groups) {
    $groupLookup[$g.GroupName.ToLower()]      = $g
    $groupLookup[$g.SamAccountName.ToLower()] = $g
}

function Test-GroupMatch {
    param([string]$Identity)
    $parts = $Identity -split '\\'
    $name  = $parts[-1].ToLower()
    if ($script:groupLookup.ContainsKey($name)) { return $script:groupLookup[$name] }
    return $null
}

# -- Prompt for server ---------------------------------------------------------
do {
    $FileServer = (Read-Host "Enter file server name (e.g. FILESERVER01)").Trim().TrimStart('\')
} while ([string]::IsNullOrWhiteSpace($FileServer))

Write-Host "  Testing connectivity to $FileServer..." -ForegroundColor Yellow
if (-not (Test-Connection -ComputerName $FileServer -Count 1 -Quiet)) {
    Write-Error "Cannot reach $FileServer. Check name and network connectivity."
    exit 1
}
Write-Host "  Reachable." -ForegroundColor Green

# -- Enumerate shares ----------------------------------------------------------
Write-Host "  Enumerating shares on $FileServer..." -ForegroundColor Yellow
try {
    $cimSession = New-CimSession -ComputerName $FileServer -ErrorAction Stop
    $rawShares  = @(Get-SmbShare -CimSession $cimSession -ErrorAction Stop |
        Where-Object {
            $_.Name -notmatch '^\w\$$' -and
            $_.Name -notmatch '^(ADMIN|IPC|PRINT|FAX)\$$'
        })
    Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Failed to enumerate shares: $_"
    exit 1
}

if ($rawShares.Count -eq 0) {
    Write-Host "No accessible shares found on $FileServer." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "Available shares:" -ForegroundColor Yellow
Write-Host "  0  - Scan ALL shares"
for ($k = 0; $k -lt $rawShares.Count; $k++) {
    Write-Host ("  {0,-3} {1}" -f ($k + 1), $rawShares[$k].Name)
}

# -- Share selection -----------------------------------------------------------
do {
    $selection = (Read-Host "Enter share numbers to scan (comma-separated, or 0 for all)").Trim()
    $valid     = $selection -match '^[0-9,\s]+$'
    if ($valid) {
        $nums = @($selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        if ($nums -contains '0') {
            $SelectedShares = $rawShares
            $valid = $true
        } else {
            $indices = @($nums | ForEach-Object { [int]$_ - 1 })
            if (($indices | Where-Object { $_ -lt 0 -or $_ -ge $rawShares.Count }).Count -gt 0) {
                Write-Host "  Invalid selection. Try again." -ForegroundColor Red
                $valid = $false
            } else {
                $SelectedShares = @($indices | ForEach-Object { $rawShares[$_] })
            }
        }
    } else {
        Write-Host "  Invalid input. Enter numbers only." -ForegroundColor Red
    }
} while (-not $valid)

Write-Host ""
Write-Host "Scanning $($SelectedShares.Count) share(s) on $FileServer..." -ForegroundColor Yellow

$Results  = [System.Collections.Generic.List[PSCustomObject]]::new()
$ErrorLog = [System.Collections.Generic.List[string]]::new()
$totalFolders = 0

foreach ($share in $SelectedShares) {
    $uncRoot = "\\$FileServer\$($share.Name)"
    Write-Host "  [$($share.Name)] $uncRoot" -ForegroundColor Gray

    # -- Share-level permissions -----------------------------------------------
    try {
        $sharePerms = @(Get-SmbShareAccess -Name $share.Name -CimSession (New-CimSession -ComputerName $FileServer) -ErrorAction Stop)
        foreach ($sp in $sharePerms) {
            $matched = Test-GroupMatch -Identity $sp.AccountName
            if ($matched) {
                $Results.Add([PSCustomObject]@{
                    SecurityGroup  = $matched.GroupName
                    SamAccountName = $matched.SamAccountName
                    Path           = $uncRoot
                    PermissionType = "ShareLevel"
                    AccessType     = $sp.AccessControlType.ToString()
                    Rights         = $sp.AccessRight.ToString()
                    Inherited      = "N/A"
                    InheritFlags   = "N/A"
                })
            }
        }
    }
    catch {
        $ErrorLog.Add("[Share] $($share.Name): $_")
    }

    # -- NTFS ACLs - root + 1 level deep --------------------------------------
    if (-not (Test-Path $uncRoot)) {
        $ErrorLog.Add("[UNC] Not accessible: $uncRoot")
        continue
    }

    $foldersToScan = [System.Collections.Generic.List[string]]::new()
    $foldersToScan.Add($uncRoot)
    try {
        $subFolders = @(Get-ChildItem -LiteralPath $uncRoot -Directory -Depth 1 -ErrorAction Stop)
        foreach ($sf in $subFolders) { $foldersToScan.Add($sf.FullName) }
    }
    catch {
        $ErrorLog.Add("[Enum] $uncRoot : $_")
    }

    foreach ($folderPath in $foldersToScan) {
        $totalFolders++
        try {
            $acl = (New-Object System.Security.AccessControl.DirectorySecurity($folderPath, 'Access')).GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
        }
        catch {
            $ErrorLog.Add("[ACL] $folderPath : $_")
            continue
        }

        foreach ($ace in $acl) {
            $matched = Test-GroupMatch -Identity $ace.IdentityReference.Value
            if ($matched) {
                $Results.Add([PSCustomObject]@{
                    SecurityGroup  = $matched.GroupName
                    SamAccountName = $matched.SamAccountName
                    Path           = $folderPath
                    PermissionType = "NTFS"
                    AccessType     = $ace.AccessControlType.ToString()
                    Rights         = $ace.FileSystemRights.ToString()
                    Inherited      = $ace.IsInherited.ToString()
                    InheritFlags   = $ace.InheritanceFlags.ToString()
                })
            }
        }
    }
}

# -- Export --------------------------------------------------------------------
$Results | Sort-Object SecurityGroup, Path | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding ASCII

if ($ErrorLog.Count -gt 0) {
    $ErrorLog | Set-Content -Path $ErrorLogFile -Encoding ASCII
}

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Summary"                                               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  File server:              $FileServer"              -ForegroundColor White
Write-Host "  Shares scanned:           $($SelectedShares.Count)"-ForegroundColor White
Write-Host "  Scan depth:               1 level"                  -ForegroundColor White
Write-Host "  Total folders scanned:    $totalFolders"            -ForegroundColor White
Write-Host "  Total ACE matches:        $($Results.Count)"        -ForegroundColor White
Write-Host "  Errors:                   $($ErrorLog.Count)"       -ForegroundColor $(if ($ErrorLog.Count -gt 0) {'Yellow'} else {'White'})
Write-Host "  Results file:             $OutputFile"              -ForegroundColor White
if ($ErrorLog.Count -gt 0) {
    Write-Host "  Error log:                $ErrorLogFile"         -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Done." -ForegroundColor Cyan

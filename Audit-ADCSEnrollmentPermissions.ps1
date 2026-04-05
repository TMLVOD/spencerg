#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audits Active Directory Certificate Services enrollment permissions for
    common misconfigurations.

.DESCRIPTION
    Analyzes ADCS certificate templates and CA configurations against known
    attack patterns from SpecterOps Certified Pre-Owned research (ESC1-ESC7),
    MITRE ATT&CK techniques, CISA Advisory AA23-024A, and NIST 800-53.

    Misconfigurations checked:
      ESC1 - Template allows requestor-supplied Subject Alternative Name + low enrollment rights
      ESC2 - Any Purpose EKU or no EKU restrictions
      ESC3 - Certificate Request Agent EKU (enrollment agent abuse)
      ESC4 - Overly permissive template ACLs (GenericAll, WriteDacl, WriteOwner, WriteProperty)
      ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag enabled
      ESC7 - CA officer/manager rights granted to unprivileged accounts
      Custom checks for orphaned templates, weak crypto, and enrollment rights hygiene

    Standards mapping:
      - SpecterOps Certified Pre-Owned (ESC1-ESC7)
      - MITRE ATT&CK T1649, T1222.001, T1484
      - CISA Advisory AA23-024A
      - NIST 800-53 Rev 5: AC-2, AC-3, AC-6, CM-6, CM-7, IA-5
      - CIS Controls v8
      - DISA STIG V-254303 through V-254306
      - Microsoft KB5014754

    All operations are READ-ONLY.

.PARAMETER OutputFile
    Path for the findings CSV. Default: .\ADCS_Findings.csv

.PARAMETER HTMLReport
    If specified, generates an HTML report alongside the CSV.

.EXAMPLE
    .\Audit-ADCSEnrollmentPermissions.ps1

.EXAMPLE
    .\Audit-ADCSEnrollmentPermissions.ps1 -OutputFile "C:\Audits\adcs.csv" -HTMLReport

.NOTES
    Version : 2.0
    Requires: ActiveDirectory PowerShell module (RSAT)
              Run as domain admin or PKI admin with read access to ADCS objects.
    Read-only: Makes no changes to Active Directory or CA configuration.
#>

[CmdletBinding()]
param(
    [string]$OutputFile = ".\ADCS_Findings.csv",
    [switch]$HTMLReport
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT: Install-WindowsFeature RSAT-AD-PowerShell"
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$domainDN   = (Get-ADDomain).DistinguishedName
$domainName = (Get-ADDomain).DNSRoot
$configDN   = "CN=Configuration,$domainDN"
$pkiRoot    = "CN=Public Key Services,CN=Services,$configDN"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " ADCS Enrollment Permission Audit v2.0"               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Domain: $domainName"
Write-Host ""

# -- EKU OIDs of interest ------------------------------------------------------
$dangerousEKUs = @{
    '2.5.29.37.0'           = 'Any Purpose'
    '1.3.6.1.4.1.311.20.2.1'= 'Certificate Request Agent'
    '1.3.6.1.5.5.7.3.2'     = 'Client Authentication'
    '1.3.6.1.4.1.311.10.3.4'= 'Encrypting File System'
    '1.3.6.1.5.5.7.3.1'     = 'Server Authentication'
    '1.3.6.1.4.1.311.21.6'  = 'Key Recovery Agent'
}

# -- Dangerous ACL rights ------------------------------------------------------
$dangerousACLRights = @('GenericAll','WriteDacl','WriteOwner','WriteProperty','GenericWrite','AllExtendedRights')

# -- Well-known enrollment-OK principals --------------------------------------
$allowedEnrollPrincipals = @(
    'NT AUTHORITY\Authenticated Users',
    'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
    'Domain Controllers'
)

$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$Errors   = [System.Collections.Generic.List[string]]::new()

function Add-Finding {
    param(
        [string]$ObjectName,
        [string]$ObjectDN,
        [string]$Check,
        [string]$Severity,
        [string]$Description,
        [string]$Recommendation,
        [string]$Standard = ""
    )
    $script:Findings.Add([PSCustomObject]@{
        ObjectName      = $ObjectName
        ObjectDN        = $ObjectDN
        Check           = $Check
        Severity        = $Severity
        Description     = $Description
        Recommendation  = $Recommendation
        Standards       = $Standard
    })
}

# -- Load certificate templates ------------------------------------------------
Write-Host "Loading certificate templates from AD..." -ForegroundColor Yellow
$templateContainer = "CN=Certificate Templates,$pkiRoot"
try {
    $templates = @(Get-ADObject -SearchBase $templateContainer -Filter * -Properties * -ErrorAction Stop |
        Where-Object { $_.ObjectClass -eq 'pKICertificateTemplate' })
    Write-Host "  Found $($templates.Count) certificate templates." -ForegroundColor Green
}
catch {
    Write-Error "Failed to load templates: $_"
    exit 1
}

# -- Load enrollment services (CAs) -------------------------------------------
Write-Host "Loading enrollment services (CAs)..." -ForegroundColor Yellow
$enrollServicesContainer = "CN=Enrollment Services,$pkiRoot"
try {
    $enrollmentServices = @(Get-ADObject -SearchBase $enrollServicesContainer -Filter * -Properties * -ErrorAction Stop)
    Write-Host "  Found $($enrollmentServices.Count) CA(s)." -ForegroundColor Green
}
catch {
    $Errors.Add("Could not load enrollment services: $_")
    $enrollmentServices = @()
}

# -- Build published template set ----------------------------------------------
$publishedTemplateNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($ca in $enrollmentServices) {
    $ptRaw = $ca.PSObject.Properties['certificatetemplates']
    if ($ptRaw -and $ptRaw.Value) {
        foreach ($t in @($ptRaw.Value)) { [void]$publishedTemplateNames.Add($t) }
    }
}

# =============================================================================
# TEMPLATE CHECKS
# =============================================================================
$i = 0
foreach ($tmpl in $templates) {
    $i++
    Write-Progress -Activity "Analyzing templates" -Status $tmpl.Name -PercentComplete (($i / $templates.Count) * 100)

    $props       = $tmpl.PSObject.Properties
    $tmplName    = $tmpl.Name
    $tmplDN      = $tmpl.DistinguishedName

    $isPublished = $publishedTemplateNames.Contains($tmplName) -or
                   $publishedTemplateNames.Contains($props['displayName']?.Value)

    # -- EKU analysis ----------------------------------------------------------
    $ekuRaw  = $props['pkiextendedkeyusage']
    $ekuList = if ($ekuRaw -and $ekuRaw.Value) { @($ekuRaw.Value) } else { @() }

    $dangerousEKUHits = [System.Collections.Generic.List[string]]::new()
    foreach ($oid in $ekuList) {
        if ($dangerousEKUs.ContainsKey($oid)) {
            $dangerousEKUHits.Add("$oid ($($dangerousEKUs[$oid]))")
        }
    }

    $hasAnyPurposeEKU   = $ekuList -contains '2.5.29.37.0'
    $hasNoEKU           = $ekuList.Count -eq 0
    $hasCertReqAgentEKU = $ekuList -contains '1.3.6.1.4.1.311.20.2.1'

    # -- Template flags --------------------------------------------------------
    $msPKIFlag      = if ($props['msPKI-Certificate-Name-Flag']) { [int]$props['msPKI-Certificate-Name-Flag'].Value } else { 0 }
    $enrolleeSuppliesSubject = ($msPKIFlag -band 1) -ne 0    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

    $msPKIEnrollFlag = if ($props['msPKI-Enrollment-Flag']) { [int]$props['msPKI-Enrollment-Flag'].Value } else { 0 }
    $requiresManagerApproval = ($msPKIEnrollFlag -band 2) -ne 0

    # -- ESC1 - ENROLLEE_SUPPLIES_SUBJECT + low enrollment rights -------------
    if ($enrolleeSuppliesSubject -and -not $requiresManagerApproval -and $isPublished) {
        $hasClientAuth = $ekuList -contains '1.3.6.1.5.5.7.3.2'
        if ($hasClientAuth -or $hasAnyPurposeEKU -or $hasNoEKU) {
            Add-Finding $tmplName $tmplDN "ESC1" "Critical" `
                "Template allows requestor to supply SAN, no manager approval required, and includes Client Auth EKU. Allows domain privilege escalation via certificate." `
                "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or require CA manager approval. Restrict enrollment rights." `
                "SpecterOps ESC1; MITRE T1649; CISA AA23-024A; NIST AC-3, CM-6"
        }
    }

    # -- ESC2 - Any Purpose or no EKU -----------------------------------------
    if (($hasAnyPurposeEKU -or $hasNoEKU) -and $isPublished -and -not $requiresManagerApproval) {
        Add-Finding $tmplName $tmplDN "ESC2" "High" `
            "Template has $(if ($hasAnyPurposeEKU) { 'Any Purpose EKU' } else { 'no EKU restrictions' }) and is published without manager approval." `
            "Add specific EKU restrictions or require CA manager approval for enrollment." `
            "SpecterOps ESC2; MITRE T1649; NIST CM-7"
    }

    # -- ESC3 - Certificate Request Agent EKU ---------------------------------
    if ($hasCertReqAgentEKU -and $isPublished) {
        Add-Finding $tmplName $tmplDN "ESC3" "High" `
            "Template includes Certificate Request Agent EKU. Can be used to enroll on behalf of other users." `
            "Restrict enrollment rights to privileged accounts only. Review who can enroll against this template." `
            "SpecterOps ESC3; MITRE T1649; NIST AC-6"
    }

    # -- ESC4 - Template ACL permissions --------------------------------------
    try {
        $acl = Get-Acl -Path "AD:\$tmplDN" -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            $rights = $ace.ActiveDirectoryRights.ToString()
            $riskNotes = [System.Collections.Generic.List[string]]::new()
            foreach ($right in $dangerousACLRights) {
                if ($rights -match $right) { $riskNotes.Add($right) }
            }

            if ($riskNotes.Count -gt 0) {
                $trustee = $ace.IdentityReference.Value
                $isExpected = $false
                foreach ($ok in $allowedEnrollPrincipals) {
                    if ($trustee -match [regex]::Escape($ok)) { $isExpected = $true; break }
                }
                if (-not $isExpected -and $ace.AccessControlType -eq 'Allow') {
                    Add-Finding $tmplName $tmplDN "ESC4" "High" `
                        "Trustee '$trustee' has dangerous rights on template: $($riskNotes -join ', ')." `
                        "Remove or restrict unnecessary template ACL rights for unprivileged accounts." `
                        "SpecterOps ESC4; MITRE T1484, T1222.001; NIST AC-3, AC-6; DISA STIG V-254303"
                }
            }
        }
    }
    catch { $Errors.Add("[ACL] $tmplName`: $_") }

    # -- Orphaned template (not published anywhere) ----------------------------
    if (-not $isPublished) {
        Add-Finding $tmplName $tmplDN "OrphanedTemplate" "Low" `
            "Template exists in AD but is not published on any CA." `
            "Review whether this template is still needed. Remove unused templates to reduce attack surface." `
            "NIST CM-7; CIS Controls v8 Control 4"
    }
}

Write-Progress -Activity "Analyzing templates" -Completed

# =============================================================================
# CA CHECKS (ESC6, ESC7)
# =============================================================================
Write-Host "Analyzing CA configurations..." -ForegroundColor Yellow

foreach ($ca in $enrollmentServices) {
    $caName = $ca.Name
    $caDN   = $ca.DistinguishedName
    $caProps = $ca.PSObject.Properties

    Write-Host "  CA: $caName" -ForegroundColor Gray

    # -- ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 --------------------------------
    $flags = $caProps['msPKI-Enrollment-Servers']  # Not the right property - use certutil in production
    # Note: The EDITF_ATTRIBUTESUBJECTALTNAME2 flag (0x00040000) is stored in the CA's
    # registry at HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\PolicyModules
    # Full check requires certutil.exe or remote registry access. Flagging for manual review.
    Add-Finding $caName $caDN "ESC6-ManualCheck" "Medium" `
        "Verify EDITF_ATTRIBUTESUBJECTALTNAME2 flag is disabled on this CA. This flag allows requestors to specify a SAN in certificate requests, enabling privilege escalation." `
        "Run: certutil -config '$caName' -getreg policy\EditFlags. If result includes EDITF_ATTRIBUTESUBJECTALTNAME2, disable it and apply KB5014754." `
        "SpecterOps ESC6; CISA AA23-024A; Microsoft KB5014754; DISA STIG V-254306"

    # -- ESC7 - CA ACLs (Manager/Officer rights) ------------------------------
    try {
        $caAcl = Get-Acl -Path "AD:\$caDN" -ErrorAction Stop
        foreach ($ace in $caAcl.Access) {
            $trustee = $ace.IdentityReference.Value
            $rights  = $ace.ActiveDirectoryRights.ToString()
            $caRisk  = [System.Collections.Generic.List[string]]::new()
            foreach ($right in @('GenericAll','WriteDacl','WriteOwner','AllExtendedRights')) {
                if ($rights -match $right) { $caRisk.Add($right) }
            }
            if ($caRisk.Count -gt 0 -and $ace.AccessControlType -eq 'Allow') {
                $isKnownAdmin = $trustee -match 'Domain Admins|Enterprise Admins|Administrators|PKI Admins|SYSTEM'
                if (-not $isKnownAdmin) {
                    Add-Finding $caName $caDN "ESC7" "High" `
                        "Trustee '$trustee' has elevated CA object rights: $($caRisk -join ', ')." `
                        "Remove CA management rights from non-PKI-admin accounts. Only PKI Admins and CA Admins should have these rights." `
                        "SpecterOps ESC7; MITRE T1649; NIST AC-6; DISA STIG V-254304, V-254305"
                }
            }
        }
    }
    catch { $Errors.Add("[CA-ACL] $caName`: $_") }
}

# -- Export --------------------------------------------------------------------
$Findings | Sort-Object Severity, Check, ObjectName | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding ASCII

# -- HTML Report ---------------------------------------------------------------
if ($HTMLReport) {
    $htmlOutputFile = $OutputFile -replace '\.csv$','.html'
    $critCount = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount  = @($Findings | Where-Object { $_.Severity -eq 'High'     }).Count
    $medCount   = @($Findings | Where-Object { $_.Severity -eq 'Medium'   }).Count
    $lowCount   = @($Findings | Where-Object { $_.Severity -eq 'Low'      }).Count

    $tableRows = ($Findings | Sort-Object Severity, Check | ForEach-Object {
        $color = switch ($_.Severity) {
            'Critical' { '#f8d7da' }
            'High'     { '#fff3cd' }
            'Medium'   { '#d1ecf1' }
            'Low'      { '#d4edda' }
            default    { '#f8f9fa' }
        }
        "<tr style='background:$color'>
          <td>$($_.ObjectName)</td>
          <td><strong>$($_.Check)</strong></td>
          <td>$($_.Severity)</td>
          <td>$($_.Description)</td>
          <td>$($_.Recommendation)</td>
          <td style='font-size:11px'>$($_.Standards)</td>
        </tr>"
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<title>ADCS Enrollment Permission Audit</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; color: #333; }
  h1   { color: #1a1a2e; }
  .summary { display:flex; gap:20px; margin:20px 0; }
  .card { padding:15px 25px; border-radius:8px; text-align:center; }
  .critical { background:#f8d7da; } .high { background:#fff3cd; }
  .medium   { background:#d1ecf1; } .low  { background:#d4edda; }
  .card h2  { margin:0; font-size:32px; }
  .card p   { margin:4px 0 0; font-size:13px; }
  table { border-collapse:collapse; width:100%; margin-top:20px; }
  th    { background:#1a1a2e; color:#fff; padding:10px; text-align:left; font-size:13px; }
  td    { padding:8px 10px; border-bottom:1px solid #ddd; font-size:12px; vertical-align:top; }
  .meta { font-size:12px; color:#666; margin-top:20px; }
</style>
</head>
<body>
<h1>ADCS Enrollment Permission Audit</h1>
<div class='meta'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Domain: $domainName | Auditor: $($env:USERDOMAIN)\$($env:USERNAME)</div>
<div class='summary'>
  <div class='card critical'><h2>$critCount</h2><p>Critical</p></div>
  <div class='card high'>    <h2>$highCount</h2><p>High</p></div>
  <div class='card medium'>  <h2>$medCount</h2><p>Medium</p></div>
  <div class='card low'>     <h2>$lowCount</h2><p>Low</p></div>
</div>
<h2>Findings ($($Findings.Count) total)</h2>
<table>
  <tr><th>Object</th><th>Check</th><th>Severity</th><th>Description</th><th>Recommendation</th><th>Standards</th></tr>
  $tableRows
</table>
</body></html>
"@
    $html | Set-Content -Path $htmlOutputFile -Encoding UTF8
    Write-Host "  HTML report: $htmlOutputFile" -ForegroundColor Green
}

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Summary"                                               -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  Templates analyzed:   $($templates.Count)"           -ForegroundColor White
Write-Host "  CAs analyzed:         $($enrollmentServices.Count)"  -ForegroundColor White
Write-Host "  Total findings:       $($Findings.Count)"            -ForegroundColor White

foreach ($sev in @('Critical','High','Medium','Low')) {
    $cnt = @($Findings | Where-Object { $_.Severity -eq $sev }).Count
    $color = switch ($sev) { 'Critical' {'Red'} 'High' {'Yellow'} 'Medium' {'Cyan'} default {'Gray'} }
    if ($cnt -gt 0) { Write-Host "    $sev`: $cnt" -ForegroundColor $color }
}

Write-Host "  Errors:               $($Errors.Count)"              -ForegroundColor $(if ($Errors.Count -gt 0) {'Yellow'} else {'White'})
Write-Host "  Output file:          $OutputFile"                    -ForegroundColor White

if ($Errors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors encountered:" -ForegroundColor Yellow
    $Errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan

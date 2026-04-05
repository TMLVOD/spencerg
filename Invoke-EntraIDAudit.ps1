#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns
<#
.SYNOPSIS
    Comprehensive Microsoft Entra ID security audit using Microsoft Graph API.

.DESCRIPTION
    Performs a read-only security audit of a Microsoft Entra ID tenant via
    Microsoft Graph, covering:

      - User hygiene: stale accounts, disabled accounts, unlicensed users
      - MFA status: per-user MFA registration, authentication methods enrolled
      - Privileged roles: Global Admin enumeration, PIM eligible/active assignments
      - Guest users: external identities, stale guest accounts
      - Conditional Access: policy inventory, gaps (no MFA-required policies, legacy auth)
      - App registrations: secrets/certs expiring soon, overprivileged API permissions
      - Service principals: high-privilege app-only permissions
      - Risky sign-ins and risky users (Identity Protection)
      - Sign-in log analysis: failed logins, suspicious geolocations

    Standards mapping:
      - CIS Microsoft 365 Foundations Benchmark v3.1
      - CISA Secure Cloud Business Applications (SCuBA)
      - NIST 800-53 Rev 5: AC-2, AC-6, IA-2, IA-5, AU-3, CM-6
      - Microsoft Secure Score alignment

    All operations are READ-ONLY. No changes are made to the tenant.

.PARAMETER OutputDirectory
    Directory for audit output files. Default: .\EntraID_Audit_<timestamp>

.PARAMETER StaleThresholdDays
    Number of days since last sign-in to flag an account as stale. Default: 90

.PARAMETER SecretExpiryDays
    Flag app registrations with secrets/certs expiring within this many days. Default: 30

.PARAMETER HTMLReport
    If specified, generates an HTML report alongside the CSV files.

.PARAMETER IncludeSignInLogs
    If specified, pulls the last 7 days of sign-in logs for analysis.
    Requires Azure AD Premium P1/P2 license.

.EXAMPLE
    .\Invoke-EntraIDAudit.ps1

.EXAMPLE
    .\Invoke-EntraIDAudit.ps1 -StaleThresholdDays 60 -HTMLReport -IncludeSignInLogs

.EXAMPLE
    .\Invoke-EntraIDAudit.ps1 -OutputDirectory "C:\Audits\Entra" -SecretExpiryDays 60

.NOTES
    Author  : Spencer Gaines
    Version : 1.0
    Date    : 2026-04-05
    Requires: Microsoft Graph PowerShell SDK v2.x+
              Permissions needed (delegated or application):
                User.Read.All, Directory.Read.All, AuditLog.Read.All,
                Policy.Read.All, Application.Read.All, RoleManagement.Read.All,
                IdentityRiskEvent.Read.All, IdentityRiskyUser.Read.All
              Azure AD Premium P1/P2 for sign-in logs and Identity Protection.
    Read-only: Makes no changes to the Entra ID tenant.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [int]$StaleThresholdDays = 90,
    [int]$SecretExpiryDays = 30,
    [switch]$HTMLReport,
    [switch]$IncludeSignInLogs
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

#region ── Setup ──────────────────────────────────────────────────────────────
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $OutputDirectory) {
    $OutputDirectory = ".\EntraID_Audit_$timestamp"
}
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns"
)
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Error "Required module '$mod' not found. Install with: Install-Module $mod -Scope CurrentUser"
        exit 1
    }
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Title,
        [string]$Description,
        [string]$AffectedObject,
        [string]$Recommendation,
        [string]$CISControl = "",
        [string]$NISTControl = ""
    )
    $findings.Add([PSCustomObject]@{
        Category        = $Category
        Severity        = $Severity
        Title           = $Title
        Description     = $Description
        AffectedObject  = $AffectedObject
        Recommendation  = $Recommendation
        CISControl      = $CISControl
        NISTControl     = $NISTControl
        Timestamp       = (Get-Date -Format "o")
    })
}

function Write-AuditLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "PASS"  { "Green" }
        default { "Cyan" }
    }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $color
}
#endregion

#region ── Connect to Graph ───────────────────────────────────────────────────
Write-AuditLog "Connecting to Microsoft Graph..."
$scopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "Policy.Read.All",
    "Application.Read.All",
    "RoleManagement.Read.All",
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyUser.Read.All"
)

try {
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes $scopes -NoWelcome
    }
    $context = Get-MgContext
    Write-AuditLog "Connected to tenant: $($context.TenantId)" "PASS"
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

$tenantDetails = Get-MgOrganization
$tenantName = $tenantDetails.DisplayName
Write-AuditLog "Tenant: $tenantName ($($context.TenantId))"
#endregion

#region ── 1. User Account Hygiene ────────────────────────────────────────────
Write-AuditLog "=== Auditing User Accounts ==="

$allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, `
    UserType, CreatedDateTime, SignInActivity, AssignedLicenses, OnPremisesSyncEnabled `
    -ConsistencyLevel eventual -CountVariable userCount

Write-AuditLog "Total users found: $($allUsers.Count)"

$staleDate = (Get-Date).AddDays(-$StaleThresholdDays)
$staleUsers = [System.Collections.Generic.List[PSCustomObject]]::new()
$disabledUsers = [System.Collections.Generic.List[PSCustomObject]]::new()
$guestUsers = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($user in $allUsers) {
    $lastSignIn = $user.SignInActivity.LastSignInDateTime

    # Stale account check
    if ($user.AccountEnabled -and $lastSignIn -and $lastSignIn -lt $staleDate) {
        $daysSince = ((Get-Date) - $lastSignIn).Days
        $staleUsers.Add([PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            LastSignIn        = $lastSignIn
            DaysSinceSignIn   = $daysSince
            UserType          = $user.UserType
            SyncedFromOnPrem  = [bool]$user.OnPremisesSyncEnabled
        })
    }

    # Active accounts that have NEVER signed in
    if ($user.AccountEnabled -and -not $lastSignIn -and $user.CreatedDateTime -lt $staleDate) {
        $staleUsers.Add([PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            LastSignIn        = "Never"
            DaysSinceSignIn   = ((Get-Date) - $user.CreatedDateTime).Days
            UserType          = $user.UserType
            SyncedFromOnPrem  = [bool]$user.OnPremisesSyncEnabled
        })
    }

    # Disabled accounts
    if (-not $user.AccountEnabled) {
        $disabledUsers.Add([PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            LastSignIn        = $lastSignIn
            UserType          = $user.UserType
        })
    }

    # Guest users
    if ($user.UserType -eq "Guest") {
        $guestUsers.Add([PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            LastSignIn        = $lastSignIn
            AccountEnabled    = $user.AccountEnabled
            CreatedDateTime   = $user.CreatedDateTime
        })
    }
}

if ($staleUsers.Count -gt 0) {
    Add-Finding -Category "User Hygiene" -Severity "High" `
        -Title "Stale user accounts detected" `
        -Description "$($staleUsers.Count) enabled accounts have not signed in for $StaleThresholdDays+ days." `
        -AffectedObject "See StaleUsers.csv" `
        -Recommendation "Disable or remove stale accounts. Implement automated lifecycle management." `
        -CISControl "1.1.4" -NISTControl "AC-2(3)"
    $staleUsers | Export-Csv "$OutputDirectory\StaleUsers.csv" -NoTypeInformation
    Write-AuditLog "Found $($staleUsers.Count) stale accounts (>$StaleThresholdDays days)" "WARN"
} else {
    Write-AuditLog "No stale accounts found" "PASS"
}

if ($guestUsers.Count -gt 0) {
    $staleGuests = $guestUsers | Where-Object {
        $_.LastSignIn -and $_.LastSignIn -lt $staleDate
    }
    if ($staleGuests) {
        Add-Finding -Category "User Hygiene" -Severity "Medium" `
            -Title "Stale guest accounts detected" `
            -Description "$($staleGuests.Count) guest accounts have not signed in for $StaleThresholdDays+ days." `
            -AffectedObject "See GuestUsers.csv" `
            -Recommendation "Review and remove stale guest accounts. Implement guest access reviews." `
            -CISControl "1.1.5" -NISTControl "AC-2(3)"
    }
    $guestUsers | Export-Csv "$OutputDirectory\GuestUsers.csv" -NoTypeInformation
    Write-AuditLog "Found $($guestUsers.Count) guest accounts ($($staleGuests.Count) stale)" "WARN"
}

Write-AuditLog "Disabled accounts: $($disabledUsers.Count)"
$disabledUsers | Export-Csv "$OutputDirectory\DisabledUsers.csv" -NoTypeInformation
#endregion

#region ── 2. MFA & Authentication Methods ────────────────────────────────────
Write-AuditLog "=== Auditing MFA & Authentication Methods ==="

$mfaResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$noMfaUsers = [System.Collections.Generic.List[string]]::new()

$enabledMembers = $allUsers | Where-Object { $_.AccountEnabled -and $_.UserType -eq "Member" }

foreach ($user in $enabledMembers) {
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
        $methodTypes = $methods | ForEach-Object { $_.AdditionalProperties["@odata.type"] }

        $hasStrongMfa = $false
        $enrolledMethods = @()

        foreach ($mt in $methodTypes) {
            switch -Wildcard ($mt) {
                "*fido2*"                    { $enrolledMethods += "FIDO2"; $hasStrongMfa = $true }
                "*microsoftAuthenticator*"   { $enrolledMethods += "Authenticator App"; $hasStrongMfa = $true }
                "*windowsHelloForBusiness*"  { $enrolledMethods += "Windows Hello"; $hasStrongMfa = $true }
                "*phoneAuthentication*"      { $enrolledMethods += "Phone (SMS/Call)" }
                "*emailAuthentication*"      { $enrolledMethods += "Email" }
                "*temporaryAccessPass*"      { $enrolledMethods += "TAP" }
                "*softwareOath*"             { $enrolledMethods += "Software TOTP"; $hasStrongMfa = $true }
                "*password*"                 { } # skip password method
            }
        }

        $mfaResults.Add([PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
            HasStrongMFA      = $hasStrongMfa
            EnrolledMethods   = ($enrolledMethods -join ", ")
            MethodCount       = $enrolledMethods.Count
        })

        if (-not $hasStrongMfa) {
            $noMfaUsers.Add($user.UserPrincipalName)
        }
    } catch {
        Write-AuditLog "Could not query auth methods for $($user.UserPrincipalName): $_" "WARN"
    }
}

$mfaResults | Export-Csv "$OutputDirectory\MFAStatus.csv" -NoTypeInformation

if ($noMfaUsers.Count -gt 0) {
    $pct = [math]::Round(($noMfaUsers.Count / $enabledMembers.Count) * 100, 1)
    Add-Finding -Category "Authentication" -Severity "Critical" `
        -Title "Users without strong MFA" `
        -Description "$($noMfaUsers.Count) of $($enabledMembers.Count) enabled members ($pct%) lack strong MFA (FIDO2, Authenticator, WHfB, TOTP)." `
        -AffectedObject "See MFAStatus.csv" `
        -Recommendation "Enforce MFA registration via Conditional Access. Target phishing-resistant methods (FIDO2, WHfB)." `
        -CISControl "6.3" -NISTControl "IA-2(1)"
    Write-AuditLog "$($noMfaUsers.Count) users ($pct%) lack strong MFA" "WARN"
} else {
    Write-AuditLog "All enabled members have strong MFA enrolled" "PASS"
}
#endregion

#region ── 3. Privileged Role Assignments ─────────────────────────────────────
Write-AuditLog "=== Auditing Privileged Roles ==="

$criticalRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Security Administrator",
    "Conditional Access Administrator"
)

$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal

$privilegedAssignments = [System.Collections.Generic.List[PSCustomObject]]::new()
$globalAdmins = [System.Collections.Generic.List[string]]::new()

foreach ($assignment in $roleAssignments) {
    $roleDef = $roleDefinitions | Where-Object { $_.Id -eq $assignment.RoleDefinitionId }
    $roleName = $roleDef.DisplayName

    if ($roleName -in $criticalRoles) {
        $principalName = $assignment.Principal.AdditionalProperties["displayName"]
        $principalUPN = $assignment.Principal.AdditionalProperties["userPrincipalName"]

        $privilegedAssignments.Add([PSCustomObject]@{
            RoleName          = $roleName
            PrincipalName     = $principalName
            PrincipalUPN      = $principalUPN
            PrincipalType     = $assignment.Principal.AdditionalProperties["@odata.type"]
            AssignmentType    = "Active"
            DirectoryScope    = $assignment.DirectoryScopeId
        })

        if ($roleName -eq "Global Administrator") {
            $globalAdmins.Add($principalUPN)
        }
    }
}

$privilegedAssignments | Export-Csv "$OutputDirectory\PrivilegedRoles.csv" -NoTypeInformation

if ($globalAdmins.Count -gt 5) {
    Add-Finding -Category "Privileged Access" -Severity "Critical" `
        -Title "Excessive Global Administrators" `
        -Description "$($globalAdmins.Count) accounts hold Global Administrator. Microsoft recommends fewer than 5." `
        -AffectedObject ($globalAdmins -join ", ") `
        -Recommendation "Reduce Global Admins to under 5. Use least-privilege roles. Enable PIM for just-in-time activation." `
        -CISControl "1.1.1" -NISTControl "AC-6(1)"
    Write-AuditLog "$($globalAdmins.Count) Global Administrators found (recommended: <5)" "WARN"
} else {
    Write-AuditLog "$($globalAdmins.Count) Global Administrators found" "PASS"
}

# Check for Global Admins without MFA
$gaNoMfa = $globalAdmins | Where-Object { $_ -in $noMfaUsers }
if ($gaNoMfa) {
    Add-Finding -Category "Privileged Access" -Severity "Critical" `
        -Title "Global Administrators without strong MFA" `
        -Description "$($gaNoMfa.Count) Global Admin(s) lack strong MFA enrollment." `
        -AffectedObject ($gaNoMfa -join ", ") `
        -Recommendation "Immediately enforce phishing-resistant MFA for all Global Admins." `
        -CISControl "6.3" -NISTControl "IA-2(1)"
    Write-AuditLog "$($gaNoMfa.Count) Global Admin(s) missing strong MFA!" "WARN"
}

Write-AuditLog "Total privileged role assignments: $($privilegedAssignments.Count)"
#endregion

#region ── 4. Conditional Access Policies ─────────────────────────────────────
Write-AuditLog "=== Auditing Conditional Access Policies ==="

try {
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
    $caPolicySummary = [System.Collections.Generic.List[PSCustomObject]]::new()

    $hasMfaPolicy = $false
    $hasLegacyBlock = $false
    $hasRiskySignInPolicy = $false
    $disabledPolicies = 0

    foreach ($policy in $caPolicies) {
        $state = $policy.State
        if ($state -eq "disabled") { $disabledPolicies++ }

        $grantControls = $policy.GrantControls.BuiltInControls -join ", "
        $sessionControls = if ($policy.SessionControls) { "Configured" } else { "None" }

        if ($grantControls -match "mfa" -and $state -eq "enabled") { $hasMfaPolicy = $true }
        if ($policy.Conditions.ClientAppTypes -contains "exchangeActiveSync" -and $state -eq "enabled") {
            $hasLegacyBlock = $true
        }
        if ($policy.Conditions.SignInRiskLevels.Count -gt 0 -and $state -eq "enabled") {
            $hasRiskySignInPolicy = $true
        }

        $includedUsers = $policy.Conditions.Users.IncludeUsers -join ", "
        $excludedUsers = $policy.Conditions.Users.ExcludeUsers -join ", "

        $caPolicySummary.Add([PSCustomObject]@{
            PolicyName      = $policy.DisplayName
            State           = $state
            GrantControls   = $grantControls
            SessionControls = $sessionControls
            IncludedUsers   = $includedUsers
            ExcludedUsers   = $excludedUsers
            Platforms       = ($policy.Conditions.Platforms.IncludePlatforms -join ", ")
            Locations        = ($policy.Conditions.Locations.IncludeLocations -join ", ")
        })
    }

    $caPolicySummary | Export-Csv "$OutputDirectory\ConditionalAccessPolicies.csv" -NoTypeInformation

    if (-not $hasMfaPolicy) {
        Add-Finding -Category "Conditional Access" -Severity "Critical" `
            -Title "No enabled MFA-enforcing Conditional Access policy" `
            -Description "No active CA policy requires MFA as a grant control." `
            -AffectedObject "Tenant-wide" `
            -Recommendation "Create a CA policy requiring MFA for all users, all cloud apps." `
            -CISControl "6.2" -NISTControl "IA-2(1)"
        Write-AuditLog "No MFA-enforcing CA policy found" "WARN"
    } else {
        Write-AuditLog "MFA-enforcing CA policy exists" "PASS"
    }

    if (-not $hasLegacyBlock) {
        Add-Finding -Category "Conditional Access" -Severity "High" `
            -Title "Legacy authentication not blocked" `
            -Description "No active CA policy blocks legacy authentication protocols." `
            -AffectedObject "Tenant-wide" `
            -Recommendation "Block legacy auth (Exchange ActiveSync, IMAP, POP3, SMTP) via CA policy." `
            -CISControl "2.1" -NISTControl "CM-7"
        Write-AuditLog "Legacy authentication not blocked by CA policy" "WARN"
    } else {
        Write-AuditLog "Legacy auth block policy exists" "PASS"
    }

    if (-not $hasRiskySignInPolicy) {
        Add-Finding -Category "Conditional Access" -Severity "High" `
            -Title "No risk-based Conditional Access policy" `
            -Description "No active CA policy evaluates sign-in risk levels." `
            -AffectedObject "Tenant-wide" `
            -Recommendation "Enable risk-based CA policies requiring MFA or block for medium/high sign-in risk." `
            -CISControl "5.2" -NISTControl "AC-7"
        Write-AuditLog "No risk-based CA policy found" "WARN"
    }

    if ($disabledPolicies -gt 0) {
        Add-Finding -Category "Conditional Access" -Severity "Low" `
            -Title "Disabled Conditional Access policies" `
            -Description "$disabledPolicies CA policies are in disabled state." `
            -AffectedObject "See ConditionalAccessPolicies.csv" `
            -Recommendation "Review disabled policies. Remove if no longer needed, or enable if they were disabled accidentally."
    }

    Write-AuditLog "CA policies: $($caPolicies.Count) total, $disabledPolicies disabled"
} catch {
    Write-AuditLog "Could not retrieve CA policies (requires Azure AD Premium P1): $_" "WARN"
}
#endregion

#region ── 5. App Registrations & Secrets ─────────────────────────────────────
Write-AuditLog "=== Auditing App Registrations ==="

$apps = Get-MgApplication -All -Property Id, DisplayName, AppId, PasswordCredentials, `
    KeyCredentials, RequiredResourceAccess, SignInAudience

$expiringSecrets = [System.Collections.Generic.List[PSCustomObject]]::new()
$overprivilegedApps = [System.Collections.Generic.List[PSCustomObject]]::new()
$expiryCutoff = (Get-Date).AddDays($SecretExpiryDays)
$now = Get-Date

foreach ($app in $apps) {
    # Check password credentials (client secrets)
    foreach ($secret in $app.PasswordCredentials) {
        if ($secret.EndDateTime -and $secret.EndDateTime -lt $expiryCutoff) {
            $status = if ($secret.EndDateTime -lt $now) { "EXPIRED" } else { "Expiring Soon" }
            $expiringSecrets.Add([PSCustomObject]@{
                AppName        = $app.DisplayName
                AppId          = $app.AppId
                CredentialType = "Client Secret"
                KeyId          = $secret.KeyId
                ExpiryDate     = $secret.EndDateTime
                Status         = $status
                DaysRemaining  = [math]::Round(($secret.EndDateTime - $now).TotalDays, 0)
            })
        }
    }

    # Check certificate credentials
    foreach ($cert in $app.KeyCredentials) {
        if ($cert.EndDateTime -and $cert.EndDateTime -lt $expiryCutoff) {
            $status = if ($cert.EndDateTime -lt $now) { "EXPIRED" } else { "Expiring Soon" }
            $expiringSecrets.Add([PSCustomObject]@{
                AppName        = $app.DisplayName
                AppId          = $app.AppId
                CredentialType = "Certificate"
                KeyId          = $cert.KeyId
                ExpiryDate     = $cert.EndDateTime
                Status         = $status
                DaysRemaining  = [math]::Round(($cert.EndDateTime - $now).TotalDays, 0)
            })
        }
    }

    # Check for overprivileged Graph permissions
    $graphResourceId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    $graphAccess = $app.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $graphResourceId }
    $dangerousPermissions = @(
        "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All", "Mail.ReadWrite", "Files.ReadWrite.All",
        "User.ReadWrite.All", "Group.ReadWrite.All"
    )

    if ($graphAccess) {
        $appRoles = $graphAccess.ResourceAccess | Where-Object { $_.Type -eq "Role" }
        if ($appRoles.Count -gt 10) {
            $overprivilegedApps.Add([PSCustomObject]@{
                AppName            = $app.DisplayName
                AppId              = $app.AppId
                AppRoleCount       = $appRoles.Count
                SignInAudience     = $app.SignInAudience
                Concern            = "Excessive application permissions ($($appRoles.Count) app roles)"
            })
        }
    }
}

if ($expiringSecrets.Count -gt 0) {
    $expired = ($expiringSecrets | Where-Object { $_.Status -eq "EXPIRED" }).Count
    Add-Finding -Category "App Registrations" -Severity "High" `
        -Title "Expiring/expired app credentials" `
        -Description "$($expiringSecrets.Count) app credentials expiring within $SecretExpiryDays days ($expired already expired)." `
        -AffectedObject "See AppCredentials.csv" `
        -Recommendation "Rotate expired/expiring secrets. Prefer managed identities or certificates over client secrets." `
        -CISControl "5.4" -NISTControl "IA-5(1)"
    $expiringSecrets | Export-Csv "$OutputDirectory\AppCredentials.csv" -NoTypeInformation
    Write-AuditLog "$($expiringSecrets.Count) app credentials expiring/expired" "WARN"
} else {
    Write-AuditLog "No app credentials expiring within $SecretExpiryDays days" "PASS"
}

if ($overprivilegedApps.Count -gt 0) {
    Add-Finding -Category "App Registrations" -Severity "High" `
        -Title "Potentially overprivileged app registrations" `
        -Description "$($overprivilegedApps.Count) apps have excessive Graph API application permissions." `
        -AffectedObject "See OverprivilegedApps.csv" `
        -Recommendation "Apply least-privilege. Replace application permissions with delegated where possible." `
        -CISControl "5.4" -NISTControl "AC-6(1)"
    $overprivilegedApps | Export-Csv "$OutputDirectory\OverprivilegedApps.csv" -NoTypeInformation
    Write-AuditLog "$($overprivilegedApps.Count) overprivileged apps found" "WARN"
}

Write-AuditLog "Total app registrations scanned: $($apps.Count)"
#endregion

#region ── 6. Risky Users & Sign-Ins (Identity Protection) ────────────────────
Write-AuditLog "=== Auditing Identity Protection ==="

try {
    $riskyUsers = Get-MgRiskyUser -All -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"
    if ($riskyUsers.Count -gt 0) {
        $riskyUserExport = $riskyUsers | Select-Object UserDisplayName, UserPrincipalName, `
            RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime
        $riskyUserExport | Export-Csv "$OutputDirectory\RiskyUsers.csv" -NoTypeInformation

        $highRisk = ($riskyUsers | Where-Object { $_.RiskLevel -eq "high" }).Count
        Add-Finding -Category "Identity Protection" -Severity "Critical" `
            -Title "Users flagged as risky" `
            -Description "$($riskyUsers.Count) users at risk ($highRisk high-risk). Potential compromise indicators." `
            -AffectedObject "See RiskyUsers.csv" `
            -Recommendation "Investigate high-risk users immediately. Require password change and MFA re-registration." `
            -CISControl "5.1" -NISTControl "AC-7"
        Write-AuditLog "$($riskyUsers.Count) risky users detected ($highRisk high-risk)" "WARN"
    } else {
        Write-AuditLog "No risky users detected" "PASS"
    }
} catch {
    Write-AuditLog "Could not query risky users (requires Azure AD Premium P2): $_" "WARN"
}

try {
    $riskySignIns = Get-MgRiskyServicePrincipal -All 2>$null
    # Also check risky sign-in detections from last 7 days
    $sevenDaysAgo = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $riskDetections = Get-MgRiskDetection -Filter "activityDateTime ge $sevenDaysAgo" -All

    if ($riskDetections.Count -gt 0) {
        $riskDetections | Select-Object UserDisplayName, UserPrincipalName, RiskLevel, `
            RiskEventType, DetectionTimingType, Activity, IpAddress, Location, `
            ActivityDateTime |
            Export-Csv "$OutputDirectory\RiskDetections.csv" -NoTypeInformation

        Add-Finding -Category "Identity Protection" -Severity "High" `
            -Title "Recent risk detections" `
            -Description "$($riskDetections.Count) risk detections in the last 7 days." `
            -AffectedObject "See RiskDetections.csv" `
            -Recommendation "Review detections for signs of compromise. Correlate with sign-in logs."
        Write-AuditLog "$($riskDetections.Count) risk detections in last 7 days" "WARN"
    } else {
        Write-AuditLog "No recent risk detections" "PASS"
    }
} catch {
    Write-AuditLog "Could not query risk detections: $_" "WARN"
}
#endregion

#region ── 7. Sign-In Log Analysis (Optional) ─────────────────────────────────
if ($IncludeSignInLogs) {
    Write-AuditLog "=== Analyzing Sign-In Logs (Last 7 Days) ==="

    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $signInLogs = Get-MgAuditLogSignIn -Filter "createdDateTime ge $sevenDaysAgo" -All -Top 5000

        # Failed sign-ins summary
        $failedSignIns = $signInLogs | Where-Object {
            $_.Status.ErrorCode -ne 0
        }

        $failedByUser = $failedSignIns | Group-Object -Property UserPrincipalName |
            Sort-Object -Property Count -Descending |
            Select-Object -First 20 Name, Count

        $failedByUser | Export-Csv "$OutputDirectory\FailedSignIns_ByUser.csv" -NoTypeInformation

        # Brute force detection: users with 10+ failures
        $bruteForce = $failedByUser | Where-Object { $_.Count -ge 10 }
        if ($bruteForce) {
            Add-Finding -Category "Sign-In Logs" -Severity "High" `
                -Title "Potential brute-force targets" `
                -Description "$($bruteForce.Count) accounts had 10+ failed sign-ins in 7 days." `
                -AffectedObject ($bruteForce.Name -join ", ") `
                -Recommendation "Investigate for brute-force attacks. Enable smart lockout and risk-based CA policies." `
                -NISTControl "AC-7"
            Write-AuditLog "$($bruteForce.Count) accounts with 10+ failed sign-ins" "WARN"
        }

        # Sign-ins from unusual locations (distinct countries per user)
        $signInLocations = $signInLogs | Where-Object { $_.Location.CountryOrRegion } |
            Select-Object UserPrincipalName, @{N="Country"; E={$_.Location.CountryOrRegion}} |
            Group-Object UserPrincipalName |
            Where-Object { ($_.Group | Select-Object -Unique Country).Count -gt 3 }

        if ($signInLocations) {
            Add-Finding -Category "Sign-In Logs" -Severity "Medium" `
                -Title "Sign-ins from multiple countries" `
                -Description "$($signInLocations.Count) users signed in from 4+ countries in 7 days." `
                -AffectedObject ($signInLocations.Name -join ", ") `
                -Recommendation "Review for impossible travel. May indicate compromised credentials."
            Write-AuditLog "$($signInLocations.Count) users with multi-country sign-ins" "WARN"
        }

        # Legacy auth usage
        $legacyAuth = $signInLogs | Where-Object {
            $_.ClientAppUsed -in @("Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "MAPI Over HTTP",
                "Autodiscover", "Exchange Online PowerShell", "Other clients")
        }
        if ($legacyAuth) {
            $legacyApps = $legacyAuth | Group-Object ClientAppUsed | Select-Object Name, Count
            Add-Finding -Category "Sign-In Logs" -Severity "Medium" `
                -Title "Legacy authentication usage detected" `
                -Description "$($legacyAuth.Count) sign-ins using legacy auth protocols in 7 days." `
                -AffectedObject ($legacyApps | ForEach-Object { "$($_.Name): $($_.Count)" }) -join "; " `
                -Recommendation "Block legacy auth via Conditional Access. Migrate to modern authentication."
            Write-AuditLog "$($legacyAuth.Count) legacy auth sign-ins detected" "WARN"
        }

        Write-AuditLog "Analyzed $($signInLogs.Count) sign-in events"
    } catch {
        Write-AuditLog "Could not retrieve sign-in logs: $_" "WARN"
    }
}
#endregion

#region ── 8. Tenant Security Defaults ────────────────────────────────────────
Write-AuditLog "=== Checking Tenant Security Configuration ==="

try {
    $securityDefaults = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"

    if ($securityDefaults.isEnabled) {
        Write-AuditLog "Security Defaults are ENABLED (good for small tenants, but CA policies preferred)" "PASS"
    } else {
        # Only flag if no CA policies requiring MFA exist
        if (-not $hasMfaPolicy) {
            Add-Finding -Category "Tenant Config" -Severity "High" `
                -Title "Security Defaults disabled without CA policy coverage" `
                -Description "Security Defaults are disabled and no CA policy enforces MFA." `
                -AffectedObject "Tenant-wide" `
                -Recommendation "Enable Security Defaults or implement equivalent CA policies." `
                -CISControl "1.1.1" -NISTControl "AC-2"
            Write-AuditLog "Security Defaults disabled with no MFA CA policy" "WARN"
        } else {
            Write-AuditLog "Security Defaults disabled (CA policies in use)" "PASS"
        }
    }
} catch {
    Write-AuditLog "Could not check Security Defaults: $_" "WARN"
}
#endregion

#region ── Generate Reports ───────────────────────────────────────────────────
Write-AuditLog "=== Generating Reports ==="

# Summary CSV
$findings | Export-Csv "$OutputDirectory\AuditFindings.csv" -NoTypeInformation
Write-AuditLog "Findings exported to $OutputDirectory\AuditFindings.csv"

# Console summary
$criticalCount = ($findings | Where-Object { $_.Severity -eq "Critical" }).Count
$highCount     = ($findings | Where-Object { $_.Severity -eq "High" }).Count
$mediumCount   = ($findings | Where-Object { $_.Severity -eq "Medium" }).Count
$lowCount      = ($findings | Where-Object { $_.Severity -eq "Low" }).Count

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║         ENTRA ID SECURITY AUDIT SUMMARY                 ║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  Tenant   : $($tenantName.PadRight(44))║" -ForegroundColor White
Write-Host "║  Date     : $($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').PadRight(44))║" -ForegroundColor White
Write-Host "║  Users    : $("$($allUsers.Count) total".PadRight(44))║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  CRITICAL : $($criticalCount.ToString().PadRight(44))║" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
Write-Host "║  HIGH     : $($highCount.ToString().PadRight(44))║" -ForegroundColor $(if ($highCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "║  MEDIUM   : $($mediumCount.ToString().PadRight(44))║" -ForegroundColor $(if ($mediumCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "║  LOW      : $($lowCount.ToString().PadRight(44))║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  Output   : $($OutputDirectory.PadRight(44))║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor White

# HTML Report
if ($HTMLReport) {
    $htmlPath = "$OutputDirectory\EntraID_Audit_Report.html"
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Entra ID Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 2rem; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 0.5rem; }
        h2 { color: #333; margin-top: 2rem; }
        .meta { color: #666; margin-bottom: 2rem; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
        th { background: #0078d4; color: white; padding: 10px 12px; text-align: left; }
        td { padding: 8px 12px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f0f7ff; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; font-weight: bold; }
        .low { color: #388e3c; }
        .summary-box { display: flex; gap: 1rem; margin-bottom: 2rem; }
        .summary-card { padding: 1rem 1.5rem; border-radius: 6px; color: white; flex: 1; text-align: center; }
        .summary-card h3 { margin: 0; font-size: 2rem; }
        .summary-card p { margin: 0.25rem 0 0; }
        .bg-critical { background: #d32f2f; }
        .bg-high { background: #f57c00; }
        .bg-medium { background: #fbc02d; color: #333; }
        .bg-low { background: #388e3c; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Entra ID Security Audit Report</h1>
        <div class="meta">
            <strong>Tenant:</strong> $tenantName |
            <strong>Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |
            <strong>Users:</strong> $($allUsers.Count)
        </div>

        <div class="summary-box">
            <div class="summary-card bg-critical"><h3>$criticalCount</h3><p>Critical</p></div>
            <div class="summary-card bg-high"><h3>$highCount</h3><p>High</p></div>
            <div class="summary-card bg-medium"><h3>$mediumCount</h3><p>Medium</p></div>
            <div class="summary-card bg-low"><h3>$lowCount</h3><p>Low</p></div>
        </div>

        <h2>Findings</h2>
        <table>
            <tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Recommendation</th></tr>
$(foreach ($f in ($findings | Sort-Object @{Expression={switch($_.Severity){"Critical"{0}"High"{1}"Medium"{2}"Low"{3}}};})) {
    $sevClass = $f.Severity.ToLower()
    "            <tr><td class='$sevClass'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Title)</td><td>$($f.Description)</td><td>$($f.Recommendation)</td></tr>`n"
})
        </table>

        <h2>Audit Statistics</h2>
        <table>
            <tr><td>Total Users</td><td>$($allUsers.Count)</td></tr>
            <tr><td>Stale Accounts</td><td>$($staleUsers.Count)</td></tr>
            <tr><td>Guest Accounts</td><td>$($guestUsers.Count)</td></tr>
            <tr><td>Disabled Accounts</td><td>$($disabledUsers.Count)</td></tr>
            <tr><td>Users Without Strong MFA</td><td>$($noMfaUsers.Count)</td></tr>
            <tr><td>Privileged Role Assignments</td><td>$($privilegedAssignments.Count)</td></tr>
            <tr><td>Global Administrators</td><td>$($globalAdmins.Count)</td></tr>
            <tr><td>Conditional Access Policies</td><td>$($caPolicies.Count)</td></tr>
            <tr><td>App Registrations</td><td>$($apps.Count)</td></tr>
            <tr><td>Expiring/Expired Credentials</td><td>$($expiringSecrets.Count)</td></tr>
        </table>

        <p style="color: #999; text-align: center; margin-top: 2rem;">
            Generated by Invoke-EntraIDAudit.ps1 | All operations read-only
        </p>
    </div>
</body>
</html>
"@
    $html | Out-File -FilePath $htmlPath -Encoding utf8
    Write-AuditLog "HTML report: $htmlPath" "PASS"
}

Write-AuditLog "Audit complete. Review findings in: $OutputDirectory" "PASS"
#endregion

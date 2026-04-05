# 🔐 Windows & Azure Security Toolkit

> **PowerShell scripts for Active Directory auditing, Entra ID security, CVE remediation, and endpoint hardening.**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://docs.microsoft.com/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Azure-lightgrey?logo=windows)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Read Only Audits](https://img.shields.io/badge/Audit%20Scripts-Read--Only-brightgreen)]()

---

## About

This toolkit is a collection of production-grade PowerShell scripts built for Windows and Azure enterprise environments. Coverage spans on-premises Active Directory (ADCS, service accounts, GPOs, share permissions), Microsoft Entra ID (formerly Azure AD), CVE remediation assessment, and endpoint agent lifecycle management.

All audit scripts are **read-only** — they make no changes to Active Directory, Group Policy, Entra ID, or any system configuration. Output is written to CSV and optionally to HTML reports.

Designed to support security teams performing internal assessments, compliance reviews, and hardening initiatives aligned with NIST 800-53, MITRE ATT&CK, CIS Controls v8, DISA STIGs, SpecterOps ESC research, and CIS Microsoft 365 Foundations Benchmark.

---

## Scripts

### 🔍 Auditing & Assessment

| Script | Description |
|--------|-------------|
| [`Audit-ADCSEnrollmentPermissions.ps1`](#audit-adcsenrollmentpermissionsps1) | Audits AD Certificate Services enrollment permissions against SpecterOps ESC1–ESC7, CISA AA23-024A, NIST 800-53, and DISA STIGs |
| [`Audit-ServiceAccountPermissions.ps1`](#audit-serviceaccountpermissionsps1) | Enumerates service accounts and checks for excessive privileges, dangerous Kerberos delegation, Kerberoastable SPNs, password hygiene, and ACL rights |
| [`Invoke-EntraIDAudit.ps1`](#invoke-entraidauditps1) | Read-only Microsoft Entra ID tenant audit via Graph API — MFA status, privileged roles, Conditional Access gaps, app registrations, risky sign-ins, and more |
| [`Invoke-GPOAudit.ps1`](#invoke-gpoauditps1) | Multi-phase GPO audit: security group references, settings inventory, stale/disabled GPO detection, delegation review, HTML report |
| [`Get-ADSystems.ps1`](#get-adsystemsps1) | Inventories all AD computer objects with LAPS coverage, staleness, password age, group membership, and OS distribution |
| [`Get-UniqueSecurityGroups.ps1`](#get-uniquesecuritygroupsps1) | Enumerates and deduplicates security group memberships from AD users within a scoped OU |
| [`Search-GPOsBySecurityGroup.ps1`](#search-gposbysecuritygroupps1) | Scans all domain GPOs for references to specified security groups — security filtering, delegation, and XML settings |
| [`Search-SharePermissions.ps1`](#search-sharepermissionsps1) | Audits NTFS and share-level ACLs on file servers against a target group list |

### 🩹 Vulnerability & Remediation

| Script | Description |
|--------|-------------|
| [`Invoke-CVERemediation.ps1`](#invoke-cvéremediationps1) | CVE assessment and hardening for mixed Windows/Azure environments — audit-only or remediation mode covering critical 2026 Patch Tuesday CVEs |

### 🛠️ Endpoint Management

| Script | Description |
|--------|-------------|
| [`Remove-ThreatLocker.ps1`](#remove-threatlockerps1) | Silently uninstalls ThreatLocker agent with architecture detection, TLS 1.2 enforcement, timeout handling, and post-removal verification |
| [`Remove-DelineaAgent.ps1`](#remove-delineaagentps1) | Uninstalls Delinea (Thycotic) Privilege Manager agent by dynamically discovering installed MSI versions via registry |

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Windows 10 / Windows Server 2016 or later |
| PowerShell | 5.1 or later |
| AD Module | `Install-WindowsFeature RSAT-AD-PowerShell` |
| GPO Module | `Install-WindowsFeature GPMC` *(GPO scripts only)* |
| Graph SDK | `Install-Module Microsoft.Graph` v2.x+ *(Entra ID audit only)* |
| Permissions | Domain-joined machine with AD read access; Entra audit requires delegated or app-only Graph permissions; CVE remediation requires local Administrator |

---

## Usage

All scripts support `Get-Help` and follow a consistent parameter pattern:

```powershell
# View full help for any script
Get-Help .\Audit-ServiceAccountPermissions.ps1 -Full

# Run with defaults (outputs CSV to current directory)
.\Audit-ServiceAccountPermissions.ps1

# Scope to a specific OU
.\Audit-ServiceAccountPermissions.ps1 -SearchBase "OU=Service Accounts,DC=corp,DC=local"

# Generate HTML report + write to Windows Event Log
.\Audit-ServiceAccountPermissions.ps1 -HTMLReport -WriteEventLog

# ADCS audit with HTML output
.\Audit-ADCSEnrollmentPermissions.ps1 -OutputFile "C:\Audits\adcs.csv" -HTMLReport

# Full GPO audit with HTML report
.\Invoke-GPOAudit.ps1 -SecurityGroupsCSV ".\UniqueSecurityGroups.csv" -HTMLReport

# Entra ID audit with HTML report and sign-in log analysis
.\Invoke-EntraIDAudit.ps1 -HTMLReport -IncludeSignInLogs

# CVE audit-only mode (no changes made)
.\Invoke-CVERemediation.ps1

# CVE remediation mode with confirmation prompts
.\Invoke-CVERemediation.ps1 -Remediate
```

---

## Script Workflow — Share Permission Audit

These three scripts are designed to chain together for a full share permissions review:

```
Step 1: Get-UniqueSecurityGroups.ps1  ──► UniqueSecurityGroups.csv
              │
              ▼
Step 2: Search-GPOsBySecurityGroup.ps1  (reads UniqueSecurityGroups.csv)
              │
              ▼
Step 3: Search-SharePermissions.ps1     (reads UniqueSecurityGroups.csv)
```

---

## Script Details

### `Audit-ADCSEnrollmentPermissions.ps1`

Analyzes ADCS certificate templates and CA configurations against known attack patterns. Checks ESC1 through ESC7 misconfigurations plus custom checks for orphaned templates and weak crypto.

**Misconfigurations detected:**
- **ESC1** — Template allows requestor-supplied SAN + low enrollment rights
- **ESC2** — Any Purpose EKU or no EKU restrictions
- **ESC3** — Certificate Request Agent EKU (enrollment agent abuse)
- **ESC4** — Overly permissive template ACLs (GenericAll, WriteDacl, WriteOwner)
- **ESC6** — `EDITF_ATTRIBUTESUBJECTALTNAME2` CA flag
- **ESC7** — CA officer/manager rights granted to unprivileged accounts

**Output:** `ADCS_Findings.csv` + optional HTML report

---

### `Audit-ServiceAccountPermissions.ps1`

Enumerates MSAs, gMSAs, and pattern-matched user accounts (e.g. `svc_*`), then runs 17 security checks per account.

**Checks include:**
- Privileged group membership (Domain Admins, Schema Admins, etc.)
- Unconstrained and constrained Kerberos delegation (T4A, S4U2Self, RBCD)
- Kerberoastable SPNs
- AS-REP roastable accounts
- Non-expiring passwords, password age, reversible encryption
- AdminCount = 1 (orphaned SDHolder)
- Stale/never-logged-on accounts
- Excessive AD ACL rights (GenericAll, WriteDACL, etc.)
- Optional WMI/WinRM service mapping and local admin checks

**Output:** `ServiceAccount_Findings.csv`, `AD_ACL_Findings.csv`, optional `ServiceAccount_Report.html`

---

### `Invoke-EntraIDAudit.ps1`

Read-only Microsoft Entra ID tenant audit via the Microsoft Graph API. Covers identity hygiene, authentication posture, privileged access, and application security.

**Audit coverage:**
- User hygiene — stale accounts, disabled users, unlicensed identities
- MFA status — per-user registration and authentication methods enrolled
- Privileged roles — Global Admin enumeration, PIM eligible/active assignments
- Guest users — external identities, stale guest accounts
- Conditional Access — policy inventory, gaps (no MFA-required policies, legacy auth enabled)
- App registrations — secrets/certs expiring soon, overprivileged API permissions
- Service principals — high-privilege app-only permissions
- Risky sign-ins and risky users (Identity Protection)
- Sign-in log analysis — failed logins, suspicious geolocations *(requires Azure AD Premium P1/P2)*

**Graph permissions required:** `User.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `Application.Read.All`, `RoleManagement.Read.All`, `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All`

**Output:** Multiple CSVs per audit category + optional HTML report

---

### `Invoke-CVERemediation.ps1`

CVE assessment and hardening script for mixed Windows/Azure environments. Runs in audit-only mode by default; pass `-Remediate` to apply automated fixes.

**CVEs covered:**

| CVE | Description | CVSS |
|-----|-------------|------|
| CVE-2026-21262 | SQL Server Elevation of Privilege | 8.8 |
| CVE-2026-26113 | Microsoft Office RCE via Preview Pane | 8.4 |
| CVE-2026-26127 | .NET DoS via Out-of-Bounds Read | 7.5 |
| CVE-2026-21195 | Windows NTLM Hash Disclosure (Spoofing) | 6.5 |
| CVE-2026-24305 | Azure Entra ID Privilege Escalation | — |
| CVE-2026-32211 | Azure MCP Server Auth Bypass | 9.1 |

**General hardening checks:**
- Windows Update compliance
- TLS 1.0/1.1 deprecation enforcement
- SMBv1 removal verification
- NTLM relay protections (EPA, LDAP signing)
- ASR rules for Office exploit mitigations
- .NET runtime inventory and patching

**Modes:** `-AuditOnly` (default, no changes) / `-Remediate` (with confirmation) / `-Remediate -Force` (unattended)

> **Note:** Test in a non-production environment before deploying with `-Remediate`.

---

### `Invoke-GPOAudit.ps1`

Four-phase GPO audit with optional HTML reporting.

- **Phase 1** — Security group references (filtering + XML content)
- **Phase 2** — Settings inventory (scripts, drive maps, software, firewall rules, audit policy, etc.)
- **Phase 3** — Stale, disabled, unlinked, or empty GPO detection
- **Phase 4** — Delegation review (non-standard accounts with elevated GPO rights)

**Output:** `GPO_SecurityGroupRefs.csv`, `GPO_Settings.csv`, `GPO_StaleReport.csv`, `GPO_Delegation.csv`, optional `GPO_AuditReport.html`

---

### `Get-ADSystems.ps1`

Inventories all AD computer objects and flags security concerns.

- LAPS coverage (`ms-Mcs-AdmPwd` attribute presence)
- Staleness detection (configurable threshold)
- Password age per machine
- `isCriticalSystemObject` flag
- OS distribution breakdown
- SPN count and group membership

**Output:** `ADSystems_Inventory.csv`

---

### `Remove-ThreatLocker.ps1`

Silently removes the ThreatLocker security agent.

- Detects x64/x86 architecture
- Enforces TLS 1.2 for download
- Validates stub file size pre-execution
- Process timeout with forced kill on expiry
- Cleans up stub binary in `finally` block
- Handles exit codes: 0 (success), 1605 (not found), 1641/3010 (reboot needed)

> **Note:** Disable ThreatLocker application control policies before running, or add an exclusion in the portal.

---

### `Remove-DelineaAgent.ps1`

Removes Delinea (Thycotic) Privilege Manager agent without hardcoded version strings.

- Dynamically discovers `ThycoticAgent_x64_*.msi` files at runtime
- Registry-based product discovery (32-bit and 64-bit paths)
- Timestamped log file with INFO/WARN/ERROR levels
- Post-removal registry verification
- Handles exit codes: 0, 1605, 1618, 1641, 3010

> **Note:** Disable agent hardening/self-protect in the Delinea portal before running.

---

## Standards Mapping

| Standard | Coverage |
|----------|----------|
| SpecterOps Certified Pre-Owned | ESC1–ESC7 |
| MITRE ATT&CK | T1649, T1222.001, T1484, T1558.003, T1110, T1078 |
| CISA Advisory | AA23-024A, SCuBA |
| NIST 800-53 Rev 5 | AC-2, AC-3, AC-6, CM-6, CM-7, IA-2, IA-5, AU-3 |
| CIS Controls v8 | Control 4, 5, 6 |
| CIS Microsoft 365 Foundations Benchmark | v3.1 |
| DISA STIG | V-254303, V-254304, V-254305, V-254306 |
| Microsoft KB | KB5014754 |
| Microsoft Secure Score | Entra ID alignment |

---

## Security Notes

- All **audit scripts are read-only** and make no changes to Active Directory, Entra ID, Group Policy, or any system
- **`Invoke-CVERemediation.ps1`** in `-Remediate` mode will make system changes — always audit first and test in non-production
- **Endpoint management scripts** (`Remove-*`) modify system state — test on non-production machines first
- Scripts use `Set-StrictMode -Version 2` and structured error handling throughout
- Event Log entries are optional and off by default

---

## License

MIT License — see [LICENSE](LICENSE) for details.

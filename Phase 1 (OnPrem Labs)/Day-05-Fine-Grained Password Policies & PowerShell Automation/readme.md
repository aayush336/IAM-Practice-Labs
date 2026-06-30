# Day 5 Lab: Fine-Grained Password Policies (PSOs) & Account Lifecycle Automation via PowerShell

---

## 1. Core Concept Overview

Day 4 established the Default Domain Policy as the single location for domain-wide password and lockout settings. But this creates an immediate problem in every real enterprise: **not all accounts carry the same risk profile**. A standard Finance Analyst account and a Domain Admin service account should not be governed by the same password policy — the privileged account demands a significantly stricter baseline. Before Windows Server 2008, there was no solution to this; one domain meant one password policy, full stop. Enterprises worked around it by creating separate domains purely to enforce different password policies — an architectural cost no one wanted to pay.

**Fine-Grained Password Policies (FGPPs)**, technically called **Password Settings Objects (PSOs)**, solve this directly. Introduced in Windows Server 2008 domain functional level and fully manageable via PowerShell since Server 2012, PSOs allow you to define multiple password and lockout policies within a single domain and apply them to specific **users or global security groups** — not OUs (this distinction trips up even experienced admins in interviews).

**Three architectural rules govern PSO behavior:**

**Rule 1 — PSOs apply to users or global security groups only.** You cannot link a PSO to an OU. If you need a PSO to apply to all IT Support staff, you create a global security group (`G-PSO-ITSupport-Strict`), put the relevant users in it, and link the PSO to that group. This is another reason why the Day 3 group structure matters — it enables PSO targeting.

**Rule 2 — Precedence determines the winner when multiple PSOs apply.** Every PSO has a mandatory `Precedence` attribute (integer, lower number = higher priority). If a user is a member of three groups, each with a different PSO, the PSO with the lowest Precedence number wins. If a PSO is applied directly to a user object AND via a group, the directly-applied PSO always wins regardless of Precedence — direct application beats group application unconditionally. This is the most-tested PSO interview concept.

**Rule 3 — The resultant PSO (the one actually enforced) is called the Resultant PSO (RPSO).** You can query it per user via PowerShell, which is how you verify correct PSO application during audits and troubleshooting.

**PowerShell lifecycle automation** is the second major topic today. IAM Engineers in production don't create, modify, or disable accounts one at a time through the GUI — they write and maintain PowerShell scripts that read from a source of truth (typically a CSV exported from an HRIS like Workday or SAP SuccessFactors) and perform bulk operations: creating 50 new-hire accounts from a CSV, disabling accounts for a termination batch, moving leavers to the `Disabled-Users` OU, stripping group memberships on departure. These scripts are the difference between a junior admin doing ticket work and a mid-level IAM Engineer building scalable, auditable processes. Today you build three production-pattern scripts that you will extend in the Day 7 capstone.

---

## 2. Real-World Enterprise Use Case

**PSO scenario:** Bhatt Corp's security policy (aligned to CIS Controls v8 and NIST 800-53) mandates tiered password controls:

- **Standard users** (Finance, Sales): 12-character minimum, 60-day max age, 5-attempt lockout — already set in Default Domain Policy (Day 4).
- **IT privileged accounts** (`G-IT-Support` and future admin accounts): 16-character minimum, 30-day max age, 3-attempt lockout, 1-hour lockout duration — stricter baseline for accounts with elevated access.
- **Service accounts** (non-interactive, used by applications): 20-character minimum, password never expires (managed via automated rotation or LAPS equivalent), 0 lockout threshold (service account lockouts cause application outages — a deliberate tradeoff requiring compensating controls like restricted logon type).

This tiered model is exactly what an IAM Engineer designs during a **Password Policy Rationalization** project — a common engagement when a company is preparing for SOC2 Type II certification or implementing CIS Benchmarks.

**Automation scenario:** HR sends a Monday-morning CSV every week containing new hires starting that day. The IAM team has a PowerShell script that runs at 07:00, reads the CSV, creates all accounts in the correct OUs with all mandatory attributes populated (Day 2 standards), adds them to the correct role groups (Day 3 AGDLP model), and sends a confirmation log to the IAM mailbox. No GUI, no per-ticket manual creation, no missed attributes. This is the process maturity target for today.

---

## 3. Detailed Step-by-Step Procedure

> **Tooling:** PowerShell (as Administrator) on DC01 for all PSO work; Active Directory Module for Windows PowerShell (`Import-Module ActiveDirectory` — pre-loaded on DC01 after AD DS install). Notepad/ISE for script authoring.

---

### Step 1: Verify domain functional level supports FGPPs
**Action:** On DC01, open PowerShell as Administrator and run:
```powershell
Get-ADDomain -Identity "Bhatt.com" | Select-Object Name, DomainMode
```

**Expected Result/Verification:** `DomainMode` returns `Windows2016Domain` or higher (any value of `Windows2008Domain` or above supports FGPPs). If it returns `Windows2003Domain`, you would need to raise the functional level first — in our lab this should not be the case since we installed Server 2022. Fine-Grained Password Policies require a minimum of Windows Server 2008 domain functional level; below that, PSO cmdlets will fail silently or throw schema errors.

---

### Step 2: Create the PSO targeting group for IT privileged accounts
**Action:** Because PSOs cannot target OUs, create a dedicated global security group for PSO targeting:
```powershell
New-ADGroup -Name "G-PSO-Privileged-Strict" `
            -SamAccountName "G-PSO-Privileged-Strict" `
            -GroupScope Global `
            -GroupCategory Security `
            -Path "OU=Groups,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com" `
            -Description "PSO targeting group - Strict password policy for privileged IT accounts"
```

Add `dkim` (IT Support) to this group for testing:
```powershell
Add-ADGroupMember -Identity "G-PSO-Privileged-Strict" -Members "dkim"
```

**Expected Result/Verification:**
```powershell
Get-ADGroup "G-PSO-Privileged-Strict" | Select-Object Name, GroupScope, GroupCategory
Get-ADGroupMember "G-PSO-Privileged-Strict" | Select-Object Name
```
Group returns `Global` scope, `Security` category. `dkim` appears as the sole member.

---

### Step 3: Create the PSO targeting group for service accounts
**Action:**
```powershell
New-ADGroup -Name "G-PSO-ServiceAccounts" `
            -SamAccountName "G-PSO-ServiceAccounts" `
            -GroupScope Global `
            -GroupCategory Security `
            -Path "OU=ServiceAccounts,OU=BHATT-CORP,DC=Bhatt,DC=com" `
            -Description "PSO targeting group - Service account password policy"
```

**Expected Result/Verification:**
```powershell
Get-ADGroup "G-PSO-ServiceAccounts" | Select-Object Name, GroupScope, GroupCategory
```
Returns `Global` and `Security`. No members yet — service accounts are created in Day 5 Step 9.

---

### Step 4: Create the Privileged Accounts PSO (Precedence 10)
**Action:** Create the strict PSO for IT privileged accounts:
```powershell
New-ADFineGrainedPasswordPolicy `
    -Name "PSO-Privileged-Strict" `
    -Precedence 10 `
    -MinPasswordLength 16 `
    -MaxPasswordAge "30.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold 3 `
    -LockoutDuration "01:00:00" `
    -LockoutObservationWindow "01:00:00" `
    -Description "Strict policy for privileged IT accounts - CIS L2 aligned"
```

**Expected Result/Verification:**
```powershell
Get-ADFineGrainedPasswordPolicy -Identity "PSO-Privileged-Strict" |
    Select-Object Name, Precedence, MinPasswordLength, MaxPasswordAge, LockoutThreshold
```
Output confirms all values match what was set. `Precedence: 10` — lower number than the service account PSO we create next, meaning this wins in a conflict.

---

### Step 5: Create the Service Account PSO (Precedence 20)
**Action:**
```powershell
New-ADFineGrainedPasswordPolicy `
    -Name "PSO-ServiceAccounts" `
    -Precedence 20 `
    -MinPasswordLength 20 `
    -MaxPasswordAge "00:00:00" `
    -MinPasswordAge "0.00:00:00" `
    -PasswordHistoryCount 48 `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold 0 `
    -LockoutDuration "00:00:00" `
    -LockoutObservationWindow "00:00:00" `
    -Description "Service account policy - no expiry, no lockout, 20-char minimum"
```

**Note on `MaxPasswordAge "00:00:00"`:** Setting MaxPasswordAge to zero means password never expires at the policy level — this is intentional for service accounts where automated rotation or LAPS handles credential lifecycle. In production, "never expires" on a service account must always be paired with a documented compensating control (monitored rotation schedule or vault management).

**Expected Result/Verification:**
```powershell
Get-ADFineGrainedPasswordPolicy -Identity "PSO-ServiceAccounts" |
    Select-Object Name, Precedence, MinPasswordLength, LockoutThreshold, MaxPasswordAge
```
`LockoutThreshold: 0` and `MaxPasswordAge: 00:00:00:00` confirm no lockout and no expiry — exactly the service account posture.

---

### Step 6: Apply (link) PSOs to their targeting groups
**Action:** PSOs are applied to subjects via `Add-ADFineGrainedPasswordPolicySubject`:
```powershell
# Apply strict PSO to the privileged accounts group
Add-ADFineGrainedPasswordPolicySubject `
    -Identity "PSO-Privileged-Strict" `
    -Subjects "G-PSO-Privileged-Strict"

# Apply service account PSO to the service accounts group
Add-ADFineGrainedPasswordPolicySubject `
    -Identity "PSO-ServiceAccounts" `
    -Subjects "G-PSO-ServiceAccounts"
```

**Expected Result/Verification:**
```powershell
Get-ADFineGrainedPasswordPolicySubject -Identity "PSO-Privileged-Strict"
Get-ADFineGrainedPasswordPolicySubject -Identity "PSO-ServiceAccounts"
```
Each returns the corresponding group name as the subject — confirming the PSO-to-group linkage is established.

---

### Step 7: Query the Resultant PSO (RPSO) per user to confirm correct application
**Action:** This is the audit/verification command every IAM Engineer uses to confirm the correct PSO is being enforced for a given account:
```powershell
# dkim is in G-PSO-Privileged-Strict, so should get PSO-Privileged-Strict
Get-ADUserResultantPasswordPolicy -Identity "dkim"

# mross is NOT in any PSO group, so should inherit Default Domain Policy (no PSO returned)
Get-ADUserResultantPasswordPolicy -Identity "mross"
```

**Expected Result/Verification:** For `dkim`: the output shows `PSO-Privileged-Strict` with `MinPasswordLength: 16`, `LockoutThreshold: 3`, `MaxPasswordAge: 30 days` — confirming the stricter policy is active. For `mross`: the cmdlet returns **nothing** (empty output) — this is correct behavior, meaning mross falls back to the Default Domain Policy (12-char, 60-day, 5-attempt) set in Day 4. An empty return from `Get-ADUserResultantPasswordPolicy` always means "Default Domain Policy governs this user" — it is not an error.

---
# Updated Scripts — EmployeeID-Anchored Naming Convention

> **Scope:** Three deliverables — updated naming convention doc, Joiner script, Leaver script. All other lab work (PSOs, AGDLP, GPOs) remains unchanged. Run all commands on **DC01 as Administrator**.

---

## Deliverable 1 — Updated Naming Convention Reference Doc

**Action:** Run in PowerShell to overwrite the old doc:

```powershell
$doc = @"
================================================================
BHATT.COM USER NAMING CONVENTION (v2.0)
IAM Team | Updated: $(Get-Date -Format 'yyyy-MM-dd')
================================================================

IDENTITY ANCHOR
---------------
The EmployeeID is the single source-of-truth key for every
account. All other identity attributes derive from it.
EmployeeID is assigned by HR at hire and never changes,
even if the employee's name, department, or role changes.

FORMAT STANDARDS
----------------
EmployeeID      : Numeric only, sequential from 1001
                  Example: 1001, 1002, 1003

sAMAccountName  : Lowercase prefix 'bh' + EmployeeID
                  Example: bh1001, bh1002, bh1003
                  - 'bh' prefix = Bhatt (company identifier)
                  - Max 20 chars (sAMAccountName AD limit)
                  - bh + 4-digit ID = 6 chars (well within limit)

UserPrincipalName (UPN):
                  bh<EmployeeID>@Bhatt.com
                  Example: bh1001@Bhatt.com
                  - Matches sAMAccountName prefix exactly
                  - Used as the primary login name

DisplayName     : Firstname Lastname (no change)
                  Example: Sarah Connor

Description     : "<Title> - <Department>"
                  Example: Finance Manager - Finance

COLLISION POLICY
----------------
Collisions are architecturally impossible under this standard.
EmployeeID is unique by HR system design. No collision-handling
logic is required in provisioning scripts.

MANDATORY ATTRIBUTES AT CREATION
---------------------------------
sAMAccountName        (derived from EmployeeID)
UserPrincipalName     (derived from EmployeeID)
GivenName / Surname   (from HR record)
DisplayName           (from HR record)
EmployeeID            (from HR system - identity anchor)
Title                 (from HR record)
Department            (from HR record)
Description           (Title - Department)
Manager               (from HR record - DistinguishedName)
AccountPassword       (temp - must change at first logon)
Enabled               (True at creation)

CURRENT EMPLOYEE ID REGISTRY
------------------------------
bh1001  Sarah Connor    Finance Manager         Finance
bh1002  Mike Ross       Finance Analyst         Finance
bh1003  David Kim       IT Support Specialist   IT
bh1004  Priya Sharma    Finance Analyst         Finance
bh1005  Raj Mehta       IT Support Specialist   IT
bh1006  Anita Desai     Sales Executive         Sales

Next available EmployeeID: 1007

CHANGE LOG
----------
v1.0 - Initial standard (first-initial + lastname) - DEPRECATED
v2.0 - EmployeeID-anchored standard (bh + EmployeeID)
================================================================
"@

New-Item -Path "C:\IAM-Docs" -ItemType Directory -Force | Out-Null
$doc | Out-File "C:\IAM-Docs\Naming-Convention-v2.txt" -Encoding UTF8
Write-Host "Naming convention doc written to C:\IAM-Docs\Naming-Convention-v2.txt" -ForegroundColor Green
```

**Expected Result/Verification:**
```powershell
Get-Content "C:\IAM-Docs\Naming-Convention-v2.txt"
```
Full document displays with all sections intact. This is your living reference — update the "Next available EmployeeID" line each time a new hire batch is processed.

---

## Deliverable 2 — Updated Joiner Script

**Action — Step 1:** Create the updated CSV template (reflecting the new convention):

```powershell
$csvContent = @"
EmployeeID,FirstName,LastName,Department,Title,ManagerEmployeeID
1007,Vikram,Nair,Sales,Sales Executive,
1008,Sunita,Pillai,Finance,Finance Analyst,1001
1009,Arjun,Tiwari,IT,IT Support Specialist,1003
"@

New-Item -Path "C:\IAM-Scripts" -ItemType Directory -Force | Out-Null
$csvContent | Out-File "C:\IAM-Scripts\NewHires.csv" -Encoding UTF8
Write-Host "NewHires.csv written." -ForegroundColor Green
```

> **CSV design note:** `ManagerEmployeeID` references the manager by EmployeeID — not by name, not by SAM. This mirrors how a real HRIS export works: the HR system stores the manager relationship as an employee number reference, not a display name. The script resolves it to a DN internally.

**Action — Step 2:** Write the updated Joiner script:

```powershell
$joinerScript = @'
# ================================================================
# BHATT.COM — Joiner Provisioning Script
# IAM Team | Version 2.0 | EmployeeID-Anchored
#
# Source CSV columns required:
#   EmployeeID, FirstName, LastName, Department,
#   Title, ManagerEmployeeID
#
# sAMAccountName  = bh + EmployeeID   (e.g. bh1007)
# UPN             = bh<ID>@Bhatt.com  (e.g. bh1007@Bhatt.com)
# Identity anchor = EmployeeID        (never name-derived)
# ================================================================

Import-Module ActiveDirectory

# --- Configuration block (edit here, not inside the logic) ---
$csvPath    = "C:\IAM-Scripts\NewHires.csv"
$logDir     = "C:\IAM-Scripts\Logs"
$domain     = "Bhatt.com"
$ouBase     = "OU=BHATT-CORP,DC=Bhatt,DC=com"
$samPrefix  = "bh"
$tempPass   = ConvertTo-SecureString "TempP@ssw0rd!LAB" -AsPlainText -Force

# --- Setup ---
New-Item -Path $logDir -ItemType Directory -Force | Out-Null
$logPath = "$logDir\Joiner-$(Get-Date -Format 'yyyyMMdd-HHmm').log"

# --- Logging function ---
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry     = "$timestamp [$Level] $Message"

    $colour = switch ($Level) {
        "INFO"    { "Cyan"    }
        "WARN"    { "Yellow"  }
        "ERROR"   { "Red"     }
        "SUCCESS" { "Green"   }
    }
    Write-Host $entry -ForegroundColor $colour
    $entry | Out-File $logPath -Append -Encoding UTF8
}

# --- Helper: resolve EmployeeID to DistinguishedName ---
function Resolve-ManagerDN {
    param([string]$ManagerEmpID)
    if ([string]::IsNullOrWhiteSpace($ManagerEmpID)) { return $null }

    $mgr = Get-ADUser -Filter {EmployeeID -eq $ManagerEmpID} `
                      -Properties EmployeeID -ErrorAction SilentlyContinue
    if ($mgr) {
        return $mgr.DistinguishedName
    } else {
        return $null
    }
}

# --- Helper: verify target OU exists before attempting create ---
function Test-OUExists {
    param([string]$OUPath)
    try {
        Get-ADOrganizationalUnit -Identity $OUPath -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

# ================================================================
# MAIN
# ================================================================

Write-Log "========================================" "INFO"
Write-Log "Joiner provisioning run started" "INFO"
Write-Log "Source CSV : $csvPath" "INFO"
Write-Log "Domain     : $domain" "INFO"
Write-Log "========================================" "INFO"

# Validate CSV exists
if (-not (Test-Path $csvPath)) {
    Write-Log "CSV not found at $csvPath. Aborting run." "ERROR"
    exit 1
}

$newHires = Import-Csv $csvPath
Write-Log "Records loaded from CSV: $($newHires.Count)" "INFO"

$successCount = 0
$failCount    = 0
$warnCount    = 0

foreach ($hire in $newHires) {

    Write-Log "--- Processing EmployeeID: $($hire.EmployeeID) | $($hire.FirstName) $($hire.LastName) ---" "INFO"

    # --------------------------------------------------
    # 1. Validate mandatory CSV fields
    # --------------------------------------------------
    $requiredFields = @("EmployeeID","FirstName","LastName","Department","Title")
    $missingFields  = $requiredFields | Where-Object { [string]::IsNullOrWhiteSpace($hire.$_) }

    if ($missingFields.Count -gt 0) {
        Write-Log "Missing required fields: $($missingFields -join ', '). Skipping record." "ERROR"
        $failCount++
        continue
    }

    # --------------------------------------------------
    # 2. Derive identity attributes from EmployeeID
    # --------------------------------------------------
    $empID = $hire.EmployeeID.Trim()
    $sam   = "$samPrefix$empID"                         # e.g. bh1007
    $upn   = "$sam@$domain"                             # e.g. bh1007@Bhatt.com
    $displayName = "$($hire.FirstName.Trim()) $($hire.LastName.Trim())"

    # --------------------------------------------------
    # 3. Duplicate check — EmployeeID must be unique
    # --------------------------------------------------
    $existingByEmpID = Get-ADUser -Filter {EmployeeID -eq $empID} `
                                  -Properties EmployeeID -ErrorAction SilentlyContinue
    if ($existingByEmpID) {
        Write-Log "EmployeeID '$empID' already exists in AD (account: $($existingByEmpID.SamAccountName)). Skipping." "ERROR"
        $failCount++
        continue
    }

    $existingBySAM = Get-ADUser -Filter {SamAccountName -eq $sam} -ErrorAction SilentlyContinue
    if ($existingBySAM) {
        Write-Log "sAMAccountName '$sam' already exists. Possible prefix collision. Skipping." "ERROR"
        $failCount++
        continue
    }

    # --------------------------------------------------
    # 4. Resolve target OU
    # --------------------------------------------------
    $dept     = $hire.Department.Trim()
    $targetOU = "OU=Users,OU=$dept,$ouBase"

    if (-not (Test-OUExists -OUPath $targetOU)) {
        Write-Log "Target OU '$targetOU' does not exist. Skipping $sam." "ERROR"
        $failCount++
        continue
    }

    # --------------------------------------------------
    # 5. Resolve manager DN via EmployeeID
    # --------------------------------------------------
    $managerDN = $null
    if (-not [string]::IsNullOrWhiteSpace($hire.ManagerEmployeeID)) {
        $managerDN = Resolve-ManagerDN -ManagerEmpID $hire.ManagerEmployeeID.Trim()
        if ($managerDN) {
            Write-Log "Manager resolved: EmployeeID $($hire.ManagerEmployeeID) → $managerDN" "INFO"
        } else {
            Write-Log "Manager EmployeeID '$($hire.ManagerEmployeeID)' not found in AD. Account will be created without manager link." "WARN"
            $warnCount++
        }
    }

    # --------------------------------------------------
    # 6. Build parameter hashtable and create account
    # --------------------------------------------------
    try {
        $userParams = @{
            SamAccountName        = $sam
            UserPrincipalName     = $upn
            GivenName             = $hire.FirstName.Trim()
            Surname               = $hire.LastName.Trim()
            DisplayName           = $displayName
            Name                  = $displayName
            EmployeeID            = $empID
            Title                 = $hire.Title.Trim()
            Department            = $dept
            Description           = "$($hire.Title.Trim()) - $dept"
            AccountPassword       = $tempPass
            ChangePasswordAtLogon = $true
            Enabled               = $true
            Path                  = $targetOU
        }

        # Only add Manager key if successfully resolved
        if ($managerDN) { $userParams["Manager"] = $managerDN }

        New-ADUser @userParams

        Write-Log "SUCCESS: $sam ($displayName) created in $targetOU" "SUCCESS"
        Write-Log "  UPN: $upn | EmployeeID: $empID | Title: $($hire.Title.Trim()) | Dept: $dept" "INFO"
        $successCount++

    } catch {
        Write-Log "FAILED to create $sam. Error: $($_.Exception.Message)" "ERROR"
        $failCount++
    }
}

# --------------------------------------------------
# 7. Run summary
# --------------------------------------------------
Write-Log "========================================" "INFO"
Write-Log "Joiner run complete." "INFO"
Write-Log "  Succeeded : $successCount" "INFO"
Write-Log "  Failed    : $failCount" "INFO"
Write-Log "  Warnings  : $warnCount" "INFO"
Write-Log "  Log file  : $logPath" "INFO"
Write-Log "========================================" "INFO"
'@

$joinerScript | Out-File "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1" -Encoding UTF8
Write-Host "Joiner script written to C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1" -ForegroundColor Green
```

**Action — Step 3:** Execute and verify:

```powershell
& "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1"
```

**Expected Result/Verification:**
```powershell
# Confirm all three new accounts exist with correct attributes
Get-ADUser -Filter {EmployeeID -ge "1007"} `
           -Properties EmployeeID, SamAccountName, UserPrincipalName,
                       Title, Department, Manager |
    Select-Object DisplayName, SamAccountName, UserPrincipalName,
                  EmployeeID, Department, Manager |
    Format-Table -AutoSize
```

Output should show `bh1007`, `bh1008`, `bh1009` — each with a UPN of `bh<ID>@Bhatt.com`, correct department, and manager DNs resolved from `ManagerEmployeeID` in the CSV. No name-derived attribute anywhere in the output.

---

## Deliverable 3 — Updated Leaver Script

```powershell
$leaverScript = @'
# ================================================================
# BHATT.COM — Leaver Offboarding Script
# IAM Team | Version 2.0 | EmployeeID-Anchored
#
# Usage:
#   .\Invoke-LeaverOffboarding.ps1 -EmployeeID 1002
#
# What this script does (in order):
#   1. Resolves the account via EmployeeID (HR system anchor)
#   2. Disables the AD account
#   3. Invalidates the current password (force-sets a random one)
#   4. Strips all security group memberships
#   5. Clears the Manager attribute
#   6. Stamps Description with offboarding date (audit breadcrumb)
#   7. Moves the object to OU=Disabled-Users
#   8. Writes a full audit log
# ================================================================

param(
    [Parameter(Mandatory=$true,
               HelpMessage="Enter the numeric EmployeeID (e.g. 1002). Do NOT include the 'bh' prefix.")]
    [ValidatePattern('^\d+$')]
    [string]$EmployeeID
)

Import-Module ActiveDirectory

# --- Configuration block ---
$disabledOU = "OU=Disabled-Users,OU=BHATT-CORP,DC=Bhatt,DC=com"
$logDir     = "C:\IAM-Scripts\Logs"
$logPath    = "$logDir\Leaver-EmpID$EmployeeID-$(Get-Date -Format 'yyyyMMdd-HHmm').log"

New-Item -Path $logDir -ItemType Directory -Force | Out-Null

# --- Logging function ---
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry     = "$timestamp [$Level] $Message"

    $colour = switch ($Level) {
        "INFO"    { "Cyan"   }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red"    }
        "SUCCESS" { "Green"  }
    }
    Write-Host $entry -ForegroundColor $colour
    $entry | Out-File $logPath -Append -Encoding UTF8
}

# --- Helper: generate a random 20-char password (for invalidation) ---
function New-RandomPassword {
    $chars  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
    $random = -join ((1..20) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return ConvertTo-SecureString $random -AsPlainText -Force
}

# ================================================================
# MAIN
# ================================================================

Write-Log "========================================" "INFO"
Write-Log "Leaver offboarding started" "INFO"
Write-Log "Target EmployeeID : $EmployeeID" "INFO"
Write-Log "Initiated by      : $env:USERNAME on $env:COMPUTERNAME" "INFO"
Write-Log "========================================" "INFO"

# --------------------------------------------------
# 1. Resolve account via EmployeeID
# --------------------------------------------------
$user = Get-ADUser -Filter {EmployeeID -eq $EmployeeID} `
                   -Properties MemberOf, Description, EmployeeID, `
                               Manager, DisplayName, Department `
                   -ErrorAction SilentlyContinue

if (-not $user) {
    Write-Log "No AD account found with EmployeeID '$EmployeeID'. Aborting." "ERROR"
    exit 1
}

Write-Log "Account resolved  : $($user.SamAccountName) ($($user.DisplayName))" "INFO"
Write-Log "Current OU        : $($user.DistinguishedName)" "INFO"
Write-Log "Department        : $($user.Department)" "INFO"

# Safety check — do not process if already in Disabled-Users OU
if ($user.DistinguishedName -like "*Disabled-Users*") {
    Write-Log "Account '$($user.SamAccountName)' is already in Disabled-Users OU. Possible duplicate run. Aborting." "WARN"
    exit 0
}

# --------------------------------------------------
# 2. Disable the account
# --------------------------------------------------
try {
    Disable-ADAccount -Identity $user.SamAccountName
    Write-Log "Step 1/6 — Account disabled: $($user.SamAccountName)" "SUCCESS"
} catch {
    Write-Log "Step 1/6 — Failed to disable account. Error: $($_.Exception.Message)" "ERROR"
    exit 1
}

# --------------------------------------------------
# 3. Invalidate password (set random — user cannot
#    re-enable and log in with old credential)
# --------------------------------------------------
try {
    Set-ADAccountPassword -Identity $user.SamAccountName `
                          -NewPassword (New-RandomPassword) `
                          -Reset
    Write-Log "Step 2/6 — Password invalidated (random replacement set)" "SUCCESS"
} catch {
    Write-Log "Step 2/6 — Password invalidation failed. Error: $($_.Exception.Message)" "WARN"
}

# --------------------------------------------------
# 4. Strip all security group memberships
#    (Domain Users is the primary group — cannot remove)
# --------------------------------------------------
$groups = $user.MemberOf
if ($groups.Count -eq 0) {
    Write-Log "Step 3/6 — No group memberships found to remove." "INFO"
} else {
    Write-Log "Step 3/6 — Removing $($groups.Count) group membership(s)..." "INFO"
    foreach ($groupDN in $groups) {
        try {
            Remove-ADGroupMember -Identity $groupDN `
                                 -Members $user.SamAccountName `
                                 -Confirm:$false
            # Extract just the group CN for readable logging
            $groupCN = ($groupDN -split ',')[0] -replace 'CN=',''
            Write-Log "  Removed from: $groupCN" "SUCCESS"
        } catch {
            Write-Log "  Could not remove from: $groupDN | Error: $($_.Exception.Message)" "WARN"
        }
    }
}

# --------------------------------------------------
# 5. Clear the Manager attribute
# --------------------------------------------------
try {
    Set-ADUser -Identity $user.SamAccountName -Manager $null
    Write-Log "Step 4/6 — Manager attribute cleared" "SUCCESS"
} catch {
    Write-Log "Step 4/6 — Could not clear Manager attribute. Error: $($_.Exception.Message)" "WARN"
}

# --------------------------------------------------
# 6. Stamp Description with offboarding audit breadcrumb
# --------------------------------------------------
try {
    $timestamp  = Get-Date -Format "yyyy-MM-dd"
    $newDesc    = "OFFBOARDED $timestamp | EmpID:$EmployeeID | Was: $($user.Description)"
    Set-ADUser -Identity $user.SamAccountName -Description $newDesc
    Write-Log "Step 5/6 — Description stamped: $newDesc" "SUCCESS"
} catch {
    Write-Log "Step 5/6 — Could not update Description. Error: $($_.Exception.Message)" "WARN"
}

# --------------------------------------------------
# 7. Move to Disabled-Users OU
# --------------------------------------------------
try {
    Move-ADObject -Identity $user.DistinguishedName -TargetPath $disabledOU
    Write-Log "Step 6/6 — Moved to: $disabledOU" "SUCCESS"
} catch {
    Write-Log "Step 6/6 — Failed to move object. Error: $($_.Exception.Message)" "ERROR"
}

# --------------------------------------------------
# 8. Final state verification
# --------------------------------------------------
$finalState = Get-ADUser -Filter {EmployeeID -eq $EmployeeID} `
                         -Properties Enabled, DistinguishedName, Description, MemberOf

Write-Log "========================================" "INFO"
Write-Log "Offboarding complete. Final state:" "INFO"
Write-Log "  SAM         : $($finalState.SamAccountName)" "INFO"
Write-Log "  Enabled     : $($finalState.Enabled)" "INFO"
Write-Log "  Location    : $($finalState.DistinguishedName)" "INFO"
Write-Log "  Description : $($finalState.Description)" "INFO"
Write-Log "  Groups left : $($finalState.MemberOf.Count) (expect 0)" "INFO"
Write-Log "  Log file    : $logPath" "INFO"
Write-Log "========================================" "INFO"
'@

$leaverScript | Out-File "C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1" -Encoding UTF8
Write-Host "Leaver script written to C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1" -ForegroundColor Green
```

**Expected Result/Verification — dry run syntax check:**
```powershell
# Confirm both scripts pass syntax validation with no errors
$scripts = @(
    "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1",
    "C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1"
)
foreach ($s in $scripts) {
    $errors = $null
    $null   = [System.Management.Automation.Language.Parser]::ParseFile($s, [ref]$null, [ref]$errors)
    if ($errors.Count -eq 0) {
        Write-Host "PASS: $s" -ForegroundColor Green
    } else {
        Write-Host "FAIL: $s" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    }
}
```

Both scripts return `PASS` with zero syntax errors before you ever execute them — this is a production habit (always parse-validate a script before running it in an environment with live accounts).

**Leaver usage example (for Day 7 capstone):**
```powershell
# Offboard Mike Ross (EmployeeID 1002)
.\Invoke-LeaverOffboarding.ps1 -EmployeeID 1002
```

---

## What Changed — Delta Summary

| Area | v1.0 (Old) | v2.0 (New) |
|---|---|---|
| SAM derivation | `f` + `lastname` | `bh` + `EmployeeID` |
| UPN format | `first.last@Bhatt.com` | `bh<ID>@Bhatt.com` |
| Collision handling | Middle-initial fallback logic | Not needed — impossible by design |
| Leaver parameter | `-SamAccountName "mross"` | `-EmployeeID 1002` |
| Manager resolution | By SAM lookup | By EmployeeID lookup |
| Duplicate check | SAM existence only | EmployeeID **and** SAM both checked |
| Identity anchor | Name-derived | EmployeeID (HR system key) |

---

All three files now live at:
- `C:\IAM-Docs\Naming-Convention-v2.txt`
- `C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1`
- `C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1`

## 4. Interview-Prep Q&A

**Q1: "A user is a member of two security groups — Group A has PSO-Standard (Precedence 30) applied to it, and Group B has PSO-Strict (Precedence 10) applied to it. Which policy governs the user, and what command proves it?"**

**Strong Answer:** PSO-Strict (Precedence 10) wins because lower Precedence number means higher priority — when multiple PSOs apply to a user through group membership, AD selects the one with the lowest Precedence value. The command to prove it is `Get-ADUserResultantPasswordPolicy -Identity <username>` — it returns the single PSO that is actively enforced for that user, called the Resultant PSO (RPSO). The RPSO accounts for all group memberships and direct assignments, resolves the Precedence conflict, and returns only the winner. If the same user also had a PSO applied directly to their user object (not via a group), that direct assignment would win unconditionally regardless of Precedence values — direct-to-user application always takes priority over group-based application.

**Q2: "Why do you strip group memberships as part of the Leaver offboarding process, rather than just disabling the account and leaving the group memberships intact?"**

**Strong Answer:** Disabling the account prevents interactive authentication, but it does not revoke the access entitlements represented by group memberships. In many environments, group membership is queried by applications directly via LDAP — some systems check group membership regardless of whether the account is enabled, because they don't verify account status at every authorization decision. Leaving group memberships intact on a disabled account also creates an audit hygiene problem: during an access review, the disabled account still shows up as an entitlement holder on those groups, and the reviewer must then determine whether the access is intentional or an oversight. Stripping groups at offboarding is a clean termination of all logical access, not just authentication capability — it ensures the access review picture is accurate, satisfies the "access revoked upon termination" control requirement in frameworks like SOC2 CC6.2 and ISO27001 A.9.2.6, and eliminates the risk of the account being re-enabled later and silently inheriting access that was never explicitly re-granted.

---

## 5. Overall Progress Tracker

**Phase 1: On-Premises Lifecycle & Access Management**

```
[■■■■■□□□□□] Day 5 of 30 — 17% Complete
```

✅ Day 1 — AD DS Logical Structure & Enterprise OU Design
✅ Day 2 — User Lifecycle Management (JML) — Joiner Phase
✅ Day 3 — Group Strategy & AGDLP Nesting Model
✅ Day 4 — GPO for Access Control
✅ Day 5 — Fine-Grained Password Policies & PowerShell Automation *(Complete)*
⬜ Day 6 — NTFS/Share Permissions & Least Privilege
⬜ Day 7 — Phase 1 Capstone

---


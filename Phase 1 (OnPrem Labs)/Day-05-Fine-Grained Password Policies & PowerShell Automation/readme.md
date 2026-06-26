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

### Step 8: Build the bulk user creation script (Joiner automation)
**Action:** Create the input CSV first. In PowerShell:
```powershell
New-Item -Path "C:\IAM-Scripts" -ItemType Directory -Force

# Create a sample new-hires CSV (simulating HRIS export)
$csvContent = @"
FirstName,LastName,Department,Title,ManagerSAM,EmployeeID
Priya,Sharma,Finance,Finance Analyst,sconnor,BH1004
Raj,Mehta,IT,IT Support Specialist,dkim,BH1005
Anita,Desai,Sales,Sales Executive,,BH1006
"@
$csvContent | Out-File "C:\IAM-Scripts\NewHires.csv" -Encoding UTF8
```

Now create the bulk provisioning script:
```powershell
$scriptContent = @'
# =============================================================
# BHATT.COM - Bulk Joiner Provisioning Script
# IAM Team | Version 1.0
# Source: C:\IAM-Scripts\NewHires.csv
# =============================================================

Import-Module ActiveDirectory

$csvPath   = "C:\IAM-Scripts\NewHires.csv"
$logPath   = "C:\IAM-Scripts\Logs\Joiner-$(Get-Date -Format 'yyyyMMdd-HHmm').log"
$domain    = "Bhatt.com"
$ouBase    = "OU=BHATT-CORP,DC=Bhatt,DC=com"
$tempPass  = ConvertTo-SecureString "TempP@ssw0rd!2024" -AsPlainText -Force

New-Item -Path "C:\IAM-Scripts\Logs" -ItemType Directory -Force | Out-Null

Function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Host $entry
    $entry | Out-File $logPath -Append
}

$newHires = Import-Csv $csvPath
Write-Log "Starting Joiner run. Records to process: $($newHires.Count)"

foreach ($hire in $newHires) {

    # --- Build sAMAccountName per naming convention ---
    $sam = ($hire.FirstName[0] + $hire.LastName).ToLower()
    $upn = "$($hire.FirstName).$($hire.LastName)@$domain".ToLower()

    # --- Collision detection ---
    if (Get-ADUser -Filter {SamAccountName -eq $sam} -ErrorAction SilentlyContinue) {
        $sam = ($hire.FirstName[0] + $hire.FirstName[1] + $hire.LastName).ToLower()
        Write-Log "SAM collision detected. Using alternate: $sam" "WARN"
    }

    # --- Determine target OU ---
    $targetOU = "OU=Users,OU=$($hire.Department),OU=BHATT-CORP,DC=Bhatt,DC=com"

    # --- Resolve manager DN if provided ---
    $managerDN = $null
    if ($hire.ManagerSAM -ne "") {
        try {
            $managerDN = (Get-ADUser -Identity $hire.ManagerSAM).DistinguishedName
        } catch {
            Write-Log "Manager '$($hire.ManagerSAM)' not found for $sam. Skipping manager link." "WARN"
        }
    }

    # --- Create the user ---
    try {
        $params = @{
            SamAccountName        = $sam
            UserPrincipalName     = $upn
            GivenName             = $hire.FirstName
            Surname               = $hire.LastName
            DisplayName           = "$($hire.FirstName) $($hire.LastName)"
            Name                  = "$($hire.FirstName) $($hire.LastName)"
            Title                 = $hire.Title
            Department            = $hire.Department
            Description           = "$($hire.Title) - $($hire.Department)"
            EmployeeID            = $hire.EmployeeID
            AccountPassword       = $tempPass
            ChangePasswordAtLogon = $true
            Enabled               = $true
            Path                  = $targetOU
        }

        if ($managerDN) { $params["Manager"] = $managerDN }

        New-ADUser @params
        Write-Log "SUCCESS: Created $sam ($($hire.FirstName) $($hire.LastName)) in $targetOU"

    } catch {
        Write-Log "FAILED: Could not create $sam. Error: $($_.Exception.Message)" "ERROR"
    }
}

Write-Log "Joiner run complete."
'@

$scriptContent | Out-File "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1" -Encoding UTF8
```

**Expected Result/Verification:** Files exist at `C:\IAM-Scripts\NewHires.csv` and `C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1`. View the CSV:
```powershell
Import-Csv "C:\IAM-Scripts\NewHires.csv"
```
Three rows display with all columns populated correctly.

---

### Step 9: Execute the Joiner script and validate output
**Action:**
```powershell
& "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1"
```

**Expected Result/Verification:** Console output (mirrored to log file) shows three `SUCCESS` lines — one per new hire. Then verify:
```powershell
Get-ADUser -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -Properties Title,Department,EmployeeID,Manager |
    Select-Object Name, SamAccountName, Department, EmployeeID |
    Sort-Object Department
```
`psharma`, `rmehta`, and `adesai` appear with correct departments and EmployeeIDs. Check the log file:
```powershell
Get-Content (Get-ChildItem "C:\IAM-Scripts\Logs\" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```
Log shows timestamped entries for all three creates — this is your audit trail, exactly the kind of artifact a compliance team would request during a SOC2 audit to prove provisioning is controlled and logged.

---

### Step 10: Build the Leaver disable-and-stage script
**Action:** Create the leaver automation script — this will be called in the Day 7 capstone:
```powershell
$leaverScript = @'
# =============================================================
# BHATT.COM - Leaver Offboarding Script
# IAM Team | Version 1.0
# Usage: .\Invoke-LeaverOffboarding.ps1 -SamAccountName "mross"
# =============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$SamAccountName
)

Import-Module ActiveDirectory

$disabledOU = "OU=Disabled-Users,OU=BHATT-CORP,DC=Bhatt,DC=com"
$logPath    = "C:\IAM-Scripts\Logs\Leaver-$(Get-Date -Format 'yyyyMMdd-HHmm').log"

New-Item -Path "C:\IAM-Scripts\Logs" -ItemType Directory -Force | Out-Null

Function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Host $entry
    $entry | Out-File $logPath -Append
}

try {
    $user = Get-ADUser -Identity $SamAccountName -Properties MemberOf, Description
} catch {
    Write-Log "User '$SamAccountName' not found in AD. Aborting." "ERROR"
    exit 1
}

Write-Log "Starting Leaver offboarding for: $SamAccountName ($($user.Name))"

# Step 1: Disable the account
Disable-ADAccount -Identity $SamAccountName
Write-Log "Account disabled: $SamAccountName"

# Step 2: Strip all group memberships (except Domain Users - primary group, cannot remove)
$groups = $user.MemberOf
foreach ($group in $groups) {
    try {
        Remove-ADGroupMember -Identity $group -Members $SamAccountName -Confirm:$false
        Write-Log "Removed from group: $group"
    } catch {
        Write-Log "Could not remove from group: $group. Error: $($_.Exception.Message)" "WARN"
    }
}

# Step 3: Update description with offboarding timestamp (audit breadcrumb)
$timestamp  = Get-Date -Format "yyyy-MM-dd"
$newDesc    = "DISABLED $timestamp - $($user.Description)"
Set-ADUser -Identity $SamAccountName -Description $newDesc
Write-Log "Description updated with offboarding date: $newDesc"

# Step 4: Move to Disabled-Users OU
Move-ADObject -Identity $user.DistinguishedName -TargetPath $disabledOU
Write-Log "Moved to Disabled-Users OU: $disabledOU"

Write-Log "Leaver offboarding complete for: $SamAccountName"
'@

$leaverScript | Out-File "C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1" -Encoding UTF8
```

**Expected Result/Verification:**
```powershell
Test-Path "C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1"
```
Returns `True`. Do **not** run it yet — it will be executed in the Day 7 capstone as part of the full JML simulation. View the script to confirm it saved correctly:
```powershell
Get-Content "C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1"
```
All sections (disable, strip groups, update description, move OU) are present.

---

### Step 11: Audit all PSOs in the domain — final verification
**Action:** Run a complete PSO inventory query — this is what you'd run during an access review or audit prep:
```powershell
Write-Host "=== ALL PSOs IN BHATT.COM ===" -ForegroundColor Cyan
Get-ADFineGrainedPasswordPolicy -Filter * |
    Select-Object Name, Precedence, MinPasswordLength, MaxPasswordAge,
                  LockoutThreshold, LockoutDuration |
    Sort-Object Precedence | Format-Table -AutoSize

Write-Host "`n=== PSO SUBJECTS (who each PSO applies to) ===" -ForegroundColor Cyan
Get-ADFineGrainedPasswordPolicy -Filter * | ForEach-Object {
    $psoName = $_.Name
    $subjects = Get-ADFineGrainedPasswordPolicySubject -Identity $psoName
    Write-Host "`nPSO: $psoName (Precedence $($_.Precedence))"
    $subjects | ForEach-Object { Write-Host "  -> Subject: $($_.Name) [$($_.ObjectClass)]" }
}

Write-Host "`n=== RESULTANT PSO PER USER ===" -ForegroundColor Cyan
Get-ADUser -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" | ForEach-Object {
    $rpso = Get-ADUserResultantPasswordPolicy -Identity $_ 2>$null
    $psoName = if ($rpso) { $rpso.Name } else { "(Default Domain Policy)" }
    Write-Host "  $($_.SamAccountName): $psoName"
}
```

**Expected Result/Verification:** Output shows two PSOs (`PSO-Privileged-Strict` at Precedence 10, `PSO-ServiceAccounts` at Precedence 20), their subjects, and the per-user RPSO breakdown confirming `dkim` gets `PSO-Privileged-Strict` while `mross`, `sconnor`, `psharma`, `adesai`, and `rmehta` all show `(Default Domain Policy)`. This output is your PSO audit report — copy it to `C:\IAM-Docs\PSO-Audit-$(Get-Date -Format 'yyyyMMdd').txt` for your documentation portfolio.

---

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


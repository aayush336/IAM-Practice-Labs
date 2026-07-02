# Day 7 Lab: Phase 1 Capstone — End-to-End JML Simulation with Full Audit Trail

---

## 1. Core Concept Overview

Every concept built across Days 1–6 was a component. Today they become a system. The **Joiner-Mover-Leaver (JML) lifecycle** is the operational heartbeat of every enterprise IAM program — and the capstone test of whether your identity infrastructure actually holds together under real workflow pressure or whether gaps appear the moment multiple actions fire in sequence.

Most IAM candidates can describe JML in an interview. Far fewer can demonstrate that their AD environment is actually wired to execute it cleanly, with an auditable trail, without manual errors, and with downstream systems (GPOs, permissions, PSOs) automatically adjusting as identity state changes. That gap — between knowing JML and having built an environment that executes it correctly — is what today closes.

**Joiner** is more than account creation. A correctly executed Joiner means: the account exists in the right OU, the right groups are assigned so AGDLP-based file access is immediate, the correct PSO governs the account, the correct GPO scope applies (drive maps, logon restrictions), the manager link is populated, and a log entry exists proving all of this happened in a controlled, repeatable way.

**Mover** is the most error-prone JML phase in production — and the one most commonly executed incorrectly. When an employee transfers departments, the following must all happen atomically: OU relocation (so new OU-linked GPOs apply), removal from old role groups (so old resource access is revoked), addition to new role groups (so new resource access is granted), manager link update (so approval workflows route correctly), Title and Department attribute update (so attribute-driven systems — dynamic groups, future ABAC policies, HR reports — reflect the new reality). Missing even one of these steps creates a **toxic combination**: the user might lose access they need for their new role, or worse, retain access from their old role indefinitely — a classic Segregation of Duties (SoD) violation that access review frameworks will flag.

**Leaver** is a race condition in production. There is a time-sensitive, compliance-mandated window between "HR notifies IAM that an employee is departing" and "IAM disables the account and revokes all access" — many frameworks (SOC2 CC6.2, ISO27001 A.9.2.6) require this to happen on or before the employee's last working day, and some require same-day execution. The Leaver process must be atomic, logged, and verifiable — so that if a compliance auditor asks "prove that bh1002's access was revoked on their last day," you have a timestamped log and a final-state AD snapshot to present.

**The Audit Trail** running through all three phases is what elevates this from "admin work" to "IAM engineering." Every action today generates a log entry, a verifiable AD state, and a human-readable audit artifact. By end of lab, you will have a complete, queryable record of what happened to three identities — exactly what you'd produce for a quarterly access review or an incident investigation.

---

## 2. Real-World Enterprise Use Case

**Monday morning at Bhatt Corp. Three HR tickets land simultaneously on the IAM queue:**

**Ticket #001 — Joiner:** A new hire, `Meera Pillai`, starts today as a Senior IT Engineer reporting to Harish Kumar (bh1040). She needs AD access, file server access appropriate to IT, PSO-governed password policy for a privileged IT account, and her workstation properly scoped via GPO.

**Ticket #002 — Mover:** `Arjun Tiwari` (bh1009, currently IT Support Specialist reporting to bh1013) has been internally transferred to the Finance department effective today, taking the role of Junior Finance Analyst reporting to bh1016 (Kavya Reddy). His IT access must be revoked, Finance access granted, and his account relocated accordingly. This is a cross-department mover — the most complex variant because it touches OU, groups, manager, Title, Department, and PSO scope simultaneously.

**Ticket #003 — Leaver:** `Mike Ross` (bh1002, Finance Analyst) has resigned effective today. Full offboarding to be executed: account disabled, password invalidated, all groups stripped, description stamped, object relocated to `Disabled-Users`.

All three must be executed, logged, and verified before end of business. The audit trail must prove all three were handled correctly and within the same working day.

---

## 3. Detailed Step-by-Step Procedure

> **Environment check before starting:** Confirm your 50-user dataset is provisioned, your scripts are in place, and your group/OU/GPO infrastructure from Days 1–6 is intact. Run the pre-flight check below first — do not begin JML execution until all checks pass.

---

### Pre-Flight: Environment Integrity Check
**Action:** Run the full pre-flight verification on DC01:
```powershell
Write-Host "=== DAY 7 PRE-FLIGHT CHECK ===" -ForegroundColor Cyan

# 1. User count
$userCount = (Get-ADUser -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com").Count
Write-Host "Total users in BHATT-CORP: $userCount (expected: 50)" `
    -ForegroundColor $(if ($userCount -eq 50) {"Green"} else {"Red"})

# 2. Scripts present
$scripts = @(
    "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1",
    "C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1"
)
foreach ($s in $scripts) {
    $exists = Test-Path $s
    Write-Host "Script $(Split-Path $s -Leaf): $(if ($exists) {'PRESENT'} else {'MISSING'})" `
        -ForegroundColor $(if ($exists) {"Green"} else {"Red"})
}

# 3. Key groups present
$groups = @(
    "G-Finance-Analysts","G-IT-Support","G-Finance-Managers",
    "DL-Finance-Share-ReadWrite","DL-Finance-Share-FullControl",
    "DL-Finance-Payroll-FullControl","G-Finance-PayrollAccess",
    "G-PSO-Privileged-Strict"
)
foreach ($g in $groups) {
    $exists = Get-ADGroup -Filter {Name -eq $g} -ErrorAction SilentlyContinue
    Write-Host "Group $g : $(if ($exists) {'EXISTS'} else {'MISSING'})" `
        -ForegroundColor $(if ($exists) {"Green"} else {"Red"})
}

# 4. Key users for today's JML exist
$keyUsers = @("bh1002","bh1009","bh1013","bh1016","bh1040")
foreach ($u in $keyUsers) {
    $exists = Get-ADUser -Filter {SamAccountName -eq $u} -ErrorAction SilentlyContinue
    Write-Host "User $u : $(if ($exists) {'EXISTS'} else {'MISSING'})" `
        -ForegroundColor $(if ($exists) {"Green"} else {"Red"})
}

# 5. Share and folder structure
$paths = @(
    "C:\Shares\Finance-Shared",
    "C:\Shares\Finance-Shared\General",
    "C:\Shares\Finance-Shared\Reports",
    "C:\Shares\Finance-Shared\Payroll"
)
foreach ($p in $paths) {
    Write-Host "Path $p : $(if (Test-Path $p) {'EXISTS'} else {'MISSING'})" `
        -ForegroundColor $(if (Test-Path $p) {"Green"} else {"Red"})
}

Write-Host "=== PRE-FLIGHT COMPLETE ===" -ForegroundColor Cyan
```

**Expected Result/Verification:** Every line returns green. Any red line must be resolved by revisiting the relevant day's lab before proceeding. Do not run JML operations against a broken environment — fixing problems mid-JML creates a partial-state mess that is harder to untangle than fixing the root cause upfront.

---

### PHASE A — JOINER: Meera Pillai (Senior IT Engineer, EmployeeID 1051)

---

### Step A1: Create the Joiner CSV for today's new hire
**Action:**
```powershell
$joinerCSV = @"
EmployeeID,FirstName,LastName,Department,Title,ManagerEmployeeID
1051,Meera,Pillai,IT,Senior IT Engineer,1040
"@
$joinerCSV | Out-File "C:\IAM-Scripts\NewHires-Day7.csv" -Encoding UTF8
```

Update the `$csvPath` parameter in the Joiner script to point to today's file:
```powershell
(Get-Content "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1") `
    -replace 'C:\\IAM-Scripts\\NewHires\.csv','C:\\IAM-Scripts\\NewHires-Day7.csv' |
    Set-Content "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1"
```

**Expected Result/Verification:**
```powershell
Import-Csv "C:\IAM-Scripts\NewHires-Day7.csv"
```
Single row displays: `EmployeeID: 1051`, `Department: IT`, `ManagerEmployeeID: 1040`. Confirm the script path variable is updated:
```powershell
Select-String -Path "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1" -Pattern "csvPath"
```
Output shows `NewHires-Day7.csv` in the `$csvPath` line.

---

### Step A2: Execute the Joiner script
**Action:**
```powershell
& "C:\IAM-Scripts\Invoke-JoinerProvisioning.ps1"
```

**Expected Result/Verification:** Console output shows:
```
[INFO]  Starting Joiner provisioning run
[INFO]  Records loaded from CSV: 1
[INFO]  Processing EmployeeID: 1051 | Meera Pillai
[INFO]  Manager resolved: EmployeeID 1040 → CN=Harish Kumar,...
[SUCCESS] bh1051 (Meera Pillai) created in OU=Users,OU=IT,OU=BHATT-CORP,...
[INFO]  Joiner run complete. Succeeded: 1 | Failed: 0
```
No `ERROR` or unexpected `WARN` lines. Verify account creation:
```powershell
Get-ADUser -Identity "bh1051" `
    -Properties EmployeeID, Title, Department, Manager, UserPrincipalName, Enabled |
    Select-Object SamAccountName, UserPrincipalName, EmployeeID,
                  Title, Department, Manager, Enabled
```
All fields populated. `Enabled: True`. `UPN: bh1051@Bhatt.com`. Manager DN resolves to Harish Kumar (bh1040).

---

### Step A3: Assign Joiner to the correct role groups
**Action:** The Joiner script creates the account but group assignment is a deliberate separate step — in production this would be driven by the HR "role" field mapped to a group-assignment matrix. Add bh1051 to the IT role group and PSO group (Senior IT Engineer qualifies as privileged):
```powershell
# IT role group (AGDLP — gives access to IT-relevant resources)
Add-ADGroupMember -Identity "G-IT-Support" -Members "bh1051"

# PSO group (Senior IT Engineer = privileged account — stricter password policy)
Add-ADGroupMember -Identity "G-PSO-Privileged-Strict" -Members "bh1051"
```

**Expected Result/Verification:**
```powershell
Get-ADPrincipalGroupMembership -Identity "bh1051" |
    Select-Object Name, GroupScope |
    Sort-Object Name
```
Output lists `G-IT-Support` (Global) and `G-PSO-Privileged-Strict` (Global) among her memberships. Verify the correct PSO will govern her:
```powershell
Get-ADUserResultantPasswordPolicy -Identity "bh1051" |
    Select-Object Name, MinPasswordLength, LockoutThreshold
```
Returns `PSO-Privileged-Strict` with `MinPasswordLength: 16`, `LockoutThreshold: 3` — confirming the stricter IT privileged policy applies from minute one of her account's existence.

---

### Step A4: Verify Joiner's full access chain end-to-end
**Action:** Validate that group membership has correctly propagated through the full AGDLP chain and that the Finance share is appropriately inaccessible to an IT user:
```powershell
# Confirm bh1051 is in G-IT-Support which is in DL-Finance-Share-Read
Write-Host "=== JOINER ACCESS CHAIN VERIFICATION: bh1051 ===" -ForegroundColor Cyan

Write-Host "`nDirect group memberships:"
Get-ADPrincipalGroupMembership -Identity "bh1051" | Select-Object Name, GroupScope

Write-Host "`nDL-Finance-Share-Read members (should include G-IT-Support):"
Get-ADGroupMember -Identity "DL-Finance-Share-Read" | Select-Object Name, ObjectClass

Write-Host "`nPayroll folder ACL (bh1051 should have NO access):"
(Get-Acl "C:\Shares\Finance-Shared\Payroll").Access |
    Select-Object IdentityReference, FileSystemRights
```

**Expected Result/Verification:** `bh1051` is in `G-IT-Support`; `G-IT-Support` is nested in `DL-Finance-Share-Read`; `DL-Finance-Share-Read` provides `ReadAndExecute` on `Finance-Shared` — giving Meera read-only access to `General` and `Reports` (as appropriate for IT Support), and zero access to `Payroll` (correctly excluded, since `DL-Finance-Share-Read` is not on Payroll's ACL). Full AGDLP chain intact. Joiner verified.

---

### PHASE B — MOVER: Arjun Tiwari (bh1009) — IT Support → Finance, Junior Finance Analyst

---

### Step B1: Document pre-Mover state (baseline snapshot)
**Action:** Always snapshot the identity state before executing a Mover — this is your rollback reference and your audit "before" state:
```powershell
Write-Host "=== PRE-MOVER STATE: bh1009 ===" -ForegroundColor Yellow

Get-ADUser -Identity "bh1009" `
    -Properties EmployeeID, Title, Department, Manager,
                DistinguishedName, MemberOf |
    Select-Object SamAccountName, EmployeeID, Title,
                  Department, Manager, DistinguishedName |
    Format-List

Write-Host "Current group memberships:"
Get-ADPrincipalGroupMembership -Identity "bh1009" |
    Select-Object Name, GroupScope
```

**Expected Result/Verification:** Output shows `Department: IT`, `Title: IT Support Specialist`, manager points to bh1013 (Kiran Sharma), `DistinguishedName` path contains `OU=Users,OU=IT`, and group memberships include `G-IT-Support`. Save this output:
```powershell
$preMoverState = Get-ADUser -Identity "bh1009" `
    -Properties Title, Department, Manager, MemberOf, DistinguishedName
```

---

### Step B2: Update identity attributes (Department, Title, Description)
**Action:**
```powershell
Set-ADUser -Identity "bh1009" `
           -Title "Junior Finance Analyst" `
           -Department "Finance" `
           -Description "Junior Finance Analyst - Finance"
```

**Expected Result/Verification:**
```powershell
Get-ADUser -Identity "bh1009" -Properties Title, Department, Description |
    Select-Object SamAccountName, Title, Department, Description
```
All three attributes reflect the new role. `Department: Finance`, `Title: Junior Finance Analyst`. This attribute update is what downstream attribute-driven systems (dynamic groups, HR sync, reporting tools) will consume — it must happen before the OU move so that any attribute-triggered automation fires with correct data.

---

### Step B3: Update Manager link (old manager: bh1013, new manager: bh1016)
**Action:**
```powershell
$newManagerDN = (Get-ADUser -Filter {EmployeeID -eq "1016"}).DistinguishedName
Set-ADUser -Identity "bh1009" -Manager $newManagerDN
```

**Expected Result/Verification:**
```powershell
Get-ADUser -Identity "bh1009" -Properties Manager |
    Select-Object SamAccountName, Manager
```
Manager DN now resolves to `CN=Kavya Reddy` (bh1016, Senior Finance Analyst). The org-chart relationship is correct — any approval workflow for bh1009's future access requests will now route to their Finance manager, not their former IT manager.

---

### Step B4: Remove old role group memberships (revoke IT access)
**Action:**
```powershell
# Remove from IT Support role group
Remove-ADGroupMember -Identity "G-IT-Support" -Members "bh1009" -Confirm:$false

# Remove from Privileged PSO group if they were added (check first)
$psoGroup = Get-ADGroupMember -Identity "G-PSO-Privileged-Strict" |
    Where-Object {$_.SamAccountName -eq "bh1009"}
if ($psoGroup) {
    Remove-ADGroupMember -Identity "G-PSO-Privileged-Strict" -Members "bh1009" -Confirm:$false
    Write-Host "Removed bh1009 from G-PSO-Privileged-Strict" -ForegroundColor Yellow
} else {
    Write-Host "bh1009 was not in G-PSO-Privileged-Strict - no action needed" -ForegroundColor Cyan
}
```

**Expected Result/Verification:**
```powershell
Get-ADGroupMember -Identity "G-IT-Support" |
    Where-Object {$_.SamAccountName -eq "bh1009"}
```
Returns nothing — bh1009 is no longer a member of `G-IT-Support`. Their path through `DL-Finance-Share-Read` (which was only for IT Support) is now severed. Verify PSO impact:
```powershell
Get-ADUserResultantPasswordPolicy -Identity "bh1009"
```
Returns **empty** (Default Domain Policy now governs them) — appropriate for a standard Finance Analyst, who does not require the privileged IT password policy.

---

### Step B5: Add new role group memberships (grant Finance access)
**Action:**
```powershell
# Add to Finance Analyst role group (grants Read/Write on Finance-Shared via AGDLP)
Add-ADGroupMember -Identity "G-Finance-Analysts" -Members "bh1009"
```

**Expected Result/Verification:**
```powershell
Get-ADPrincipalGroupMembership -Identity "bh1009" |
    Select-Object Name, GroupScope | Sort-Object Name
```
Output shows `G-Finance-Analysts` present, `G-IT-Support` absent. The AGDLP chain now flows: `bh1009 → G-Finance-Analysts → DL-Finance-Share-ReadWrite → Modify on Finance-Shared`. Verify Payroll remains correctly blocked (Junior Analyst should not have Payroll access):
```powershell
(Get-Acl "C:\Shares\Finance-Shared\Payroll").Access |
    Select-Object IdentityReference
```
`G-Finance-Analysts` is not in the Payroll ACL — bh1009 correctly gets Finance General/Reports access but not Payroll.

---

### Step B6: Move account to the correct OU (IT Users → Finance Users)
**Action:** OU move is the final step — done last to avoid GPO application changing before access is correctly reconfigured:
```powershell
$targetOU = "OU=Users,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com"
Move-ADObject -Identity $preMoverState.DistinguishedName -TargetPath $targetOU
```

**Expected Result/Verification:**
```powershell
Get-ADUser -Identity "bh1009" | Select-Object SamAccountName, DistinguishedName
```
`DistinguishedName` now reads `CN=Arjun Tiwari,OU=Users,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com`. The account has left the IT OU and entered the Finance OU — meaning `GPO-Finance-LogonRestrictions` and `GPO-Finance-DriveMaps` now apply to this user. On next login, drive `F:` will map automatically (bh1009 is now in `G-Finance-Analysts`, which is an Item-Level Targeting target for that GPO).

---

### Step B7: Force GPO update and validate on Computer-01
**Action:** On **Computer-01**, log in as **bh1009** (Arjun Tiwari). Open PowerShell and run:
```powershell
gpupdate /force
```

**Expected Result/Verification:** After GPO refresh, open **File Explorer** — drive `F:` labeled `Finance Shared` appears, mapped to `\\DC01\Finance-Shared`. This confirms the full Mover chain worked: OU move triggered GPO scope change, group change triggered drive map Item-Level Targeting. Run the post-Mover state snapshot for audit documentation:
```powershell
# Back on DC01
Write-Host "=== POST-MOVER STATE: bh1009 ===" -ForegroundColor Green
Get-ADUser -Identity "bh1009" `
    -Properties Title, Department, Manager, DistinguishedName, MemberOf |
    Select-Object SamAccountName, Title, Department, Manager, DistinguishedName |
    Format-List
Write-Host "Current group memberships:"
Get-ADPrincipalGroupMembership -Identity "bh1009" | Select-Object Name, GroupScope
```
Compare this output against the pre-Mover snapshot from Step B1 — every field should reflect the change. This before/after pair is your Mover audit artifact.

---

### PHASE C — LEAVER: Mike Ross (bh1002, Finance Analyst)

---

### Step C1: Document pre-Leaver state (baseline snapshot)
**Action:**
```powershell
Write-Host "=== PRE-LEAVER STATE: bh1002 ===" -ForegroundColor Yellow

Get-ADUser -Identity "bh1002" `
    -Properties EmployeeID, Title, Department, Manager,
                Enabled, MemberOf, DistinguishedName, Description |
    Select-Object SamAccountName, EmployeeID, Title, Department,
                  Manager, Enabled, Description, DistinguishedName |
    Format-List

Write-Host "Group memberships to be stripped:"
Get-ADPrincipalGroupMembership -Identity "bh1002" |
    Select-Object Name, GroupScope
```

**Expected Result/Verification:** Output shows `Enabled: True`, account located in `OU=Users,OU=Finance`, membership in `G-Finance-Analysts` (and any other groups). This is your "access before termination" evidence — in a real environment, this snapshot would be attached to the offboarding ticket as proof of what access was revoked.

---

### Step C2: Execute the Leaver script
**Action:**
```powershell
& "C:\IAM-Scripts\Invoke-LeaverOffboarding.ps1" -EmployeeID 1002
```

**Expected Result/Verification:** Console output progresses through all six steps:
```
[INFO]    Leaver offboarding started
[INFO]    Target EmployeeID: 1002
[INFO]    Account resolved: bh1002 (Mike Ross)
[SUCCESS] Step 1/6 — Account disabled: bh1002
[SUCCESS] Step 2/6 — Password invalidated
[SUCCESS] Step 3/6 — Removing N group membership(s)...
[SUCCESS]   Removed from: G-Finance-Analysts
[SUCCESS] Step 4/6 — Manager attribute cleared
[SUCCESS] Step 5/6 — Description stamped: OFFBOARDED 2024-xx-xx | EmpID:1002 | Was: Finance Analyst - Finance
[SUCCESS] Step 6/6 — Moved to: OU=Disabled-Users,OU=BHATT-CORP,...
[INFO]    Offboarding complete. Groups left: 0
```
No `ERROR` lines. All six steps succeed.

---

### Step C3: Verify the Leaver final state (multi-attribute check)
**Action:**
```powershell
Write-Host "=== POST-LEAVER VERIFICATION: bh1002 ===" -ForegroundColor Cyan

$leaver = Get-ADUser -Filter {EmployeeID -eq "1002"} `
    -Properties Enabled, DistinguishedName, Description,
                MemberOf, PasswordLastSet, LockedOut

Write-Host "`n-- Account State --"
Write-Host "SAM         : $($leaver.SamAccountName)"
Write-Host "Enabled     : $($leaver.Enabled)"          # Must be False
Write-Host "LockedOut   : $($leaver.LockedOut)"
Write-Host "Location    : $($leaver.DistinguishedName)" # Must show Disabled-Users
Write-Host "Description : $($leaver.Description)"      # Must show OFFBOARDED stamp

Write-Host "`n-- Group Memberships Remaining --"
if ($leaver.MemberOf.Count -eq 0) {
    Write-Host "CLEAN - No group memberships remain (Domain Users primary group only)" `
        -ForegroundColor Green
} else {
    Write-Host "WARNING - $($leaver.MemberOf.Count) group(s) still assigned:" `
        -ForegroundColor Red
    $leaver.MemberOf | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

Write-Host "`n-- AGDLP Residual Check --"
Write-Host "Checking Finance Analyst group for bh1002..."
$residual = Get-ADGroupMember -Identity "G-Finance-Analysts" |
    Where-Object {$_.SamAccountName -eq "bh1002"}
if (-not $residual) {
    Write-Host "CLEAN - bh1002 not found in G-Finance-Analysts" -ForegroundColor Green
} else {
    Write-Host "FAIL - bh1002 still in G-Finance-Analysts" -ForegroundColor Red
}
```

**Expected Result/Verification:** Every check returns clean:
- `Enabled: False`
- `DistinguishedName` contains `Disabled-Users`
- `Description` begins with `OFFBOARDED`
- `Group Memberships Remaining: 0`
- `G-Finance-Analysts: CLEAN`

This is the full compliance-ready verification output. In a real environment, you'd save this to the offboarding ticket or audit log.

---

### Step C4: Attempt login with bh1002 to confirm access is truly revoked
**Action:** On **Computer-01**, attempt to log in as `bh1002`. Enter the old temporary password (or any password).

**Expected Result/Verification:** Windows returns `"The referenced account is currently disabled and may not be logged on to."` — not a password error, but an explicit account-disabled message. This confirms disable propagated correctly to the authenticating DC. A password error would indicate disable didn't apply; a different error message (e.g., workstation restriction) would indicate a different control is doing the blocking. The specific "account disabled" message is the clean confirmation we need.

---

### PHASE D — Consolidated Audit Trail Report

---

### Step D1: Generate the full JML audit report for the day
**Action:** Run the consolidated audit report — this is the artifact you'd deliver to a compliance team or attach to all three tickets:
```powershell
$reportPath = "C:\IAM-Scripts\Logs\JML-AuditReport-$(Get-Date -Format 'yyyyMMdd').txt"

$report = @"
================================================================
BHATT.COM IAM — JML AUDIT REPORT
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Executed by: $env:USERNAME on $env:COMPUTERNAME
================================================================

--- JOINER: bh1051 (Meera Pillai) ---
"@

$joiner = Get-ADUser -Identity "bh1051" `
    -Properties EmployeeID, Title, Department, Manager,
                Enabled, MemberOf, DistinguishedName

$report += @"

  SAM           : $($joiner.SamAccountName)
  UPN           : $($joiner.UserPrincipalName)
  EmployeeID    : $($joiner.EmployeeID)
  Title         : $($joiner.Title)
  Department    : $($joiner.Department)
  Manager       : $($joiner.Manager)
  Enabled       : $($joiner.Enabled)
  Location      : $($joiner.DistinguishedName)
  Groups        : $(($joiner.MemberOf | ForEach-Object {($_ -split ',')[0] -replace 'CN=',''}) -join ', ')
  PSO Applied   : $((Get-ADUserResultantPasswordPolicy -Identity "bh1051" -ErrorAction SilentlyContinue).Name ?? "(Default Domain Policy)")
  Status        : PROVISIONED

--- MOVER: bh1009 (Arjun Tiwari) IT Support → Finance Junior Analyst ---
"@

$mover = Get-ADUser -Identity "bh1009" `
    -Properties EmployeeID, Title, Department, Manager,
                Enabled, MemberOf, DistinguishedName

$report += @"

  SAM           : $($mover.SamAccountName)
  New Title     : $($mover.Title)
  New Dept      : $($mover.Department)
  New Manager   : $($mover.Manager)
  New Location  : $($mover.DistinguishedName)
  Groups Now    : $(($mover.MemberOf | ForEach-Object {($_ -split ',')[0] -replace 'CN=',''}) -join ', ')
  Old Group     : G-IT-Support (removed)
  New Group     : G-Finance-Analysts (added)
  Status        : TRANSFER COMPLETE

--- LEAVER: bh1002 (Mike Ross) ---
"@

$leaver = Get-ADUser -Filter {EmployeeID -eq "1002"} `
    -Properties EmployeeID, Title, Department, Enabled,
                MemberOf, DistinguishedName, Description

$report += @"

  SAM           : $($leaver.SamAccountName)
  EmployeeID    : $($leaver.EmployeeID)
  Enabled       : $($leaver.Enabled)
  Location      : $($leaver.DistinguishedName)
  Groups Left   : $($leaver.MemberOf.Count) (expected: 0)
  Description   : $($leaver.Description)
  Status        : OFFBOARDED

================================================================
END OF REPORT
================================================================
"@

$report | Out-File $reportPath -Encoding UTF8
Write-Host "Audit report written to: $reportPath" -ForegroundColor Green
Get-Content $reportPath
```

**Expected Result/Verification:** Report file exists at `C:\IAM-Scripts\Logs\JML-AuditReport-<date>.txt`. All three sections show clean final states. This single file is your complete daily JML audit artifact — the kind of deliverable a SOC2 auditor would request as evidence of controlled identity lifecycle management.

---

### Step D2: Final environment state summary — full 50-user domain verification
**Action:**
```powershell
Write-Host "=== FINAL DOMAIN STATE SUMMARY ===" -ForegroundColor Cyan

Write-Host "`nUsers by Department:"
Get-ADUser -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -Properties Department |
    Group-Object Department |
    Select-Object Name, Count |
    Sort-Object Name | Format-Table -AutoSize

Write-Host "Users by Enabled State:"
Get-ADUser -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -Properties Enabled |
    Group-Object Enabled |
    Select-Object Name, Count | Format-Table -AutoSize

Write-Host "Users in Disabled-Users OU:"
Get-ADUser -Filter * `
    -SearchBase "OU=Disabled-Users,OU=BHATT-CORP,DC=Bhatt,DC=com" |
    Select-Object SamAccountName, Name
```

**Expected Result/Verification:**
- Department breakdown: Finance ~18, IT ~18 (bh1009 moved in, bh1051 added), Sales ~15
- Enabled state: 50 Enabled (bh1051 new), 1 Disabled (bh1002 leaver)
- Disabled-Users OU: contains `bh1002` (Mike Ross) only

Total accounts in BHATT-CORP: 51 (50 original + bh1051 new hire). One disabled, 50 active. The domain is in a clean, consistent, fully auditable state.

---

## 4. Interview-Prep Q&A

**Q1: "During a Mover process, an engineer updates the user's Department attribute and moves them to the new OU, but forgets to change their group memberships. Six months later, an access review flags this user as having Finance AND IT resource access simultaneously. What is this called, and what control should have prevented it?"**

**Strong Answer:** This is a **Segregation of Duties (SoD) violation** created by an incomplete Mover process — specifically, a case of **toxic access accumulation** or **entitlement creep**, where a user retains access from a prior role while gaining access for their new role. The user now has access to IT resources (via residual `G-IT-Support` membership) and Finance resources (via newly added `G-Finance-Analysts` membership) simultaneously — which, depending on what those resources contain, may violate SoD controls (e.g., someone who can both process Finance transactions and modify IT audit logging controls is a segregation-of-duties risk). The control that should have prevented it is a **Mover Checklist enforced atomically** — group removal from old role groups must be a mandatory step in the Mover workflow, not an optional one. In a mature IAM program, this is either automated (a provisioning engine handles the full role change atomically based on the HRIS event) or enforced via a structured Mover runbook with a mandatory sign-off on "old group memberships removed" before the ticket is closed. The access review detecting it six months later is a compensating control — it should not be the primary control. Prevention at Mover execution time is the primary control.

**Q2: "A compliance auditor requests proof that a departed employee's access was revoked on their last working day. What specific artifacts do you produce, and what do they prove?"**

**Strong Answer:** Three artifacts together constitute complete evidence. First, the **Leaver script execution log** at `C:\IAM-Scripts\Logs\Leaver-EmpID<id>-<datetime>.log` — it contains a timestamped record of every action taken (disable, password invalidation, group removals, OU move) including the initiating admin's username and machine name, proving the action was controlled and traceable to a specific operator. Second, the **AD object final state** — queried via `Get-ADUser` on the departed employee's account showing `Enabled: False`, `DistinguishedName` in the `Disabled-Users` OU, `Description` stamped with the offboarding date, and `MemberOf` count of zero — proving the end state is correct independent of what the log claims. Third, the **JML Audit Report** — a consolidated artifact correlating the action log with the verified final state, suitable for non-technical stakeholders. Together, these three artifacts address the three things an auditor is actually verifying: that access was revoked (log proves action), that it is currently revoked (AD state proves current condition), and that revocation happened on the correct date (timestamp on both log and description stamp). If asked "what if the script ran but the disable failed silently?" — the final-state verification step in the script's Step 6 and the `Enabled: False` confirmation in the audit report catch that scenario explicitly.

---

## 5. Overall Progress Tracker

**Phase 1 Complete. Phase 2 begins next.**

```
[■■■■■■■□□□] Day 7 of 30 — 23% Complete
```

✅ Day 1 — AD DS Logical Structure & Enterprise OU Design
✅ Day 2 — User Lifecycle Management (JML) — Joiner Phase
✅ Day 3 — Group Strategy & AGDLP Nesting Model
✅ Day 4 — GPO for Access Control
✅ Day 5 — Fine-Grained Password Policies & PowerShell Automation
✅ Day 6 — NTFS & Share Permissions Layering & ABAC Introduction
✅ Day 7 — Phase 1 Capstone: End-to-End JML Simulation *(Complete)*

**Phase 2: Privileged Access, Delegation & Tiering Architectures**
⬜ Day 8 — Least Privilege Deep Dive & Built-in Privileged Groups
⬜ Day 9 — OU Delegation of Control
⬜ Day 10 — RBAC Design & Access Matrix Documentation
⬜ Day 11 — Microsoft Tiering Model (Tier 0/1/2)
⬜ Day 12 — Privileged Account Management & Protected Users Group
⬜ Day 13 — LAPS Deployment
⬜ Day 14 — JIT Access & Time-Bound Elevation Automation
⬜ Day 15 — Phase 2 Capstone

---

**Phase 1 is complete. You now have a production-pattern AD environment with 51 users, a clean AGDLP access model, GPO-enforced controls, PSO-tiered password policies, and a fully auditable JML process backed by versioned scripts and timestamped logs.**

**Also update your session continuity prompt before starting a new chat:**
- bh1009 is now in Finance (Junior Finance Analyst, manager: bh1016)
- bh1051 (Meera Pillai, Senior IT Engineer) added, EmployeeID 1051
- bh1002 (Mike Ross) is disabled and in Disabled-Users OU
- Next available EmployeeID: **1052**


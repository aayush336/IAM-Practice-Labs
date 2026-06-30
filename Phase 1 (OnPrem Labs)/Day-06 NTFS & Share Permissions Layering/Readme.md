# Day 6 Lab: NTFS & Share Permissions Layering — Least Privilege in Practice, Effective Permissions Troubleshooting & ABAC Introduction

---

## 1. Core Concept Overview

Day 3 built the AGDLP group model and applied a single layer of NTFS permissions onto `Finance-Shared`. In real production environments, however, file servers rarely have one flat permission layer — they have **nested folder hierarchies where different subfolders require different access levels for different roles**, and the way NTFS and Share permissions interact when both are present is one of the most heavily tested troubleshooting scenarios for any IAM or Sysadmin role.

**Two permission layers exist simultaneously on any SMB share, and they don't work the way most beginners assume:**

**Share Permissions** apply only when the resource is accessed *over the network* (via `\\DC01\ShareName`). They are coarse-grained (Read, Change, Full Control only) and apply uniformly to the entire share — there's no concept of "different share permissions for different subfolders."

**NTFS Permissions** apply to the file system itself, regardless of access method (network or local console logon), and are granular — they can differ folder-by-folder, file-by-file, and support detailed rights like Modify, Write, List Folder Contents, Read & Execute, Special Permissions.

**The Effective Permission Rule — the single most-tested interview concept in this domain:** When a user accesses a resource over the network, Windows calculates the **most restrictive combination** of Share permissions and NTFS permissions. If Share permissions grant Full Control but NTFS grants only Read, the effective result is Read. If NTFS grants Full Control but Share permissions grant only Read, the effective result is Read. **The more restrictive of the two always wins.** This is why enterprise standard practice (which we already applied on Day 3, and will reinforce today) is to set Share permissions broadly (`Authenticated Users: Full Control` or matching DL groups at Full/Change) and do all *actual* access control enforcement at the NTFS layer — because NTFS is granular per-folder and Share permissions are not.

**Permission Inheritance and Explicit Deny:** By default, child folders inherit permissions from their parent. This inheritance can be broken (disabled) on a specific subfolder to apply a different, more restrictive permission set — a common pattern for a "Payroll" subfolder inside a general "Finance" share that only a subset of Finance staff should access. Within NTFS, **explicit Deny always overrides any Allow**, regardless of where the Allow came from (even a more specific, more local Allow). This makes Deny a powerful but dangerous tool — overuse of explicit Deny entries is itself considered an anti-pattern because it makes effective-permission troubleshooting exponentially harder; the enterprise-preferred method to restrict access is to simply not grant Allow, not to add a Deny.

**ABAC (Attribute-Based Access Control) — introduced conceptually today:** RBAC (which we've built via AGDLP) grants access based on *role/group membership*. ABAC extends this by making access decisions based on *attributes* of the user, resource, or environment — e.g., "only users whose `Department` attribute equals `Finance` AND whose `Title` contains `Manager` can access the Payroll folder," evaluated dynamically rather than through static group membership. True ABAC requires Dynamic Access Control (DAC) with Central Access Policies — a Windows Server feature we will only conceptually introduce today (full DAC implementation is out of scope for a single lab day), but understanding the RBAC-to-ABAC evolution is essential interview knowledge, since most mature enterprises are moving toward attribute-aware access models, especially in cloud/hybrid environments (Day 23+).

---

## 2. Real-World Enterprise Use Case

Your Finance department, now staffed with 17 employees across four organizational levels (Director, Manager, Senior Analyst, Analyst, Junior Analyst), has a real business requirement: **not everyone in Finance should see Payroll data.**

This is an extremely common real-world scenario. A Finance share typically has subfolder segmentation like:

```
Finance-Shared\
 ├── General\          (all Finance staff: Read/Write)
 ├── Reports\          (all Finance staff: Read; Senior Analysts+: Write)
 └── Payroll\          (ONLY Finance Director + Finance Manager: Read/Write)
```

This is exactly the kind of nested, least-privilege folder design an IAM Engineer is asked to implement during any Finance/HR data segregation project — frequently driven by compliance requirements (SOX controls around payroll data access, GDPR/data minimization principles, or basic separation-of-duties between general accounting staff and payroll-specific compensation data).

The practical challenge: **all of Finance currently has Modify access to `Finance-Shared` via `DL-Finance-Share-ReadWrite`** (built Day 3). If we create a `Payroll` subfolder inside `Finance-Shared` and do nothing else, every Finance Analyst would inherit Modify access to Payroll too — a serious least-privilege violation. Today's lab fixes this by breaking inheritance on the Payroll subfolder and applying a new, more restrictive Domain Local group scoped only to Director + Manager level.

We will also use your **50-user dataset** to test effective permissions across multiple role levels — Director, Manager, Senior Analyst, and Analyst — so the lab reflects a genuine multi-tier access scenario rather than a 2-3 person toy example.

---

## 3. Detailed Step-by-Step Procedure

> **Tooling:** File Explorer + `icacls`/PowerShell `Get-Acl`/`Set-Acl` on DC01. Ensure your 50-user dataset (EmployeeIDs 1001–1050) is already provisioned before starting — this lab assumes `bh1010` (Finance Director), `bh1001` (Finance Manager), `bh1015`/`bh1016`/`bh1047` (Senior Finance Analysts), and `bh1002` (Finance Analyst) all exist.

---

### Step 1: Create the nested folder structure inside Finance-Shared
**Action:** On DC01, open PowerShell as Administrator:
```powershell
New-Item -Path "C:\Shares\Finance-Shared\General" -ItemType Directory -Force
New-Item -Path "C:\Shares\Finance-Shared\Reports" -ItemType Directory -Force
New-Item -Path "C:\Shares\Finance-Shared\Payroll" -ItemType Directory -Force
```

**Expected Result/Verification:**
```powershell
Get-ChildItem "C:\Shares\Finance-Shared" -Directory
```
Output shows three subfolders: `General`, `Payroll`, `Reports`. Each currently inherits the Day 3 NTFS ACL from the parent (`DL-Finance-Share-FullControl`, `DL-Finance-Share-ReadWrite`, `DL-Finance-Share-Read`).

---

### Step 2: Verify current inheritance — confirm Payroll has the problem
**Action:** Check the inherited permissions on the new Payroll folder before fixing anything:
```powershell
(Get-Acl "C:\Shares\Finance-Shared\Payroll").Access |
    Select-Object IdentityReference, FileSystemRights, IsInherited
```

**Expected Result/Verification:** Output shows `DL-Finance-Share-ReadWrite` with `IsInherited: True` — confirming that, right now, every Finance Analyst (via `G-Finance-Analysts` nested in this DL group) has Modify access to Payroll. This is the least-privilege violation we are about to correct.

---

### Step 3: Create the Payroll-specific Domain Local group
**Action:** In PowerShell on DC01:
```powershell
New-ADGroup -Name "DL-Finance-Payroll-FullControl" `
            -SamAccountName "DL-Finance-Payroll-FullControl" `
            -GroupScope DomainLocal `
            -GroupCategory Security `
            -Path "OU=Groups,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" `
            -Description "Full control on Finance-Shared\Payroll - Director and Manager only"
```

Create a new Global role group for the privileged Payroll-access population:
```powershell
New-ADGroup -Name "G-Finance-PayrollAccess" `
            -SamAccountName "G-Finance-PayrollAccess" `
            -GroupScope Global `
            -GroupCategory Security `
            -Path "OU=Groups,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" `
            -Description "Role group - Finance staff authorized for Payroll data access"
```

**Expected Result/Verification:**
```powershell
Get-ADGroup -Filter {Name -like "*Payroll*"} | Select-Object Name, GroupScope
```
Returns both groups with correct scopes: `DL-Finance-Payroll-FullControl` (DomainLocal), `G-Finance-PayrollAccess` (Global).

---

### Step 4: Populate and nest the Payroll access groups (AGDLP applied again)
**Action:** Add the Finance Director and Finance Manager to the Global role group, using their EmployeeID-derived SAM names:
```powershell
Add-ADGroupMember -Identity "G-Finance-PayrollAccess" -Members "bh1010","bh1001"
```

Nest the Global group into the Domain Local group:
```powershell
Add-ADGroupMember -Identity "DL-Finance-Payroll-FullControl" -Members "G-Finance-PayrollAccess"
```

**Expected Result/Verification:**
```powershell
Get-ADGroupMember -Identity "G-Finance-PayrollAccess" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "DL-Finance-Payroll-FullControl" | Select-Object Name, ObjectClass
```
First command shows `Rajesh Kulkarni (bh1010)` and `Sarah Connor (bh1001)`. Second command shows `G-Finance-PayrollAccess` with `ObjectClass: group` — confirming clean AGDLP nesting, no direct user assignment.

---

### Step 5: Break inheritance on the Payroll folder
**Action:** This is the critical step — disable inheritance so Payroll stops inheriting the broader Finance-Shared ACL:
```powershell
$path = "C:\Shares\Finance-Shared\Payroll"
$acl  = Get-Acl $path

# Break inheritance, and DO NOT copy existing inherited entries
# (false = do not preserve copies of inherited rules)
$acl.SetAccessRuleProtection($true, $false)

Set-Acl -Path $path -AclObject $acl
```

**Expected Result/Verification:**
```powershell
(Get-Acl $path).Access | Select-Object IdentityReference, IsInherited
```
Output should now be **empty or show zero entries** — all previously inherited ACEs (including `DL-Finance-Share-ReadWrite`) have been stripped. The folder currently has no explicit permissions at all, meaning effectively no one (except the file owner/SYSTEM via underlying NTFS defaults) can access it yet — this is the "deny by default" state we want before applying the correct narrow ACL.

---

### Step 6: Apply the new, restrictive ACL to Payroll
**Action:**
```powershell
$path = "C:\Shares\Finance-Shared\Payroll"
$acl  = Get-Acl $path

# Grant Full Control to the Payroll-specific DL group only
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Bhatt\DL-Finance-Payroll-FullControl","FullControl","ContainerInherit,ObjectInherit","None","Allow")))

# Always retain SYSTEM and local Administrators baseline
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))

Set-Acl -Path $path -AclObject $acl
```

**Expected Result/Verification:**
```powershell
(Get-Acl $path).Access | Select-Object IdentityReference, FileSystemRights, IsInherited
```
Exactly three ACEs appear: `DL-Finance-Payroll-FullControl`, `SYSTEM`, `BUILTIN\Administrators` — all with `IsInherited: False` (since these are now explicit, not inherited). No `DL-Finance-Share-ReadWrite` entry remains, confirming Finance Analysts no longer have any path to Payroll access.

---

### Step 7: Apply differentiated permissions on General and Reports subfolders
**Action:** Unlike Payroll, `General` and `Reports` should remain accessible to all Finance staff — but `Reports` should additionally restrict *write* access to Senior Analyst level and above, while Analysts/Juniors get Read-only on Reports. Create a new DL group for this tier:
```powershell
New-ADGroup -Name "DL-Finance-Reports-Write" `
            -SamAccountName "DL-Finance-Reports-Write" `
            -GroupScope DomainLocal `
            -GroupCategory Security `
            -Path "OU=Groups,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" `
            -Description "Write access on Finance-Shared\Reports - Senior Analyst and above"

New-ADGroup -Name "G-Finance-SeniorAnalysts" `
            -SamAccountName "G-Finance-SeniorAnalysts" `
            -GroupScope Global `
            -GroupCategory Security `
            -Path "OU=Groups,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" `
            -Description "Role group - Senior Finance Analysts and above"

# Populate with Senior Finance Analysts (1015, 1016, 1047) + Manager (1001) + Director (1010)
Add-ADGroupMember -Identity "G-Finance-SeniorAnalysts" -Members "bh1015","bh1016","bh1047","bh1001","bh1010"

Add-ADGroupMember -Identity "DL-Finance-Reports-Write" -Members "G-Finance-SeniorAnalysts"
```

Now break inheritance on Reports and apply a two-tier ACL — Write for Seniors, Read for everyone else in Finance:
```powershell
$path = "C:\Shares\Finance-Shared\Reports"
$acl  = Get-Acl $path
$acl.SetAccessRuleProtection($true, $false)

# Senior tier: Modify
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Bhatt\DL-Finance-Reports-Write","Modify","ContainerInherit,ObjectInherit","None","Allow")))

# All Finance staff: Read-only baseline (existing Read DL group reused)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Bhatt\DL-Finance-Share-ReadWrite","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")))

$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))

Set-Acl -Path $path -AclObject $acl
```

> **Note on layered Allow rules:** Here, `DL-Finance-Share-ReadWrite` (containing all Finance Analysts) is given `ReadAndExecute` on Reports specifically — overriding what they'd normally get (Modify) at the parent level, because this folder broke inheritance and defines its own explicit rules. This demonstrates how folder-level ACLs override parent-level grants without needing any Deny entries — the preferred least-privilege pattern.

**Expected Result/Verification:**
```powershell
(Get-Acl "C:\Shares\Finance-Shared\Reports").Access |
    Select-Object IdentityReference, FileSystemRights
```
Shows `DL-Finance-Reports-Write: Modify` and `DL-Finance-Share-ReadWrite: ReadAndExecute` — two different access levels on the same folder via two different DL groups.

---

### Step 8: Leave General folder on default inheritance (no change needed)
**Action:** Verify `General` still inherits cleanly from the parent (we intentionally did not break inheritance here):
```powershell
(Get-Acl "C:\Shares\Finance-Shared\General").Access |
    Select-Object IdentityReference, FileSystemRights, IsInherited
```

**Expected Result/Verification:** Output shows the original Day 3 ACEs (`DL-Finance-Share-FullControl`, `DL-Finance-Share-ReadWrite`, `DL-Finance-Share-Read`) all with `IsInherited: True`. This confirms `General` correctly remains open to all Finance staff at their existing Day 3 access levels — only `Payroll` and `Reports` needed customization.

---

### Step 9: Effective Permissions troubleshooting — using the built-in GUI tool
**Action:** On DC01, right-click `C:\Shares\Finance-Shared\Payroll` → **Properties → Security tab → Advanced → Effective Access tab**. Click **"Select a user"** → type `bh1002` (Mike Ross, Finance Analyst) → **OK** → click **View effective access**.

**Expected Result/Verification:** Every permission row shows **denied/unchecked** (red X or absence of checkmark) — confirming Mike Ross has zero effective access to Payroll. Now repeat for `bh1010` (Finance Director) — every permission row should show **granted** (green checkmark), confirming Full Control. This GUI tool is exactly what a Helpdesk Tier-2 or IAM Analyst uses during a live "why can't I access X" ticket investigation — no PowerShell needed for a quick check.

---

### Step 10: Effective Permissions troubleshooting — PowerShell equivalent (scriptable, audit-friendly)
**Action:** Build a reusable effective-access check function:
```powershell
function Test-EffectiveAccess {
    param(
        [string]$Path,
        [string]$SamAccountName
    )
    $user = Get-ADUser -Identity $SamAccountName
    $sid  = $user.SID

    $acl = Get-Acl $Path
    $applicableRules = $acl.Access | Where-Object {
        $groupSID = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
        try {
            $groupMembers = Get-ADGroupMember -Identity $groupSID -Recursive -ErrorAction SilentlyContinue
            ($groupMembers.SID -contains $sid) -or ($_.IdentityReference -eq $sid)
        } catch { $false }
    }

    Write-Host "Effective access for $SamAccountName on $Path" -ForegroundColor Cyan
    if ($applicableRules) {
        $applicableRules | Select-Object IdentityReference, FileSystemRights, AccessControlType
    } else {
        Write-Host "  NO ACCESS - no matching ACE found for this user (directly or via group)" -ForegroundColor Red
    }
}

# Test across multiple role levels on Payroll
Test-EffectiveAccess -Path "C:\Shares\Finance-Shared\Payroll" -SamAccountName "bh1010"  # Director - should have access
Test-EffectiveAccess -Path "C:\Shares\Finance-Shared\Payroll" -SamAccountName "bh1001"  # Manager - should have access
Test-EffectiveAccess -Path "C:\Shares\Finance-Shared\Payroll" -SamAccountName "bh1015"  # Sr. Analyst - should NOT have access
Test-EffectiveAccess -Path "C:\Shares\Finance-Shared\Payroll" -SamAccountName "bh1002"  # Analyst - should NOT have access
```

**Expected Result/Verification:** `bh1010` and `bh1001` return the `DL-Finance-Payroll-FullControl` ACE with `FullControl`. `bh1015` and `bh1002` return `NO ACCESS`. This four-user differential proves the Payroll restriction works correctly across the full Finance hierarchy — not just for the two users it was designed for, but correctly excluding everyone else, including a Senior Analyst who might otherwise be assumed to have broader access.

---

### Step 11: Validate Share-vs-NTFS "most restrictive wins" rule directly
**Action:** Temporarily demonstrate the effective permission rule by intentionally restricting the share-level permission below the NTFS level:
```powershell
# Temporarily set share permission for DL-Finance-Share-Read to Read only (already correct)
# but demonstrate the rule by checking what a Read-only share user gets even with
# stronger NTFS rights — using DL-Finance-Share-Read (G-IT-Support members)

Get-SmbShareAccess -Name "Finance-Shared" | Select-Object AccountName, AccessRight
```

Then check what `bh1003` (David Kim, IT Support — in `DL-Finance-Share-Read`) has at the NTFS layer on `General`:
```powershell
Test-EffectiveAccess -Path "C:\Shares\Finance-Shared\General" -SamAccountName "bh1003"
```

**Expected Result/Verification:** Share-level access for IT Support's DL group shows `Read`. Even though NTFS on `General` might theoretically allow more (it doesn't in this design, but if it did), the **Share permission caps it at Read** when `bh1003` connects via `\\DC01\Finance-Shared`. This is the live demonstration that the lower of the two permission layers always governs network access — document this finding as your Step 11 verification artifact.

---

### Step 12: ABAC concept exercise — design (not implement) an attribute-based rule
**Action:** No lab commands here — this is a design exercise to build ABAC thinking. Write the following into a new doc:
```powershell
$abacNote = @"
ABAC CONCEPT EXERCISE - Payroll Access Rule

Current implementation (RBAC):
  Access = Member of DL-Finance-Payroll-FullControl
  (static group membership, manually maintained)

Equivalent ABAC rule (conceptual - Dynamic Access Control):
  Access = (user.Department == "Finance") AND
           (user.Title CONTAINS "Director" OR user.Title CONTAINS "Manager")

Key difference:
  RBAC requires an admin to manually add/remove users from the
  DL-Finance-Payroll-FullControl group whenever someone is promoted,
  demoted, or transferred.

  ABAC would automatically re-evaluate access the moment the user's
  Title or Department attribute changes in AD - no manual group
  maintenance required, because the policy reads attributes live
  at access-evaluation time rather than relying on static group
  membership snapshots.

  Tradeoff: ABAC requires Dynamic Access Control infrastructure
  (Central Access Policies, claims-based authentication enabled
  on the domain, classification of resources) - significantly
  higher setup complexity than RBAC, which is why most enterprises
  remain RBAC-based for on-prem file shares and reserve true ABAC
  for cloud/hybrid scenarios (Azure ABAC, Entra Conditional Access)
  covered in Phase 4.
"@
$abacNote | Out-File "C:\IAM-Docs\ABAC-Concept-Notes.txt" -Encoding UTF8
```

**Expected Result/Verification:**
```powershell
Get-Content "C:\IAM-Docs\ABAC-Concept-Notes.txt"
```
Document displays correctly. This conceptual artifact is exactly the kind of comparison document a mid-level IAM Engineer would produce when a security architect asks "should we move toward ABAC?" — you're not implementing DAC today, but you now understand precisely what it would replace and why it's harder to maintain at small scale but more scalable at attribute-driven enterprise scale.

---

## 4. Interview-Prep Q&A

**Q1: "A user has Full Control NTFS permission on a folder, but when they map the network share and try to delete a file, they get Access Denied. They have local console access to the same folder via RDP and CAN delete the file there. What's happening, and how do you fix it?"**

**Strong Answer:** This is the classic Share-vs-NTFS effective permission scenario. Share permissions and NTFS permissions are evaluated independently for network access, and the more restrictive of the two always wins — but Share permissions only apply when accessing the resource *over the network* (`\\server\share`), not via local console/RDP access to the file system directly. If NTFS grants Full Control but the Share permission is set to Read-only, a network user is capped at Read regardless of their NTFS rights — but a console/RDP session bypasses the share layer entirely and is governed by NTFS alone, which is why Full Control works locally but not over the network. The fix is to check `Get-SmbShareAccess -Name <ShareName>` and raise the share-level permission for that user's group to at least Change (which allows delete), since NTFS already grants the necessary rights — share permissions just need to stop being the bottleneck. The enterprise best practice to prevent this entire class of ticket is exactly what we did in Day 3 and reinforced today: set Share permissions broadly (Full Control or Change for relevant groups) and do all fine-grained access control exclusively at the NTFS layer, since NTFS is what supports folder-level granularity and Share permissions do not.

**Q2: "Why is it considered an anti-pattern to use explicit Deny permissions to restrict a specific user's access, instead of simply not granting them Allow in the first place?"**

**Strong Answer:** Explicit Deny always overrides any Allow in NTFS, regardless of where that Allow originates — including a more specific, more local Allow rule. This makes Deny a powerful tool, but it creates two real operational problems. First, it makes effective-permission troubleshooting significantly harder, because an administrator investigating "why can't this user access this resource" must now check not just whether an Allow exists, but whether a Deny exists anywhere in the user's full group membership chain across every applicable ACE — a Deny buried in one rarely-reviewed group can silently block access that every other rule grants, and it's invisible unless someone is specifically looking for it. Second, Deny entries tend to accumulate over time as quick-fix exceptions ("just deny this one user from this one folder") rather than being captured in the role-based group model, which means the access model drifts away from being fully represented by group membership — defeating the entire purpose of AGDLP, where group membership alone should tell you a user's complete entitlement picture. The correct least-privilege pattern, which we used throughout today's lab, is to simply not include a user (or their group) in any Allow rule for a resource they shouldn't access — absence of Allow achieves the same restrictive outcome as Deny, without the audit and troubleshooting complexity that explicit Deny introduces.

---

## 5. Overall Progress Tracker

**Phase 1: On-Premises Lifecycle & Access Management**

```
[■■■■■■□□□□] Day 6 of 30 — 20% Complete
```

✅ Day 1 — AD DS Logical Structure & Enterprise OU Design
✅ Day 2 — User Lifecycle Management (JML) — Joiner Phase
✅ Day 3 — Group Strategy & AGDLP Nesting Model
✅ Day 4 — GPO for Access Control
✅ Day 5 — Fine-Grained Password Policies & PowerShell Automation
✅ Day 6 — NTFS & Share Permissions Layering, ABAC Introduction *(Complete)*
⬜ Day 7 — Phase 1 Capstone (End-to-End JML Simulation)

---


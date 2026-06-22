# Day 3 Lab: Group Strategy — Security Groups, AGDLP Nesting Model & RBAC via Group-Based Access

---

## 1. Core Concept Overview

If the OU structure (Day 1) is the skeleton of AD and user objects (Day 2) are the people inside it, then groups are the access control engine. Every enterprise RBAC implementation in Active Directory runs through groups — not direct user-to-resource permission assignments. Understanding group types, group scopes, and the nesting model is the single most-tested IAM concept at the Analyst/Engineer level, and getting it wrong in production causes permission bloat, audit failures, and change-management nightmares.

### Group Types — Two only:

* **Security Groups** have a SID (Security Identifier) and can be placed on ACLs (Access Control Lists). These are what grant or deny access to resources. They can also be used for email distribution if Exchange is present, but their primary purpose is access control.
* **Distribution Groups** have no SID and cannot be placed on ACLs. They exist purely as email distribution lists. An IAM Engineer almost exclusively works with Security Groups — Distribution Groups are largely an Exchange/messaging team concern.

### Group Scopes — Three, and scope confusion is a career-level error:

* **Domain Local (DL):** Can contain users, global groups, and universal groups from any domain in the forest. Can only be assigned permissions to resources within the same domain. These are your resource access groups — placed directly on the ACL of a file share, printer, or application.
* **Global (G):** Can contain users and other global groups only from the same domain. Can be assigned permissions in any domain in the forest. These are your role groups — they represent job roles or departments ("all Finance Analysts").
* **Universal (U):** Can contain users and groups from any domain in the forest. Can be assigned permissions in any domain. Stored in the Global Catalog (replication overhead). Used primarily in multi-domain forests for cross-domain role aggregation.

### The AGDLP Model — the nesting pattern every IAM Engineer must know:

AGDLP stands for Accounts → Global groups → Domain Local groups → Permissions. It is Microsoft's recommended group nesting strategy and the enterprise standard for scalable, auditable RBAC in AD.

```text
Account (User)  →  Global Group (Role)  →  Domain Local Group (Resource)  →  Permission (ACL)
     dkim        →   G-IT-AllStaff       →   DL-Finance-Share-Read          →   Read on \\DC01\Finance

```

The logic is: users are collected into Global groups by role/department, Global groups are nested into Domain Local groups by what resource they need access to, and Domain Local groups sit on the resource ACL. When you add a new Finance Analyst, you add them to one Global group (`G-Finance-Analysts`) — and they instantly inherit every resource that group has been nested into. When you want to revoke Finance Analyst access to a share, you remove the Global group from the Domain Local group — and every Finance Analyst loses that access simultaneously, with one change. This is group-based RBAC in practice, and it is the model that makes access reviews and access certifications tractable at enterprise scale.

AGUDLP (inserting Universal groups between Global and Domain Local) is the multi-domain forest extension — Universal groups aggregate Global groups from multiple domains before being nested into Domain Local groups. In our single-domain lab, AGDLP is the applicable model.

---

## 2. Real-World Enterprise Use Case

Consider a real enterprise scenario: Bhatt Corp has a Finance file share (`\\DC01\Finance-Shared`) containing sensitive payroll and budget files. Three types of access are needed:

* **Finance Managers** need Full Control (read, write, delete, manage permissions)
* **Finance Analysts** need Read/Write (modify files, but not manage permissions)
* **IT Support** needs Read-Only (for troubleshooting, audit support — not operational access)

Without AGDLP, an admin might just right-click the folder and add `mross` and `sconnor` directly to the ACL. This works for 5 users. At 500 users, the ACL becomes unreadable, audits can't determine "what does a Finance Analyst get access to" without inspecting every resource one by one, and offboarding requires hunting down every resource that user was directly assigned to. This is called direct user-to-resource assignment and it is explicitly an anti-pattern that access review frameworks (SOC2, ISO27001 A.9) will flag.

With AGDLP, the same three levels of access become:

```text
G-Finance-Managers    → nested into → DL-Finance-Share-FullControl  → ACL on \\DC01\Finance-Shared
G-Finance-Analysts    → nested into → DL-Finance-Share-ReadWrite     → ACL on \\DC01\Finance-Shared
G-IT-Support          → nested into → DL-Finance-Share-Read          → ACL on \\DC01\Finance-Shared

```

Adding a new Finance Manager? Add them to `G-Finance-Managers` — they automatically get Full Control on every resource that group is nested into (potentially dozens of shares, applications, and printers). Offboarding a Finance Analyst? Remove them from `G-Finance-Analysts` — access revoked everywhere simultaneously. This is how enterprise IAM scales.

---

## 3. Detailed Step-by-Step Procedure

Tooling: ADUC on DC01 for group creation, then PowerShell for nesting and verification. We will also create a real shared folder and apply the AGDLP ACL end-to-end so you can verify access from Computer-01.

### Step 1: Create the Finance shared folder (the resource being protected)

**Action:** On DC01, open File Explorer and navigate to `C:\`. Create a new folder named `Shares`. Inside `Shares`, create a subfolder named `Finance-Shared`. Right-click `Finance-Shared` → **Properties** → **Sharing** tab → **Advanced Sharing** → check "Share this folder". Set the share name to `Finance-Shared`. Click **Permissions** → remove `Everyone` → click **OK** (we will configure proper permissions via AGDLP groups shortly). Click **OK** to close.

**Expected Result/Verification:** Running the following in PowerShell on DC01 confirms the share exists:

```powershell
Get-SmbShare -Name "Finance-Shared"

```

Output shows `Finance-Shared` with Path `C:\Shares\Finance-Shared` and Status `OK`.

### Step 2: Create the Global groups (role layer — the "G" in AGDLP)

**Action:** In ADUC, navigate to `BHATT-CORP` → `Finance` → `Groups`. Right-click → **New** → **Group**. Create the following two groups, each with Group scope: **Global** and Group type: **Security**:

* `G-Finance-Managers`
* `G-Finance-Analysts`

Then navigate to `BHATT-CORP` → `IT` → `Groups` and create:

* `G-IT-Support`

> **Naming convention note:** The `G-` prefix signals Global scope — a production standard that makes group purpose readable at a glance during audits. Always prefix by scope.

**Expected Result/Verification:**

```powershell
Get-ADGroup -Filter {Name -like "G-Finance*" -or Name -like "G-IT*"} |
    Select-Object Name, GroupScope, GroupCategory

```

All three groups return GroupScope: `Global` and GroupCategory: `Security` — not Distribution, not Universal.

### Step 3: Create the Domain Local groups (resource layer — the "DL" in AGDLP)

**Action:** In ADUC, navigate to `BHATT-CORP` → `Finance` → `Groups`. Create three new groups, each with Group scope: **Domain Local** and Group type: **Security**:

* `DL-Finance-Share-FullControl`
* `DL-Finance-Share-ReadWrite`
* `DL-Finance-Share-Read`

> **Naming convention note:** `DL-` prefix signals Domain Local scope. The suffix describes the resource and the permission level — a reader should know exactly what access this group grants without opening any documentation.

**Expected Result/Verification:**

```powershell
Get-ADGroup -Filter {Name -like "DL-Finance*"} |
    Select-Object Name, GroupScope, GroupCategory

```

All three return GroupScope: `DomainLocal` and GroupCategory: `Security`.

### Step 4: Populate the Global groups with users (the "A" — Accounts into Global groups)

**Action:** Open PowerShell as Administrator on DC01 and run:

```powershell
# Add Sarah Connor (Finance Manager) to the Manager global group
Add-ADGroupMember -Identity "G-Finance-Managers" -Members "sconnor"

# Add Mike Ross (Finance Analyst) to the Analyst global group
Add-ADGroupMember -Identity "G-Finance-Analysts" -Members "mross"

# Add David Kim (IT Support) to the IT Support global group
Add-ADGroupMember -Identity "G-IT-Support" -Members "dkim"

```

**Expected Result/Verification:**

```powershell
Get-ADGroupMember -Identity "G-Finance-Managers" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "G-Finance-Analysts" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "G-IT-Support"       | Select-Object Name, SamAccountName

```

Each group returns exactly one member, correctly matched to their role.

### Step 5: Nest the Global groups into Domain Local groups (the "GDL" nesting)

**Action:** In PowerShell on DC01:

```powershell
# G-Finance-Managers → DL-Finance-Share-FullControl
Add-ADGroupMember -Identity "DL-Finance-Share-FullControl" -Members "G-Finance-Managers"

# G-Finance-Analysts → DL-Finance-Share-ReadWrite
Add-ADGroupMember -Identity "DL-Finance-Share-ReadWrite" -Members "G-Finance-Analysts"

# G-IT-Support → DL-Finance-Share-Read (IT gets read-only on Finance share)
Add-ADGroupMember -Identity "DL-Finance-Share-Read" -Members "G-IT-Support"

```

**Expected Result/Verification:**

```powershell
Get-ADGroupMember -Identity "DL-Finance-Share-FullControl" | Select-Object Name, ObjectClass

```

The member returned should be the group `G-Finance-Managers` with ObjectClass: `group` — not a user. This confirms the nesting is group-to-group (AGDLP), not user-to-DL (which would be a direct assignment anti-pattern).

### Step 6: Apply NTFS permissions using the Domain Local groups (the "P" — Permissions)

**Action:** In PowerShell on DC01, apply NTFS permissions to the `Finance-Shared` folder using the Domain Local groups:

```powershell
$path = "C:\Shares\Finance-Shared"
$acl  = Get-Acl $path

# Remove inherited permissions and start clean
$acl.SetAccessRuleProtection($true, $false)

# DL-Finance-Share-FullControl → FullControl
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Bhatt\DL-Finance-Share-FullControl","FullControl","ContainerInherit,ObjectInherit","None","Allow")))

# DL-Finance-Share-ReadWrite → Modify (read + write, no permission management)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Bhatt\DL-Finance-Share-ReadWrite","Modify","ContainerInherit,ObjectInherit","None","Allow")))

# DL-Finance-Share-Read → ReadAndExecute
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Bhatt\DL-Finance-Share-Read","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")))

# Apply SYSTEM and local Administrators baseline (always retain these)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))

Set-Acl -Path $path -AclObject $acl

```

**Expected Result/Verification:**

```powershell
(Get-Acl "C:\Shares\Finance-Shared").Access |
    Select-Object IdentityReference, FileSystemRights, AccessControlType

```

Output should list exactly five ACEs: `DL-Finance-Share-FullControl`, `DL-Finance-Share-ReadWrite`, `DL-Finance-Share-Read`, `SYSTEM`, and `BUILTIN\Administrators` — and critically, no individual usernames (`sconnor`, `mross`, `dkim`) appear anywhere in the ACL. Users only appear on the ACL indirectly through group nesting. This is the defining visual confirmation that AGDLP is implemented correctly.

### Step 7: Apply share-level permissions

**Action:** Set the SMB share permissions to allow the Domain Local groups appropriate access at the share level. Run on DC01:

```powershell
# Grant share-level access (NTFS is the real enforcement layer; share = coarse gate)
Grant-SmbShareAccess -Name "Finance-Shared" -AccountName "Bhatt\DL-Finance-Share-FullControl" `
    -AccessRight Full -Force
Grant-SmbShareAccess -Name "Finance-Shared" -AccountName "Bhatt\DL-Finance-Share-ReadWrite" `
    -AccessRight Change -Force
Grant-SmbShareAccess -Name "Finance-Shared" -AccountName "Bhatt\DL-Finance-Share-Read" `
    -AccessRight Read -Force

# Remove the default Everyone share permission if present
Revoke-SmbShareAccess -Name "Finance-Shared" -AccountName "Everyone" -Force

```

**Expected Result/Verification:**

```powershell
Get-SmbShareAccess -Name "Finance-Shared"

```

Output shows only your three `DL-` groups with their respective access rights — `Everyone` is absent, confirming the share is not openly accessible before NTFS filters apply.

### Step 8: End-to-end validation from Computer-01

**Action:** Log into Computer-01 as `mross` (Finance Analyst). Open File Explorer and navigate to `\\DC01\Finance-Shared`. Try the following:

* Create a new text file inside the share (e.g., `test-analyst.txt`) → should succeed (Modify permission).
* Right-click the folder → **Properties** → **Security** tab → try clicking **Edit** to modify permissions → should fail with "Access Denied" (no FullControl).

Then log out and log back in as `sconnor` (Finance Manager):

* Navigate to `\\DC01\Finance-Shared` → right-click → **Properties** → **Security** tab → **Edit** → should succeed (FullControl allows permission management).

**Expected Result/Verification:** The differential behavior between `mross` (Modify but no permission management) and `sconnor` (Full Control including permission management) confirms the AGDLP model is functioning correctly end-to-end — from user account, through global role group, through domain local resource group, to the ACE on the folder.

### Step 9: Audit the effective group membership chain via PowerShell

**Action:** Run this final verification to prove the complete AGDLP chain is intact:

```powershell
# Confirm mross → G-Finance-Analysts → DL-Finance-Share-ReadWrite
Write-Host "=== mross direct group memberships ==="
Get-ADPrincipalGroupMembership -Identity "mross" | Select-Object Name, GroupScope

Write-Host "=== DL-Finance-Share-ReadWrite members (should show G-Finance-Analysts) ==="
Get-ADGroupMember -Identity "DL-Finance-Share-ReadWrite" | Select-Object Name, ObjectClass

Write-Host "=== G-Finance-Analysts members (should show mross) ==="
Get-ADGroupMember -Identity "G-Finance-Analysts" | Select-Object Name, SamAccountName

```

**Expected Result/Verification:** Reading the three output blocks in sequence tells the complete access story: `mross` is in `G-Finance-Analysts` (Global, group scope), `G-Finance-Analysts` is a member of `DL-Finance-Share-ReadWrite` (DomainLocal, ObjectClass: group), and that DL group sits on the ACL with Modify rights. A senior IAM engineer or an access reviewer should be able to reconstruct the entire permission chain from these three queries alone — no GUI needed.

---

## 4. Interview-Prep Q&A

**Q1: "Why do we put Global groups on ACLs instead of just Domain Local groups directly? What breaks if you skip the Global group layer and nest users directly into Domain Local groups?"**

> **Strong Answer:** Domain Local groups can technically hold user accounts directly — nothing in AD prevents it. But skipping the Global group layer collapses role-based access into resource-based access, which destroys scalability and auditability. When you query "what is a Finance Analyst entitled to," the answer should come from examining one Global group (`G-Finance-Analysts`) and seeing every Domain Local group it's nested in. If users are placed directly into Domain Local groups, you have to query every DL group across every resource to reconstruct a single user's entitlement picture — which is exactly the audit problem AGDLP was designed to eliminate. The Global group is the role; the Domain Local group is the resource access point. Conflating them means you no longer have roles — you just have resource lists, which is pre-RBAC thinking.

**Q2: "An auditor asks you to prove that no users have been granted direct access to the Finance share — how do you do that in under 60 seconds?"**

> **Strong Answer:** Two commands — first, check the NTFS ACL: `(Get-Acl "C:\Shares\Finance-Shared").Access | Select-Object IdentityReference` — if any `IdentityReference` shows a user account (`Bhatt\mross`, etc.) rather than a group name, that's a direct assignment violation. Second, check the SMB share permissions: `Get-SmbShareAccess -Name "Finance-Shared"` — same logic. If both commands return only group names (and specifically only Domain Local group names per AGDLP), the access model is clean. Then — for deeper proof — run `Get-ADGroupMember` on each DL group to confirm those groups contain only other groups (Global groups), not user accounts. Three commands, complete chain of evidence, done in under a minute. In production, this logic is what access review scripts automate and run nightly.

---

## 5. Overall Progress Tracker

### Phase 1: On-Premises Lifecycle & Access Management

**[■■■□□□□□□□] Day 3 of 30 — 10% Complete**

* ✅ Day 1 — AD DS Logical Structure & Enterprise OU Design
* ✅ Day 2 — User Lifecycle Management (JML) — Joiner Phase
* ✅ Day 3 — Group Strategy & AGDLP Nesting Model (Complete)
* ⬜ Day 4 — GPO Access Control
* ⬜ Day 5 — Fine-Grained Password Policies & PowerShell Automation
* ⬜ Day 6 — NTFS/Share Permissions & Least Privilege
* ⬜ Day 7 — Phase 1 Capstone
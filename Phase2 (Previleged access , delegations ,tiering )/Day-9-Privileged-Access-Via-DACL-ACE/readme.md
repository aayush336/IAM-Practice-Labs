# DAY 9 LAB — OU Delegation of Control: Granular Administrative Rights Without Domain Admins

---

## 1. Core Concept Overview

OU Delegation of Control is the mechanism that resolves the exact gap Day 8 identified: IT staff need *some* administrative capability, but granting that capability through Domain Admins membership is catastrophic overkill. Delegation solves this by attaching **granular Access Control Entries (ACEs) directly to an OU's Access Control List (ACL)** — allowing a security principal to perform specific, narrowly-scoped actions against objects *within that OU only*, with zero rights anywhere else in the domain.

**The underlying mechanism:**

Every OU in Active Directory has a security descriptor, just like a file or folder. That security descriptor contains a Discretionary Access Control List (DACL) made up of ACEs. Each ACE specifies: a security principal (user or group), a permission (e.g., "Reset Password," "Write Member," "Create/Delete User objects"), and a scope (this object only, or this object and all descendants). When you run the **Delegation of Control Wizard** (or its PowerShell/`dsacls` equivalent), you are not creating a new kind of permission system — you're writing standard NTDS ACEs onto the OU's DACL, the exact same underlying mechanism as NTFS permissions on a file share, just applied to directory objects instead of files.

**Why this is architecturally superior to group-based privilege escalation:**

1. **Object-type and property-level granularity.** Unlike Domain Admins (all-or-nothing), delegation can grant rights to a specific *property* of a specific *object class*. For example, you can grant "Reset Password" on `user` objects without granting "Write Member" (group membership changes) — meaning a Helpdesk technician can unlock a user's account but cannot add that user to `G-Finance-PayrollAccess`. This is the textbook definition of Least Privilege: the permission set matches the job function exactly, with no residual capability.

2. **Scope containment via OU boundary.** A delegated ACE applied to `OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com` only affects objects inside that OU (and sub-OUs, if inheritance is enabled). A Helpdesk technician delegated rights in the IT OU has **zero** rights to reset passwords for Finance or Sales users — the OU boundary is a hard security boundary, not just an organizational convenience.

3. **No membership in any privileged group required.** Delegated rights live on the OU's ACL, not on group membership. This means delegation doesn't show up in a `Get-ADGroupMember -Identity "Domain Admins"` audit (Day 8's Step 1) — it requires a *separate* audit discipline (checking OU-level ACLs directly), which is exactly what this lab will teach you to do.

4. **Reversibility and blast-radius control.** Revoking a delegated right means removing one ACE from one OU — a surgical, auditable action. Revoking Domain Admins membership from an over-privileged account, by contrast, often breaks scheduled tasks, service accounts, or scripts that were never supposed to depend on that membership in the first place, because DA rights are so broad that dependencies accumulate invisibly.

**The critical failure mode this lab prevents:** delegation "creep." Every wizard-driven delegation in the real world tends to over-grant — administrators click "Full Control" on the OU because it's the path of least resistance, quietly recreating a mini-Domain-Admins inside a supposedly scoped OU. Today's lab deliberately uses the **precise, named-permission** approach (via `dsacls`, which shows you exactly what ACE you're writing) specifically to build the habit of granting the *minimum* permission set, not the convenient one.

---

## 2. Real-World Enterprise Use Case

In Bhatt.com, IT Support staff — **bh1003, bh1005, bh1024, bh1025, bh1039, bh1041** (all members of `G-IT-Support`) — regularly need to reset passwords and unlock accounts for Finance and Sales users who call the helpdesk. Today, they have no AD rights to do this at all (Day 8 confirmed this gap), meaning every password reset currently requires escalating to someone with Domain Admin rights — a slow, poorly scaled, high-risk pattern.

In a real bank or enterprise, this exact scenario is the single most common justification given for over-provisioning helpdesk staff into Domain Admins or Account Operators: "they just need to reset passwords." Delegation is the correct answer, and it's precisely what a GAO Analyst reviewing access requests would expect to see: a Helpdesk function with **Reset Password** and **Unlock Account** rights scoped to the OUs they support, and *nothing else* — they cannot create users, cannot delete users, cannot modify group membership, and cannot touch GPOs.

Separately, **bh1013 (Kiran Sharma, IT Manager)** needs broader capability within the IT OU specifically — the ability to create and manage computer objects as new machines are provisioned, and to manage group membership within IT's own groups — without needing rights over Finance or Sales, and without needing Domain Admins.

Today's lab builds both delegation models: a narrow **Helpdesk Password Reset** delegation (applied across Finance, IT, and Sales) and a broader **IT OU Management** delegation (applied only to the IT OU, for bh1013).

---

## 3. Detailed Step-by-Step Procedure

### Step 1: Create the delegation principal groups

Following AGDLP discipline, delegation rights should be granted to a group, never directly to a user account — this preserves the pattern you've used since Day 3.

**On DC01**, open **Active Directory Users and Computers (ADUC)**. Navigate to `OU=Groups,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com`.

**Right-click → New → Group:**
- Name: `G-Helpdesk-PasswordReset`
- Group scope: **Global**
- Group type: **Security**

**Right-click → New → Group** again:
- Name: `G-ITManagers-OUAdmin`
- Group scope: **Global**
- Group type: **Security**

Add members via PowerShell:

```powershell
Add-ADGroupMember -Identity "G-Helpdesk-PasswordReset" -Members bh1003, bh1005, bh1024, bh1025, bh1039, bh1041

Add-ADGroupMember -Identity "G-ITManagers-OUAdmin" -Members bh1013
```

**Expected Result/Verification:**
```powershell
Get-ADGroupMember -Identity "G-Helpdesk-PasswordReset" | Select Name, SamAccountName
Get-ADGroupMember -Identity "G-ITManagers-OUAdmin" | Select Name, SamAccountName
```
Output confirms `G-Helpdesk-PasswordReset` contains the six IT Support staff, and `G-ITManagers-OUAdmin` contains bh1013 only.

---

```
```

### Step-by-Step Delegation Process on GUI

1. **Open ADUC:** Launch **Active Directory Users and Computers** (`dsa.msc`).
2. **Locate the OU:** Navigate to the OU where you want to delegate permissions (e.g., `OU=Users,OU=Finance,OU=BHATT-CORP`).
3. **Launch Wizard:** Right-click the OU and select **Delegate Control...**
4. **Add Users/Groups:** In the wizard, click **Add** and select the group `G-Helpdesk-PasswordReset`. Click **Next**.
5. **Select Tasks:** Choose **"Create a custom task to delegate"** and click **Next**.
6. **Scope:** Select **"Only the following objects in the folder"** and check the box for **"User objects"**. Click **Next**.
7. **Define Permissions:**
* Check the box for **"General"**.
* In the list below, check:
* **Reset password**
* **Write lockoutTime**


---
To manage Active Directory access programmatically, it is vital to understand that a **DACL (Discretionary Access Control List)** is just a list of **ACEs (Access Control Entries)**.

When you want to script these, you are essentially defining four things for every ACE:

1. **Who:** The user or group (the Trustee).
2. **Action:** What kind of access (`Allow` or `Deny`).
3. **Right:** What is allowed (`Reset Password`, `Write Property`, etc.).
4. **Scope:** Where it applies (e.g., only on this object, or inherited by child objects).

### Common AD Delegation "Rights"

When using `Add-ADPermission` (or building `ActiveDirectoryAccessRule` objects), these are the most common values you will use.

| Category | PowerShell Parameter Value | Description |
| --- | --- | --- |
| **Common Rights** | `GenericAll` | Full Control over the object. |
|  | `GenericRead` | Read all properties of the object. |
|  | `ReadProperty` | Read specific properties of the object. |
|  | `WriteProperty` | Write to specific properties (e.g., `lockoutTime`). |
| **Extended Rights** | `ExtendedRight` | Required for special tasks. |
|  | `"Reset Password"` | Specifically for resetting user passwords. |
|  | `"Send As"` | Often used for mailbox delegation in Exchange. |
|  | `"Validated write to DNS host name"` | Used for computer account management. |
| **Object Management** | `CreateChild` | Ability to create objects (e.g., users) in an OU. |
|  | `DeleteChild` | Ability to delete objects in an OU. |

### How to use these in a script

When you use `Add-ADPermission` (or `New-Object System.DirectoryServices.ActiveDirectoryAccessRule`), you combine these rights with an **Inheritance** type:

* **`None`**: Applies only to the object itself.
* **`Descendents`**: Applies only to child objects (e.g., apply "Reset Password" to all users *inside* the OU).
* **`All`**: Applies to the object itself and all its children.

### Example: The "Easy" Way to Script

Instead of complex `dsacls` strings, you define these objects cleanly:

```powershell
# Define the right to reset passwords
$resetPassRight = "Reset Password"
# Define the right to write the lockout time property
$writeLockout = "lockoutTime"

# Apply the Reset Password extended right to descendant users
Add-ADPermission -Identity "OU=Users,DC=Bhatt,DC=com" -User "Bhatt\Helpdesk" `
    -AccessRights ExtendedRight -ExtendedRights $resetPassRight -InheritanceType Descendents

# Apply the Write permission to the lockoutTime property
Add-ADPermission -Identity "OU=Users,DC=Bhatt,DC=com" -User "Bhatt\Helpdesk" `
    -AccessRights WriteProperty -Properties $writeLockout -InheritanceType Descendents

```

By focusing on these specific `AccessRights` and `ExtendedRights` parameters, you can build modular scripts to delegate any administrative task without ever needing to touch a cryptic `dsacls` command line again.


```
```

### Step 2: Delegate Reset Password + Unlock Account rights across Finance, IT, and Sales

Use `dsacls` for precision — it names the exact ACE being written rather than abstracting it behind wizard clicks.

```powershell
$targetOUs = @(
    "OU=Users,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com",
    "OU=Users,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com",
    "OU=Users,OU=Sales,OU=BHATT-CORP,DC=Bhatt,DC=com"
)

$trustee = "Bhatt\G-Helpdesk-PasswordReset"

foreach ($ou in $targetOUs) {
    dsacls $ou /I:S /G "$($trustee):CA;Reset Password;user"
    dsacls $ou /I:S /G "$($trustee):WP;lockoutTime;user"
}
```

**What this grants, precisely:**
- `CA;Reset Password;user` — Control Access right to reset passwords on `user` objects
- `WP;lockoutTime;user` — Write Property right on the `lockoutTime` attribute (this is the actual mechanism behind "Unlock Account" — clearing lockoutTime to 0 unlocks an account)
- `/I:S` — inheritance applies to this object and all descendant objects (i.e., all users within the OU)

**Expected Result/Verification:**
```powershell
dsacls "OU=Users,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" | Select-String "G-Helpdesk-PasswordReset"
```
Output shows two ACE lines referencing `G-Helpdesk-PasswordReset` — one for Reset Password, one for the `lockoutTime` write property. Repeat the check for the IT and Sales OUs to confirm all three received identical ACEs.

---

### Step 3: Delegate broader IT OU management rights to bh1013's group

```powershell
$itOU = "OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com"
$mgrTrustee = "Bhatt\G-ITManagers-OUAdmin"

# Create/delete/manage computer objects within IT OU
dsacls $itOU /I:S /G "$($mgrTrustee):CCDC;computer"

# Read/Write group membership for groups within IT\Groups only
dsacls "OU=Groups,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com" /I:S /G "$($mgrTrustee):WP;member;group"
```

**What this grants, precisely:**
- `CCDC;computer` — Create Child / Delete Child rights scoped to the `computer` object class only (bh1013 can provision and decommission IT-owned machines, but cannot create or delete `user` objects)
- `WP;member;group` — Write Property on the `member` attribute of `group` objects, scoped only to `OU=Groups,OU=IT` (bh1013 can add/remove members of IT's own groups like `G-IT-Support`, but has no rights over `G-Finance-Analysts` or any Finance/Sales group)

**Expected Result/Verification:**
```powershell
dsacls $itOU | Select-String "G-ITManagers-OUAdmin"
dsacls "OU=Groups,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com" | Select-String "G-ITManagers-OUAdmin"
```
Output confirms the `CCDC;computer` ACE on the IT OU and the `WP;member;group` ACE on IT's Groups sub-OU, both attributed to `G-ITManagers-OUAdmin`.

---

### Step 4: Validate negative scope — confirm Helpdesk cannot touch Payroll or group membership

This is the step most delegation exercises skip, and it's the one that actually proves Least Privilege was achieved rather than assumed.

**Log on to Computer-01 as bh1003** (a member of `G-Helpdesk-PasswordReset`).

```powershell
# This SHOULD succeed - password reset within delegated scope
Set-ADAccountPassword -Identity bh1004 -Reset -NewPassword (ConvertTo-SecureString "TempPass2026!" -AsPlainText -Force)

# This SHOULD FAIL - group membership modification was never delegated
Add-ADGroupMember -Identity "G-Finance-PayrollAccess" -Members bh1004
```

**Expected Result/Verification:**
The password reset command completes successfully with no error. The `Add-ADGroupMember` command returns an **Access Denied** error (`insufficient access rights`). This confirms the delegation is precisely scoped — bh1003 can perform the one task delegated (password reset) and is correctly blocked from an adjacent, more sensitive task (payroll group membership) that was never granted.

---

### Step 5: Document the delegation model as a governance artifact

**Manually create** `C:\IAM-Docs\Day9-DelegationModel.txt`:

```
BHATT.COM — OU DELEGATION OF CONTROL MODEL
Date: <today's date>

DELEGATION 1: G-Helpdesk-PasswordReset
  Members: bh1003, bh1005, bh1024, bh1025, bh1039, bh1041
  Scope: OU=Users,OU=Finance | OU=Users,OU=IT | OU=Users,OU=Sales
  Rights granted: Reset Password (CA), Unlock Account (WP;lockoutTime)
  Rights explicitly NOT granted: Create/Delete users, group membership
    changes, GPO management, computer object management

DELEGATION 2: G-ITManagers-OUAdmin
  Members: bh1013
  Scope: OU=IT (computer objects) | OU=Groups,OU=IT (group membership)
  Rights granted: Create/Delete computer objects, manage membership of
    IT-owned groups only
  Rights explicitly NOT granted: User object management, rights in
    Finance/Sales OUs, any Domain Admin equivalent capability

VALIDATION: Negative-scope test confirmed bh1003 can reset passwords but
cannot modify group membership (Access Denied), proving delegation
boundary is enforced, not assumed.

NEXT STEP: Day 10 will formalize this into a complete RBAC Access Matrix
covering all custom groups and delegated rights as a single governance
artifact.
```

**Expected Result/Verification:**
File exists on disk at `C:\IAM-Docs\Day9-DelegationModel.txt` and accurately reflects both delegations and the negative-scope validation result.

---

## 4. Interview-Prep Q&A

**Q1: "A helpdesk team says they need Account Operators membership to do their jobs. How would you evaluate that request, and what would you recommend instead?"**

**Model Answer:** My first step would be to decompose "do their jobs" into the specific, discrete actions the helpdesk actually performs — typically password resets and account unlocks, occasionally basic user attribute updates. Account Operators is a built-in group with a much broader footprint than that: it can create and delete most user, group, and computer objects domain-wide (with some built-in exceptions like Domain Admins and Administrators), and critically, it also grants logon rights to Domain Controllers in some configurations — meaning any Account Operators member becomes a potential credential-theft target the moment they interact with a DC. That's a massive mismatch between the granted capability and the actual job function. Instead, I'd implement OU-scoped delegation: grant a dedicated security group the specific "Reset Password" control access right and write access to the lockoutTime attribute, scoped only to the OUs the helpdesk actually supports. This achieves the same operational outcome — helpdesk can reset passwords and unlock accounts — while eliminating the ability to create/delete objects, modify group membership, or interact with Domain Controllers at all. I'd also run a negative-scope test after implementing it, attempting an out-of-scope action as a helpdesk account to confirm it's actually denied, not just assumed to be denied.

**Q2: "What's the difference between delegating rights via the GUI Delegation of Control Wizard versus using dsacls or PowerShell directly, and why might an auditor care about which method was used?"**

**Model Answer:** Functionally, both methods write the same underlying ACEs to the OU's security descriptor — there's no difference in the resulting AD state. The difference is in precision and auditability during the *creation* process. The GUI wizard presents pre-bundled "common tasks" checkboxes (like "Reset user passwords" or "Create, delete, and manage user accounts") that often bundle multiple discrete permissions together in ways that aren't fully visible to the person clicking through it — it's easy to accidentally grant more than intended because the wizard abstracts away the exact ACE being written. Using `dsacls` or direct PowerShell cmdlets like `Set-Acl` requires you to specify the exact object class, exact property, and exact right being granted, which forces a deliberate, documented decision at each step and produces command history that itself serves as an audit trail of intent. An auditor cares about this because during an access review, the question isn't just "what rights exist" — it's "was this access granted deliberately and is it still necessary," and evidence of precise, documented delegation (rather than wizard-driven bundles) makes it far easier to demonstrate that Least Privilege was a deliberate design decision rather than an accidental byproduct of convenient tooling.

---

## 5. Overall Progress Tracker

**Phase 1: Foundational Identity Lifecycle & Access Control** — ✅ Complete (Days 1–7)
**Phase 2: Privileged Access, Delegation & Tiering** — In Progress

```
[█████████░░░░░░░░░░░░░░░░░░░] 30.0% Complete (9/30 days)
```

| Day | Topic | Status |
|---|---|---|
| 1 | AD DS Logical Structure & Enterprise OU Design | ✅ |
| 2 | User Lifecycle Management — Joiner Phase (JML) | ✅ |
| 3 | Group Strategy & AGDLP Nesting Model | ✅ |
| 4 | GPO for Access Control | ✅ |
| 5 | Fine-Grained Password Policies (PSOs) | ✅ |
| 6 | NTFS & Share Permissions, ABAC Intro | ✅ |
| 7 | Phase 1 Capstone — End-to-End JML Simulation | ✅ |
| 8 | Least Privilege Deep Dive — Privileged Groups & Attack Surface | ✅ |
| **9** | **OU Delegation of Control** | ✅ |
| 10 | RBAC Design & Access Matrix Documentation | ⬜ |
| 11 | Microsoft Tiering Model (Tier 0/1/2) | ⬜ |
| 12 | Privileged Account Management | ⬜ |
| 13 | LAPS Deployment | ⬜ |
| 14 | JIT Access Concepts & Time-Bound Elevation | ⬜ |
| 15 | Phase 2 Capstone | ⬜ |
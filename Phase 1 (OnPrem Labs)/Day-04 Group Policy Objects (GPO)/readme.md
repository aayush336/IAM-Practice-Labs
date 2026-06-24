# Day 4 Lab: Group Policy Objects (GPO) for Access Control — Password Policies, Account Lockout, Login Restrictions & Drive Mapping via Groups

---

## 1. Core Concept Overview

Group Policy is the enforcement layer of Active Directory. If Day 1 built the structure, Day 2 populated identities, and Day 3 built the access model, then Day 4 is where you enforce behavior — what users can do, how their machines are configured, and what security baselines apply to which population. Every IAM Engineer must understand GPO deeply because it is the primary mechanism for translating a security policy document into a technically enforced control.

* **What a GPO actually is:** A Group Policy Object is a collection of settings stored in two places simultaneously — the Group Policy Container (GPC) in AD (storing metadata and version info) and the Group Policy Template (GPT) in SYSVOL (storing the actual policy settings in folder/file format, replicated to all DCs). When a client machine or user logs in, the Group Policy Client service contacts a Domain Controller and downloads applicable GPOs, applying them in a defined order. This dual-storage architecture matters because SYSVOL replication issues are a common real-world GPO troubleshooting scenario.
* **GPO Processing Order — LSDOU:** GPOs apply in a strict hierarchical order: Local policy (on the machine itself) → Site-linked GPOs → Domain-linked GPOs → OU-linked GPOs (from parent OU down to the most specific child OU). The last writer wins — a GPO linked to a child OU overrides the same setting from a parent OU or domain-level GPO. This is critical for understanding why you link the `Default Domain Policy` at the domain level but department-specific restrictions at the OU level.
* **Two halves of every GPO:** Every GPO contains a **Computer Configuration** section (applies to machine objects, regardless of who logs in — enforced at boot/startup) and a **User Configuration** section (applies to user objects, regardless of which machine they log into — enforced at login). Knowing which half to configure a setting in is a fundamental skill; configuring a password policy in User Configuration is a common beginner mistake — password policies must be in Computer Configuration at the domain level to be effective (or via Fine-Grained Password Policies in Day 5).
* **GPO Filtering mechanisms:** By default, a GPO linked to an OU applies to every object in that OU. Two override mechanisms exist: **Security Filtering** (only apply this GPO to members of a specific security group — replaces the old "Authenticated Users" default) and **WMI Filtering** (only apply if the machine matches a WMI query, e.g., Windows 10 machines only). Security Filtering is the IAM-relevant mechanism — it's how you apply a GPO to a subset of users within the same OU without moving them.

The four GPOs we build today cover the highest-value enterprise controls an IAM Engineer is responsible for: domain password policy, account lockout policy, logon restrictions (restricting which machines a user can log into), and drive mapping via Group Policy Preferences (replacing login scripts with a group-aware, GPO-driven approach).

---

## 2. Real-World Enterprise Use Case

In production, an IAM Engineer inherits an environment where the `Default Domain Policy` has been modified directly over years — a single GPO accumulating dozens of unrelated settings from different admins, with no documentation. This is universally considered an anti-pattern. The enterprise standard is: the `Default Domain Policy` touches only password and account lockout policy (because those settings only function at the domain level), and every other control lives in purpose-built, named GPOs linked at the appropriate OU level.

The four scenarios being implemented today map directly to real enterprise requirements:

* **Password Policy:** A compliance team is implementing CIS Benchmark Level 1 for Windows Server. The IAM team must enforce minimum 12-character passwords, complexity enabled, 60-day maximum age. This goes in `Default Domain Policy` — it's the only GPO that can set domain-wide password policy via the Account Policies node.
* **Account Lockout:** Security team requires that after 5 failed login attempts, the account locks for 30 minutes — a control that directly limits credential-stuffing and brute-force attacks. Same GPO as password policy (domain level).
* **Logon Workstation Restrictions:** Finance department policy requires that Finance users (`mross`, `sconnor`) can only log into Finance-designated computers — not IT machines, not random workstations. This prevents a compromised Finance credential from being used to authenticate against a machine outside the Finance perimeter.
* **Drive Mapping via GPP:** Instead of legacy login scripts (`net use`), the enterprise standard for the last decade is Group Policy Preferences (GPP) drive mapping with Item-Level Targeting — the GPO maps the `Finance-Shared` share as drive `F:` but only for members of `G-Finance-Analysts` and `G-Finance-Managers`. IT Support don't see the `F:` drive even if the GPO is linked to the same OU. This is ABAC-adjacent behavior driven by group membership at the GPO layer.

---

## 3. Detailed Step-by-Step Procedure

**Tooling:** Group Policy Management Console (GPMC) on DC01. Open via **Server Manager** → **Tools** → **Group Policy Management**, or run `gpmc.msc` from Run.

### Step 1: Open GPMC and survey the baseline state

**Action:** Open GPMC on DC01 (`gpmc.msc`). Expand **Forest: Bhatt.com** → **Domains** → **Bhatt.com**. Observe the existing `Default Domain Policy` and `Default Domain Controllers Policy` linked at the domain level.
Click `Default Domain Policy` → **Settings** tab in the right pane → click **show all** to expand the current settings.

**Expected Result/Verification:** The Settings tab shows existing Password Policy and Account Lockout Policy values — likely Windows defaults (max password age: 42 days, minimum length: 7 characters, lockout threshold: 0 — meaning no lockout). Document these baseline values mentally; you are about to replace them with enterprise-grade controls.

### Step 2: Edit the Default Domain Policy — Password Policy

**Action:** In GPMC, right-click `Default Domain Policy` → **Edit**. The Group Policy Management Editor opens. Navigate to:
`Computer Configuration` → `Policies` → `Windows Settings` → `Security Settings` → `Account Policies` → `Password Policy`

Configure each setting by double-clicking it, checking "Define this policy setting," and entering the value:

| Setting | Value |
| --- | --- |
| **Enforce password history** | 24 passwords remembered |
| **Maximum password age** | 60 days |
| **Minimum password age** | 1 day |
| **Minimum password length** | 12 characters |
| **Password must meet complexity requirements** | Enabled |
| **Store passwords using reversible encryption** | Disabled |

**Expected Result/Verification:** All six settings show a tick/checkmark under the "Policy Setting" column in the editor, with your configured values displayed. Close the Group Policy Management Editor — do not close GPMC itself.

### Step 3: Configure Account Lockout Policy in the same GPO

**Action:** In the same `Default Domain Policy` editor session (or re-open it), navigate to:
`Computer Configuration` → `Policies` → `Windows Settings` → `Security Settings` → `Account Policies` → `Account Lockout Policy`

Configure:

| Setting | Value |
| --- | --- |
| **Account lockout duration** | 30 minutes |
| **Account lockout threshold** | 5 invalid logon attempts |
| **Reset account lockout counter after** | 30 minutes |

**Expected Result/Verification:** After setting the threshold to 5, Windows will auto-suggest values for lockout duration and reset counter — accept or manually set them to 30 minutes each. The three settings should now all show defined values. This is the configuration that makes brute-force attacks operationally expensive — 5 attempts per 30-minute window means no more than 240 guesses per day per account.

### Step 4: Force a GPO refresh and verify password policy application

**Action:** On DC01, open PowerShell as Administrator and run:

```powershell
gpupdate /force

```

Then verify the domain password policy is live:

```powershell
Get-ADDefaultDomainPasswordPolicy -Identity "Bhatt.com"

```

**Expected Result/Verification:** Output shows:

```text
ComplexityEnabled           : True
LockoutDuration             : 00:30:00
LockoutObservationWindow    : 00:30:00
LockoutThreshold            : 5
MaxPasswordAge              : 60.00:00:00
MinPasswordAge              : 1.00:00:00
MinPasswordLength           : 12
PasswordHistoryCount        : 24
ReversibleEncryptionEnabled : False

```

All values reflect your configuration exactly. If any value shows the old default, wait 5 minutes and re-run (DC-to-DC replication; in a single-DC lab this is typically instant after `gpupdate /force`).

### Step 5: Create a new GPO for logon workstation restrictions

**Action:** In GPMC, right-click the Finance OU (`BHATT-CORP` → `Finance`) → **Create a GPO in this domain, and Link it here**. Name it `GPO-Finance-LogonRestrictions`.
Right-click the new GPO → **Edit**. Navigate to:
`Computer Configuration` → `Policies` → `Windows Settings` → `Security Settings` → `Local Policies` → `User Rights Assignment`

Double-click "Allow log on locally". Check "Define these policy settings". Click **Add User or Group** and add the following:

* `Bhatt\G-Finance-Managers`
* `Bhatt\G-Finance-Analysts`
* `Bhatt\Domain Admins` *(always retain Domain Admins — failing to do this can lock admins out of machines in that OU)*

Remove any other entries that were pre-populated if present.

**Expected Result/Verification:** The "Allow log on locally" right shows exactly three principals: `G-Finance-Managers`, `G-Finance-Analysts`, and `Domain Admins`. This means when `Computer-01` is eventually moved to the Finance Computers OU and this GPO applies to it, only Finance users and Domain Admins can interactively log into it — a standard workstation-scoping control in segmented enterprise environments.

### Step 6: Create a GPO for Finance drive mapping with Item-Level Targeting

**Action:** In GPMC, right-click `BHATT-CORP` → `Finance` → **Create a GPO in this domain, and Link it here**. Name it `GPO-Finance-DriveMaps`.
Right-click → **Edit**. Navigate to:
`User Configuration` → `Preferences` → `Windows Settings` → `Drive Maps`

Right-click in the right pane → **New** → **Mapped Drive**. Configure:

* **Action:** Create
* **Location:** `\\DC01\Finance-Shared`
* **Label as:** Finance Shared
* **Drive Letter:** `F:`
* Check **"Reconnect"**

Now — critically — click the **Common** tab at the top of this dialog. Check **"Item-level targeting"** → click **Targeting…**
In the Targeting Editor: click **New Item** → **Security Group**. Click the **…** browse button and select `G-Finance-Analysts`. Click **OK**.
Click **New Item** again → **Security Group** → select `G-Finance-Managers`.
Between the two group conditions, change the logical operator from AND to OR by right-clicking the second item → **Item Options** → **OR**. This means: map drive `F:` if the user is a Finance Analyst OR a Finance Manager.
Click **OK** → **OK** to save.

**Expected Result/Verification:** The Drive Maps node in the GPO editor shows one entry: `F:` `\\DC01\Finance-Shared` with a targeting icon (small funnel symbol) indicating Item-Level Targeting is active. This funnel icon is the visual confirmation that the drive mapping won't apply blindly to every user in the Finance OU — it will only apply to members of the specified groups.

### Step 7: Move Computer-01 into the Finance OU structure

**Action:** In ADUC, locate `Computer-01` (currently in the default Computers container or wherever it joined). Right-click → **Move** → navigate to `BHATT-CORP` → `Finance` → `Computers` → **OK**.

**Expected Result/Verification:**

```powershell
Get-ADComputer -Identity "Computer-01" | Select-Object Name, DistinguishedName

```

`DistinguishedName` should show `CN=Computer-01,OU=Computers,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com` — confirming the machine is now in scope for Finance OU-linked GPOs.

### Step 8: Apply and verify GPOs on Computer-01

**Action:** Log into `Computer-01` as a Domain Admin (to ensure unrestricted access during testing). Open PowerShell as Administrator and run:

```powershell
gpupdate /force

```

Then check which GPOs are applied to this machine:

```powershell
gpresult /r

```

**Expected Result/Verification:** The output under "COMPUTER SETTINGS → Applied Group Policy Objects" should list `Default Domain Policy` and `GPO-Finance-LogonRestrictions`. Under "USER SETTINGS → Applied Group Policy Objects" (when logged in as a Finance user), `GPO-Finance-DriveMaps` should appear.

### Step 9: Validate drive mapping from a Finance user session

**Action:** Log out of `Computer-01` (Domain Admin session). Log back in as `mross` (Finance Analyst). Open File Explorer.

**Expected Result/Verification:** Drive `F:` labeled `Finance Shared` appears automatically in File Explorer under "This PC," pointing to `\\DC01\Finance-Shared`. Open it — `mross` should see the contents and be able to create a file (Modify permission from Day 3's AGDLP). The drive appeared without `mross` manually mapping it, without a login script, and without any admin action beyond the group membership established on Day 3 — this is GPP Item-Level Targeting delivering RBAC-aware drive mapping.

### Step 10: Test account lockout policy in practice

**Action:** On `Computer-01` (or the DC01 login screen), attempt to log in as `dkim` with an intentionally wrong password five times consecutively.

**Expected Result/Verification:** On the 6th attempt, Windows returns a message indicating the account is locked out (rather than "wrong password"). Then on DC01, verify via PowerShell:

```powershell
Get-ADUser dkim -Properties LockedOut, BadLogonCount, BadPasswordTime |
    Select-Object Name, LockedOut, BadLogonCount, BadPasswordTime

```

`LockedOut` returns `True`, `BadLogonCount` returns `5`. To unlock (cleanup after test):

```powershell
Unlock-ADAccount -Identity dkim

```

`LockedOut` returns `False` after unlock — account restored. This is the exact command a Tier-1 Helpdesk operator would run for a standard "account locked out" ticket.

---

## 4. Interview-Prep Q&A

### Q1: "A user in the Finance OU complains that drive F: is not mapping at login, even though the GPO-Finance-DriveMaps policy is linked to their OU. Walk me through your troubleshooting process."

> **Strong Answer:** I'd work through the GPO processing chain systematically. First, run `gpresult /r` on the affected machine as that user and check whether `GPO-Finance-DriveMaps` appears under Applied Group Policy Objects. If it doesn't appear, the issue is either a Security Filtering problem (the user or computer isn't in the filtered group — check if Authenticated Users was removed and not replaced correctly), a WMI filter mismatch, or a link order/precedence issue where a higher-precedence GPO is blocking it via Block Inheritance or Enforce flags. If the GPO does appear as applied but the drive still doesn't map, the issue is in the Item-Level Targeting logic — the user likely isn't a member of `G-Finance-Analysts` or `G-Finance-Managers`. Verify with `Get-ADPrincipalGroupMembership`. A third possibility: the GPO is in User Configuration but the machine has loopback processing enabled in Replace mode — which would suppress user-side GPO settings. I'd also check the Windows event log under Applications and Services Logs → Microsoft → Windows → Group Policy → Operational for specific GPO processing errors tied to that GPO's GUID.

### Q2: "Why should you never configure anything except password and account lockout policy inside the Default Domain Policy, and what's the risk if you do?"

> **Strong Answer:** The Default Domain Policy is the one GPO in the environment that is almost never disabled, blocked, or filtered — it applies to every object in the entire domain by default and carries historical precedence as the Microsoft-recommended location for domain-wide account policies. If you start adding workstation settings, software installations, or user restrictions into it, you're mixing unrelated policy concerns into an untouchable baseline GPO, which creates three problems: first, the GPO becomes a single point of failure — if you need to disable or roll back one setting, you risk impacting all other settings in the same GPO since you can't selectively disable individual settings without a full GPO disable; second, change-management traceability is destroyed — auditors expect the Default Domain Policy to contain only account policies, and finding drive mappings or software policy in it signals poor GPO hygiene and raises questions about what else was done carelessly; third, troubleshooting becomes harder because every GPO-related problem must rule out Default Domain Policy interaction. The enterprise principle is one GPO, one purpose — and Default Domain Policy's purpose is domain account policy only.

---

## 5. Overall Progress Tracker

### Phase 1: On-Premises Lifecycle & Access Management

**[■■■■□□□□□□] Day 4 of 30 — 13% Complete**

* ✅ Day 1 — AD DS Logical Structure & Enterprise OU Design
* ✅ Day 2 — User Lifecycle Management (JML) — Joiner Phase
* ✅ Day 3 — Group Strategy & AGDLP Nesting Model
* ✅ Day 4 — GPO for Access Control (Complete)
* ⬜ Day 5 — Fine-Grained Password Policies & PowerShell Automation
* ⬜ Day 6 — NTFS/Share Permissions & Least Privilege
* ⬜ Day 7 — Phase 1 Capstone


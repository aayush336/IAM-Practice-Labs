# Day 1 Lab: AD DS Logical Structure — Designing an Enterprise OU Model for Bhatt.com

---

## 1. Core Concept Overview

Active Directory's logical structure is built on four core containers, and conflating them is one of the most common mistakes junior admins make in interviews and in production.

**Forest** is the top-level security boundary in AD. It's a collection of one or more domains that share a common schema, configuration partition, and Global Catalog. When you installed AD DS on DC01, you created the Bhatt.com forest — even though it currently contains only one domain, the forest is technically the outermost trust boundary. Anything outside the forest is, by default, untrusted.

**Domain** is a partition within the forest that shares a common directory database (NTDS.dit), security policies (default password policy, Kerberos policy), and replication scope. Bhatt.com is simultaneously your forest root domain and your only domain — a "single domain forest," which is the most common topology in small-to-mid enterprises (over 80% of real-world AD deployments are single-domain, single-forest).

**Organizational Units (OUs)** are NOT a security boundary — this is the single most-tested interview concept in IAM. OUs are an *administrative and management* boundary. They exist purely so you can: (a) apply Group Policy Objects to a specific subset of objects, and (b) delegate administrative permissions over a specific subset of objects. Security boundaries are forests and domains; OUs are organizational/delegation boundaries only. A user moved to a different OU does not change their SID, their domain security policy, or their trust relationships — it only changes which GPOs apply to them and who has delegated rights over them.

**Sites** represent physical/network topology (IP subnets) and control replication traffic and authentication referral (a client authenticates against the nearest Domain Controller based on Site). In our single-DC lab, Sites won't show much value yet, but the concept matters: a multinational company with offices in Mumbai and New York doesn't want a Mumbai user authenticating against a New York DC over a WAN link — Sites solve that.

The critical design skill being trained today is: **how do you structure OUs to mirror business function (not org chart) so that GPO application and delegation scale cleanly?** Industry best practice is a hybrid model — top-level OUs by location or business unit, with consistent sub-OUs for Users, Computers, Groups, and Service Accounts inside each. This is what lets a Tier-0/Tier-1/Tier-2 administrative model (which you'll build in Phase 2) actually function.

---

## 2. Real-World Enterprise Use Case

Imagine Bhatt.com is a mid-size company (500–2000 employees) with an IT department, a Finance department, and a Sales department spread across one HQ location. In production, an IAM Engineer is asked to design the OU structure *before* a single user is migrated, because restructuring OUs later (while users, GPOs, and delegated permissions are already live) is disruptive and risky.

A flat structure (all 2000 users dumped in the default "Users" container) is an anti-pattern interviewers will immediately flag, because:
- The default `Users` container cannot have a GPO linked to it directly (it's a container, not an OU) — meaning you can't apply password policy, software restrictions, or login scripts to it via standard GPO linking.
- You cannot delegate "Helpdesk can reset passwords for Sales department only" without a Sales-specific OU.
- Audit and compliance teams need to query "show me everyone in Finance" instantly — that requires a clean OU mapped to department, not a manual search through a flat list.

The standard enterprise pattern — which we will replicate in Bhatt.com today — is:

```
Bhatt.com
 └── BHATT-CORP (top-level OU, named after the company, NOT "Bhatt.com")
      ├── _Admins (Tier-0/privileged accounts — built in Phase 2)
      ├── IT
      │    ├── Users
      │    ├── Computers
      │    └── Groups
      ├── Finance
      │    ├── Users
      │    ├── Computers
      │    └── Groups
      ├── Sales
      │    ├── Users
      │    ├── Computers
      │    └── Groups
      ├── ServiceAccounts
      └── Disabled-Users (Leaver staging OU)
```

Naming the top-level OU something other than the domain name (e.g., `BHATT-CORP` instead of mirroring `Bhatt.com`) is itself a real-world convention — it avoids confusion with built-in containers and makes the custom hierarchy visually distinct in ADUC.

---

## 3. Detailed Step-by-Step Procedure

> **Tooling for today:** Active Directory Users and Computers (ADUC) on DC01. We will do this via GUI first (to build muscle memory) and then validate via PowerShell (to build the scripting habit you'll need for Phase 1, Day 5 onward).

### Step 1: Log into DC01 and open ADUC
**Action:** Log into **DC01 (10.10.10.102)** with your Domain Admin account. Open **Server Manager → Tools → Active Directory Users and Computers** (or run `dsa.msc` from Run).

**Expected Result/Verification:** ADUC opens showing the `Bhatt.com` domain node expanded in the left pane, with default containers visible: `Builtin`, `Computers`, `Domain Controllers`, `ForeignSecurityPrincipals`, `Users`.

---

### Step 2: Enable "Advanced Features" view
**Action:** In ADUC, click **View → Advanced Features**.

**Expected Result/Verification:** The left pane now additionally shows `LostAndFound`, `Program Data`, and `System` containers. This view is required for later labs (viewing security tab on objects, SDDL, etc.), so we enable it now as a standing habit.

---

### Step 3: Create the top-level company OU
**Action:** Right-click on **Bhatt.com** (the domain root) → **New → Organizational Unit**. In the dialog, type `BHATT-CORP` as the name. **Important:** Uncheck or note the checkbox "Protect container from accidental deletion" — leave it **checked** (default) for production-realism, since this is the enterprise-standard safeguard against accidental OU deletion.

**Expected Result/Verification:** `BHATT-CORP` appears as a new OU directly under the `Bhatt.com` domain node in the left pane, with a distinct OU icon (looks like a folder with a small book/badge, different from the plain folder icon of a container).

---

### Step 4: Create the departmental sub-OUs
**Action:** Right-click **BHATT-CORP** → **New → Organizational Unit**. Create the following four OUs one at a time, all nested directly under `BHATT-CORP`: `IT`, `Finance`, `Sales`, `ServiceAccounts`. Leave "Protect from accidental deletion" checked for all.

**Expected Result/Verification:** Expanding `BHATT-CORP` in the left pane shows exactly four child OUs: `IT`, `Finance`, `Sales`, `ServiceAccounts`, each with the OU folder icon.

---

### Step 5: Create the Tier-0 and Leaver staging OUs
**Action:** Right-click **BHATT-CORP** → **New → Organizational Unit** twice more, creating `_Admins` and `Disabled-Users`. (The underscore prefix on `_Admins` is a real-world naming convention that forces it to sort to the top of the OU list alphabetically, making privileged-account OUs visually prominent during audits.)

**Expected Result/Verification:** `BHATT-CORP` now contains six child OUs total: `_Admins`, `Disabled-Users`, `Finance`, `IT`, `Sales`, `ServiceAccounts` — and `_Admins` appears first in the list due to the underscore.

---

### Step 6: Build the standard sub-structure inside each department
**Action:** Inside **IT**, right-click → **New → Organizational Unit** and create three sub-OUs: `Users`, `Computers`, `Groups`. Repeat this identical three-OU pattern inside **Finance** and inside **Sales**.

**Expected Result/Verification:** Expanding `IT`, `Finance`, and `Sales` each shows three identical sub-OUs (`Users`, `Computers`, `Groups`). The structure should now be visually symmetric across all three departments — this symmetry is what allows a single GPO or delegation template to be reused across departments later.

---

### Step 7: Validate the entire structure via PowerShell
**Action:** Open **PowerShell as Administrator** on DC01 and run:
```powershell
Get-ADOrganizationalUnit -Filter * -SearchBase "DC=Bhatt,DC=com" |
    Select-Object Name, DistinguishedName |
    Sort-Object DistinguishedName
```

**Expected Result/Verification:** The output lists all OUs created, and the `DistinguishedName` column confirms correct nesting, e.g.:
```
Name           DistinguishedName
----           -----------------
BHATT-CORP     OU=BHATT-CORP,DC=Bhatt,DC=com
_Admins        OU=_Admins,OU=BHATT-CORP,DC=Bhatt,DC=com
Disabled-Users OU=Disabled-Users,OU=BHATT-CORP,DC=Bhatt,DC=com
Finance        OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com
Users          OU=Users,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com
...
```
If the `DistinguishedName` path for any sub-OU does not show the correct parent chain (e.g., `Users` under `Finance` under `BHATT-CORP`), the nesting was done incorrectly and must be fixed by dragging the OU to the correct parent in ADUC before proceeding to Day 2.

---

### Step 8: Move your 2 sample users into the new structure (preview of Day 2)
**Action:** In ADUC, locate your 2 existing sample users (likely sitting in the default `Users` container). Drag-and-drop one user into `BHATT-CORP → IT → Users`, and the other into `BHATT-CORP → Finance → Users`.

**Expected Result/Verification:** Run `Get-ADUser -Filter * | Select-Object Name, DistinguishedName` in PowerShell. Both sample users should now show a `DistinguishedName` reflecting their new OU path (e.g., `CN=John Doe,OU=Users,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com`) instead of the default `CN=John Doe,CN=Users,DC=Bhatt,DC=com`. Note the syntax difference: default container uses `CN=Users`, your custom OU uses `OU=Users` — confirming you're now in a true OU, not a container.

---

## 4. Interview-Prep Q&A

**Q1: "What's the difference between an OU and the default 'Users' container, and why does it matter operationally?"**
**Strong Answer:** The default `Users` and `Computers` containers are *containers*, not Organizational Units — structurally they cannot have a GPO linked to them directly via Group Policy Management Console, and you have very limited delegation options on them. OUs, by contrast, support both GPO linking and granular delegation of control. Operationally, this means any enterprise that leaves accounts in the default containers loses the ability to apply targeted policy or delegate admin rights to that population, which is why redirecting or moving objects out of default containers into a custom OU structure is one of the first tasks in any AD deployment (often automated via `redirusr`/`redircmp` for new computer/user objects).

**Q2: "Is an OU a security boundary? If a user is moved from the Finance OU to the IT OU, does their access to Finance-only file shares change automatically?"**
**Strong Answer:** No — an OU is purely an administrative/management boundary, not a security boundary. The user's actual access to resources is governed by group membership and ACLs (NTFS/share permissions), not by their OU location. Moving a user to a different OU only changes (a) which GPOs apply to them, and (b) who has delegated administrative rights over their object. If that user is still a member of the `Finance-Share-ReadWrite` security group, they retain that access regardless of OU location, until someone explicitly removes them from the group. This distinction — OU as organizational/GPO scope vs. group membership as the actual access control mechanism — is exactly why RBAC in AD is built on groups, which we cover Day 3.

---

## 5. Overall Progress Tracker

**Phase 1: On-Premises Lifecycle & Access Management**

```
[■□□□□□□□□□] Day 1 of 30 — 3% Complete
```

✅ Day 1 — AD DS Logical Structure & Enterprise OU Design *(Complete)*
⬜ Day 2 — User Lifecycle Management (JML)
⬜ Day 3 — Group Strategy & AGDLP Model
⬜ Day 4 — GPO Access Control
⬜ Day 5 — Fine-Grained Password Policies & PowerShell Automation
⬜ Day 6 — NTFS/Share Permissions & Least Privilege
⬜ Day 7 — Phase 1 Capstone

---

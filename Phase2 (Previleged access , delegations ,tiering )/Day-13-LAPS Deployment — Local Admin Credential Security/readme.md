# DAY 13 LAB — LAPS Deployment: Securing Local Administrator Credentials

---

## 1. Core Concept Overview

### 1.1 The Problem LAPS Solves — And Why Days 8–12 Didn't Already Solve It

Everything built through Day 12 governs **domain accounts** — bh10xx users, `adm-bh1011`, group memberships, delegated OU rights. None of it touches a completely separate, often-overlooked credential class: the **local Administrator account** that exists on every Windows machine by default, independent of Active Directory entirely. Computer-01, Computer-02, and Computer-03 each have their own local `Administrator` account with its own local SAM database — this account exists even if the machine were never domain-joined at all.

The default enterprise anti-pattern — and the exact reason LAPS exists — is that organizations historically set **the same local Administrator password on every machine**, usually via a golden image or manual imaging process, and then never rotate it. This creates a catastrophic lateral-movement primitive: if an attacker compromises the local Administrator credential on *any one* machine (via offline SAM extraction, a stolen image, or a disgruntled former IT staffer who imaged the machines), that identical credential grants local admin on **every other machine built from the same image** — potentially the entire fleet. This is functionally a Pass-the-Hash amplifier that has nothing to do with domain-level Kerberos protections at all, because local SAM authentication for a local account never touches the KDC — it's a local NTLM-only authentication event, evaluated entirely by the target machine's own SAM, regardless of any Protected Users or tiering control we've built.

**Why Days 8–12 couldn't have caught this:** every control we've built so far operates on the assumption that authentication flows through the domain's Kerberos/NTLM authentication stack — GPO deny-logon rights, Protected Users, LogonWorkstations, tiering. A local account authenticating to its own machine's SAM database bypasses the domain controller entirely. `adm-bh1011`'s meticulous Protected Users configuration from Day 12 provides **zero** protection against someone using Computer-02's local Administrator account to log on to Computer-02 — different account, different authentication path, different attack surface.

### 1.2 How LAPS Actually Works — Mechanism, Not Just Effect

**Legacy LAPS (Microsoft LAPS, the CSE/GPO-based version — what we'll deploy today, since Windows Server 2019 predates Windows LAPS' native integration which requires Server 2019+ with specific updates or Server 2022):**

1. A **schema extension** adds two new attributes to the `computer` object class in AD: `ms-Mcs-AdmPwd` (stores the current local admin password in **cleartext**, not hashed — a deliberate design choice we'll examine below) and `ms-Mcs-AdmPwdExpirationTime` (stores when the current password expires, as an Active Directory-native timestamp).

2. A **Client Side Extension (CSE)**, a DLL installed on each managed machine, is invoked during Group Policy processing (specifically, during the same GPO refresh cycle that processes other computer-side policy). The CSE checks the local machine's `ms-Mcs-AdmPwdExpirationTime` attribute (read via LDAP against its own computer object) against the current time.

3. If the password is expired (or the attribute is empty, e.g., on first run), the CSE **generates a new random password locally on the machine itself** — following complexity/length rules defined in the LAPS GPO — and immediately: (a) sets it as the local Administrator account's password via the local SAM API, and (b) writes the new plaintext password back to its own `ms-Mcs-AdmPwd` attribute in AD, along with a new expiration timestamp.

4. **Critically, the password is generated and set entirely client-side.** The DC never generates or transmits the password to the machine — the machine generates its own password locally and *reports* it to AD. This matters for the threat model: even if someone were intercepting DC-to-client traffic, they wouldn't catch a password in transit *from* the DC, because the DC never sends one.

**Why cleartext storage in `ms-Mcs-AdmPwd`, given IAM Days 1–12 have emphasized least-privilege and defense-in-depth relentlessly — doesn't this contradict that?** No — the security model shifts the entire protection burden onto **AD's own read-permission ACL on that specific attribute**, which is a deliberate and correct design given the alternative. LAPS restricts read access to `ms-Mcs-AdmPwd` to an explicitly delegated set of principals (Domain Admins by default, plus whoever we delegate in Step 4 below) via a standard confidentiality bit set on the attribute's ACE — the same underlying ACE mechanism as everything we delegated in Day 9. This means retrieving a machine's local admin password requires **directory-level read access explicitly granted**, which is fully auditable via the same 4662 (object access) event auditing we'll build in Day 17 — a far stronger and more visible control point than, say, an encrypted password whose decryption key management would itself become a new, harder-to-audit secret to protect. Encrypting it would just relocate the trust problem to key management without actually solving it — this is worth saying explicitly, because it's exactly the kind of design-tradeoff reasoning a senior interviewer probes for.

**Windows LAPS (the modern, Server 2019+ with specific KBs / Server 2022+ native version)** improves on this by supporting AES-256 encryption of the stored password (not just plaintext), a shorter default rotation window, post-authentication automatic rotation (the password rotates immediately after use, not just on schedule), and optional Entra ID / Azure AD integration for hybrid environments — directly relevant groundwork for Phase 4 (Days 23–30). Bhatt.com's DC01 is Windows Server 2022 (per our original infrastructure spec), which *does* support Windows LAPS natively — today's lab deploys **Windows LAPS** rather than legacy Microsoft LAPS, since our DC is already capable of it and there's no reason to deploy the superseded version.

### 1.3 Why Random, Per-Machine, Auto-Rotating — Tied Back to the Attack Model

The three properties LAPS enforces — **randomized** (not a shared/derived password), **per-machine** (not fleet-wide identical), **auto-rotating** (not "set once, forget") — each defeat a specific attack step:

- **Randomized** defeats offline cracking value: even if an attacker extracts the local SAM hash from one machine, there's no pattern to reverse-engineer that would predict any other machine's password.
- **Per-machine** defeats the golden-image lateral-movement primitive described in 1.1: compromising Computer-01's local Administrator grants *zero* access to Computer-02 or Computer-03.
- **Auto-rotating** defeats the "credential theft has a shelf life problem for the attacker" — even a successfully exfiltrated password becomes worthless after the next rotation cycle (default 30 days in Windows LAPS, configurable), without requiring any human to remember to do it.

---

## 2. Real-World Enterprise Use Case

Local Administrator credential sprawl is one of the most consistently cited findings in penetration tests against mid-sized enterprises, and it's a named, specific control in most banking cybersecurity frameworks — RBI's framework explicitly calls out privileged local account management, and PCI-DSS Requirement 8.6 addresses shared/group credential prohibition, which an unrotated identical local Administrator password directly violates (it is, by definition, a shared credential across every machine built from the same image).

In Bhatt.com's context specifically, this lab directly closes a gap our tiering model (Day 11) and PAM design (Day 12) **could not** close: `adm-bh1011`'s hardening prevents domain-credential-based lateral movement, but says nothing about local Administrator access on Computer-01, Computer-02, or Computer-03. A red-team engagement against a real bank IT environment frequently finds this exact sequencing gap — organizations invest heavily in domain-tier privileged access management while leaving every workstation's local admin account on an identical, years-old password from the original imaging process. Today's lab, combined with Day 12, gives Bhatt.com coverage across **both** credential classes: domain-tier (Protected Users, tiering, dedicated admin accounts) and local-tier (LAPS).

We'll also use this lab to formally delegate LAPS password *read* rights to `G-Helpdesk-PasswordReset` (built in Day 9) for a specific, realistic reason: helpdesk staff occasionally need local admin access on a workstation to resolve an issue a standard user account can't fix (e.g., reinstalling a broken driver) — LAPS lets us grant that access without ever having Helpdesk staff know or need a domain-tier credential, keeping the Day 11 tiering boundary fully intact.

---

## 3. Detailed Step-by-Step Procedure

### Step 1: Verify and update the AD schema for Windows LAPS

Windows LAPS requires schema attributes that don't exist by default until explicitly added — this is a **forest-wide, irreversible schema modification**, so we verify current state before acting.

**On DC01**, open **Windows PowerShell (Run as Administrator)**.

```powershell
# Check if Windows LAPS schema attributes already exist
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter {name -eq "ms-LAPS-Password"}
```

**Expected Result/Verification:** An empty result confirms the schema hasn't been extended yet — proceed to extend it. If this returns an object, skip to Step 2 (already extended).

```powershell
# Update the schema to add Windows LAPS attributes (requires Schema Admins
# membership - use adm-bh1011 for this, since schema modification is
# precisely the Tier0 task category that account exists for)
Update-LapsADSchema -Verbose
```

**Note on why `adm-bh1011` specifically must run this:** Schema modification requires Schema Admins group membership, and per our Day 8 finding and Day 12 justification, no standard bh10xx account — including bh1011's own daily-use account — should ever hold that membership. This is precisely the "genuinely Tier 0 task" scenario the dedicated account was built for. If `adm-bh1011` is not currently a member of Schema Admins, add it temporarily for this operation only:

```powershell
Add-ADGroupMember -Identity "Schema Admins" -Members "adm-bh1011"
# ... run Update-LapsADSchema while logged on as adm-bh1011 ...
Remove-ADGroupMember -Identity "Schema Admins" -Members "adm-bh1011" -Confirm:$false
```

**Expected Result/Verification:**
```powershell
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter {name -eq "ms-LAPS-Password"} |
    Select Name, DistinguishedName
```
Output now confirms the `ms-LAPS-Password` schema attribute exists. Also confirm Schema Admins membership was removed immediately after (`Get-ADGroupMember -Identity "Schema Admins"` should show no members, or only the built-in Administrator if that was already present) — leaving standing Schema Admins membership even temporarily-justified is itself a finding if not promptly reverted.

---

### Step 2: Delegate the ability for computer objects to self-write their LAPS password attribute

Recall from Section 1.2: each machine's CSE writes its own password back to its own computer object. This requires an ACE granting `SELF` write access to the LAPS attributes, scoped per-OU (matching our existing OU delegation discipline from Day 9).

```powershell
$targetOUs = @(
    "OU=Computers,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com",
    "OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com"
)

foreach ($ou in $targetOUs) {
    Set-LapsADComputerSelfPermission -Identity $ou
}
```

**Expected Result/Verification:**
```powershell
foreach ($ou in $targetOUs) {
    dsacls $ou | Select-String "ms-LAPS"
}
```
Output shows `SELF` granted write access to `ms-LAPS-Password` and `ms-LAPS-PasswordExpirationTime` on both OUs. This confirms Computer-01 (Finance\Computers), Computer-02, and Computer-03 (IT\Computers) can each write their own — and only their own — LAPS attribute, never another machine's.

---

### Step 3: Delegate LAPS password *read* rights — deliberately narrow scope

This is the step that determines who can actually retrieve a plaintext local admin password. Per Section 1.2, this ACE is the entire security boundary — get this wrong and LAPS provides no real protection.

```powershell
# G-ITManagers-OUAdmin (Day 9) gets read rights across IT-managed machines
Set-LapsADReadPasswordPermission -Identity "OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -AllowedPrincipals "Bhatt\G-ITManagers-OUAdmin"

# G-Helpdesk-PasswordReset (Day 9) gets read rights scoped ONLY to Finance
# workstations (Computer-01) - reflecting the realistic scenario that
# Helpdesk supports end-user Finance/Sales machines, not IT's own servers
Set-LapsADReadPasswordPermission -Identity "OU=Computers,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -AllowedPrincipals "Bhatt\G-Helpdesk-PasswordReset"
```

**Why this is scoped deliberately unevenly across the two groups, not symmetrically:** `G-Helpdesk-PasswordReset` explicitly does **not** get read rights on IT's OU (Computer-02, Computer-03) — those are IT-managed server-class assets, and Helpdesk's realistic job function (per the Day 2/9 role definition) is end-user support, not server administration. Granting symmetric access "to keep things simple" would be exactly the kind of scope creep Day 10's RBAC matrix discipline exists to prevent — every delegation should map to an actual documented job function, not be granted by default convenience.

**Expected Result/Verification:**
```powershell
dsacls "OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com" | Select-String "G-ITManagers-OUAdmin|ms-LAPS-Password"
dsacls "OU=Computers,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" | Select-String "G-Helpdesk-PasswordReset|ms-LAPS-Password"
```
Confirm `G-ITManagers-OUAdmin` has an `extended right` / `CONTROL_ACCESS` grant on `ms-LAPS-Password` scoped to the IT Computers OU, and `G-Helpdesk-PasswordReset` has the equivalent scoped only to Finance Computers OU — with no cross-grant.

---

### Step 4: Build and configure the Windows LAPS GPO

**On DC01**, open **Group Policy Management** (`gpmc.msc`).

**Right-click Group Policy Objects → New:**
- Name: `GPO-WindowsLAPS-Workstations`

**Edit**, navigate to:
`Computer Configuration → Policies → Administrative Templates → System → LAPS`

Configure the following settings explicitly (each with reasoning, not just the value):

| Setting | Value | Reasoning |
|---|---|---|
| **Configure password backup directory** | Enabled → **Active Directory** | We're using AD as the backend, not Azure/Entra (Entra integration is Day 24+ scope) |
| **Password Settings** | Enabled → Complexity: Large+small+numbers+specials; Length: **20**; Age (Days): **30** | 20 chars exceeds even our Day 5 strict PSO's 16-char minimum — local admin credentials warrant at least parity with our strictest domain policy, arguably more since they're a flatter, single-factor attack surface |
| **Post-authentication actions** | Enabled → Reset password, Grace period: **8 hours** | Ensures that immediately *after* someone legitimately checks out and uses a LAPS password, it rotates again rather than remaining valid until the next scheduled 30-day cycle — closing the "used once, valid for a month" exposure window |
| **Name of administrator account to manage** | *(leave blank — manages default "Administrator")* | Explicit default; documented rather than left ambiguous |

**Link the GPO** to both target OUs:

```powershell
$gpo = Get-GPO -Name "GPO-WindowsLAPS-Workstations"
New-GPLink -Guid $gpo.Id -Target "OU=Computers,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com"
New-GPLink -Guid $gpo.Id -Target "OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com"
```

**Expected Result/Verification:**
```powershell
Get-GPInheritance -Target "OU=Computers,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" | Select -ExpandProperty GpoLinks
Get-GPInheritance -Target "OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com" | Select -ExpandProperty GpoLinks
```
Both show `GPO-WindowsLAPS-Workstations` linked, alongside the existing GPOs from Days 4 and 11 — confirming no conflicting or overwritten links.

---

### Step 5: Force policy refresh and validate on all three client machines

**On Computer-01, Computer-02, and Computer-03** (via RDP or console, using a standard domain account with local logon rights — not `adm-bh1011`, per Day 12's tiering rule):

```powershell
gpupdate /force
```

**Then trigger the LAPS CSE to run immediately** rather than waiting for the next scheduled interval (default policy processing background refresh is 90–120 minutes, impractical for lab validation):

```powershell
Invoke-LapsPolicyProcessing
```

**Expected Result/Verification (run on each of the three machines):**
```powershell
Get-LapsDiagnostics
```
Output shows `Policy is present : True`, the resolved password backup directory as Active Directory, and a successful last-rotation timestamp within the last few minutes. If this returns an error or "Policy is present: False," the GPO link or `gpupdate` hasn't propagated — re-run `gpupdate /force` and confirm via `gpresult /r` that `GPO-WindowsLAPS-Workstations` appears under Applied Group Policy Objects before retrying.

---

### Step 6: Retrieve a password from DC01 as a delegated principal, confirming scoped access works — and confirming it's correctly denied where not delegated

**As a member of `G-ITManagers-OUAdmin` (bh1013), from DC01 or a machine with RSAT:**

```powershell
Get-LapsADPassword -Identity "Computer-02" -AsPlainText
```

**Expected Result/Verification:** Returns the current password, expiration timestamp, and generation timestamp for Computer-02 — confirming bh1013's delegated read access (Step 3) functions correctly for an IT-OU machine.

**As the same bh1013 account, attempt the same against Computer-01 (Finance OU — not delegated to G-ITManagers-OUAdmin):**

```powershell
Get-LapsADPassword -Identity "Computer-01" -AsPlainText
```

**Expected Result/Verification:** This should return an **Access Denied** error — confirming the deliberately asymmetric scoping from Step 3 is actually enforced, not just configured. This negative test is the step most LAPS deployments skip, and it's the one that actually proves least-privilege was achieved on the read side, not just the write side.

**As a member of `G-Helpdesk-PasswordReset` (bh1003), confirm the inverse:**
```powershell
Get-LapsADPassword -Identity "Computer-01" -AsPlainText   # should SUCCEED (Finance OU, delegated)
Get-LapsADPassword -Identity "Computer-02" -AsPlainText   # should FAIL (IT OU, not delegated)
```

---

### Step 7: Document the LAPS deployment and delegation model

**Manually create** `C:\IAM-Docs\Day13-LAPS-Deployment.txt`:

```
BHATT.COM — WINDOWS LAPS DEPLOYMENT
Date: <today's date>

SCOPE: Windows LAPS (AD-backed, not Entra-integrated) deployed to all
three client machines: Computer-01 (Finance), Computer-02 (IT),
Computer-03 (IT).

SCHEMA: Extended via Update-LapsADSchema, executed under adm-bh1011
with temporary Schema Admins membership, immediately reverted post-use.

PASSWORD POLICY: 20-character complex, 30-day rotation, 8-hour
post-authentication reset grace period. Exceeds Day 5's strict PSO
minimum (16 chars) deliberately, given local admin's flatter,
single-factor exposure profile.

READ DELEGATION (asymmetric, by design):
  G-ITManagers-OUAdmin -> read access to IT OU machines only
    (Computer-02, Computer-03)
  G-Helpdesk-PasswordReset -> read access to Finance OU machines only
    (Computer-01)
  No group holds read access across both OUs - reflects actual
  documented job function boundaries per Day 10's RBAC matrix.

VALIDATION: Negative-scope test confirmed both groups are denied
read access outside their delegated OU (Access Denied on
cross-OU Get-LapsADPassword attempts).

GAP CARRIED FORWARD: DC01 itself has no LAPS-managed local admin
account - LAPS is deployed only to Tier 2 client machines per this
lab's scope. DC01's local Administrator account security is governed
separately via Tier0 controls (Day 11-12) and is a candidate for
review under Day 16 (Security Auditing).
```

**Expected Result/Verification:** File exists and accurately documents scope, policy values with justification, delegation asymmetry, and the explicitly disclosed DC01 gap — consistent with the disclosed-limitation discipline established since Day 11.

---

## 4. Interview-Prep Q&A

**Q1: "LAPS stores the local administrator password in cleartext in an Active Directory attribute rather than encrypting or hashing it. A security-conscious colleague raises concern about this. How do you evaluate whether this is actually a weakness, and what mitigates it?"**

**Model Answer:** I'd first clarify that "cleartext in AD" is only half the picture — Windows LAPS actually supports AES-256 encryption of the stored value as a configurable option, so the concern is more precisely about the legacy Microsoft LAPS model, or Windows LAPS deployed without encryption enabled. But even accepting the cleartext case, I'd evaluate this against what the realistic alternative actually is, not against an idealized "encrypted" strawman. If the password were encrypted at rest, something still needs to hold the decryption key, and that key becomes a new secret requiring its own access control, storage, and rotation discipline — you haven't eliminated the trust problem, you've relocated it one layer deeper, and arguably made it *less* auditable, because now there are two things to protect (the ciphertext's read access, and the key's read access) instead of one clear, single control point. LAPS's actual security model is that read access to the `ms-Mcs-AdmPwd` (or Windows LAPS equivalent) attribute is itself gated by a standard AD ACE — the exact same delegation mechanism we used throughout Day 9 — and every read of that attribute is fully visible via directory access auditing, specifically Event ID 4662 with the correct object-access auditing enabled, which we'll build formally in Day 17. That gives us a single, well-understood, fully-audited control point rather than a two-layer secret-management problem. The mitigating factors that actually matter are: scoping read delegation as narrowly as possible — which is exactly what we did in this lab, splitting IT and Finance OU read access between two different groups with no overlap — and ensuring the audit trail for attribute reads is actually monitored, not just theoretically available.

**Q2: "Your organization has LAPS deployed and working correctly on all workstations, but a penetration tester still successfully achieves fleet-wide lateral movement using a stolen local Administrator credential. What are the most likely explanations, given LAPS is confirmed to be functioning?"**

**Model Answer:** Given LAPS itself is functioning correctly, I'd investigate several specific gaps rather than assume LAPS failed. First, scope gaps — exactly like the one we found and fixed in Day 12 with Computer-02 and Computer-03 landing outside GPO scope by default — a machine that's domain-joined but sitting in the default Computers container, or in an OU the LAPS GPO isn't linked to, would still have an unmanaged, potentially default or shared local Administrator password, giving an attacker a foothold machine to pivot from. Second, I'd check whether the local Administrator account is actually the account LAPS is managing — if "Name of administrator account to manage" was left blank assuming the built-in Administrator, but the environment has a *renamed* built-in admin account or a *second* local admin-equivalent account created separately (a common legacy IT practice, e.g., a "svc_localadmin" account added to the local Administrators group), LAPS would be faithfully rotating a password on an account nobody's actually using, while the real exploited account sits completely unmanaged. Third, I'd check for a stale image or offline-media exposure path — if a machine was reimaged from an older golden image that pre-dates LAPS deployment and was never subsequently joined to receive the GPO before being put into production, or if VM snapshots/backups from before LAPS deployment still exist and are restorable, an attacker could recover the pre-LAPS shared password from that stale artifact entirely outside LAPS's visibility. In all three cases, the pattern is the same lesson as Day 12's Computer-02/03 discovery: a security control's *design* being correct is necessary but not sufficient — its actual *coverage* across every relevant asset has to be independently verified, not assumed from the control's presence elsewhere in the environment.

---

## 5. Overall Progress Tracker

**Phase 1: Foundational Identity Lifecycle & Access Control** — ✅ Complete (Days 1–7)
**Phase 2: Privileged Access, Delegation & Tiering** — In Progress

```
[█████████████░░░░░░░░░░░░░░░] 43.3% Complete (13/30 days)
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
| 9 | OU Delegation of Control | ✅ |
| 10 | RBAC Design & Access Matrix Documentation | ✅ |
| 11 | Microsoft Tiering Model (Tier 0/1/2) | ✅ |
| 12 | Privileged Account Management — Dedicated Admin Accounts, Protected Users | ✅ |
| **13** | **LAPS Deployment — Local Admin Credential Security** | ✅ |
| 14 | JIT Access Concepts & Time-Bound Elevation | ⬜ |
| 15 | Phase 2 Capstone | ⬜ |

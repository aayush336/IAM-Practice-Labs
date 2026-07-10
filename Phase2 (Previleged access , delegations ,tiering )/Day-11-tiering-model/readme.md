# DAY 11 LAB — Microsoft Tiering Model (Tier 0/1/2): Architecture Theory & Single-DC Simulation

---

## 1. Core Concept Overview

The Microsoft Tiering Model is the architectural answer to a problem Days 8 and 9 only partially solved: even with delegation replacing Domain Admins for routine tasks, **credential exposure across trust boundaries** remains possible if a highly-privileged account and a low-trust workstation ever share the same authentication path. Tiering closes this gap not through *permissions* (what Day 9 addressed) but through **logon path segmentation** — controlling not just what an account can do, but *where that account is ever allowed to authenticate from.*

**The three-tier model:**

| Tier | Scope | Assets | Example in Bhatt.com |
|---|---|---|---|
| **Tier 0** | Full control of the identity/security fabric | Domain Controllers, AD FS servers, PKI/CA servers, Domain Admin accounts, GPOs linked at domain root | DC01, Domain Admins, Enterprise Admins |
| **Tier 1** | Control of enterprise servers and services | Application servers, database servers, server admin accounts | (In a larger build-out: file servers, SQL servers — not yet provisioned in this lab) |
| **Tier 2** | Control of user workstations and end-user support | Workstations, helpdesk accounts, standard user support tools | Computer-01, `G-Helpdesk-PasswordReset` members |

**The core rule — and the one most environments violate without realizing it:** *an account belonging to a given tier must never log on interactively to an asset belonging to a lower tier.* A Tier 0 account (Domain Admin) must never log on to a Tier 2 workstation — not for convenience, not "just this once" to check something. This is the direct technical enforcement of the credential-caching risk explained in Day 8: if the rule is never broken, a Tier 0 credential can *never* be harvested from a compromised Tier 2 workstation, because it was never present there to begin with.

**Why this requires more than delegation alone:** Day 9's OU delegation controls *what actions* an account can perform against directory objects. Tiering controls *where* an account is permitted to establish an interactive or network logon session at all — a completely different control plane. A Helpdesk account with perfectly scoped delegated rights (Day 9) can still be a Tier 0 compromise vector if that same account is also, say, a local admin on DC01 through some unrelated legacy group nesting. Tiering is what catches and prevents that class of gap.

**Enforcement mechanisms (the practical "how"):**

1. **User Rights Assignment via GPO** — "Deny log on locally," "Deny log on through Remote Desktop Services," and "Deny access to this computer from the network" rights, applied via GPO to enforce that Tier 0 accounts cannot authenticate to Tier 1/2 assets and vice versa.
2. **Authentication Policies and Silos** (available in Windows Server 2012 R2 Functional Level and above) — a more advanced mechanism that cryptographically restricts which hosts a Kerberos-authenticating account can obtain a TGT for use against, enforced at the KDC level rather than just the target machine's local policy.
3. **OU-based segmentation** — Tier 0 assets and accounts live in dedicated, tightly restricted OUs with their own GPOs, separate from Tier 1/2 OU structures — ensuring GPO inheritance never accidentally applies a lower-tier policy (like a permissive logon right) to a Tier 0 asset.

**Single-DC lab limitation, stated honestly:** In a real enterprise, Tier 0 typically spans multiple DCs, PKI infrastructure, and federation servers, with Tier 1 covering dozens of member servers. Bhatt.com has exactly one DC (DC01) and one client machine (Computer-01) — meaning a full 3-tier physical separation isn't achievable at this scale. Today's lab therefore builds the *architectural pattern* (OU structure, GPO enforcement logic, and the deny-logon rule) using DC01 as the sole Tier 0 asset and Computer-01 as the sole Tier 2 asset, with Tier 1 modeled organizationally (documented, OU-prepared) for when server assets are introduced in a future environment expansion. This is a deliberate, disclosed simplification — not a shortcut taken silently.

---

## 2. Real-World Enterprise Use Case

In a bank's IAM function, tiering is frequently the single largest finding in a penetration test or red-team engagement: testers routinely demonstrate a full domain compromise by finding *one* instance of a Domain Admin account that was RDP'd into a standard workstation for a one-off task months earlier, whose credential was still cacheable or whose session artifacts persisted. Regulatory frameworks in banking (RBI guidelines in India, and equivalents like FFIEC in the US) increasingly expect demonstrable segmentation between privileged identity infrastructure and general end-user computing — tiering is the concrete technical control that satisfies that expectation.

For Bhatt.com specifically: DC01 must be treated as Tier 0 in the fullest sense — meaning **no account except designated Tier 0 admin accounts should ever be permitted to log on locally or via RDP to DC01**, including bh1011 (IT Director) and bh1013 (IT Manager) using their standard day-to-day accounts, even though they are senior IT staff. This directly extends the Day 8 finding: seniority does not equal Tier 0 eligibility. Tier 0 eligibility is a function of *dedicated, purpose-built accounts* (which Day 12 — Privileged Account Management — will formally build), not organizational rank.

---

## 3. Detailed Step-by-Step Procedure

### Step 1: Create the Tier 0 administrative OU structure

**On DC01**, open **Active Directory Users and Computers (ADUC)**. Navigate to `OU=BHATT-CORP,DC=Bhatt,DC=com`.

**Right-click BHATT-CORP → New → Organizational Unit:**
- Name: `Tier0-Admin`
- ✅ Protect container from accidental deletion

Inside `Tier0-Admin`, create two sub-OUs the same way:
- `OU=Accounts,OU=Tier0-Admin,OU=BHATT-CORP,DC=Bhatt,DC=com`
- `OU=Groups,OU=Tier0-Admin,OU=BHATT-CORP,DC=Bhatt,DC=com`

**Expected Result/Verification:**
```powershell
Get-ADOrganizationalUnit -Filter {Name -eq "Tier0-Admin"} -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com"
Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Tier0-Admin,OU=BHATT-CORP,DC=Bhatt,DC=com"
```
Output confirms `Tier0-Admin` exists with `Accounts` and `Groups` sub-OUs nested beneath it, isolated from the existing Finance/IT/Sales OU tree.

---

### Step 2: Create the Tier 0 security group (empty — populated in Day 12)

```powershell
New-ADGroup -Name "G-Tier0-Admins" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Groups,OU=Tier0-Admin,OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -Description "Tier 0 - Domain/Enterprise Admin equivalent accounts only. No standard user accounts."
```

**Expected Result/Verification:**
```powershell
Get-ADGroup -Identity "G-Tier0-Admins" -Properties Description | Select Name, GroupScope, Description
```
Output confirms the group exists in the correct OU with the description stamped. Membership is intentionally left empty in this lab — Day 12 (Privileged Account Management) will create the dedicated admin accounts that populate it, so that today's OU/GPO structure isn't built around accounts that don't exist yet.

---

### Step 3: Build the Tier 0 logon-restriction GPO

**On DC01**, open **Group Policy Management** (`gpmc.msc`).

**Right-click Group Policy Objects → New:**
- Name: `GPO-Tier0-LogonRestriction-DC`

**Right-click `GPO-Tier0-LogonRestriction-DC` → Edit**, navigate to:
`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment`

Configure the following:

| Right | Setting |
|---|---|
| **Allow log on locally** | Add: `G-Tier0-Admins`, `Administrators` (built-in). Remove all other entries. |
| **Deny log on through Remote Desktop Services** | Add: `Domain Users` (blocks everyone except accounts explicitly exempted below by not being in Domain Users' deny scope — for this lab, document as a placeholder since RDP to DC01 is out of scope for standard operations) |

**Link the GPO:**
Right-click `OU=Domain Controllers` (the built-in DC OU) → **Link an Existing GPO** → select `GPO-Tier0-LogonRestriction-DC`.

**Expected Result/Verification:**
```powershell
Get-GPO -Name "GPO-Tier0-LogonRestriction-DC" | Select DisplayName, GpoStatus
Get-GPInheritance -Target "OU=Domain Controllers,DC=Bhatt,DC=com" | Select-Object -ExpandProperty GpoLinks
```
Output confirms the GPO exists, is enabled, and is linked to the Domain Controllers OU. Run `gpresult /r` on DC01 to confirm the GPO appears in Applied Group Policy Objects.

---

### Step 4: Build the Tier 2 deny-logon GPO for Computer-01 (protecting the workstation tier from privileged accounts)

This is the inverse control — preventing Tier 0 accounts from ever being used on Tier 2 assets, which is the actual credential-caching prevention mechanism.

**Right-click Group Policy Objects → New:**
- Name: `GPO-Tier2-DenyTier0Logon-Workstations`

**Edit**, navigate to the same User Rights Assignment path, and configure:

| Right | Setting |
|---|---|
| **Deny log on locally** | Add: `G-Tier0-Admins` |
| **Deny log on through Remote Desktop Services** | Add: `G-Tier0-Admins` |
| **Deny access to this computer from the network** | Add: `G-Tier0-Admins` |

**Link the GPO** to `OU=Computers,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com` (Computer-01's location).

**Expected Result/Verification:**
```powershell
Get-GPO -Name "GPO-Tier2-DenyTier0Logon-Workstations" | Select DisplayName, GpoStatus
Get-GPInheritance -Target "OU=Computers,OU=Finance,OU=BHATT-CORP,DC=Bhatt,DC=com" | Select-Object -ExpandProperty GpoLinks
```
Output confirms the GPO is linked to Computer-01's OU. Since `G-Tier0-Admins` is currently empty (Step 2), this control is architecturally in place but has no members to test against yet — validated functionally in Day 12 once Tier 0 accounts exist.

---

### Step 5: Document the tiering model and its single-DC scope limitation

**Manually create** `C:\IAM-Docs\Day11-TieringModel.txt`:

```
BHATT.COM — MICROSOFT TIERING MODEL IMPLEMENTATION
Date: <today's date>

TIER 0 (Identity Control Plane):
  Assets: DC01
  Accounts: G-Tier0-Admins (empty - populated Day 12 with dedicated
    admin accounts, NOT standard bh10xx user accounts)
  Enforcement: GPO-Tier0-LogonRestriction-DC restricts logon-locally
    on DC01 to G-Tier0-Admins + built-in Administrators only

TIER 1 (Enterprise Server Control Plane):
  Assets: None currently provisioned in this lab environment
  Status: Organizationally reserved - OU structure and GPO pattern
    established here will extend to Tier 1 when server assets
    (file servers, SQL, etc.) are introduced in a future expansion
  Disclosed limitation: Single-DC lab cannot fully demonstrate
    3-tier physical separation

TIER 2 (Workstation/End-User Control Plane):
  Assets: Computer-01
  Accounts: All standard bh10xx user accounts, G-Helpdesk-PasswordReset
  Enforcement: GPO-Tier2-DenyTier0Logon-Workstations denies
    G-Tier0-Admins from logging on locally, via RDP, or over the
    network to Computer-01

CRITICAL RULE ESTABLISHED: No account may ever authenticate to an
asset in a lower tier than its own. This is enforced bidirectionally:
Tier 0 accounts are denied on Tier 2 assets (Step 4), and only Tier 0
accounts are permitted on Tier 0 assets (Step 3).

DEPENDENCY: G-Tier0-Admins is intentionally empty pending Day 12
(Privileged Account Management), which will create dedicated
admin_bh1011-style accounts distinct from standard user accounts,
so that Tier 0 membership is never granted to a day-to-day account.
```

**Expected Result/Verification:**
File exists at `C:\IAM-Docs\Day11-TieringModel.txt` and accurately documents the tier boundaries, current enforcement state, and the explicit disclosed limitation of simulating a 3-tier model on single-DC infrastructure.

---

## 4. Interview-Prep Q&A

**Q1: "Explain the Microsoft Tiering Model and why 'Deny log on' GPO restrictions are considered more effective than relying solely on the principle of least privilege via group membership."**

**Model Answer:** The Tiering Model segments the environment into three trust levels — Tier 0 (identity infrastructure like Domain Controllers and PKI), Tier 1 (enterprise servers), and Tier 2 (workstations and end-user assets) — with a strict rule that credentials from a higher tier must never be exposed on a lower-tier asset. Least privilege via group membership, which we built through Day 9's delegation, controls *what actions* an account can perform against directory objects, but it does nothing to prevent *where* that account authenticates. A Domain Admin account with perfectly scoped, minimal group memberships elsewhere can still be catastrophically exposed if it's ever used to log on to a standard workstation, because the authentication event itself caches credential material in that workstation's memory — regardless of how restrained the account's actual AD permissions are. Deny log on GPO restrictions close this specific gap by making it a technical impossibility, not just a policy expectation, for a Tier 0 account to authenticate anywhere except Tier 0 assets. This is why the two controls are complementary, not substitutes: delegation limits what an account can do, tiering limits where an account's credentials can ever be present, and a mature IAM program requires both — an environment with excellent delegation but no tiering is still one workstation compromise away from full domain takeover.

**Q2: "Your organization only has a single Domain Controller and no dedicated server tier — how would you explain to leadership why implementing tiering is still worthwhile, given the model was designed for larger multi-server environments?"**

**Model Answer:** I'd frame it around the fact that tiering is fundamentally a *behavioral and architectural discipline*, not a feature that requires a minimum number of servers to provide value. Even in a single-DC environment, the highest-value part of the model — ensuring that the Domain Controller's administrative credentials are never used on a standard end-user workstation — is fully achievable and addresses the single most common real-world attack path: credential theft from a compromised workstation escalating to full domain compromise. I'd implement the OU structure, dedicated Tier 0 admin accounts, and deny-logon GPOs now, at the scale that exists today, explicitly documenting where the model is simplified (no distinct Tier 1 server tier yet) rather than claiming full compliance we haven't earned. This has two benefits: it delivers real risk reduction immediately, and it means that when the environment grows — additional servers, additional domain controllers — the tiering pattern, OU structure, and enforcement GPOs already exist and simply need to be extended to new assets, rather than being retrofitted onto an environment that's already grown organically without them. Leadership generally responds well to this framing because it separates "is this valuable right now" (yes) from "is this the complete enterprise-scale implementation" (not yet, and here's the roadmap).

---

## 5. Overall Progress Tracker

**Phase 1: Foundational Identity Lifecycle & Access Control** — ✅ Complete (Days 1–7)
**Phase 2: Privileged Access, Delegation & Tiering** — In Progress

```
[███████████░░░░░░░░░░░░░░░░░] 36.7% Complete (11/30 days)
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
| **11** | **Microsoft Tiering Model (Tier 0/1/2)** | ✅ |
| 12 | Privileged Account Management | ⬜ |
| 13 | LAPS Deployment | ⬜ |
| 14 | JIT Access Concepts & Time-Bound Elevation | ⬜ |
| 15 | Phase 2 Capstone | ⬜ |

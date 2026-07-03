# DAY 8 LAB — Least Privilege Deep Dive: Built-In Privileged Groups Anatomy & Attack Surface Analysis

---

## 1. Core Concept Overview

Every Active Directory forest ships with a set of built-in privileged groups that exist the moment you promote a domain controller. These groups are not optional scaffolding — they are permanent, deeply embedded control points that define who can do what across the domain and forest. Understanding their exact scope, nesting relationships, and blast radius is foundational to every privileged access decision you'll make for the rest of this bootcamp.

**The core built-in privileged groups, in order of blast radius:**

| Group | Scope | Blast Radius |
|---|---|---|
| **Enterprise Admins** | Universal (root domain only) | Entire forest — every domain, every object |
| **Domain Admins** | Global | Entire domain — every OU, every GPO, every DC |
| **Schema Admins** | Universal (root domain only) | Can modify the AD schema itself — forest-wide structural changes |
| **Administrators** (BUILTIN) | Domain Local | Local admin rights on every DC via automatic nesting |
| **Account Operators** | Domain Local | Can create/modify/delete most user, group, and computer objects (with exceptions) |
| **Server Operators** | Domain Local | Can log on locally to DCs, manage services, backup/restore files on DCs |
| **Backup Operators** | Domain Local | Can bypass file-level permissions entirely for backup/restore — a full data exfiltration path |
| **Print Operators** | Domain Local | Can log on locally to DCs and manage printers — an underrated pivot point |

**Why Domain Admins is never used for daily operations — the mechanism, not just the rule:**

1. **Persistent high-value credential exposure.** Every time a Domain Admins account authenticates interactively — even to check email or browse a file share — its credential material (password hash, and if Kerberos, ticket-granting ticket) gets cached in the LSASS process memory of whatever machine it touched. If that machine is a standard workstation (not a hardened PAW — Privileged Access Workstation), it's now a credential-theft target. Tools like Mimikatz extract these cached credentials directly from memory.

2. **Golden Ticket / Kerberoasting amplification.** A compromised Domain Admin account isn't just "one more admin account" — it's a domain-wide skeleton key. An attacker who dumps a Domain Admin's NTLM hash or Kerberos TGT can forge tickets (Golden Tickets) that impersonate *any* user in the domain indefinitely, because Domain Admins membership implicitly grants rights to reset the krbtgt account password hash — the master key for the entire Kerberos realm.

3. **Lateral movement multiplication.** Domain Admins are, by default, local Administrators on every domain-joined machine (via the domain-wide SID history and default GPO behavior). If a DA logs into a compromised workstation, the attacker doesn't need to escalate — they inherit full domain control the moment that session touches the box (a classic "Pass-the-Hash" or "Pass-the-Ticket" scenario).

4. **No accountability granularity.** Domain Admins is a single flat group. When five people share DA rights for convenience, you lose the ability to answer "who changed this GPO" or "who created this account" with any precision — a direct audit and forensic failure.

**The Least Privilege remediation model:**
- Daily administrative tasks (password resets, group membership changes, OU-scoped object management) are delegated via granular ACEs on specific OUs (this is exactly what Day 9's lab will build).
- Domain Admins membership is reserved for forest/domain-wide structural changes only (schema updates, trust configuration, DC promotion/demotion, GPO changes at the domain root) — and even then, ideally via a Privileged Access Workstation and just-in-time elevation (Day 14).
- True administrative work is done through **role-scoped custom groups** (like the `G-*` and `DL-*` groups you've already built) layered with **OU delegation** — never through blanket built-in group membership.

**Attack surface analysis mindset:** every account added to a built-in privileged group is a new node in your attack graph. The correct question is never "does this person need to get things done?" — it's "what is the minimum built-in or custom group membership that satisfies exactly this task, and nothing else?"

---

## 2. Real-World Enterprise Use Case

In the Bhatt.com environment, **bh1011 (Sanjay Patil, IT Director)** oversees the entire IT function — but that does not mean bh1011 should hold Domain Admins membership day-to-day. In a real banking or enterprise environment, this exact anti-pattern (IT Director or senior IT staff parked permanently in Domain Admins "because they're senior") is one of the most commonly cited findings in SOX, PCI-DSS, and internal audit reports, and it's a frequent root-cause factor in ransomware case studies (e.g., large-scale domain compromises where a single over-privileged, poorly monitored administrator account was the pivot point for domain-wide encryption).

The correct model: bh1011 gets a **separate, dedicated administrative account** (which you'll build formally in Day 12 — Privileged Account Management) that is added to Domain Admins *only* when performing genuinely forest/domain-scoped work, while bh1011's day-to-day account (and the day-to-day accounts of bh1013 Kiran Sharma - IT Manager, bh1021 Aditya Kumar - Senior System Administrator, bh1022 Preethi Subramaniam - Senior IT Engineer) operate through delegated OU permissions scoped to exactly what their role requires — password resets, computer object management, group membership changes within IT's OU — without ever touching Domain Admins.

This lab establishes the **audit baseline**: documenting exactly who currently holds membership in each built-in privileged group in Bhatt.com, so that Day 9's delegation model has a clean "before" state to compare against.

---

## 3. Detailed Step-by-Step Procedure

### Step 1: Enumerate current membership of all built-in privileged groups

**On DC01**, open **Start → Windows PowerShell (Run as Administrator)**.

```powershell
$privilegedGroups = @(
    "Enterprise Admins",
    "Domain Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators"
)

foreach ($group in $privilegedGroups) {
    Write-Host "`n=== $group ===" -ForegroundColor Cyan
    try {
        Get-ADGroupMember -Identity $group -ErrorAction Stop |
            Select-Object Name, SamAccountName, objectClass |
            Format-Table -AutoSize
    }
    catch {
        Write-Host "  Group not found or query failed: $_" -ForegroundColor Yellow
    }
}
```

**Expected Result/Verification:**
Output should show `Administrator` (built-in) as the sole member of Domain Admins, Enterprise Admins, and Schema Admins in a fresh lab build. If any `bh10xx` account appears in these groups without a documented reason, that's a finding to remediate. Administrators (BUILTIN) will show Domain Admins and Enterprise Admins nested inside it — this is default AD behavior, not a misconfiguration.
```
```
### Step 2: Export the privileged group audit to a permanent record

```powershell
$auditPath = "C:\IAM-Scripts\Logs\PrivilegedGroups-Audit-$(Get-Date -Format 'yyyy-MM-dd').txt"

$output = foreach ($group in $privilegedGroups) {
    "=== $group ==="
    try {
        Get-ADGroupMember -Identity $group -ErrorAction Stop |
            Select-Object Name, SamAccountName, objectClass |
            Format-Table -AutoSize |
            Out-String
    }
    catch {
        "  Group not found or query failed: $_"
    }
    ""
}

$output | Out-File -FilePath $auditPath -Encoding UTF8
Write-Host "Audit exported to $auditPath" -ForegroundColor Green
```

**Expected Result/Verification:**
Run `Get-Content $auditPath` and confirm the file contains all 8 group sections with membership listings. This file becomes your baseline — in Day 21 (Incident Response), you'll compare a live snapshot against this baseline to detect unauthorized privilege escalation.

---

### Step 3: Identify indirect/nested privileged membership (the blind spot most admins miss)

Direct membership checks miss nested groups. A user added to a custom group that itself was accidentally nested inside Domain Admins would be invisible to a naive check.

```powershell
# Recursive check - does any G-* or DL-* group in Bhatt.com have privileged nesting?
$allGroups = Get-ADGroup -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" -Properties MemberOf

foreach ($grp in $allGroups) {
    $memberOfNames = $grp.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }
    $privilegedMatch = $memberOfNames | Where-Object { $privilegedGroups -contains $_ }
    if ($privilegedMatch) {
        Write-Host "FINDING: $($grp.Name) is nested inside privileged group(s): $privilegedMatch" -ForegroundColor Red
    }
}

Write-Host "Nested privilege scan complete." -ForegroundColor Green
```

**Expected Result/Verification:**
In the current Bhatt.com environment, this should return **no findings** — none of your `G-*` or `DL-*` groups should be nested inside any built-in privileged group. If this ever returns a result in a real environment, it represents a critical, often-overlooked escalation path (an attacker who compromises a seemingly low-privilege custom group inherits Domain Admins rights transitively).

---

### Step 4: Document the Least Privilege attack surface finding for IT leadership

**Manually create** `C:\IAM-Docs\Day8-PrivilegedGroups-AttackSurface.txt` and record:

```
BHATT.COM — PRIVILEGED GROUP ATTACK SURFACE ANALYSIS
Date: <today's date>
Performed by: IAM Architect (bootcamp exercise)

FINDING 1: Domain Admins / Enterprise Admins / Schema Admins currently contain
only the built-in Administrator account. This is the correct baseline state.

FINDING 2: No custom G-* or DL-* groups are nested inside built-in privileged
groups. No indirect escalation path exists via group nesting.

FINDING 3: bh1011 (IT Director), bh1013 (IT Manager), bh1021/bh1022
(Senior IT staff) currently have NO elevated AD rights beyond standard
domain user — this is a Least Privilege gap, not a strength, because it
means they cannot yet perform even basic delegated administrative tasks
(e.g., password resets for their own department). This gap will be
resolved via OU Delegation of Control in Day 9, NOT via Domain Admins
membership.

RECOMMENDATION: Proceed to Day 9 (OU Delegation) to grant IT staff
task-scoped rights within their own OU, preserving Least Privilege while
enabling operational capability.
```

**Expected Result/Verification:**
File exists on disk and accurately reflects the current state. This document becomes the "before" artifact you'll reference when Day 9 grants delegated rights — proving the change was deliberate, scoped, and audited rather than ad hoc.

---

## 4. Interview-Prep Q&A

**Q1: "Why is it considered a security anti-pattern for IT administrators to use their Domain Admin account for everyday tasks like checking email or browsing the web, even if they're careful?"**

**Model Answer:** The risk isn't about carelessness — it's about credential exposure surface. Every interactive logon caches credential material (NTLM hash, and Kerberos TGT/session keys) in the LSASS process memory of the machine being used. A standard workstation, even one used carefully, is a far less hardened environment than a Domain Controller or a dedicated Privileged Access Workstation — it has a browser, email client, and general-purpose software installed, all of which expand the attack surface for credential-theft tooling like Mimikatz. If that workstation is ever compromised — via phishing, a malicious browser extension, or an unpatched vulnerability — the attacker doesn't need to compromise the Domain Admin account directly; they extract it from memory the moment it authenticates. Because Domain Admins membership implicitly grants control over the krbtgt account and therefore the entire Kerberos trust boundary, that single credential theft event can lead to a Golden Ticket attack, giving the attacker persistent, domain-wide impersonation rights that survive password resets. This is why the industry standard is separation of duties: a distinct, tightly monitored privileged account used only from hardened PAWs for genuinely domain-scoped tasks, while daily operational work is done through least-privilege delegated rights on a standard account.

**Q2: "What is the difference between direct and nested (transitive) group membership in the context of privileged access, and why does it matter for an access review?"**

**Model Answer:** Direct membership means an account is explicitly listed as a member of a group — visible immediately via a tool like `Get-ADGroupMember`. Nested (transitive) membership occurs when a group is itself added as a member of another group, meaning every member of the child group inherits the parent group's rights without being directly listed anywhere on the parent. This matters enormously for privileged access reviews because a naive audit that only checks direct membership of, say, Domain Admins can completely miss an escalation path: if a seemingly innocuous custom group like `G-Finance-Analysts` were accidentally nested inside Domain Admins (through a misconfiguration or a deliberate attack), every Finance Analyst would silently inherit Domain Admin rights, and a shallow audit would never surface it. A proper access review has to walk the group membership graph recursively — checking not just "who is a direct member of this privileged group" but "what groups are members of this group, and are any of those, in turn, unexpectedly privileged." This is exactly the blind spot that tools like BloodHound are built to visualize at scale, and it's why Step 3 of today's lab specifically performed a recursive nesting check rather than relying on direct membership alone.

---

## 5. Overall Progress Tracker

**Phase 1: Foundational Identity Lifecycle & Access Control** — ✅ Complete (Days 1–7)
**Phase 2: Privileged Access, Delegation & Tiering** — In Progress

```
[████████░░░░░░░░░░░░░░░░░░░░] 26.7% Complete (8/30 days)
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
| **8** | **Least Privilege Deep Dive — Privileged Groups & Attack Surface** | ✅ |
| 9 | OU Delegation of Control | ⬜ |
| 10 | RBAC Design & Access Matrix Documentation | ⬜ |
| 11 | Microsoft Tiering Model (Tier 0/1/2) | ⬜ |
| 12 | Privileged Account Management | ⬜ |
| 13 | LAPS Deployment | ⬜ |
| 14 | JIT Access Concepts & Time-Bound Elevation | ⬜ |
| 15 | Phase 2 Capstone | ⬜ |

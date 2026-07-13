# DAY 12 LAB — Privileged Account Management: Dedicated Admin Accounts, Protected Users, and Logon Path Enforcement

---

## 1. Core Concept Overview

### 1.1 The "One Person, Two Identities" Principle — Mechanically, Not Just Procedurally

Day 11 built the *architecture* of tiering — OU structure, an empty `G-Tier0-Admins` group, and GPOs enforcing where Tier 0 credentials can and cannot authenticate. But that architecture is inert without solving the question Day 8 first raised and left open: **what account actually gets Tier 0 membership?**

The naive answer — "give bh1011's existing account Domain Admin rights when needed" — recreates the exact credential-caching risk Day 8 described, because bh1011's day-to-day account is *also* the account used to check email, browse the intranet, and log on to Computer-01 for routine work. The moment that single account touches both a Tier 2 workstation *and* Tier 0 resources, tiering is architecturally defeated regardless of how well the GPOs are built — you cannot deny-logon a Tier 0 asset to an account that also needs Tier 2 access for its day job.

The resolution is **identity separation, not permission separation**: bh1011 (Sanjay Patil) retains his standard user account (`bh1011`) for all day-to-day work — email, file access, helpdesk tickets — with zero elevated rights. A **second, entirely distinct account object** — today we'll build `adm-bh1011` — exists solely for genuinely Tier 0 tasks (domain-wide GPO changes, schema-adjacent operations, DC administration) and is *never* used for anything else. Two accounts, one human, two completely separate credential lifecycles, two completely separate logon paths. This is the on-premises equivalent of what commercial PAM platforms (CyberArk, BeyondTrust, Delinea) automate through credential vaulting and just-in-time checkout — we are building the underlying account architecture that those tools would otherwise manage for us.

**Why this specific decision matters at scale:** if every senior IT staff member (bh1011, bh1013, bh1021, bh1022) got a dedicated Tier 0 account "to be safe," we'd be back to privilege sprawl — just with cleaner-looking account names. The correct design principle is **Tier 0 membership should be minimal by headcount**, reserved only for the individuals whose job function genuinely requires domain/forest-wide authority. In Bhatt.com, that's bh1011 alone — Day 9's delegation already gives bh1013 (via `G-ITManagers-OUAdmin`) and the Day 9 Helpdesk group everything they need for their actual job functions without touching Tier 0 at all. Today's lab deliberately creates exactly **one** dedicated admin account, not four, and the reasoning for that scoping decision is itself a governance artifact we'll document.

### 1.2 The Protected Users Security Group — Mechanism, Not Just Effect

`Protected Users` is a built-in domain-local security group (introduced in Windows Server 2012 R2, functional from any DC in the domain running Server 2012 or later) that doesn't grant *any* permissions — unlike every group we've built so far, it has an empty ACL footprint. Instead, membership triggers **behavioral changes enforced by the authentication stack itself** the moment a member account authenticates. This is a fundamentally different control category from anything we've configured in Days 1–11: it's not access control, it's *authentication protocol hardening applied per-account*.

Specifically, membership in Protected Users changes four independent behaviors, each defeating a specific, named attack technique:

**(a) NTLM authentication is disabled entirely for the account.** The account cannot authenticate via NTLM to *any* resource, even if NTLM is the only protocol the target server supports — Kerberos becomes mandatory. **Attack defeated:** Pass-the-Hash. PtH works by extracting an NTLM hash from memory and replaying it directly against a target without ever knowing the plaintext password. If NTLM is categorically unavailable for the account, a stolen NTLM hash for a Protected Users member is worthless — there's no protocol left that will accept it.

**(b) Kerberos long-term keys are never cached on the client.** Under normal Windows credential caching, after a successful logon, the machine retains the user's Kerberos long-term key (derived from the password) in LSASS memory to support silent re-authentication (e.g., resuming from sleep). For Protected Users members, this caching is suppressed. **Attack defeated:** offline/cached credential extraction. If a Tier 0 account somehow *did* touch a lower-tier machine (defense-in-depth against the Day 11 GPO failing or being misconfigured), there is no long-term key sitting in memory for Mimikatz to scrape — this is a second, independent layer behind the deny-logon GPO, not a replacement for it.

**(c) Kerberos TGT lifetime is capped and non-renewable — default 4 hours, versus the domain default of 10 hours renewable up to 7 days.** Once issued, the ticket cannot be renewed; the account must re-authenticate against a DC (interactively, with the password) to get a new one. **Attack defeated:** Golden Ticket / Pass-the-Ticket persistence. Even if an attacker somehow captures a Protected Users member's TGT, its usable window is bounded to a maximum of 4 hours and cannot be extended — compare this to a standard account's ticket, renewable for up to a week without the user ever re-entering a password.

**(d) The account cannot be used as the source of Kerberos constrained or unconstrained delegation, and DES/RC4 encryption types are disabled — AES is enforced.** **Attacks defeated:** delegation abuse (an attacker tricking a delegation-enabled service into impersonating the privileged account against a third resource) and Kerberoasting-adjacent downgrade attacks that rely on requesting weaker RC4-encrypted service tickets to crack offline more easily.

**The critical operational trade-off — stated honestly, not glossed over:** because long-term keys are never cached (point b) and TGTs cannot be renewed (point c), a Protected Users account has **zero resilience to DC unavailability**. If DC01 is unreachable when `adm-bh1011`'s 4-hour ticket expires, the account simply cannot authenticate anywhere — there's no cached fallback. In a single-DC lab environment like Bhatt.com, this is an accepted risk *because* Tier 0 accounts should rarely be in active use anyway; in a real multi-DC enterprise, this trade-off is why Protected Users deployment is usually paired with guaranteed DC high availability for the sites where Tier 0 admins operate. This is exactly the kind of nuance a senior interviewer will probe — "what breaks" is as important as "what's protected."

### 1.3 Logon Workstations — A Complementary, Independent Enforcement Layer

Day 11's GPOs enforce logon restriction via **User Rights Assignment** (Deny log on locally/RDP/network), which is evaluated by the target machine's local security subsystem at logon time. There is a second, older, and architecturally distinct mechanism: the `userWorkstations` attribute on the account object itself (configured via "Log On To" in ADUC, or `-LogonWorkstations` in PowerShell). This restriction is enforced **at authentication time by the Netlogon service (for NTLM) and by the KDC (for Kerberos)**, checking the client-presented workstation name against the account's allow-list *before* a ticket or authentication token is even issued.

The distinction matters operationally: GPO-based deny-logon rights are enforced *locally by the target machine* and apply based on OU/GPO linkage — if a new machine gets joined to the domain and lands in an OU the GPO doesn't cover, the restriction silently doesn't apply. `userWorkstations` is enforced *centrally, on the account itself*, regardless of which OU any given machine sits in — it's a second, independent control that doesn't depend on correct GPO linkage scope. Today's lab uses both, deliberately, as defense-in-depth: if one enforcement layer has a gap (exactly the kind of gap we're about to find with the newly added Computer-02/03), the other still holds the line.

### 1.4 Break-Glass Accounts — Conceptual Note (Not Implemented Today)

A mature PAM design also includes a small number of **break-glass (emergency access) accounts** — credentials sealed (physically or via a vault) for use only when normal Tier 0 access paths are unavailable (e.g., all designated admin accounts are locked out, or Protected Users' 4-hour ticket expiry has stranded every admin during a DC outage). These accounts are typically excluded from Protected Users specifically *because* Protected Users' lack of credential caching would defeat their purpose as a last resort during DC unavailability, and their use is required to trigger mandatory incident review. Bhatt.com does not implement a break-glass account in this lab — it's flagged here as a conceptual gap for architectural completeness, and is a natural candidate for revisiting during Phase 3 (Incident Response, Days 16–22).

---

## 2. Real-World Enterprise Use Case

Privileged Account Management is one of the most heavily scrutinized control areas in banking IT audits, precisely because the failure mode is catastrophic and well-documented: nearly every large-scale ransomware case study involving full domain encryption traces back to a single privileged credential — often a *shared* or *daily-use* admin account — being harvested from a compromised endpoint, then used to move laterally with zero friction because no logon-path segmentation existed. Regulatory frameworks relevant to Indian banking (RBI's Cyber Security Framework for Banks) and international equivalents (PCI-DSS Requirement 7/8, FFIEC IT Handbook) explicitly require documented separation between standard and privileged access, and increasingly expect demonstrable technical controls — not just policy documents — proving that separation is enforced, not merely requested.

Commercial PAM platforms (CyberArk Privileged Access Manager, BeyondTrust Password Safe, Delinea Secret Server) automate exactly what we're building manually today: **credential vaulting** (the admin account's password is never known to the human, checked out on demand and rotated after use), **session isolation** (privileged sessions are proxied through a jump host, never initiated directly from the admin's daily workstation), and **just-in-time elevation** (Tier 0 group membership is granted for a bounded window, not standing — this is exactly what Day 14, JIT Access, will build). What we're doing in this lab — dedicated admin account, Protected Users, logon-path restriction — is the **underlying AD-native control set** that these commercial tools sit on top of and orchestrate. Understanding this manually-built foundation is precisely what separates a GAO Analyst who can *evaluate* whether a CyberArk deployment is actually configured correctly from one who can only confirm the tool is "installed."

For Bhatt.com specifically: bh1011 (Sanjay Patil, IT Director) is the only individual whose role genuinely requires forest/domain-wide authority — schema decisions, trust configuration, GPO changes at the domain root, DC-level administration. bh1013, bh1021, and bh1022 all have sufficient delegated capability from Day 9 to perform their actual job functions without ever needing Tier 0 access, and giving them dedicated admin accounts "just in case" would be the privilege-sprawl anti-pattern Day 8 explicitly warned against.

---

## 3. Detailed Step-by-Step Procedure

### Step 1: Document the Tier 0 account provisioning decision *before* creating anything

This decision precedes any AD change and is itself an auditable governance artifact — provisioning a Tier 0 account without a documented justification is a finding in its own right, even if the technical controls are perfect.

**Manually create** `C:\IAM-Docs\Day12-Tier0AccountJustification.txt`:

```
BHATT.COM — TIER 0 DEDICATED ACCOUNT PROVISIONING DECISION
Date: <today's date>

DECISION: One (1) dedicated Tier 0 administrative account will be
provisioned: adm-bh1011, linked to bh1011 (Sanjay Patil, IT Director).

JUSTIFICATION: bh1011 is the only individual in Bhatt.com whose
documented job function requires forest/domain-wide administrative
authority (DC administration, domain-root GPO changes, future
schema/trust operations). bh1013 (IT Manager), bh1021, bh1022
(Senior IT staff) all hold sufficient delegated rights via
G-ITManagers-OUAdmin (Day 9) and G-IT-Support (Day 3/9) to perform
their actual job functions without Tier 0 membership.

REJECTED ALTERNATIVE: Provisioning dedicated admin accounts for all
four senior IT staff was considered and rejected — this would
reproduce the privilege-sprawl anti-pattern identified in Day 8
(multiple standing Domain-Admin-equivalent accounts with no
operational necessity for the breadth of access granted).

REVIEW CADENCE: This justification should be re-evaluated at each
quarterly access recertification (Day 20 process) to confirm the
Tier 0 account count remains minimal and role-justified.
```

**Expected Result/Verification:** File exists on disk and is dated prior to any account creation step below — establishing a documented "decide first, provision second" sequence, which is the correct order of operations for any privileged access grant in a governed environment.

---

### Step 2: Create the dedicated Tier 0 account object

**On DC01**, open **Windows PowerShell (Run as Administrator)**.

```powershell
$adminPassword = ConvertTo-SecureString "T!0Adm-Bh1011-9x2mK7pQ" -AsPlainText -Force

New-ADUser -Name "adm-bh1011" `
    -SamAccountName "adm-bh1011" `
    -UserPrincipalName "adm-bh1011@Bhatt.com" `
    -DisplayName "ADMIN - Sanjay Patil (Tier0)" `
    -Description "Tier0 Privileged Admin Account - Linked to bh1011 (Sanjay Patil, IT Director) - EmployeeID:1011 - DO NOT USE FOR DAILY TASKS" `
    -EmployeeID "1011" `
    -Path "OU=Accounts,OU=Tier0-Admin,OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -AccountPassword $adminPassword `
    -Enabled $true `
    -ChangePasswordAtLogon $false `
    -CannotChangePassword $false `
    -PasswordNeverExpires $false
```

**Design reasoning behind each parameter — this is the depth that matters:**

- **`-EmployeeID "1011"`** — we deliberately stamp the *same* EmployeeID as bh1011's standard account onto this admin account. This is the traceability anchor: a future audit query (`Get-ADUser -Filter {EmployeeID -eq "1011"}`) will return *both* accounts, making the human-to-privileged-account linkage queryable rather than relying on naming convention alone (which could drift or be misread).
- **`-SamAccountName "adm-bh1011"`** — this is a deliberate, minimal extension of the v2.0 naming convention: `adm-` prefix + the existing `bh<EmployeeID>` pattern, rather than inventing a parallel scheme. This keeps the convention internally consistent and immediately greppable — any account starting with `adm-` is unambiguously a Tier 0 privileged account, and the suffix still resolves to the correct EmployeeID.
- **`-Description`** contains an explicit, human-readable "DO NOT USE FOR DAILY TASKS" warning — this is not just documentation politeness; it's the first line of defense against **credential misuse drift**, where an admin account starts getting used for convenience over time because nothing in the account itself discourages it.
- **`-PasswordNeverExpires $false`** — intentionally, Tier 0 accounts should have *stricter* password rotation than standard accounts, not looser. We'll apply the existing strict PSO in Step 4 rather than exempting this account from expiry.
- **We did NOT set `-ChangePasswordAtLogon $true`** — unlike a standard Joiner flow, a Tier 0 admin account's initial password should be handled via a controlled handoff (in a real environment, immediately rotated into a PAM vault), not left as a "change on first use" self-service flow that could be intercepted or delayed.

**Expected Result/Verification:**
```powershell
Get-ADUser -Identity "adm-bh1011" -Properties EmployeeID, Description, DistinguishedName |
    Select-Object SamAccountName, UserPrincipalName, EmployeeID, Description, DistinguishedName
```
Output confirms the account exists in `OU=Accounts,OU=Tier0-Admin,OU=BHATT-CORP,DC=Bhatt,DC=com`, with `EmployeeID` set to `1011` (matching bh1011, queryable as a linkage), and the warning description correctly stamped.

---

### Step 3: Harden the account against delegation and enforce AES-only Kerberos encryption

Even though Protected Users (Step 4) will enforce most of this dynamically, we apply explicit account-level hardening as defense-in-depth — if the account is ever accidentally removed from Protected Users during a future change, these settings persist independently.

```powershell
# Mark account as sensitive and cannot be delegated - blocks it from being used
# as an impersonation target even by legitimately delegation-enabled services
Set-ADAccountControl -Identity "adm-bh1011" -AccountNotDelegated $true

# Restrict supported Kerberos encryption types to AES256 and AES128 only
# (value 24 = AES128 [8] + AES256 [16] bitmask; excludes DES and RC4)
Set-ADUser -Identity "adm-bh1011" -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
```

**Why both settings, given Protected Users will enforce similar behavior dynamically:** `AccountNotDelegated` and `msDS-SupportedEncryptionTypes` are **static account attributes**, evaluated by the KDC independent of group membership at the moment a ticket is requested. Protected Users' equivalent protections are **dynamic, membership-dependent behaviors** — if the account is ever temporarily removed from Protected Users (e.g., during a group membership audit or a misconfigured recertification action from Day 20's future process), these two settings continue enforcing regardless. This is the layered-control principle applied to a single account, not just across accounts.

**Expected Result/Verification:**
```powershell
Get-ADUser -Identity "adm-bh1011" -Properties AccountNotDelegated, msDS-SupportedEncryptionTypes |
    Select-Object SamAccountName, AccountNotDelegated, msDS-SupportedEncryptionTypes
```
Output confirms `AccountNotDelegated : True` and `msDS-SupportedEncryptionTypes : 24`.

---

### Step 4: Populate Protected Users, G-Tier0-Admins, and extend the existing strict PSO

```powershell
# Populate the Tier0 group created empty in Day 11
Add-ADGroupMember -Identity "G-Tier0-Admins" -Members "adm-bh1011"

# Add to the built-in Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members "adm-bh1011"

# Extend Day 5's strict PSO to cover this account - reusing the existing
# G-PSO-Privileged-Strict group rather than building a new PSO, since its
# policy (16-char min, 30-day max age, 3-attempt lockout) is exactly
# appropriate for a Tier0 admin account
Add-ADGroupMember -Identity "G-PSO-Privileged-Strict" -Members "adm-bh1011"
```

**Why we reuse `G-PSO-Privileged-Strict` rather than building a fourth PSO:** Day 5 already established a fine-grained password policy precisely suited to this use case. Building a redundant, near-identical PSO would violate the same "role explosion" anti-pattern discussed in Day 10 — if two policies enforce nearly identical rules, maintaining both creates unnecessary governance overhead with no security benefit. Extending an existing, well-understood control is the correct engineering decision here.

**Expected Result/Verification:**
```powershell
Get-ADGroupMember -Identity "G-Tier0-Admins" | Select Name, SamAccountName
Get-ADGroupMember -Identity "Protected Users" | Select Name, SamAccountName
Get-ADUserResultantPasswordPolicy -Identity "adm-bh1011"
```
First command confirms `adm-bh1011` is now the sole member of `G-Tier0-Admins` (populated for the first time since Day 11). Second confirms Protected Users membership. Third returns the `PSO-Privileged-Strict` policy object as the resultant policy for this account (16-char minimum, 30-day max age, 3-attempt lockout) — confirming the correct PSO is now governing, per the precedence rules established in Day 5.

---

### Step 5: Apply the Logon Workstations restriction (independent enforcement layer)

```powershell
Set-ADUser -Identity "adm-bh1011" -LogonWorkstations "DC01"
```

**Expected Result/Verification:**
```powershell
Get-ADUser -Identity "adm-bh1011" -Properties LogonWorkstations | Select SamAccountName, LogonWorkstations
```
Output confirms `LogonWorkstations : DC01`. This means even if a future GPO misconfiguration accidentally omitted a machine from the Day 11 deny-logon scope, `adm-bh1011` still could not authenticate to it — the KDC and Netlogon service will reject the authentication attempt at the account level, independent of any GPO.

---

### Step 6: Locate and correctly place the newly joined Computer-02 and Computer-03 — closing a real GPO scope gap

This step addresses a genuine, common real-world gap: newly domain-joined machines land in the default `Computers` container by default, **not** under any OU with GPOs linked — meaning Day 11's `GPO-Tier2-DenyTier0Logon-Workstations` (linked only to `OU=Computers,OU=Finance`) does **not** currently apply to Computer-02 or Computer-03.

```powershell
# Confirm current location of the newly joined machines
Get-ADComputer -Identity "Computer-02" -Properties DistinguishedName | Select Name, DistinguishedName
Get-ADComputer -Identity "Computer-03" -Properties DistinguishedName | Select Name, DistinguishedName
```

**Expected Result/Verification:** Both will almost certainly show `CN=Computer-02,CN=Computers,DC=Bhatt,DC=com` and `CN=Computer-03,CN=Computers,DC=Bhatt,DC=com` — the default container, outside any OU structure and therefore outside all GPO linkage built so far.

**Remediate by moving both into the IT department's Computers OU** (they are IT-managed server assets, not end-user workstations, but Bhatt.com's OU model doesn't yet have a dedicated server tier — per Day 11's disclosed Tier 1 limitation, we place them under IT\Computers as the closest correct fit):

```powershell
Move-ADObject -Identity (Get-ADComputer -Identity "Computer-02").DistinguishedName `
    -TargetPath "OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com"

Move-ADObject -Identity (Get-ADComputer -Identity "Computer-03").DistinguishedName `
    -TargetPath "OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com"
```

**Link the existing Day 11 Tier 2 GPO to this OU** so the deny-logon restriction now covers all three client machines, not just Computer-01:

```powershell
$itComputersOU = "OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com"
$gpo = Get-GPO -Name "GPO-Tier2-DenyTier0Logon-Workstations"
New-GPLink -Guid $gpo.Id -Target $itComputersOU
```

**Expected Result/Verification:**
```powershell
Get-ADComputer -Filter "Name -like 'Computer-0*'" -Properties DistinguishedName | Select Name, DistinguishedName
Get-GPInheritance -Target $itComputersOU | Select-Object -ExpandProperty GpoLinks
```
First command confirms Computer-02 and Computer-03 now show `OU=Computers,OU=IT,OU=BHATT-CORP,DC=Bhatt,DC=com` in their DN. Second confirms `GPO-Tier2-DenyTier0Logon-Workstations` is now linked there. **This is a genuine gap that would have silently persisted** if we'd only validated the tiering model against Computer-01 (the machine that existed when the GPO was built) — a good illustration of why environment changes require re-validating existing controls, not just extending new ones.

---

### Step 7: Validate enforcement — negative test across all three client machines

**Attempt interactive logon as `adm-bh1011` on Computer-01, Computer-02, and Computer-03** (via console or RDP, using the credentials from Step 2).

**Expected Result/Verification:** All three attempts must fail with **"The sign-in method you're trying to use isn't allowed"** (the standard Windows message for a Deny-Logon-Locally right violation) — confirming the Day 11 GPO (now correctly scoped after Step 6) and the Step 5 `LogonWorkstations` restriction are both independently blocking access. If Computer-02 or Computer-03 had *not* been remediated in Step 6, `LogonWorkstations` alone would still have blocked the attempt — demonstrating why the two-layer control design matters in practice, not just in theory.

**Then, log on to DC01 directly as `adm-bh1011`** — this should succeed, confirming the account functions correctly at its intended Tier 0 boundary.

```powershell
# From DC01, after successful logon as adm-bh1011, verify Protected Users
# effects are actually active on the resulting ticket
klist
```

**Expected Result/Verification:** `klist` output shows the issued TGT with a **Ticket flags** field lacking `renewable`, and an expiry timestamp approximately 4 hours from logon time — confirming Protected Users' non-renewable, capped-lifetime enforcement is live for this session, not just configured on paper.

---

### Step 8: Update the privileged group audit baseline (linking back to Day 8)

```powershell
$auditPath = "C:\IAM-Scripts\Logs\PrivilegedGroups-Audit-$(Get-Date -Format 'yyyy-MM-dd').txt"

"=== G-Tier0-Admins (Day 12 update) ===" | Out-File -FilePath $auditPath -Append -Encoding UTF8
Get-ADGroupMember -Identity "G-Tier0-Admins" | Select Name, SamAccountName |
    Format-Table -AutoSize | Out-String | Out-File -FilePath $auditPath -Append -Encoding UTF8

"=== Protected Users (Day 12 update) ===" | Out-File -FilePath $auditPath -Append -Encoding UTF8
Get-ADGroupMember -Identity "Protected Users" | Select Name, SamAccountName |
    Format-Table -AutoSize | Out-String | Out-File -FilePath $auditPath -Append -Encoding UTF8
```

**Expected Result/Verification:** The Day 8 audit baseline file now has a Day 12 addendum showing `adm-bh1011` as the sole member of both `G-Tier0-Admins` and `Protected Users` — closing the loop between the attack-surface baseline established in Day 8 and the actual privileged account now provisioned against that baseline.

---

## 4. Interview-Prep Q&A

**Q1: "Walk me through exactly what happens differently, at the protocol level, when a Protected Users group member authenticates, compared to a standard domain account — and explain a scenario where Protected Users membership could actually cause a production outage."**

**Model Answer:** At the protocol level, four things change simultaneously. First, NTLM is removed as a viable authentication mechanism entirely — the account must use Kerberos, and if it attempts to reach a resource that only supports NTLM (some legacy applications, certain non-Windows SMB implementations, or resources accessed by IP address rather than name, which forces NTLM fallback because Kerberos requires an SPN resolvable via the name used), authentication fails outright rather than degrading gracefully. Second, the client no longer caches the account's Kerberos long-term key in LSASS after logon — this is what normally allows a laptop to authenticate to cached resources or resume sessions without hitting a DC every time. Third, the initial TGT issued is capped at a non-renewable lifetime, four hours by default, versus the standard 10-hour renewable-to-7-days ticket — the account must fully re-authenticate against a live DC when that expires, with no renewal path. Fourth, DES and RC4 encryption types are excluded from what the KDC will negotiate for this account, and the account cannot be used as a target of constrained or unconstrained Kerberos delegation. 

For the outage scenario: imagine a Protected Users admin account is used to run a long-lived interactive session — say, a multi-hour AD migration task — and partway through, network connectivity to the only reachable DC is interrupted (a WAN link flap, or in a single-DC environment like ours, the DC itself becoming briefly unavailable for patching). A standard account would likely continue operating using its cached credentials and existing renewable ticket. A Protected Users account has no cached credential to fall back on, and once its four-hour ticket expires mid-task with no DC reachable, the session is authentication-dead — the admin cannot even re-authenticate to retry, because there's no long-term key cached locally to build a new AS-REQ from, and the KDC itself is unreachable. This is a real, documented trade-off, which is why Protected Users deployment in production is typically paired with guaranteed high-availability DC access for the sites where Tier 0 work actually happens, or the sensitive task is scheduled to complete well within the ticket lifetime window.

**Q2: "You've provisioned a dedicated Tier 0 admin account, added it to Protected Users, and restricted its logon workstations. A colleague argues this is redundant — 'Protected Users already prevents credential theft, why also bother with GPO deny-logon rights and LogonWorkstations?' How do you respond?"**

**Model Answer:** I'd push back on the premise that Protected Users "prevents credential theft" — it reduces the *exploitability* of certain theft techniques but does nothing to prevent the credential from being *present* on a lower-tier machine in the first place, which is a meaningfully different failure mode. Protected Users' protections — no NTLM, no cached long-term key, short non-renewable TGTs — all activate *after* the account has already authenticated somewhere. If the deny-logon GPO and LogonWorkstations restriction didn't exist, nothing would stop someone from actually logging into Computer-01 with `adm-bh1011`'s credentials in the first place — Protected Users doesn't prevent the logon attempt, it constrains what artifacts that logon leaves behind and how long they remain useful. That's a real reduction in risk, but it's not the same as preventing the exposure event entirely.

There's also a defense-in-depth argument specific to *failure modes*, not just theoretical layering: GPO-based deny-logon rights are enforced locally by the target machine and depend entirely on correct OU/GPO linkage scope — which we just demonstrated firsthand in this very lab, when Computer-02 and Computer-03 landed outside the GPO's scope by default after being domain-joined, and would have been silently unprotected if we hadn't caught it. LogonWorkstations, by contrast, is enforced centrally by the KDC and Netlogon service based on the account object itself, completely independent of which OU any given machine happens to be in. If one layer has a scope gap — exactly the gap we found — the other still holds. Relying on Protected Users alone leaves the actual logon event completely unconstrained; relying on GPO alone leaves you exposed to exactly the kind of OU-placement gap we just fixed. Using all three together means a single misconfiguration in any one layer doesn't result in a full control failure — which is the entire point of defense-in-depth as a design discipline, not just a checklist item.

---

## 5. Overall Progress Tracker

**Phase 1: Foundational Identity Lifecycle & Access Control** — ✅ Complete (Days 1–7)
**Phase 2: Privileged Access, Delegation & Tiering** — In Progress

```
[████████████░░░░░░░░░░░░░░░░] 40.0% Complete (12/30 days)
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
| **12** | **Privileged Account Management — Dedicated Admin Accounts, Protected Users** | ✅ |
| 13 | LAPS Deployment | ⬜ |
| 14 | JIT Access Concepts & Time-Bound Elevation | ⬜ |
| 15 | Phase 2 Capstone | ⬜ |

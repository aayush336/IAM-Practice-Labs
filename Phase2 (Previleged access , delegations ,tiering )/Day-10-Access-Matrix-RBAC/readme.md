# DAY 10 LAB — RBAC Design & Access Matrix Documentation

---

## 1. Core Concept Overview

Role-Based Access Control (RBAC) is the discipline of mapping **job functions** to **access entitlements** in a formal, documented way — so that "what can this person do" is answered by looking up their role in a matrix, not by reverse-engineering their accumulated group memberships one by one. Everything you've built since Day 3 (AGDLP groups) and Day 9 (OU delegation) *is* RBAC in practice — today's lab is about making that implicit model **explicit, documented, and auditable**, which is the artifact a bank's access governance function (and a GAO Analyst specifically) actually reviews.

**Why RBAC matters as a governance discipline, not just a technical pattern:**

1. **Entitlement traceability.** Without a formal access matrix, answering "why does bh1024 have Reset Password rights?" requires manually tracing group memberships and OU ACLs across the directory. With an access matrix, the answer is a single lookup: bh1024 → IT Support role → `G-Helpdesk-PasswordReset` → documented entitlement. This traceability is precisely what SOX ITGC (IT General Controls) testing and internal/external audits demand — access must be attributable to a *documented business reason*, not just a technical possibility.

2. **Separation of Duties (SoD) enforcement.** A well-built matrix surfaces toxic combinations before they become incidents — for example, a role that can both *request* and *approve* a payroll change, or a role with both Helpdesk password-reset rights and Finance payroll access. SoD conflicts are far easier to catch by scanning a matrix than by auditing live AD state after the fact.

3. **Joiner/Mover/Leaver automation input.** Your `Invoke-JoinerProvisioning.ps1` script (built Day 2, refined through the bootcamp) currently derives group assignment from `Department` in the CSV. A formal RBAC matrix is what justifies *why* Department X maps to Groups Y and Z — it's the business-rule documentation that sits behind the automation, not a replacement for it.

4. **Recertification baseline.** Day 20 (Access Certification & Recertification) will require comparing *current* group membership against an *expected* baseline per role. Today's matrix is that baseline. Without it, quarterly access reviews devolve into "does this look okay?" gut checks rather than a structured comparison against documented entitlement.

**The RBAC model structure used in enterprise IAM (and in Bhatt.com):**

```
Role Definition → maps to → One or more AD Groups (Global) → nested into → Domain Local Groups → grants → Resource Access
```

A **Role** in this model is not an AD object — it's a documented business concept (e.g., "Finance Analyst," "IT Support Technician") that resolves to a specific, fixed set of Global groups. This indirection matters: if tomorrow "IT Support Technician" needs an additional entitlement, you update the role definition and add the group to every current holder — you don't hunt down individual users one at a time.

**A critical RBAC failure mode this lab guards against — role explosion:** if every minor variation in access needs a new role, you end up with hundreds of near-identical roles that are impossible to govern. The discipline is to define roles at the *job function* level (Finance Analyst) and handle genuine exceptions via a documented, time-bound exception process — not by silently forking a new role.

---

## 2. Real-World Enterprise Use Case

In a bank's IAM governance function, the Access Matrix is one of the first artifacts requested during an internal audit, a regulatory exam, or a SOC 2 / ISO 27001 assessment. The auditor's question is rarely "show me your AD console" — it's "show me the documented mapping between job roles and system entitlements, and prove that current access matches it." A GAO (Governance, Access, and Oversight) Analyst role specifically exists to *own* this artifact: building it, keeping it current as roles evolve, and running periodic reconciliation between the matrix (what *should* be true) and live directory state (what *is* true).

In Bhatt.com, you already have five distinct role clusters across three departments, each with real groups behind them: Finance (Managers, Analysts, Senior Analysts, Payroll Access), IT (Support, IT Managers via Day 9 delegation, Privileged Strict via PSO), and Sales (implicitly, via department membership — no specialized Sales groups have been built yet, which is itself a finding this lab will surface). Today's lab formalizes all of it into one governance document, explicitly including the two delegations built in Day 9 (`G-Helpdesk-PasswordReset`, `G-ITManagers-OUAdmin`) as first-class entitlements — because delegated OU rights are access just as much as group membership is, and a matrix that omits them is incomplete.

---

## 3. Detailed Step-by-Step Procedure

### Step 1: Inventory all current entitlement-granting groups and delegations

**On DC01**, open **Windows PowerShell (Run as Administrator)**.

```powershell
Write-Host "=== Global Groups (Role Layer) ===" -ForegroundColor Cyan
Get-ADGroup -Filter {GroupScope -eq "Global"} -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" |
    Select-Object Name, GroupCategory | Sort-Object Name | Format-Table -AutoSize

Write-Host "`n=== Domain Local Groups (Resource Layer) ===" -ForegroundColor Cyan
Get-ADGroup -Filter {GroupScope -eq "DomainLocal"} -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" |
    Select-Object Name, GroupCategory | Sort-Object Name | Format-Table -AutoSize
```

**Expected Result/Verification:**
Global groups list shows `G-Finance-Managers`, `G-Finance-Analysts`, `G-Finance-SeniorAnalysts`, `G-Finance-PayrollAccess`, `G-IT-Support`, `G-PSO-Privileged-Strict`, `G-PSO-ServiceAccounts`, `G-Helpdesk-PasswordReset`, `G-ITManagers-OUAdmin`. Domain Local groups list shows the five `DL-Finance-*` groups from Day 6. This confirms the full current entitlement inventory before building the matrix.

---

### Step 2: Build the Role-to-Group crosswalk

This is a manual documentation step — the professional judgment layer that no script can replace, because it requires knowing *why* each group exists, not just that it exists.

**Manually create** `C:\IAM-Docs\Day10-RBAC-AccessMatrix.csv` with the following structure:

```csv
RoleName,Department,AD_GlobalGroup,ResourceAccess_via_DL_Group,DelegatedOU_Rights,SoD_Flag
Finance Manager,Finance,G-Finance-Managers,DL-Finance-Share-FullControl,None,None
Finance Analyst,Finance,G-Finance-Analysts,DL-Finance-Share-ReadWrite,None,None
Senior Finance Analyst,Finance,G-Finance-SeniorAnalysts,DL-Finance-Reports-Write,None,None
Payroll Processor,Finance,G-Finance-PayrollAccess,DL-Finance-Payroll-FullControl,None,REVIEW: overlaps with Finance Manager/Director - verify SoD between payroll processing and approval
IT Support Technician,IT,G-IT-Support,DL-Finance-Share-Read,None,None
IT Helpdesk (Password Reset),IT,G-Helpdesk-PasswordReset,None,"Reset Password + Unlock Account on Finance/IT/Sales Users OUs",FLAG: verify no overlap with G-Finance-PayrollAccess membership
IT Manager (OU Admin),IT,G-ITManagers-OUAdmin,None,"Computer object mgmt + group membership mgmt within IT OU only",None
Privileged Strict (Tier),IT,G-PSO-Privileged-Strict,None,None,"FLAG: verify this group's members are also reviewed under Day 11 Tiering model"
Sales Executive,Sales,None documented,None documented,None,"GAP: no dedicated Sales AD group exists yet - Sales staff currently rely on Domain Users default access only"
```

**Expected Result/Verification:**
Open the CSV in Excel or a text editor and confirm all 9 rows are present, with the `SoD_Flag` column populated for the three genuine governance findings this exercise surfaces — including the explicit **Sales gap** (no dedicated Sales group has been built in this lab environment through Day 9, which is a real finding, not an oversight to hide).

---

### Step 3: Reconcile the matrix against live membership (matrix vs. reality check)

```powershell
$roleGroups = @(
    "G-Finance-Managers", "G-Finance-Analysts", "G-Finance-SeniorAnalysts",
    "G-Finance-PayrollAccess", "G-IT-Support", "G-Helpdesk-PasswordReset",
    "G-ITManagers-OUAdmin", "G-PSO-Privileged-Strict"
)

$reconciliation = foreach ($grp in $roleGroups) {
    $members = Get-ADGroupMember -Identity $grp | Select-Object -ExpandProperty SamAccountName
    [PSCustomObject]@{
        Group       = $grp
        MemberCount = $members.Count
        Members     = ($members -join ", ")
    }
}

$reconciliation | Format-Table -AutoSize
$reconciliation | Export-Csv "C:\IAM-Scripts\Logs\Day10-LiveMembership-Reconciliation.csv" -NoTypeInformation
```

**Expected Result/Verification:**
Output table shows live member counts and names per group — e.g., `G-Finance-PayrollAccess` shows bh1001 and bh1010 (2 members). Cross-check this against the matrix: confirm no user appears in both `G-Finance-PayrollAccess` and `G-Helpdesk-PasswordReset` (the SoD flag raised in Step 2) — in the current Bhatt.com state, this check should pass clean since no user holds both.

---

### Step 4: Formally flag and document the Sales entitlement gap

Since the matrix surfaced a real gap (no dedicated Sales groups exist), document it as a finding rather than silently leaving it as an omission.

**Append to** `C:\IAM-Docs\Day10-RBAC-AccessMatrix.csv` findings section, or create a companion file `C:\IAM-Docs\Day10-Findings.txt`:

```
FINDING: Sales department (bh1006, bh1007, bh1012, bh1014, bh1027-1033,
bh1043-1046, bh1050) currently has no dedicated Global or Domain Local
groups. Sales staff operate on Domain Users default access only, with
no documented role-based entitlement structure.

RISK: Without dedicated Sales groups, there is no mechanism to grant or
restrict Sales-specific resource access (e.g., a future Sales-Shared
folder) without either using Domain Users (too broad) or ad hoc
individual ACLs (violates AGDLP and breaks auditability).

RECOMMENDATION: Future lab day should establish G-Sales-Executives,
G-Sales-SeniorExecutives, and G-Sales-Managers following the same
AGDLP pattern as Finance, once a Sales resource requirement emerges.
Logged here as a backlog item, not actioned in this lab.
```

**Expected Result/Verification:**
File exists on disk and the finding is documented with specific affected EmployeeIDs, a clear risk statement, and a scoped recommendation — this is exactly the format a GAO Analyst would use to log a finding in a real access review deliverable.

---

## 4. Interview-Prep Q&A

**Q1: "What is the difference between Role-Based Access Control (RBAC) and simply using Active Directory security groups, and why would an organization need a formal RBAC matrix on top of groups that already exist?"**

**Model Answer:** AD security groups are the *technical mechanism* that enforces access — they're what actually gets checked at authentication/authorization time. RBAC is the *governance layer* on top of that mechanism: a documented, business-approved mapping between job roles and the specific groups (and delegated rights) that constitute that role's access. The distinction matters because groups alone don't answer "why" — you can see that bh1024 is a member of `G-Helpdesk-PasswordReset`, but AD itself doesn't tell you that this membership was deliberately approved as part of the IT Support Technician role definition versus being an artifact of someone forgetting to remove it after a role change. A formal RBAC matrix closes that gap: it's the authoritative source of truth for "what should this role have," which live AD membership is then reconciled against. This is also what makes recertification and audit response tractable — an auditor asking "prove that bh1024's access is appropriate" is answered by pointing to the IT Support Technician row in the matrix and showing the group membership matches, rather than having someone manually justify each entitlement from memory during the audit.

**Q2: "During RBAC matrix design, you discover that one role has entitlements that could enable both initiating and approving the same type of transaction. How do you handle this, and why does it matter?"**

**Model Answer:** This is a Separation of Duties (SoD) conflict, and it needs to be explicitly flagged and investigated rather than resolved unilaterally by an IAM engineer — because whether it's actually a problem depends on business context I may not have (compensating controls like transaction logging and mandatory secondary review might already mitigate it). My process is: first, document the specific overlap precisely — which group or role grants which specific right, and where the conflict actually manifests (e.g., can this role both create a payroll record and approve its disbursement, or is it a narrower overlap like being able to reset a payroll approver's password). Second, flag it in the access matrix as a formal finding with the specific EmployeeIDs or roles involved, rather than quietly fixing it, because SoD remediation often requires a business decision, not just a technical one — for example, splitting a role in two, or accepting the risk with a documented compensating control like mandatory dual-authorization logging. Third, escalate to the control owner (often Internal Audit, Compliance, or a designated risk owner) rather than resolving it myself, since I as the IAM engineer control the technical implementation but not the risk acceptance decision. This is exactly the discipline reflected in today's lab, where the Payroll Processor role was flagged for SoD review rather than silently modified.

---

## 5. Overall Progress Tracker

**Phase 1: Foundational Identity Lifecycle & Access Control** — ✅ Complete (Days 1–7)
**Phase 2: Privileged Access, Delegation & Tiering** — In Progress

```
[██████████░░░░░░░░░░░░░░░░░░] 33.3% Complete (10/30 days)
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
| **10** | **RBAC Design & Access Matrix Documentation** | ✅ |
| 11 | Microsoft Tiering Model (Tier 0/1/2) | ⬜ |
| 12 | Privileged Account Management | ⬜ |
| 13 | LAPS Deployment | ⬜ |
| 14 | JIT Access Concepts & Time-Bound Elevation | ⬜ |
| 15 | Phase 2 Capstone | ⬜ |


---

# Day 2: User Lifecycle Management (JML) — Creation Standards & Attribute Population

## 1. Core Concept Overview
User Lifecycle Management—specifically JML (Joiner-Mover-Leaver)—is the operational backbone of an IAM program. 
* **Naming Convention Standardization:** Enforcing rigid patterns for `sAMAccountName` and `UserPrincipalName` (UPN) to prevent identity collisions and downstream authentication failures.
* **Mandatory Attribute Population:** Ensuring that metadata fields like `manager`, `department`, and `employeeID` are populated at creation. Downstream HRIS systems, automated provisioning engines, and dynamic role assignments depend entirely on this data.
* **Account State Hygiene:** Enforcing credential non-repudiation by defaulting to "User must change password at next logon."

---

## 2. Real-World Enterprise Use Case
In production, failing to enforce strict attribute discipline at the point of onboarding leads to critical downstream workflow failures:
* If the **Manager** attribute is omitted, self-service access request systems fail to route approval notifications.
* If the **Department** attribute is left blank, the identity is excluded from dynamic security groups that provision critical application access or licensing.
* If **Credential Hygiene** is ignored and an admin knows a live password, the organization breaks non-repudiation controls audited under frameworks like SOC2, ISO27001, and NIST 800-53.

---

## 3. Detailed Step-by-Step Procedure

### Naming Convention Standard
* **sAMAccountName:** first initial + last name (lowercase)
* **UPN:** `firstname.lastname@Bhatt.com`
* **Collision Rule:** Append middle initial; else append a sequential integer.
* **Description:** `<Title> - <Department>`

### Step 1: Provisioning the Manager Account
1. In ADUC, navigate to `BHATT-CORP -> Finance -> Users`.
2. Create a new user: **Sarah Connor** (`sarah.connor@Bhatt.com`, sAMAccountName: `sconnor`).
3. Set a temporary password and check **User must change password at next logon**.
4. Set organizational metadata under properties: `Title = Finance Manager`, `Department = Finance`, `Description = Finance Manager - Finance`.

### Step 2: Provisioning the Joiner Account with Manager Association
1. Create a new user under Finance: **Mike Ross** (`mike.ross@Bhatt.com`, sAMAccountName: `mross`).
2. Open properties -> **Organization** tab. Under **Manager**, browse and assign `Sarah Connor`.
3. Populated metadata: `Title = Finance Analyst`, `Department = Finance`.

### Step 3: Scripted EmployeeID Insertion & Hygiene Verification
Because older ADUC management consoles hide the `employeeID` field from basic properties, open PowerShell as an Administrator on your DC and execute the standalone validation script:

```powershell
.\provision-validation.ps1
Ensure that all users show unique EmployeeID listings (BH1001, BH1002, etc.) and verify that PasswordExpired evaluates to True.

4. Interview-Prep Q&A
Q1: Why is it bad practice for an admin to set a permanent password and hand it to a user verbally, rather than using 'must change password at next logon'?
Answer: It completely destroys the principle of credential non-repudiation. If an administrator knows an operational password, it is impossible to prove during an incident response investigation whether an action was performed by the actual employee or an internal admin with knowledge of that shared secret. Forcing a change upon first logon guarantees exclusive end-user ownership.

Q2: Why populate the 'manager' attribute on every user object, even though it grants no direct technical access?
Answer: The manager attribute acts as critical structural metadata. Modern automated workflow platforms, self-service access management systems, and HR synchronization routines query this field to auto-route approvals or generate organizational visualization trees. Gaps here silently stall corporate identity compliance flows.

5. Progress Tracker
[■■□□□□□□□□] Day 2 of 30 — 7% Complete

[x] Day 1 — AD DS Logical Structure & Enterprise OU Design

[x] Day 2 — User Lifecycle Management (JML)

[ ] Day 3 — Group Strategy & AGDLP Model
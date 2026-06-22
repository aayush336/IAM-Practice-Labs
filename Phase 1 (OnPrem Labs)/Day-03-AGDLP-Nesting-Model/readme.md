# Day 3: Group Strategy — Security Groups, AGDLP Nesting Model & RBAC via Group-Based Access

## 1. Core Concept Overview
If the OU structure is the skeleton of AD and user objects are the people inside it, then groups are the access control engine[cite: 1]. Every enterprise RBAC implementation in Active Directory runs through groups[cite: 1].

* **Group Types:**
  * **Security Groups:** Have a SID (Security Identifier) and can be placed on ACLs to grant or deny access to resources[cite: 1].
  * **Distribution Groups:** Have no SID and cannot be placed on ACLs; they exist purely as email distribution lists[cite: 1].
* **Group Scopes:**
  * **Domain Local (DL):** Can contain users, global groups, and universal groups from any domain in the forest, but can only be assigned permissions to resources within the same domain[cite: 1]. These are your resource access groups[cite: 1].
  * **Global (G):** Can contain users and other global groups only from the same domain, but can be assigned permissions in any domain[cite: 1]. These represent job roles or departments[cite: 1].
  * **Universal (U):** Can contain users and groups from any domain and be assigned permissions in any domain; used primarily in multi-domain forests[cite: 1].
* **The AGDLP Model:** AGDLP stands for **A**ccounts → **G**lobal groups → **D**omain **L**ocal groups → **P**ermissions[cite: 1]. It is Microsoft's recommended group nesting strategy for scalable, auditable RBAC[cite: 1].

---

## 2. Real-World Enterprise Use Case
Consider a real enterprise scenario where Bhatt Corp has a Finance file share (`\\DC01\Finance-Shared`) requiring three types of access: Finance Managers (Full Control), Finance Analysts (Read/Write), and IT Support (Read-Only)[cite: 1].

Adding users directly to the ACL works for 5 users, but at 500 users, the ACL becomes unreadable and offboarding requires hunting down every resource that user was directly assigned to[cite: 1]. This direct user-to-resource assignment is an anti-pattern that access review frameworks (SOC2, ISO27001 A.9) will flag[cite: 1].

With AGDLP, the same access looks like this:
* **G-Finance-Managers** → nested into → **DL-Finance-Share-FullControl** → ACL on `\\DC01\Finance-Shared`[cite: 1]
* **G-Finance-Analysts** → nested into → **DL-Finance-Share-ReadWrite** → ACL on `\\DC01\Finance-Shared`[cite: 1]
* **G-IT-Support** → nested into → **DL-Finance-Share-Read** → ACL on `\\DC01\Finance-Shared`[cite: 1]

---

## 3. Detailed Step-by-Step Procedure

### Step 1: Create the Finance Shared Folder
1. On DC01, navigate to `C:\` and create `C:\Shares\Finance-Shared`[cite: 1].
2. Share the folder via Advanced Sharing, remove "Everyone" from share permissions, and leave NTFS for the AGDLP groups[cite: 1].

### Step 2: Create the Global Groups (Role Layer)
In ADUC (`BHATT-CORP -> Finance -> Groups`), create two Security groups with Global scope[cite: 1]:
* `G-Finance-Managers`[cite: 1]
* `G-Finance-Analysts`[cite: 1]

In `BHATT-CORP -> IT -> Groups`, create[cite: 1]:
* `G-IT-Support`[cite: 1]

### Step 3: Create the Domain Local Groups (Resource Layer)
In `BHATT-CORP -> Finance -> Groups`, create three Security groups with Domain Local scope[cite: 1]:
* `DL-Finance-Share-FullControl`[cite: 1]
* `DL-Finance-Share-ReadWrite`[cite: 1]
* `DL-Finance-Share-Read`[cite: 1]

### Step 4: Populate Global Groups & Execute Nesting
Add the respective accounts to their Global role groups, and nest those Global groups into the Domain Local resource groups[cite: 1]:
* `sconnor` → `G-Finance-Managers` → `DL-Finance-Share-FullControl`[cite: 1]
* `mross` → `G-Finance-Analysts` → `DL-Finance-Share-ReadWrite`[cite: 1]
* `dkim` → `G-IT-Support` → `DL-Finance-Share-Read`[cite: 1]

### Step 5: Validate the AGDLP Chain
Run the validation script (`verify-agdlp.ps1`) via PowerShell to confirm that NTFS and SMB share permissions are assigned exclusively to the Domain Local groups, and that the nesting chain is intact without any direct-assignment violations[cite: 1].

---

## 4. Interview-Prep Q&A

### Q1: What breaks if you skip the Global group layer and nest users directly into Domain Local groups?
**Answer:** Skipping the Global group layer collapses role-based access into resource-based access, which destroys scalability and auditability[cite: 1]. If users are placed directly into Domain Local groups, you have to query every DL group across every resource to reconstruct a single user's entitlement picture[cite: 1]. The Global group represents the role; the Domain Local group represents the resource access point[cite: 1]. 

### Q2: An auditor asks you to prove that no users have been granted direct access to the Finance share — how do you do that in under 60 seconds?
**Answer:** Use two commands. First, check the NTFS ACL: `(Get-Acl "C:\Shares\Finance-Shared").Access | Select-Object IdentityReference`[cite: 1]. Second, check the SMB share permissions: `Get-SmbShareAccess -Name "Finance-Shared"`[cite: 1]. If both commands return only group names (and specifically only Domain Local group names), the access model is clean[cite: 1]. 

---

## 5. Progress Tracker
[■■■□□□□□□□] Day 3 of 30 — 10% Complete

- [x] Day 1 — AD DS Logical Structure & Enterprise OU Design
- [x] Day 2 — User Lifecycle Management (JML) — Joiner Phase
- [x] Day 3 — Group Strategy & AGDLP Nesting Model
- [ ] Day 4 — GPO Access Control
- [ ] Day 5 — Fine-Grained Password Policies & PowerShell Automation
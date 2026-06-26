# Day 5: Fine-Grained Password Policies (PSOs) & Bulk JML PowerShell Automation

---

## Section 1 — Core Concept Overview

### Fine-Grained Password Policies (FGPPs)

Prior to Windows Server 2008, a domain could have exactly **one** password policy — defined in the Default Domain Policy GPO. Every user, admin, and service account was governed by the same rules. This was a fundamental security limitation.

**Fine-Grained Password Policies** (FGPPs), implemented via **Password Settings Objects (PSOs)**, solve this by allowing multiple distinct password policies within a single domain, applied directly to **users or global security groups** — not OUs.

PSOs live in a special AD container:
```
CN=Password Settings Container,CN=System,DC=Bhatt,DC=com
```

---

### PSO Attribute Reference Table

| Attribute | AD Attribute Name | Purpose |
|---|---|---|
| Minimum Password Length | msDS-MinimumPasswordLength | Character floor |
| Password History Count | msDS-PasswordHistoryLength | Prevents reuse |
| Max Password Age | msDS-MaximumPasswordAge | Expiry window |
| Min Password Age | msDS-MinimumPasswordAge | Prevents rapid cycling |
| Complexity Enabled | msDS-PasswordComplexityEnabled | Upper/lower/digit/symbol |
| Lockout Threshold | msDS-LockoutThreshold | Failed attempts before lockout |
| Lockout Duration | msDS-LockoutDuration | How long account stays locked |
| Lockout Observation Window | msDS-LockoutObservationWindow | Window to count failures |
| Precedence | msDS-PasswordSettingsPrecedence | Conflict resolution (lower = wins) |
| Reversible Encryption | msDS-PasswordReversibleEncryptionEnabled | Legacy protocols only |

---

### PSO Precedence & Conflict Resolution

When a user is a member of **multiple groups**, each with a different PSO:
- The PSO with the **lowest precedence number** wins
- If a PSO is applied **directly to a user**, it always overrides group-based PSOs regardless of precedence
- Resultant PSO is visible via `Get-ADUserResultantPasswordPolicy`

---

### Why PSOs Are a Core IAM Control

From an IAM engineering standpoint, PSOs enforce the **principle of tiered identity assurance**:

- **Tier 0 (Admins):** Strictest policy — long passwords, short lockout, short max age
- **Tier 1 (Service Accounts):** No expiry (managed via LAPS or vaulting), high complexity, very high lockout threshold
- **Tier 2 (Standard Users):** Balanced policy aligned to NIST SP 800-63B
- **Tier 3 (Temporary/Contractors):** Short max age, forced rotation

---

### PowerShell JML Automation — The Engineering Rationale

Manual user provisioning at enterprise scale introduces:
- **Inconsistency** — human error in attribute population
- **Latency** — delayed access provisioning violates SLA
- **Audit gaps** — no structured logging of provisioning actions

Bulk PowerShell JML scripts solve all three by creating a **repeatable, logged, auditable identity provisioning pipeline** — the on-premises equivalent of an IGA workflow.

---

## Section 2 — Real-World Enterprise Use Case

**Scenario:** You are the IAM Engineer at Bhatt Corp. The CISO has issued two directives following an audit finding:

> *"Our domain has a single password policy treating Domain Admins the same as interns. Additionally, our HR team sends a monthly joiner CSV and IT manually creates each account — a process taking 3 hours with frequent errors."*

**Your mandate:**
1. Implement three tiered PSOs — one for admins, one for service accounts, one for standard users
2. Build a bulk JML provisioning script that ingests an HR CSV, creates users in the correct OUs, assigns groups, enforces PSO membership, and writes an audit log

This is precisely the work performed by IAM engineers at banks, telcos, and enterprise environments running AD as their authoritative identity store.

---

## Section 3 — Step-by-Step Procedure

### PRE-FLIGHT: Create Directory Structure

```powershell
New-Item -ItemType Directory -Path "C:\IAMLab\Day5" -Force
New-Item -ItemType Directory -Path "C:\IAMLab\Day5\Logs" -Force
```
**Expected Result:** Directories created without error.

---

### PART A — Create the Three PSOs

#### Step A1 — PSO for Admins (Strictest Policy)

```powershell
New-ADFineGrainedPasswordPolicy `
    -Name "PSO-Admins" `
    -Precedence 10 `
    -MinPasswordLength 16 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "30.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold 3 `
    -LockoutDuration "00:30:00" `
    -LockoutObservationWindow "00:30:00" `
    -Description "Tier 0 - Domain and Enterprise Admins"
```

**Expected Result:** No output = success. PSO created in Password Settings Container.

**Verify:**
```powershell
Get-ADFineGrainedPasswordPolicy -Filter {Name -eq "PSO-Admins"} | 
    Select-Object Name, Precedence, MinPasswordLength, LockoutThreshold
```
> You should see `PSO-Admins | 10 | 16 | 3`

---

#### Step A2 — PSO for Service Accounts

```powershell
New-ADFineGrainedPasswordPolicy `
    -Name "PSO-ServiceAccounts" `
    -Precedence 20 `
    -MinPasswordLength 20 `
    -PasswordHistoryCount 48 `
    -MaxPasswordAge "0.00:00:00" `
    -MinPasswordAge "0.00:00:00" `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold 5 `
    -LockoutDuration "00:15:00" `
    -LockoutObservationWindow "00:15:00" `
    -Description "Tier 1 - Service and Application Accounts - No Expiry"
```

> **Note:** `MaxPasswordAge "0.00:00:00"` = password never expires. Service account passwords are managed via vaulting (CyberArk/LAPS in production).

**Verify:**
```powershell
Get-ADFineGrainedPasswordPolicy -Filter {Name -eq "PSO-ServiceAccounts"} | 
    Select-Object Name, Precedence, MinPasswordLength, MaxPasswordAge
```

---

#### Step A3 — PSO for Standard Users

```powershell
New-ADFineGrainedPasswordPolicy `
    -Name "PSO-StandardUsers" `
    -Precedence 30 `
    -MinPasswordLength 12 `
    -PasswordHistoryCount 12 `
    -MaxPasswordAge "90.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold 5 `
    -LockoutDuration "00:15:00" `
    -LockoutObservationWindow "00:15:00" `
    -Description "Tier 2 - Standard domain users across all departments"
```

**Verify:**
```powershell
Get-ADFineGrainedPasswordPolicy -Filter * | 
    Sort-Object Precedence | 
    Select-Object Name, Precedence, MinPasswordLength, MaxPasswordAge, LockoutThreshold
```
> **Expected:** All three PSOs listed in precedence order (10, 20, 30).

---

### PART B — Create PSO Shadow Groups & Apply Policies

PSOs cannot be applied to OUs — they must target **users or global security groups**. The IAM best practice is to use dedicated **shadow groups** per PSO.

#### Step B1 — Create Shadow Groups in _Admins OU

```powershell
# Group for PSO-Admins
New-ADGroup `
    -Name "G-PSO-Admins" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=_Admins,OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -Description "Shadow group for PSO-Admins policy enforcement"

# Group for PSO-ServiceAccounts
New-ADGroup `
    -Name "G-PSO-ServiceAccounts" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=_Admins,OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -Description "Shadow group for PSO-ServiceAccounts policy enforcement"

# Group for PSO-StandardUsers
New-ADGroup `
    -Name "G-PSO-StandardUsers" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=_Admins,OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -Description "Shadow group for PSO-StandardUsers policy enforcement"
```

**Verify:**
```powershell
Get-ADGroup -Filter {Name -like "G-PSO-*"} | Select-Object Name, GroupScope, DistinguishedName
```
> **Expected:** Three groups returned, all with `DistinguishedName` containing `OU=_Admins,OU=BHATT-CORP`.

---

#### Step B2 — Link PSOs to Their Shadow Groups

```powershell
Add-ADFineGrainedPasswordPolicySubject `
    -Identity "PSO-Admins" `
    -Subjects "G-PSO-Admins"

Add-ADFineGrainedPasswordPolicySubject `
    -Identity "PSO-ServiceAccounts" `
    -Subjects "G-PSO-ServiceAccounts"

Add-ADFineGrainedPasswordPolicySubject `
    -Identity "PSO-StandardUsers" `
    -Subjects "G-PSO-StandardUsers"
```

**Verify:**
```powershell
Get-ADFineGrainedPasswordPolicySubject -Identity "PSO-Admins"
Get-ADFineGrainedPasswordPolicySubject -Identity "PSO-ServiceAccounts"
Get-ADFineGrainedPasswordPolicySubject -Identity "PSO-StandardUsers"
```
> **Expected:** Each command returns the corresponding shadow group as the applied subject.

---

#### Step B3 — Add Domain Admins to Admin PSO Group

```powershell
Add-ADGroupMember -Identity "G-PSO-Admins" -Members "Administrator"
```

**Verify resultant PSO on Administrator:**
```powershell
Get-ADUserResultantPasswordPolicy -Identity "Administrator"
```
> **Expected:** Returns `PSO-Admins` with `MinPasswordLength: 16` and `LockoutThreshold: 3`

---

### PART C — Build the Bulk JML Provisioning Script

#### Step C1 — Create the HR Input CSV

**Open Notepad and save as** `C:\IAMLab\Day5\new_joiners.csv`

```csv
FirstName,LastName,Department,JobTitle,Manager
Priya,Sharma,IT,Security Analyst,Administrator
Rohan,Mehta,Finance,Junior Accountant,Administrator
Sneha,Patel,Sales,Sales Executive,Administrator
Karan,Joshi,IT,Helpdesk Technician,Administrator
Divya,Nair,Finance,Finance Manager,Administrator
```

---

#### Step C2 — Build the Full Provisioning Script

**Save as** `C:\IAMLab\Day5\Invoke-BulkJoiner.ps1`

```powershell
<#
.SYNOPSIS
    Bulk JML Joiner Script — Bhatt Corp IAM Lab Day 5
.DESCRIPTION
    Reads HR CSV, provisions AD users in correct OUs,
    assigns department groups, adds to PSO group,
    and writes a structured audit log.
#>

# ── Configuration Block ──────────────────────────────────────────
$CsvPath     = "C:\IAMLab\Day5\new_joiners.csv"
$LogPath     = "C:\IAMLab\Day5\Logs\JoinerLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$DefaultPass = ConvertTo-SecureString "Welcome@Bhatt1!" -AsPlainText -Force
$Domain      = "DC=Bhatt,DC=com"
$BaseCorp    = "OU=BHATT-CORP,$Domain"

# Department → OU and Group mappings
$DeptConfig = @{
    "IT"      = @{ OU = "OU=Users,OU=IT,$BaseCorp";      Group = "G-IT-Support"        }
    "Finance" = @{ OU = "OU=Users,OU=Finance,$BaseCorp";  Group = "G-Finance-ReadOnly"  }
    "Sales"   = @{ OU = "OU=Users,OU=Sales,$BaseCorp";    Group = "G-Sales-General"     }
}

# ── Logging Function ─────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $Entry
    Write-Host $Entry
}

# ── Script Start ─────────────────────────────────────────────────
Write-Log "========== Bulk Joiner Script Started =========="
Write-Log "CSV Source: $CsvPath"

# Validate CSV exists
if (-not (Test-Path $CsvPath)) {
    Write-Log "ERROR: CSV not found at $CsvPath. Aborting." -Level "ERROR"
    exit 1
}

$Joiners = Import-Csv -Path $CsvPath
Write-Log "Records to process: $($Joiners.Count)"

$Success = 0
$Failed  = 0

foreach ($User in $Joiners) {

    # ── Derive Identity Attributes ────────────────────────────────
    $FirstName   = $User.FirstName.Trim()
    $LastName    = $User.LastName.Trim()
    $Department  = $User.Department.Trim()
    $JobTitle    = $User.JobTitle.Trim()
    
    $SAM        = ($FirstName.Substring(0,1) + $LastName).ToLower()   # psharma
    $UPN        = "$($FirstName.ToLower()).$($LastName.ToLower())@Bhatt.com"
    $DisplayName = "$FirstName $LastName"

    Write-Log "Processing: $DisplayName | SAM: $SAM | Dept: $Department"

    # ── Validate Department Mapping ───────────────────────────────
    if (-not $DeptConfig.ContainsKey($Department)) {
        Write-Log "SKIP: Unknown department '$Department' for $DisplayName" -Level "WARN"
        $Failed++
        continue
    }

    $TargetOU    = $DeptConfig[$Department].OU
    $TargetGroup = $DeptConfig[$Department].Group

    # ── Check for Duplicate sAMAccountName ───────────────────────
    $Existing = Get-ADUser -Filter {SamAccountName -eq $SAM} -ErrorAction SilentlyContinue
    if ($Existing) {
        Write-Log "SKIP: User $SAM already exists in AD." -Level "WARN"
        $Failed++
        continue
    }

    # ── Create the AD User ────────────────────────────────────────
    try {
        New-ADUser `
            -Name              $DisplayName `
            -GivenName         $FirstName `
            -Surname           $LastName `
            -SamAccountName    $SAM `
            -UserPrincipalName $UPN `
            -DisplayName       $DisplayName `
            -Department        $Department `
            -Title             $JobTitle `
            -Path              $TargetOU `
            -AccountPassword   $DefaultPass `
            -ChangePasswordAtLogon $true `
            -Enabled           $true

        Write-Log "CREATED: $DisplayName ($SAM) in $TargetOU"

        # ── Assign Department Group ───────────────────────────────
        Add-ADGroupMember -Identity $TargetGroup -Members $SAM
        Write-Log "GROUP: $SAM added to $TargetGroup"

        # ── Assign PSO Standard Users Group ──────────────────────
        Add-ADGroupMember -Identity "G-PSO-StandardUsers" -Members $SAM
        Write-Log "PSO: $SAM added to G-PSO-StandardUsers"

        $Success++

    } catch {
        Write-Log "FAILED: Could not create $DisplayName. Error: $($_.Exception.Message)" -Level "ERROR"
        $Failed++
    }
}

# ── Summary ───────────────────────────────────────────────────────
Write-Log "========== Run Complete =========="
Write-Log "Succeeded : $Success"
Write-Log "Failed    : $Failed"
Write-Log "Log saved : $LogPath"
```

---

#### Step C3 — Execute the Script

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
& "C:\IAMLab\Day5\Invoke-BulkJoiner.ps1"
```

**Expected Output (console):**
```
[2025-...] [INFO] ========== Bulk Joiner Script Started ==========
[2025-...] [INFO] Records to process: 5
[2025-...] [INFO] CREATED: Priya Sharma (psharma) in OU=Users,OU=IT...
[2025-...] [INFO] GROUP: psharma added to G-IT-Support
[2025-...] [INFO] PSO: psharma added to G-PSO-StandardUsers
... (repeated for all 5 users)
[2025-...] [INFO] Succeeded : 5 | Failed : 0
```

---

#### Step C4 — Verification Battery

**Verify all users were created:**
```powershell
Get-ADUser -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" `
    -Properties Department, Title | 
    Where-Object {$_.Name -ne "Administrator"} |
    Select-Object Name, SamAccountName, Department, Title | 
    Format-Table -AutoSize
```

**Verify group memberships:**
```powershell
Get-ADGroupMember -Identity "G-IT-Support" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "G-PSO-StandardUsers" | Select-Object Name, SamAccountName
```

**Verify PSO is applying to a provisioned user:**
```powershell
Get-ADUserResultantPasswordPolicy -Identity "psharma"
```
> **Expected:** Returns `PSO-StandardUsers` with `MinPasswordLength: 12`

**Review the audit log:**
```powershell
Get-Content "C:\IAMLab\Day5\Logs\JoinerLog_*.txt" | Select-Object -Last 20
```

---

## Section 4 — Interview-Prep Q&A

**Q1: A user is a member of two groups — one linked to PSO-Admins (precedence 10) and one linked to PSO-StandardUsers (precedence 30). Which PSO applies, and how would you verify it?**

> **Model Answer:** The PSO with the **lowest precedence number wins**, so `PSO-Admins` (precedence 10) applies. This is by design — lower number = higher priority. You verify the resultant policy using `Get-ADUserResultantPasswordPolicy -Identity "<username>"`. In production, this is a critical audit check during access reviews: privileged users must confirm they are governed by the strictest PSO, not a more lenient standard-user policy that snuck in via an unexpected group membership.

---

**Q2: Why can't PSOs be applied to OUs, and what is the IAM engineering workaround?**

> **Model Answer:** PSOs are applied via `msDS-PSOAppliesTo` attribute, which only accepts **user objects** or **global security groups** — not OUs. This is an architectural constraint of the Password Settings Object model introduced in Windows Server 2008. The IAM workaround is the **shadow group pattern**: create a dedicated global security group per PSO (e.g., `G-PSO-Admins`), link the PSO to that group, then manage group membership as part of your JML provisioning process. This also makes PSO application auditable, since group membership is tracked in AD event logs (Event ID 4728/4729), whereas OU membership changes are not tied to password policy events.

---

## Section 5 — Progress Tracker

```
Day  1 [██████████] AD DS Structure & Enterprise OU Design         ✅
Day  2 [██████████] User Lifecycle Management — Joiner Phase        ✅
Day  3 [██████████] Group Strategy & AGDLP Nesting                  ✅
Day  4 [██████████] GPO for Access Control                          ✅
Day  5 [██████████] Fine-Grained PSOs & Bulk JML Automation         ✅
Day  6 [░░░░░░░░░░] Mover Phase — Role Change & OU Transfer         ⏭
Day  7 [░░░░░░░░░░] Leaver Phase — Full Offboarding Automation      ⏭
Day  8 [░░░░░░░░░░] AD Tiered Admin Model                           ⏭
...
Day 30 [░░░░░░░░░░] Capstone — Full IGA Simulation                  ⏭
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 1 Complete: On-Premises AD Identity Foundations  ✅ (Days 1–5)
Phase 2 Active:   JML Lifecycle Engineering            ⏭ (Days 6–10)
Phase 3 Pending:  Hybrid Identity & Azure AD Connect   ⏭ (Days 11–20)
Phase 4 Pending:  IGA Platforms & Governance           ⏭ (Days 21–30)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5 of 30 days complete | 17% through curriculum
```

---

**Phase 1 is complete.** You have built a production-grade on-premises AD identity foundation: structured OUs, full JML joiner automation, AGDLP group nesting, GPO-based access control, and tiered password enforcement via PSOs.

**Day 6 begins the Mover Phase** — handling role changes, department transfers, OU migrations, and group re-assignment mid-lifecycle, with a full PowerShell mover script. Ready when you are.
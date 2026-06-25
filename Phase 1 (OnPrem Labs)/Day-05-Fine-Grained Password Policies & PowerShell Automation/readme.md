# Day 5 — Fine-Grained Password Policies (PSOs) & Account Lifecycle Automation

---

## Section 1 — Core Concept Overview

### What is a Fine-Grained Password Policy (FGPP)?

Before Windows Server 2008, every domain could have exactly one password policy — the Default Domain Policy (DDP). If your domain admins needed stricter passwords than helpdesk staff, you had no mechanism to enforce that. You had to put them in a separate domain, which is operationally expensive.

Fine-Grained Password Policies solve this by introducing a new AD object class: `msDS-PasswordSettings` (commonly called a PSO — Password Settings Object). A PSO is stored in `CN=Password Settings Container,CN=System,DC=Bhatt,DC=com` and can be applied to security groups or individual user objects (never OUs).

### PSO Attributes — what you configure

| Attribute | What it controls |
| --- | --- |
| `msDS-PasswordSettingsPrecedence` | Priority (lower = higher priority) |
| `msDS-MinimumPasswordLength` | Min chars |
| `msDS-PasswordComplexityEnabled` | Upper/lower/digit/special |
| `msDS-MinimumPasswordAge` | How soon password can change again |
| `msDS-MaximumPasswordAge` | When it expires (0 = never) |
| `msDS-LockoutThreshold` | Failed attempts before lockout |
| `msDS-LockoutObservationWindow` | Time window for counting failures |
| `msDS-LockoutDuration` | How long account stays locked |
| `msDS-PasswordHistoryLength` | Can't reuse last N passwords |
| `msDS-PasswordReversibleEncryptionEnabled` | CHAP compatibility — leave false unless needed |

### Shadow Groups — the operational pattern

Since PSOs can't be applied to OUs, enterprise teams use shadow groups: a dedicated security group (e.g. `PSO-Admins`) that mirrors OU membership. Scripts or scheduled tasks keep the shadow group in sync with OU membership. The PSO is applied to the shadow group. This is standard enterprise pattern.

### Precedence resolution rules

* Lower number = higher precedence. A PSO with precedence 10 wins over precedence 20.
* If a user has a directly applied PSO, it always beats any group-applied PSO, regardless of precedence number.
* If a user is in multiple groups each with a PSO, the group PSO with the lowest precedence number wins.
* The "winner" is called the Resultant PSO (RPSO). If no PSO applies, the Default Domain Policy governs.

### Account Lifecycle Automation — JML Framework

JML (Joiner/Mover/Leaver) is the IAM industry's standard model for the three states of an employee's identity lifecycle:

* **Joiner** — new hire. Provision AD account, assign group memberships, home folder, email. In bulk: parse HR CSV → loop `New-ADUser`.
* **Mover** — department transfer, promotion. Move OU, update group memberships, change title/manager attributes.
* **Leaver** — resignation or termination. Disable account, strip group memberships, move to Disabled OU, set account description with date, forward mailbox (optional), retain for 90 days, then delete.

Automating JML via PowerShell is a critical IAM engineering skill — in enterprise environments, provisioning tickets arrive in bulk from HR systems (SAP SuccessFactors, Workday). Manual provisioning at scale is error-prone and an audit failure.

---

## Section 2 — Real-World Enterprise Use Case

**Scenario:** A mid-size bank with 3,000 users on-prem AD, pre-migration to hybrid Azure AD.

The CISO mandates different password policies per user tier as part of a PCI-DSS compliance drive:

* **Privileged admins** (40 users): 16-character minimum, 60-day expiry, 5 failed attempt lockout in 10 min.
* **Service accounts** (120 accounts): 24-character minimum, never expire, lockout disabled (to avoid production outages from runaway scripts).
* **All other users** (2,840): Default Domain Policy — 10 char, 90-day expiry.

The IAM team creates three PSOs. They run a nightly scheduled task that syncs `OU=Admins` membership into `GRP-PSO-Admins` shadow group, and `OU=ServiceAccounts` into `GRP-PSO-ServiceAccounts`. PSOs are linked to those groups. Every morning, when HR onboards 15 new joiners from an Excel export, the IAM engineer runs the bulk-create PowerShell script, which reads the CSV, creates accounts, drops them into the right OU, and adds them to relevant groups — a 3-minute operation that would otherwise take 2+ hours manually.

On the leaver side, when HR confirms a termination, the offboarding script fires within 15 minutes of notification — disabling the account, stripping all group memberships, moving it to `OU=Disabled,DC=Bhatt,DC=com`, and logging an audit entry.

This is exactly the workflow you replicate in your Bhatt.com lab today.

---

## Section 3 — Detailed Step-by-Step Procedure

Lab environment: Windows Server 2022 DC (`DC01.Bhatt.com`) + Windows 10 client. Run all commands in an elevated PowerShell session on the DC.

### Phase A — Prepare the OU and Group Structure

#### Step A1 — Create the OU structure for PSO shadow groups

Open Active Directory Users and Computers (ADUC). Expand `Bhatt.com`. Right-click `Bhatt.com` → **New** → **Organizational Unit**. Name it `PSO-ShadowGroups`. Repeat to create `OU=Disabled` at the root if it doesn't exist.

Or via PowerShell:

```powershell
# On DC01 — elevated PowerShell
New-ADOrganizationalUnit -Name "PSO-ShadowGroups" -Path "DC=Bhatt,DC=com"
New-ADOrganizationalUnit -Name "Disabled" -Path "DC=Bhatt,DC=com"

```

> **Expected Result/Verification:** In ADUC, refresh the domain root. You should see `PSO-ShadowGroups` and `Disabled` as child OUs directly under `Bhatt.com`.

#### Step A2 — Create shadow security groups

```powershell
New-ADGroup -Name "PSO-Admins" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=PSO-ShadowGroups,DC=Bhatt,DC=com" `
    -Description "Shadow group for Admin PSO enforcement"

New-ADGroup -Name "PSO-ServiceAccounts" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=PSO-ShadowGroups,DC=Bhatt,DC=com" `
    -Description "Shadow group for Service Account PSO enforcement"

```

> **Expected Result/Verification:** Run `Get-ADGroup -Filter * -SearchBase "OU=PSO-ShadowGroups,DC=Bhatt,DC=com"`. Output should list both `PSO-Admins` and `PSO-ServiceAccounts`.

### Phase B — Create the PSO Objects

#### Step B1 — Create the Admins PSO (high-security)

```powershell
New-ADFineGrainedPasswordPolicy `
    -Name "Admins-PSO" `
    -Precedence 10 `
    -MinPasswordLength 16 `
    -ComplexityEnabled $true `
    -PasswordHistoryCount 24 `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -MaxPasswordAge (New-TimeSpan -Days 60) `
    -LockoutThreshold 5 `
    -LockoutObservationWindow (New-TimeSpan -Minutes 10) `
    -LockoutDuration (New-TimeSpan -Minutes 30) `
    -ReversibleEncryptionEnabled $false `
    -Description "High-security PSO for privileged administrators"

```

> **Expected Result/Verification:** Run `Get-ADFineGrainedPasswordPolicy -Identity "Admins-PSO"`. Confirm `MinPasswordLength : 16` and `Precedence : 10`.

#### Step B2 — Create the Service Accounts PSO (no expiry)

```powershell
New-ADFineGrainedPasswordPolicy `
    -Name "ServiceAcct-PSO" `
    -Precedence 20 `
    -MinPasswordLength 24 `
    -ComplexityEnabled $true `
    -PasswordHistoryCount 48 `
    -MinPasswordAge (New-TimeSpan -Days 0) `
    -MaxPasswordAge (New-TimeSpan -Days 0) `
    -LockoutThreshold 0 `
    -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
    -LockoutDuration (New-TimeSpan -Minutes 0) `
    -ReversibleEncryptionEnabled $false `
    -Description "PSO for service accounts — no expiry, no lockout"

```

*Note: `MaxPasswordAge` of `New-TimeSpan -Days 0` means password never expires. `LockoutThreshold 0` disables lockout entirely.*

> **Expected Result/Verification:** Run `Get-ADFineGrainedPasswordPolicy -Identity "ServiceAcct-PSO"`. Confirm `MaxPasswordAge : 00:00:00` and `LockoutThreshold : 0`.

#### Step B3 — Apply PSOs to shadow groups

```powershell
Add-ADFineGrainedPasswordPolicySubject `
    -Identity "Admins-PSO" `
    -Subjects "PSO-Admins"

Add-ADFineGrainedPasswordPolicySubject `
    -Identity "ServiceAcct-PSO" `
    -Subjects "PSO-ServiceAccounts"

```

> **Expected Result/Verification:**
> ```powershell
> Get-ADFineGrainedPasswordPolicySubject -Identity "Admins-PSO"
> Get-ADFineGrainedPasswordPolicySubject -Identity "ServiceAcct-PSO"
> 
> ```
> 
> 
> Each command should return the respective shadow group object.

#### Step B4 — Add a test user to the shadow group and verify resultant PSO

```powershell
# Create a test admin user
New-ADUser -Name "TestAdmin01" `
    -SamAccountName "tadmin01" `
    -UserPrincipalName "tadmin01@Bhatt.com" `
    -Path "OU=PSO-ShadowGroups,DC=Bhatt,DC=com" `
    -AccountPassword (ConvertTo-SecureString "Temp@1234!" -AsPlainText -Force) `
    -Enabled $true

# Add to shadow group
Add-ADGroupMember -Identity "PSO-Admins" -Members "tadmin01"

# Check resultant PSO
Get-ADUserResultantPasswordPolicy -Identity "tadmin01"

```

> **Expected Result/Verification:** The output should show `Name : Admins-PSO` and `MinPasswordLength : 16`. This confirms PSO inheritance is working correctly.

#### Step B5 — Verify via Active Directory Administrative Center (ADAC)

Open Active Directory Administrative Center from Server Manager → Tools.
In the left pane, click `Bhatt (local)`. In the right pane, click `System` → double-click `Password Settings Container`. You should see `Admins-PSO` and `ServiceAcct-PSO` listed. Double-click `Admins-PSO` to review all settings in GUI form.

> **Expected Result/Verification:** Both PSOs are visible in ADAC under the Password Settings Container with correct attribute values visible in the detail pane.

### Phase C — Account Lifecycle Automation (JML Scripts)

#### Step C1 — Prepare the Joiners CSV

Create the file `C:\IAMLab\Day5\new_hires.csv` with this content:

```text
FirstName,LastName,Department,JobTitle,OU
Priya,Sharma,IT,Systems Analyst,"OU=IT,OU=Corp,DC=Bhatt,DC=com"
Rahul,Mehta,Finance,Finance Analyst,"OU=Finance,OU=Corp,DC=Bhatt,DC=com"
Ananya,Iyer,IT,Service Desk,"OU=IT,OU=Corp,DC=Bhatt,DC=com"

```

Ensure the `OU=IT` and `OU=Finance` OUs exist. Create them quickly:

```powershell
New-ADOrganizationalUnit -Name "Corp" -Path "DC=Bhatt,DC=com"
New-ADOrganizationalUnit -Name "IT" -Path "OU=Corp,DC=Bhatt,DC=com"
New-ADOrganizationalUnit -Name "Finance" -Path "OU=Corp,DC=Bhatt,DC=com"

```

> **Expected Result/Verification:** File exists at `C:\IAMLab\Day5\new_hires.csv` and the three target OUs are visible in ADUC.

#### Step C2 — Bulk Joiner Script

Create `C:\IAMLab\Day5\Bulk-Create-Users.ps1`:

```powershell
# Bulk-Create-Users.ps1 — Day 5 JML Joiner Automation
# Lab: Bhatt.com | Author: IAMLab

$csvPath  = "C:\IAMLab\Day5\new_hires.csv"
$logPath  = "C:\IAMLab\Day5\Logs\joiner_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$defaultPassword = ConvertTo-SecureString "Welcome@Bhatt1!" -AsPlainText -Force

# Ensure log dir exists
New-Item -ItemType Directory -Path "C:\IAMLab\Day5\Logs" -Force | Out-Null

$hires = Import-Csv -Path $csvPath

foreach ($hire in $hires) {

    $samAccount = ($hire.FirstName.Substring(0,1) + $hire.LastName).ToLower()
    $upn        = "$samAccount@Bhatt.com"
    $fullName   = "$($hire.FirstName) $($hire.LastName)"

    try {
        New-ADUser `
            -Name              $fullName `
            -GivenName         $hire.FirstName `
            -Surname           $hire.LastName `
            -SamAccountName    $samAccount `
            -UserPrincipalName $upn `
            -Department        $hire.Department `
            -Title             $hire.JobTitle `
            -Path              $hire.OU `
            -AccountPassword   $defaultPassword `
            -ChangePasswordAtLogon $true `
            -Enabled           $true

        $msg = "[$(Get-Date -Format 'HH:mm:ss')] CREATED: $fullName | $samAccount | $($hire.OU)"
        Write-Host $msg -ForegroundColor Green
        Add-Content -Path $logPath -Value $msg

    } catch {
        $err = "[$(Get-Date -Format 'HH:mm:ss')] ERROR: $fullName | $($_.Exception.Message)"
        Write-Host $err -ForegroundColor Red
        Add-Content -Path $logPath -Value $err
    }
}

Write-Host "`nProvisioning complete. Log: $logPath"

```

Run it:

```powershell
& "C:\IAMLab\Day5\Bulk-Create-Users.ps1"

```

> **Expected Result/Verification:** Three green success lines appear in console. Run `Get-ADUser -Filter * -SearchBase "OU=Corp,DC=Bhatt,DC=com" -Properties Department,Title | Select Name,Department,Title` — all three users should be listed with correct department and title.

#### Step C3 — Mover Script (role transfer)

```powershell
# Move-User.ps1 — Mover automation (department transfer)
# Scenario: Priya Sharma moves from IT to Finance

param(
    [string]$SamAccount   = "psharma",
    [string]$NewOU        = "OU=Finance,OU=Corp,DC=Bhatt,DC=com",
    [string]$NewTitle     = "Senior Finance Analyst",
    [string]$NewDept      = "Finance",
    [string]$RemoveGroup  = "",        # Optional: remove from old dept group
    [string]$AddGroup     = ""         # Optional: add to new dept group
)

$user = Get-ADUser -Identity $SamAccount -Properties DistinguishedName

# Update attributes
Set-ADUser -Identity $SamAccount -Title $NewTitle -Department $NewDept

# Move to new OU
Move-ADObject -Identity $user.DistinguishedName -TargetPath $NewOU

# Group membership update (if supplied)
if ($RemoveGroup) { Remove-ADGroupMember -Identity $RemoveGroup -Members $SamAccount -Confirm:$false }
if ($AddGroup)    { Add-ADGroupMember    -Identity $AddGroup    -Members $SamAccount }

Write-Host "MOVED: $SamAccount → $NewOU | Title: $NewTitle" -ForegroundColor Cyan

```

Run it:

```powershell
& "C:\IAMLab\Day5\Move-User.ps1" -SamAccount "psharma" `
    -NewOU "OU=Finance,OU=Corp,DC=Bhatt,DC=com" `
    -NewTitle "Senior Finance Analyst" -NewDept "Finance"

```

> **Expected Result/Verification:**
> ```powershell
> Get-ADUser -Identity "psharma" -Properties Department,Title,DistinguishedName |
>     Select Name,Department,Title,DistinguishedName
> 
> ```
> 
> 
> `Department` should read `Finance`, `Title` should read `Senior Finance Analyst`, and the `DN` should reference `OU=Finance,OU=Corp`.

#### Step C4 — Leaver Script (disable + archive)

```powershell
# Disable-Leaver.ps1 — Leaver automation (offboarding)

param(
    [string]$SamAccount = "rmehta",
    [string]$DisabledOU = "OU=Disabled,DC=Bhatt,DC=com"
)

$user = Get-ADUser -Identity $SamAccount `
    -Properties MemberOf, DistinguishedName, Description

# 1. Disable account
Disable-ADAccount -Identity $SamAccount

# 2. Strip all group memberships (skip primary group — Domain Users)
foreach ($group in $user.MemberOf) {
    try {
        Remove-ADGroupMember -Identity $group -Members $SamAccount -Confirm:$false
    } catch {
        Write-Warning "Could not remove from $group : $($_.Exception.Message)"
    }
}

# 3. Update description with offboarding date
$note = "DISABLED $(Get-Date -Format 'yyyy-MM-dd') | Offboarded"
Set-ADUser -Identity $SamAccount -Description $note

# 4. Move to Disabled OU
Move-ADObject -Identity $user.DistinguishedName -TargetPath $DisabledOU

Write-Host "OFFBOARDED: $SamAccount | Moved to $DisabledOU" -ForegroundColor Yellow

```

Run it:

```powershell
& "C:\IAMLab\Day5\Disable-Leaver.ps1" -SamAccount "rmehta"

```

> **Expected Result/Verification:**
> ```powershell
> Get-ADUser -Identity "rmehta" -Properties Enabled, Description, DistinguishedName |
>     Select Name, Enabled, Description, DistinguishedName
> 
> ```
> 
> 
> `Enabled` must be `False`. `Description` must contain `DISABLED`. `DN` must reference `OU=Disabled,DC=Bhatt,DC=com`.

#### Step C5 — View all PSOs and their subjects (audit check)

```powershell
# Full PSO audit report
Get-ADFineGrainedPasswordPolicy -Filter * | ForEach-Object {
    $pso = $_
    $subjects = Get-ADFineGrainedPasswordPolicySubject -Identity $pso.Name
    [PSCustomObject]@{
        PSO           = $pso.Name
        Precedence    = $pso.Precedence
        MinPwdLength  = $pso.MinPasswordLength
        MaxPwdAge     = $pso.MaxPasswordAge
        LockoutThresh = $pso.LockoutThreshold
        AppliedTo     = ($subjects.Name -join ", ")
    }
} | Format-Table -AutoSize

```

> **Expected Result/Verification:** A clean table showing both PSOs, their key settings, and the shadow groups they are applied to. This is the kind of output you'd produce for a compliance audit report.

---

## Section 4 — Interview-Prep Q&A

**Q1: "You have a service account that keeps getting locked out in production during off-hours, disrupting a critical batch job. How do you investigate whether a PSO is correctly applied, and what specific change would you make to prevent lockouts while maintaining security?"**

> **Model Answer:**
> The first step is determining the Resultant PSO for that service account:
> ```powershell
> Get-ADUserResultantPasswordPolicy -Identity "svc-batchjob"
> 
> ```
> 
> 
> If no PSO is applied, the account is governed by the Default Domain Policy, which likely has a lockout threshold of 5. To fix this, you add the service account (or its dedicated group) to the `PSO-ServiceAccounts` shadow group, which has `LockoutThreshold : 0` (lockout disabled). A threshold of 0 means no lockout will ever occur, which is appropriate for non-interactive service accounts where a human is not typing the password — the risk of credential stuffing is low because the password is managed programmatically.
> You would then verify with `Get-ADUserResultantPasswordPolicy` again to confirm the RPSO changed from the DDP to `ServiceAcct-PSO`, and check `LockoutThreshold` reads `0`.
> The deeper security control here is ensuring the service account password is rotated regularly (ideally via a PAM vault like CyberArk or a gMSA — Group Managed Service Account — which eliminates manual password management entirely and removes the lockout risk at the root).

**Q2: "During a bulk provisioning run, your script creates 200 users but 12 of them fail silently because their target OUs don't exist yet in AD. How would you redesign the Joiner script to handle this gracefully?"**

> **Model Answer:**
> The core problem is that `New-ADUser` throws a terminating error when the `Path` (OU) doesn't exist, but a bare `try/catch` without proper OU validation allows the loop to continue without flagging the root cause.
> A hardened approach adds pre-validation of the OU before attempting user creation:
> ```powershell
> # Pre-validate OU existence
> $ouExists = [bool](Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($hire.OU)'" `
>     -ErrorAction SilentlyContinue)
> 
> if (-not $ouExists) {
>     $msg = "[WARN] OU not found, skipping: $($hire.OU) for user $fullName"
>     Write-Warning $msg
>     Add-Content -Path $logPath -Value $msg
>     continue   # skip to next CSV row
> }
> 
> ```
> 
> 
> You would also implement a summary report at the end — a hashtable tracking `$created`, `$skipped`, `$failed` counts, written to the log and emailed to the IAM team. In enterprise pipelines, this is often fed into a ticketing system (ServiceNow) as a provisioning completion record.
> A further improvement for production: idempotency check — before creating, query `Get-ADUser -Identity $samAccount -ErrorAction SilentlyContinue` and skip if the user already exists, logging it as a duplicate rather than an error. This makes the script safe to re-run after partial failures without creating duplicate accounts.

---

## Section 5 — Overall Progress Tracker

Day 5 complete. You've covered every layer of enterprise password policy enforcement — PSO creation, precedence resolution, shadow group binding, and RPSO verification — along with production-grade JML automation scripts for the full account lifecycle. The leaver and mover scripts are directly portfolio-worthy for your GAO Analyst interviews. 

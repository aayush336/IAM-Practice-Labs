
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
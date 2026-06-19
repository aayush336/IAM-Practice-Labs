<#
.SYNOPSIS
    Validates identity attributes and baseline security states for Day 2 JML.
.DESCRIPTION
    Queries Active Directory to verify description, title, department, manager,
    employeeID alignment, and the password-must-change status.
#>

Write-Host "--- Verifying General & Organizational Attributes ---" -ForegroundColor Cyan
Get-ADUser sconnor -Properties Title,Department,Description | 
    Select-Object Name,Title,Department,Description

Write-Host "--- Verifying Machine-Readable Manager Links ---" -ForegroundColor Cyan
Get-ADUser mross -Properties Manager,Title,Department | 
    Select-Object Name,Manager,Title,Department

Write-Host "--- Verifying HR System Join-Key (EmployeeID) ---" -ForegroundColor Cyan
Get-ADUser -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" -Properties EmployeeID | 
    Select-Object Name, EmployeeID

Write-Host "--- Verifying Credential Non-Repudiation Baseline ---" -ForegroundColor Cyan
Get-ADUser -Filter * -SearchBase "OU=BHATT-CORP,DC=Bhatt,DC=com" -Properties PasswordExpired,PasswordLastSet | 
    Select-Object Name, PasswordExpired, PasswordLastSet
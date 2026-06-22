<#
.SYNOPSIS
    Validates the AGDLP access control implementation on the Finance share.
.DESCRIPTION
    Audits NTFS permissions, SMB share permissions, and reconstructs the 
    effective group membership chain to prove correct role-based nesting.
#>

$path = "C:\Shares\Finance-Shared"

Write-Host "--- Auditing NTFS Direct-Assignment Violations ---" -ForegroundColor Cyan
(Get-Acl $path).Access | Select-Object IdentityReference, FileSystemRights, AccessControlType

Write-Host "`n--- Auditing SMB Share Access Control ---" -ForegroundColor Cyan
Get-SmbShareAccess -Name "Finance-Shared"

Write-Host "`n--- Reconstructing the AGDLP Nesting Chain for Analyst 'mross' ---" -ForegroundColor Cyan
Write-Host "1. Account -> Global Role Group:"
Get-ADPrincipalGroupMembership -Identity "mross" | Select-Object Name, GroupScope

Write-Host "`n2. Global Role Group -> Domain Local Resource Group:"
Get-ADGroupMember -Identity "DL-Finance-Share-ReadWrite" | Select-Object Name, ObjectClass

Write-Host "`n3. Validating Global Role Members:"
Get-ADGroupMember -Identity "G-Finance-Analysts" | Select-Object Name, SamAccountName


Get-ADOrganizationalUnit -Filter * -SearchBase "DC=Bhatt,DC=com" |
    Select-Object Name, DistinguishedName |
    Sort-Object DistinguishedName
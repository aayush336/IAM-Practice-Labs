<#
.SYNOPSIS
    Automates the daily Git push for the 30-Day IAM Sprint.
.DESCRIPTION
    Runs git add, git commit with a custom or automatic message, and pushes to GitHub.
#>

# 1. Ensure we are in the script's directory
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptPath

# 2. Check if there are any changes to commit
$GitStatus = git status --porcelain
if ([string]::IsNullOrEmpty($GitStatus)) {
    Write-Host "No new changes detected. Your local repo is clean!" -ForegroundColor Yellow
    Exit
}

# 3. Prompt for a daily commit message (Defaults to generic text if left empty)
$DefaultMessage = "Update IAM Lab: $(Get-Date -Format 'yyyy-MM-dd')"
$CommitMessage = Read-Host "Enter commit message (Press Enter for default: '$DefaultMessage')"
if ([string]::IsNullOrEmpty($CommitMessage)) {
    $CommitMessage = $DefaultMessage
}

# 4. Run the Git sequence
Write-Host "Staging files..." -ForegroundColor Cyan
git add .

Write-Host "Committing changes..." -ForegroundColor Cyan
git commit -m "$CommitMessage"

Write-Host "Pushing to GitHub..." -ForegroundColor Cyan
git push origin main

Write-Host "Successfully updated your GitHub presence!" -ForegroundColor Green
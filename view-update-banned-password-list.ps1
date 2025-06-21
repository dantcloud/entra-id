<#
    Updates the banned password list in Microsoft Entra ID (Azure AD).
    -------------------------------------------------------------------
    This script imports a list of banned passwords from a CSV file 
    and applies them to your Entra ID tenant using Microsoft Graph PowerShell SDK.
    It either creates a new password policy or updates an existing one.

 **Note:** This requires the **Authentication Policy Administrator** role – 
 it provides the least privilege required to manage banned password policies.  
  
 It also requires the **Directory.ReadWrite.All** permission scope – 
 it allows reading and writing to directory settings 
 (eg. banned password list).

 www.dan-t.cloud
 
- Always validate any code obtained from external sources to confirm it aligns with your organisation's security and operational requirements.
- Ensure this script is thoroughly reviewed and tested in a non-production environment before using it in a live system.
 
#>

# Connect to Microsoft Graph with required scope
Connect-MgGraph -Scopes "Directory.ReadWrite.All" -NoWelcome

# Verify that the scope is granted
$grantedScopes = (Get-MgContext).Scopes
if ($grantedScopes -notcontains "Directory.ReadWrite.All") {
    Write-Host "ERROR: Missing required 'Directory.ReadWrite.All' scope." -ForegroundColor Red
    return
}

# Set path to banned passwords CSV file (must have a column called 'Password')
$csvPath = "C:\CompanyName\Security\BannedPasswords.csv"
if (-not (Test-Path $csvPath)) {
    Write-Host "ERROR: Input file not found at $csvPath" -ForegroundColor Red
    return
}

# Import and validate passwords
$newPasswordsRaw = Import-Csv -Path $csvPath | Select-Object -ExpandProperty 'Password'
$newPasswords = @()

foreach ($pw in $newPasswordsRaw) {
    if ($pw.Length -ge 4 -and $pw.Length -le 16) {
        $newPasswords += $pw.Trim()
    } else {
        Write-Host "WARNING: '$pw' is not between 4 and 16 characters and will be skipped." -ForegroundColor Yellow
    }
}

if ($newPasswords.Count -eq 0) {
    Write-Host "ERROR: No valid passwords found in the file." -ForegroundColor Red
    return
}

# Define Entra directory setting template ID for password policy
$templateId = "5cf42378-d67d-4f36-ba46-e8b86229381d"

# Check for existing password policy
$existingPolicy = Get-MgBetaDirectorySetting | Where-Object { $_.TemplateId -eq $templateId }

# Format password list as tab-delimited string
$passwordListString = ($newPasswords | Sort-Object -Unique) -join ([char]9)

if (-not $existingPolicy) {
    Write-Host "INFO: No existing password policy found. Creating new one..." -ForegroundColor Cyan

    $settings = @(
        @{ Name = "BannedPasswordList"; Value = $passwordListString },
        @{ Name = "BannedPasswordCheck"; Value = "true" },
        @{ Name = "EnableBannedPasswordCheck"; Value = "true" },
        @{ Name = "EnableBannedPasswordCheckOnPremises"; Value = "false" },
        @{ Name = "BannedPasswordCheckOnPremisesMode"; Value = "Enforce" },
        @{ Name = "LockoutDurationInSeconds"; Value = 60 },
        @{ Name = "LockoutThreshold"; Value = 10 }
    )

    $policyParams = @{
        TemplateId = $templateId
        Values     = $settings
    }

    try {
        $newPolicy = New-MgBetaDirectorySetting -BodyParameter $policyParams -ErrorAction Stop
        Write-Host "SUCCESS: New password policy created. ID: $($newPolicy.Id)" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to create password policy." -ForegroundColor Red
        Write-Host $_.Exception.Message
        return
    }

} else {
    Write-Host "INFO: Existing policy found (ID: $($existingPolicy.Id)). Updating..." -ForegroundColor Cyan

    $policyValues = (Get-MgBetaDirectorySetting -DirectorySettingId $existingPolicy.Id).Values
    $existingListRaw = ($policyValues | Where-Object { $_.Name -eq "BannedPasswordList" }).Value -split ([char]9)

    $mergedPasswords = ($existingListRaw + $newPasswords | Sort-Object -Unique)

    if ($mergedPasswords.Count -gt 1000) {
        Write-Host "INFO: Trimming merged list to 1000 entries..." -ForegroundColor Yellow
        $mergedPasswords = $mergedPasswords | Select-Object -First 1000
    }

    ($policyValues | Where-Object { $_.Name -eq "BannedPasswordList" }).Value = $mergedPasswords -join ([char]9)

    try {
        Update-MgBetaDirectorySetting -DirectorySettingId $existingPolicy.Id -Values $policyValues -ErrorAction Stop
        Write-Host "SUCCESS: Banned password list updated." -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to update password policy." -ForegroundColor Red
        Write-Host $_.Exception.Message
        return
    }
}

# Optional: Export the updated list for review
$outputFile = "C:\CompanyName\Security\UpdatedBannedPasswords.csv"
$finalPolicy = Get-MgBetaDirectorySetting -DirectorySettingId $existingPolicy.Id
$finalList = ($finalPolicy.Values | Where-Object { $_.Name -eq "BannedPasswordList" }).Value -split ([char]9)
$finalList | Sort-Object -Unique | Out-File -FilePath $outputFile -Encoding UTF8
Write-Host "INFO: Final banned password list exported to: $outputFile" -ForegroundColor Gray

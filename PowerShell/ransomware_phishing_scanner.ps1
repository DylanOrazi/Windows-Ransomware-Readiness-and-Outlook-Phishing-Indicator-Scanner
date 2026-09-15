<#
Ransomware Readiness and Outlook Phishing Indicator Scanner 
Author: Dylan Orazi

Purpose:
    Defensive PowerShell scanner that reviews ransomware readiness,
    phishing indicators, endpoint protection status, suspicious file
    indicators, startup/persistence locations, backup readiness, and
    reporting outputs.
    
Safety:
    This script is defensive and read-only.
    It does not create malware.
    It does not encrypt files.
    It does not delete files.
    It does not open attachments.
    It does not click links.
    It does not download files.
    It does not send emails.
    It does not delete or move emails.
    It does not scan company systems.
#>

# -------------------------------
# Scanner Initialization
# -------------------------------

$ScriptStartTime = Get-Date

# Get the project root folder.
# The script lives inside the PowerShell folder, so the project root is one folder above it.
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDirectory

# Define project folders.
$ReportsFolder = Join-Path $ProjectRoot "Reports"
$ExportsFolder = Join-Path $ProjectRoot "Exports"
$ScreenshotsFolder = Join-Path $ProjectRoot "Screenshots"
$TestDataFolder = Join-Path $ProjectRoot "Test_Data"
$TestFilesFolder = Join-Path $ProjectRoot "Test_Files"
$DocumentationFolder = Join-Path $ProjectRoot "Documentation"

# Create output folders if they do not already exist.
$RequiredFolders = @(
    $ReportsFolder,
    $ExportsFolder,
    $ScreenshotsFolder,
    $TestDataFolder,
    $TestFilesFolder,
    $DocumentationFolder
)

foreach ($Folder in $RequiredFolders) {
    if (-not (Test-Path $Folder)) {
        New-Item -Path $Folder -ItemType Directory | Out-Null
    }
}

# Create timestamp for output files.
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Define output files.
$ReportFile = Join-Path $ReportsFolder "Ransomware_Phishing_Readiness_Report_$Timestamp.txt"
$FindingsCsv = Join-Path $ExportsFolder "Scanner_Findings_$Timestamp.csv"
$RunLogFile = Join-Path $ExportsFolder "Scanner_Run_Log_$Timestamp.txt"

# Global findings collection.
$Findings = @()

# Global risk score.
$GlobalRiskScore = 0


# -------------------------------
# Helper Functions
# -------------------------------

function Write-SectionHeader {
    param (
        [string]$Title
    )

    $Line = "-" * 70
    Write-Host ""
    Write-Host $Line -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    Write-Host $Line -ForegroundColor DarkGray
}

function Add-Finding {
    param (
        [string]$Category,
        [string]$RiskLevel,
        [string]$Finding,
        [string]$Evidence,
        [string]$Recommendation,
        [int]$RiskPoints
    )

    $FindingId = "FIND-" + ("{0:D4}" -f ($script:Findings.Count + 1))

    $FindingObject = [PSCustomObject]@{
        Finding_ID     = $FindingId
        Category       = $Category
        Risk_Level     = $RiskLevel
        Finding        = $Finding
        Evidence       = $Evidence
        Recommendation = $Recommendation
        Risk_Points    = $RiskPoints
        Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    $script:Findings += $FindingObject
    $script:GlobalRiskScore += $RiskPoints

    $Color = "White"

    switch ($RiskLevel) {
        "Critical" { $Color = "Red" }
        "High"     { $Color = "Red" }
        "Medium"   { $Color = "Yellow" }
        "Low"      { $Color = "Green" }
        "Info"     { $Color = "Cyan" }
        default    { $Color = "White" }
    }

    Write-Host "[$RiskLevel] $Finding" -ForegroundColor $Color
}

function Get-RiskLevelFromScore {
    param (
        [int]$Score
    )

    if ($Score -ge 81) {
        return "Critical"
    }
    elseif ($Score -ge 51) {
        return "High"
    }
    elseif ($Score -ge 21) {
        return "Medium"
    }
    else {
        return "Low"
    }
}

function Get-FindingCountByRiskLevel {
    param (
        [string]$RiskLevel
    )

    return ($Findings | Where-Object { $_.Risk_Level -eq $RiskLevel }).Count
}

function Get-TopRiskCategories {
    $CategorySummary = $Findings |
        Group-Object Category |
        ForEach-Object {
            [PSCustomObject]@{
                Category     = $_.Name
                FindingCount = $_.Count
                RiskPoints   = ($_.Group | Measure-Object Risk_Points -Sum).Sum
            }
        } |
        Sort-Object RiskPoints -Descending

    return $CategorySummary
}

function Get-TopRiskFindings {
    $TopFindings = $Findings |
        Where-Object { $_.Risk_Points -gt 0 } |
        Sort-Object Risk_Points -Descending |
        Select-Object -First 10

    return $TopFindings
}

function Get-RiskScoreInterpretation {
    param (
        [int]$Score
    )

    if ($Score -ge 81) {
        return "Critical risk level indicates that the scanner found multiple high-risk indicators or several combined medium-risk issues. In this project, the score is expected to be high when safe test phishing records and ransomware-style test files are present."
    }
    elseif ($Score -ge 51) {
        return "High risk level indicates that the scanner found meaningful security concerns that should be reviewed and prioritized."
    }
    elseif ($Score -ge 21) {
        return "Medium risk level indicates that some security improvements or suspicious indicators were identified."
    }
    else {
        return "Low risk level indicates that few or no major risk indicators were detected during this scan."
    }
}

function Get-GeneralRecommendations {
    $Recommendations = @()

    if (($Findings | Where-Object { $_.Category -like "*Email*" -and $_.Risk_Points -gt 0 }).Count -gt 0) {
        $Recommendations += "Review suspicious email findings before opening attachments or clicking links."
    }

    if (($Findings | Where-Object { $_.Category -eq "Suspicious File Indicators" -and $_.Risk_Points -gt 0 }).Count -gt 0) {
        $Recommendations += "Investigate suspicious ransomware-style filenames or extensions and avoid opening suspicious files."
    }

    if (($Findings | Where-Object { $_.Category -eq "Ransomware Protection" -and $_.Risk_Points -gt 0 }).Count -gt 0) {
        $Recommendations += "Review ransomware protection settings such as Controlled Folder Access."
    }

    if (($Findings | Where-Object { $_.Category -like "*Backup*" -and $_.Risk_Points -gt 0 }).Count -gt 0) {
        $Recommendations += "Review backup and recovery readiness, including cloud sync, backup folders, restore points, and shadow copies."
    }

    if (($Findings | Where-Object { $_.Category -like "*User Account*" -or $_.Category -like "*Password*" }).Count -gt 0) {
        $Recommendations += "Review user account security, password policy, lockout policy, and local administrator access."
    }

    if (($Findings | Where-Object { $_.Category -like "*Persistence*" -and $_.Risk_Points -gt 0 }).Count -gt 0) {
        $Recommendations += "Review startup folders, Registry Run keys, and scheduled tasks for unexpected persistence entries."
    }

    if ($Recommendations.Count -eq 0) {
        $Recommendations += "No major risk-based recommendations were generated during this scan."
    }

    return $Recommendations
}

function Write-ReportLine {
    param (
        [string]$Text
    )

    Add-Content -Path $ReportFile -Value $Text
}

function Initialize-Report {
    $ComputerName = $env:COMPUTERNAME
    $CurrentUser = $env:USERNAME
    $PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    $ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-ReportLine "WINDOWS RANSOMWARE READINESS AND OUTLOOK PHISHING INDICATOR SCANNER"
    Write-ReportLine "=================================================================="
    Write-ReportLine ""
    Write-ReportLine "SCAN SUMMARY"
    Write-ReportLine "------------"
    Write-ReportLine "Scan Time: $ScanTime"
    Write-ReportLine "Computer Name: $ComputerName"
    Write-ReportLine "Current User: $CurrentUser"
    Write-ReportLine "PowerShell Version: $PowerShellVersion"
    Write-ReportLine "Project Root: $ProjectRoot"
    Write-ReportLine ""
    Write-ReportLine "SAFETY STATEMENT"
    Write-ReportLine "----------------"
    Write-ReportLine "This scanner is defensive and read-only."
    Write-ReportLine "It does not create malware, encrypt files, delete files, open attachments, click links, download files, send email, move email, or scan company systems."
    Write-ReportLine ""
}

function Export-Findings {
    if ($Findings.Count -gt 0) {
        $Findings | Export-Csv -Path $FindingsCsv -NoTypeInformation
    }
    else {
        $NoFindings = [PSCustomObject]@{
            Finding_ID     = "NONE"
            Category       = "Scanner Summary"
            Risk_Level     = "Info"
            Finding        = "No findings were created during this scanner run."
            Evidence       = "Scanner framework executed successfully."
            Recommendation = "Continue building scanner modules."
            Risk_Points    = 0
            Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }

        $NoFindings | Export-Csv -Path $FindingsCsv -NoTypeInformation
    }
}

function Finalize-Report {
    $ScriptEndTime = Get-Date 
    $Duration = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
    $OverallRiskLevel = Get-RiskLevelFromScore -Score $GlobalRiskScore
    $RiskInterpretation = Get-RiskScoreInterpretation -Score $GlobalRiskScore

    $CriticalCount = Get-FindingCountByRiskLevel -RiskLevel "Critical"
    $HighCount = Get-FindingCountByRiskLevel -RiskLevel "High"
    $MediumCount = Get-FindingCountByRiskLevel -RiskLevel "Medium"
    $LowCount = Get-FindingCountByRiskLevel -RiskLevel "Low"
    $InfoCount = Get-FindingCountByRiskLevel -RiskLevel "Info"

    Write-ReportLine ""
    Write-ReportLine "OVERALL RISK SUMMARY"
    Write-ReportLine "--------------------"
    Write-ReportLine "Overall Risk Score: $GlobalRiskScore"
    Write-ReportLine "Overall Risk Level: $OverallRiskLevel"
    Write-ReportLine "Total Findings: $($Findings.Count)"
    Write-ReportLine "Critical Findings: $CriticalCount"
    Write-ReportLine "High Findings: $HighCount"
    Write-ReportLine "Medium Findings: $MediumCount"
    Write-ReportLine "Low Findings: $LowCount"
    Write-ReportLine "Informational Findings: $InfoCount"
    Write-ReportLine "Scan Duration: $($Duration.ToString())"
    Write-ReportLine ""
    Write-ReportLine "RISK SCORE INTERPRETATION"
    Write-ReportLine "-------------------------"
    Write-ReportLine $RiskInterpretation
    Write-ReportLine ""

    Write-ReportLine "IMPORTANT TESTING NOTE"
    Write-ReportLine "----------------------"
    Write-ReportLine "This project uses safe test data. The sample Outlook-style CSV file and Test_Files folder intentionally contain suspicious indicators so the scanner can demonstrate detection logic."
    Write-ReportLine "A high or critical score during testing does not mean the personal computer is infected. It means the scanner detected the intentionally created phishing and ransomware-style indicators."
    Write-ReportLine ""

    Write-ReportLine "RISK SUMMARY BY CATEGORY"
    Write-ReportLine "------------------------"

    $CategorySummary = Get-TopRiskCategories

    if ($CategorySummary -and $CategorySummary.Count -gt 0) {
        foreach ($Category in $CategorySummary) {
            Write-ReportLine "Category: $($Category.Category)"
            Write-ReportLine "Finding Count: $($Category.FindingCount)"
            Write-ReportLine "Risk Points: $($Category.RiskPoints)"
            Write-ReportLine ""
        }
    }
    else {
        Write-ReportLine "No category summary was available."
        Write-ReportLine ""
    }

    Write-ReportLine "TOP RISK FINDINGS"
    Write-ReportLine "-----------------"

    $TopRiskFindings = Get-TopRiskFindings

    if ($TopRiskFindings -and $TopRiskFindings.Count -gt 0) {
        foreach ($Item in $TopRiskFindings) {
            Write-ReportLine "Finding ID: $($Item.Finding_ID)"
            Write-ReportLine "Category: $($Item.Category)"
            Write-ReportLine "Risk Level: $($Item.Risk_Level)"
            Write-ReportLine "Finding: $($Item.Finding)"
            Write-ReportLine "Evidence: $($Item.Evidence)"
            Write-ReportLine "Recommendation: $($Item.Recommendation)"
            Write-ReportLine "Risk Points: $($Item.Risk_Points)"
            Write-ReportLine ""
        }
    }
    else {
        Write-ReportLine "No risk-scored findings were available."
        Write-ReportLine ""
    }

    Write-ReportLine "GENERAL RECOMMENDATIONS"
    Write-ReportLine "-----------------------"

    $GeneralRecommendations = Get-GeneralRecommendations

    foreach ($Recommendation in $GeneralRecommendations) {
        Write-ReportLine "- $Recommendation"
    }

    Write-ReportLine ""

    Write-ReportLine "FULL FINDINGS SUMMARY"
    Write-ReportLine "---------------------"

    if ($Findings.Count -gt 0) {
        foreach ($Item in $Findings) {
            Write-ReportLine "Finding ID: $($Item.Finding_ID)"
            Write-ReportLine "Category: $($Item.Category)"
            Write-ReportLine "Risk Level: $($Item.Risk_Level)"
            Write-ReportLine "Finding: $($Item.Finding)"
            Write-ReportLine "Evidence: $($Item.Evidence)"
            Write-ReportLine "Recommendation: $($Item.Recommendation)"
            Write-ReportLine "Risk Points: $($Item.Risk_Points)"
            Write-ReportLine ""
        }
    }
    else {
        Write-ReportLine "No findings were created during this run."
        Write-ReportLine ""
    }

    Write-ReportLine "REPORT OUTPUTS"
    Write-ReportLine "--------------"
    Write-ReportLine "TXT Report: $ReportFile"
    Write-ReportLine "CSV Findings: $FindingsCsv"
    Write-ReportLine "Run Log: $RunLogFile"
    Write-ReportLine ""

    Write-ReportLine "PROJECT STATUS"
    Write-ReportLine "--------------"
    Write-ReportLine "Risk summary improvements completed."
}

function Show-ScannerBanner {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Windows Ransomware Readiness and Outlook Phishing Scanner" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Scanner framework initialized." -ForegroundColor Green
    Write-Host ""
    Write-Host "Safety Notice:" -ForegroundColor Yellow
    Write-Host "This scanner is defensive and read-only."
    Write-Host "It will not open attachments, click links, encrypt files, delete files, or modify emails."
    Write-Host ""
}


# -------------------------------
# Placeholder Scanner Modules
# -------------------------------

function Run-SystemInformationModule {
    Write-SectionHeader "System Information Module"

    $ComputerName = $env:COMPUTERNAME
    $CurrentUser = $env:USERNAME
    $PowerShellVersion = $PSVersionTable.PSVersion.ToString()

    Write-Host "Computer Name: $ComputerName"
    Write-Host "Current User: $CurrentUser"
    Write-Host "PowerShell Version: $PowerShellVersion"

    Add-Finding `
        -Category "System Information" `
        -RiskLevel "Info" `
        -Finding "System information collected successfully." `
        -Evidence "Computer: $ComputerName; User: $CurrentUser; PowerShell: $PowerShellVersion" `
        -Recommendation "Use this information as context for the scanner report." `
        -RiskPoints 0
}

function Run-ScannerFrameworkTest {
    Write-SectionHeader "Scanner Framework Test"

    Add-Finding `
        -Category "Scanner Framework" `
        -RiskLevel "Info" `
        -Finding "Scanner framework executed successfully." `
        -Evidence "Report, CSV findings, and run log paths were initialized." `
        -Recommendation "Continue building scanner modules in later phases." `
        -RiskPoints 0
}

function Run-EndpointProtectionDetectionModule {
    Write-SectionHeader "Endpoint Protection Detection Module"

    Write-Host "Checking registered antivirus products and endpoint protection indicators..."

    try {
        $AntivirusProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop

        if ($AntivirusProducts) {
            foreach ($Product in $AntivirusProducts) {
                $ProductName = $Product.displayName

                Write-Host "Detected Antivirus Product: $ProductName" -ForegroundColor Green

                Add-Finding `
                -Category "Endpoint Protection" `
                -RiskLevel "Info" `
                -Finding "Antivirus product detected." `
                -Evidence "Detected product: $ProductName" `
                -Recommendation "Confirm that endpoint protection is actively monitored and updated." `
                -RiskPoints 0
            }
        }
        else {
            Add-Finding `
                -Category "Endpoint Protection" `
                -RiskLevel "Medium" `
                -Finding "No antivirus products were returned by Windows Security Center." `
                -Evidence "SecurityCenter2 AnitVirusProduct query returned no products." `
                -Recommendation "Verify that endpoint protection is installed, enabled, and reporting correctly." `
                -RiskPoints 15
        }
    }
    catch {
        Add-Finding `
            -Category "Endpoint Protection" `
            -RiskLevel "Info" `
            -Finding "Windows Security Center antivirus product query could not be completed." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify antivirus status in Windows Security." `
            -RiskPoints 0 .\Documentation
    }
}

function Run-WindowsDefenderStatusModule {
    Write-SectionHeader "Windows Defender and Ransomware Protection Module"

    Write-Host "Checking Microsoft Defender status..."

    try {
        $DefenderStatus = Get-MpComputerStatus -ErrorAction Stop

        if ($DefenderStatus.AMServiceEnabled -eq $true) {
            Add-Finding `
                -Category "Microsoft Defender" `
                -RiskLevel "Info" `
                -Finding "Microsoft Defender antimalware service is enabled." `
                -Evidence "AMServiceEnabled: $($DefenderStatus.AMServiceEnabled)" `
                -Recommendation "Continue monitoring Defender status." `
                -RiskPoints 0
        }
        else {
            Add-Finding `
                -Category "Microsoft Defender" `
                -RiskLevel "High" `
                -Finding "Microsoft Defender antimalware service appears disabled." `
                -Evidence "AMServiceEnabled: $($DefenderStatus.AMServiceEnabled)" `
                -Recommendation "Verify that endpoint protection is enabled or replaced by approved third-party protection." `
                -RiskPoints 30
        }
            
        if ($DefenderStatus.RealTimeProtectionEnabled -eq $true) {
            Add-Finding `
                -Category "Microsoft Defender" `
                -RiskLevel "Info" `
                -Finding "Real-time protection is enabled." `
                -Evidence "RealTimeProtectionEnabled: $($DefenderStatus.RealTimeProtectionEnabled)" `
                -Recommendation "Keep real-time protection enabled." `
                -RiskPoints 0
        }
        else {
            Add-Finding `
                -Category "Microsoft Defender" `
                -RiskLevel "High" `
                -Finding "Real-time protection appears disabled." `
                -Evidence "RealTimeProtectionEnabled: $($DefenderStatus.RealTimeProtectionEnabled)" `
                -Recommendation "Enable real-time protection or confirm that another approved protection product is active." `
                -RiskPoints 30
        }

        if ($DefenderStatus.AntispywareSignatureLastUpdated) {
            Add-Finding `
                -Category "Microsoft Defender" `
                -RiskLevel "Info" `
                -Finding "Defender security intelligence update information was collected." `
                -Evidence "Antispyware signature last updated: $($DefenderStatus.AntispywareSignatureLastUpdated)" `
                -Recommendation "Keep security intelligence updated regularly." `
                -RiskPoints 0
        }

        $CfaStatus = Get-MpPreference -ErrorAction Stop

        if ($CfaStatus.EnableControlledFolderAccess -eq 1) {
            Add-Finding `
                -Category "Ransomware Protection" `
                -RiskLevel "Info" `
                -Finding "Controlled Folder Access is enabled." `
                -Evidence "EnableControlledFolderAccess: $($CfaStatus.EnableControlledFolderAccess)" `
                -Recommendation "Review protected folders and allowed apps periodically." `
                -RiskPoints 0
        }
        elseif ($CfaStatus.EnabledControlledFolderAccess -eq 2) {
            Add-Finding `
                -Category "Ransomware Protection" `
                -RiskLevel "Info" `
                -Finding "Controlled Folder Access is in audit mode." `
                -Evidence "EnableControlledFolderAccess: $($CfaStatus.EnableControlledFolderAccess)" `
                -Recommendation "Review audit results before enforcing Controlled Folder Access." `
                -RiskPoints 0
        }
        else {
            Add-Finding `
                -Category "Ransomware Protection" `
                -RiskLevel "Medium" `
                -Finding "Controlled Folder Access is not enabled." `
                -Evidence "EnabledControlledFolderAccess: $($CfaStatus.EnableControlledFolderAccess)" `
                -Recommendation "Consider enabling Controlled Folder Access for ransomware protection on important folders." `
                -RiskPoints 10
        }
    }
    catch {
        Add-Finding `
            -Category "Microsoft Defender" `
            -RiskLevel "Info" `
            -Finding "Microsoft Defender status could not be fully collected." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify Defender and ransomware protection settings in Windows Security." `
            -RiskPoints 0 .\Documentation
    }
}

function Run-SophosDetectionModule {
    Write-SectionHeader "Sophos Detection Module"

    Write-Host "Checking for Sophos-related services, processes, and installed applications..."

    $SophosDetected = $false 
    $SophosEvidence = @()

    try {
        $SophosServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -like "*Sophos*" -or $_.DisplayName -like "*Sophos*"
        }

        if ($SophosServices) {
            $SophosDetected = $true
            
            foreach ($Service in $SophosServices) {
                $SophosEvidence += "Service: $($Service.DisplayName) [$($Service.Status)]"
            }
        }

        $SophosProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -like "*Sophos*"
        }

        if ($SophosProcesses) {
            $SophosDetected = $true

            foreach ($Process in $SophosProcesses) {
                $SophosEvidence += "Process: $($Process.ProcessName)"
            }
        }

        $InstallAppPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        foreach ($Path in $InstallAppPaths) {
            $SophosApps = Get-ItemProperty $Path -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -like "*Sophos*"
            }

            if ($SophosApps) {
                $SophosDetected = $true

                foreach ($App in $SophosApps) {
                    $SophosEvidence += "Installed App: $($App.DisplayName)"
                }
            }
        }

        if ($SophosDetected -eq $true) {
            $EvidenceText = $SophosEvidence -join "; "

            Add-Finding `
                -Category "Sophos Detection" `
                -RiskLevel "Info" `
                -Finding "Sophos endpoint protection indicator were detected." `
                -Evidence $EvidenceText `
                -Recommendation "Confirm Sophos status through the approved management console or local client interface." `
                -RiskPoints 0
        }
        else {
            Add-Finding `
                -Category "Sophos Detection" `
                -RiskLevel "Info" `
                -Finding "Sophos endpoint protection was not detected on this device." `
                -Evidence "No Sophos services, processes, or installed applications were found." `
                -Recommendation "No action is required if Sophos is not expected on this personal lab device." `
                -RiskPoints 0
        }
    }
    catch {
        Add-Finding `
            -Category "Sophos Detection" `
            -RiskLevel "Info" `
            -Finding "Sophos detection check could not be completed." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify whether Sophos is installed if required." `
            -RiskPoints 0
    }
}

function Run-FirewallStatusModule {
    Write-SectionHeader "Windows Firewall Status Module"

    Write-Host "Checking Windows Firewall profile status..."

    try {
        $FirewallProfiles = Get-NetFirewallProfile -ErrorAction Stop

        foreach ($Profile in $FirewallProfiles) {
            $ProfileName = $Profile.Name 
            $Enabled = $Profile.Enabled 

            Write-Host "$ProfileName Firewall Enabled: $Enabled"

            if ($Enabled -eq $true) {
                Add-Finding `
                    -Category "Windows Firewall" `
                    -RiskLevel "Info" `
                    -Finding "$ProfileName firewall profile is enabled." `
                    -Evidence "$ProfileName Enabled: $Enabled" `
                    -Recommendation "Keep firewall protection enabled." `
                    -RiskPoints 0
            }
            else {
                Add-Finding `
                    -Category "Windows Firewall" `
                    -RiskLevel "Medium" `
                    -Finding "$ProfileName firewall profile is disabled." `
                    -Evidence "$ProfileName Enabled: $Enabled" `
                    -Recommendation "Enable the $ProfileName firewall profile unless there is an approved exception." `
                    -RiskPoints 15
            }
        }
    }
    catch {
        Add-Finding `
            -Category "Windows Firewall" `
            -RiskLevel "Info" `
            -Finding "Windows Firewall profile status could not be collected." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify firewall status in Windows Security or Windows Defender Firewall." `
            -RiskPoints 0
    }
}

function Run-SuspiciousFileIndicatorModule {
    Write-SectionHeader "Suspicious Ransomware File Indicator Module"

    Write-Host "Scanning safe test folder for ransomware-style file indicator..."
    Write-Host "Scan Path: $TestFilesFolder"
    
    if (-not (Test-Path $TestFilesFolder)) {
        Add-Finding `
            -Category "Suspicious File Indicators" `
            -RiskLevel "Info" `
            -Finding "Test_Files folder was not found." `
            -Evidence "Expected path: $TestFilesFolder" `
            -Recommendation "Create the Test-Files folder before running ransomware-style file indicator checks." `
            -RiskPoints 0

        Return 
    }

    $SuspiciousExtensions = @(
        ".encrypted",
        ".locked",
        ".crypt",
        ".crypto",
        ".ransom",
        ".pay"
    )

    $RansomNoteNames = @(
        "README_RESTORE_FILES.txt",
        "DECRYPT_INSTRUCTIONS.txt",
        "HOW_TO_RECOVER_FILES.txt",
        "RECOVER_FILES.txt"
    )

    $Files = Get-ChildItem -Path $TestFilesFolder -File -Recurse -ErrorAction SilentlyContinue

    if (-not $Files -or $Files.Count -eq 0) {
        Add-Finding `
            -Category "Suspicious File Indicators" `
            -RiskLevel "Info" `
            -Finding "No files were found in the Test_Files folder." `
            -Evidence "Scan path contained no files: $TestFilesFolder" `
            -Recommendation "Add safe test files to validate scanner detection" `

        return 
    }

    Write-Host "Files scanned: $($Files.Count)"

    $SuspiciousExtensionMatches = @() 
    $RansomNoteMatches = @()

    foreach ($File in $Files) {
        $FileName = $File.Name
        $FileExtension = $File.Extension.ToLower()

        if ($SuspiciousExtensions -contains $FileExtensions) {
            $SuspiciousExtensionMatches += $File.FullName

            Add-Finding `
                -Category "Suspicious File Indicators" `
                -RiskLevel "High" `
                -Finding "Suspicious ransomware-style file extension detected." `
                -Evidence "File: $($File.FullName); Extension: $FileExtension" `
                -Recommendation "Review the file. In a real environment, isolate the endpoint and investigate before opening or modifying suspicious files." `
                -RiskPoints 20
        }

        if ($RansomNoteNames -contains $FileName) {
            $RansomNoteMatches += $File.FullName

            Add-Finding `
                -Category "Suspicious File Indicators" `
                -RiskLevel "High" `
                -Finding "Potential ransomware note filename detected." `
                -Evidence "File: $($File.FullName)" `
                -Recommendation "Treat ransom-note filenames as high-priority indicators. In a real environment, disconnect the device from the network and escalate to IT/security." `
                -RiskPoints 25

        }
    }

    if ($SuspiciousExtensionMatches.Count -eq 0 -and $RansomNoteMatches.Count -eq 0) {
        Add-Finding `
            -Category "Suspicious File Indicators" `
            -RiskLevel "Info" `
            -Finding "No suspicious ransomware-style file indicators were detected in the test folder." `
            -Evidence "Files scanned: $($Files.Count)" `
            -Recommendation "Continue monitoring selected folders for suspicious ransomware-style indicators." `
            -RiskPoints 0
    }
    else {
        $SummaryEvidence = "Suspicious extensions found: $($SuspiciousExtensionMatches.Count); Potential ransom notes found: $($RansomNoteMatches.Count)"

        Add-Finding `
            -Category "Suspicious File Indicators" `
            -Risklevel "High" `
            -Finding "Suspicious ransomware-style indicators were detected in the test folder." `
            -Evidence $SummaryEvidence `
            -Recommendation "Review all suspicious indicators. In a real environment, perserve evidence, avoid opening suspicious files, isolate the endpoint, and escalate immediately." `
            -RiskPoints 10
    }
}

function Run-OutlookCsvPhishingIndicatorModule {
    Write-SectionHeader "Outlook-Style CSV Phishing Indicator Module"

    $EmailCsvPath = Join-Path $TestDataFolder "sample_outlook_messages.csv"

    Write-Host "Scanning Outlook-style sample email CSV for phishing indicators..."
    Write-Host "CSV Path: $EmailCsvPath"

    if (-not (Test-Path $EmailCsvPath)) {
        Add-Finding `
            -Category "Email phishing Indicators." `
            -RiskLevel "Info" `
            -Finding "Sample Outlook email CSV was not found." `
            -Evidence "Expected path: $EmailCsvPath" `
            -Recommendation "Create sample_outlook_messages.csv in the Test_Data folder before running the phishing indicator module."
            -RiskPoints 0

        return 
    }

    try {
        $EmailMessages = Import-Csv -Path $EmailCsvPath -ErrorAction Stop
    }
    catch {
        Add-Finding `
            -Category "Email phishing Indicators." `
            -RiskLevel "Medium" `
            -Finding "Sample Outlook email CSV could not be imported." `
            -Evidence $_.Exception.Message `
            -Recommendation "Verify that the CSV file is formatted correctly and can be opened in VS Code or Excel." `
            -RiskPoints 10

        return 
    }

    if (-not $EmailMessages -or $EmailMessages.Count -eq 0) {
        Add-Finding `
            -Category "Email phishing Indicators." `
            -RiskLevel "Info" `
            -Finding "No email records were found in the sample Outlook CSV." `
            -Evidence "CSV imported successfully but contains no message rows." `
            -Recommendation "Add safe sample email records to test phishing indicator detection." `
            -RiskPoints 0

        return 
    }

    Write-Host "Email records scanned: $($EmailMessages.Count)"

    $RiskyAttachmentExtensions = @(
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".ps1",
        ".zip",
        ".rar",
        ".7z",
        ".iso",
        ".img",
        ".docm",
        ".xlsm",
        ".pptm",
        ".html",
        ".htm",
        ".lnk"
    )

    $UrgentKeywords = @(
        "urgent",
        "immediately",
        "final notice",
        "expires today",
        "required immediately",
        "account locked",
        "verify your account",
        "open attachment",
        "payment is required"
    )

    $PhishingThemeKeywords = @(
        "password",
        "payroll",
        "invoice",
        "payment",
        "wire transfer",
        "account",
        "verify",
        "sign in",
        "login",
        "document shared",
        "unusual sign-in",
        "security alert"
    )

    $RansomwareKeywords = @(
        "restore files",
        "encrypted files",
        "decrypt",
        "recovery",
        "recovery files",
        "restore access"
    )

    $UrlShorteners = @(
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gq",
        "buff.ly",
        "rebrand.ly"
    )

    foreach ($Message in $EmailMessages) {
        $MessageId = $Message.Message_ID
        $SenderName = $Message.Sender_Name 
        $SenderEmail = $Message.Sender_Email
        $ReplyTo = $Message.Reply_To
        $ReturnPath = $Message.Return_Path
        $Subject = $Message.Subject
        $AttachmentNames = $Message.Attachment_Names
        $Links = $Message.links
        $BodyPreview = $Message.Body_Preview
        $AuthenticationResults = $Message.Authentication_Results 

        $CombinedText = "Subject $BodyPreview $Links $AttachmentNames $AuthenticationResults".ToLower() 

        # -------------------------------
        # Risky Attachment Detection
        # -------------------------------

        if ($AttachmentNames) {
            $AttachmentList = $AttachmentNames -split ";"

            foreach ($Attachment in $AttachmentList) {
                $AttachmentTrimmed = $Attachment.Trim()
                $AttachmentExtension = [System.IO.Path]::GetExtension($AttachmentTrimmed).ToLower()

                if ($RiskyAttachmentExtensions -contains $AttachmentExtension) {
                    $RiskLevel = "Medium"
                    $RiskPoints = 10

                    if ($AttachmentExtension -in @(".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1")) {
                        $RiskLevel = "High"
                        $RiskPoints = 20
                    }
                    elseif ($AttachmentExtension -in @(".docm", ".xlsm", "pptm")) {
                        $RiskLevel = "High"
                        $RiskPoints = 20
                    }
                    elseif ($AttachmentExtension -in @(".zip", ".rar", ".7z", ".iso", "img")) {
                        $RiskLevel = "Medium"
                        $RiskPoints = 10
                    }

                    Add-Finding `
                        -Category "Email Attachment Risk" `
                        -RiskLevel $Risklevel `
                        -Finding "Risky email attachment extension detected." `
                        -Evidence "Message ID: $MessageId; Subject; Attachment: $AttachmentTrimmed; Extension: $AttachmentExtension" `
                        -Recommendation "Do not open unexpected attachments. Verify the sender and report suspicious attachments to IT/security." `
                        -RiskPoints $RiskPoints 
                }
            }
        }

        # -------------------------------
        # Suspicious Link Detection
        # -------------------------------
 
        if ($Links) {
            $LinkList = $Links -split ";"

            foreach ($Link in $LinkList) {
                $LinkTrimmed = $Link.Trim()
                $LinkLower = $LinkTrimmed.ToLower()

                if ($LinkLower.StartsWith("http://")) {
                    Add-Finding `
                        -Category "Email Link Risk" `
                        -RiskLevel "Medium" `
                        -Finding "HTTP link detected in email message." `
                        -Evidence "Message ID: $MessageId; Subject: $Subject; Link: $LinkTrimmed" `
                        -Recommendation "Use caution with non-HTTPS links. Do not click suspicious links without verification." `
                        -RiskPoints 10
                    
                }

                if ($LinkLower -match '^https?://\d{1,3}(\.\d{1,3}){3}') {
                    Add-Finding `
                        -Category "Email Link Risk" `
                        -RiskLevel "High" `
                        -Finding "IP-address-based link detected in email message." `
                        -Evidence "Message ID: $MessageId; Subject: $Subject; Link: $LinkTrimmed" `
                        -Recommendation "Treat IP-address-based email links as suspicious and report them for review." `
                        -RiskPoints 20
                }

                foreach ($Shortener in $UrlShorteners) {
                    if ($LinkLower -like "*$Shortener*") {
                        Add-Finding `
                            -Category "Email Link Risk" `
                            -RiskLevel "Medium" `
                            -Finding "URL shortener detected in email message." `
                            -Evidence "Message ID: $MessageId; Subject: $Subject; Link: $LinkTrimmed; Shortener: $Shortener" `
                            -Recommendation "Avoid clicking shortened URLs in unexpected emails. Verify the destination with IT/security." `
                            -RiskPoints 10
                    }
                }

                if ($LinkTrimmed.Length -gt 120) {
                    Add-Finding `
                        -Category "Email Link Risk" `
                        -RiskLevel "Medium" `
                        -Finding "Very long URL detected in email message." `
                        -Evidence "Message ID: $MessageId; Subject: $Subject; URL length: $($LinkTrimmed.Length)" `
                        -Recommendation "Review long URLs carefully because they may hide suspicious parameters or redirects." `
                        -RiskPoints 5
                }
            }
        }

        # -------------------------------
        # Urgent Language Detection
        # -------------------------------

        foreach ($Keyword in $UrgentKeywords) {
            if ($CombinedText -like "*Keywords*") {
                Add-Finding `
                    -Category "Email Language Risk" `
                    -RiskLevel "Medium" `
                    -Finding "Urgent or pressure-based language detected." `
                    -Evidence "Message ID: $MessageId; Subject: $Subject; Keyword: $Keyword" `
                    -Recommendation "Treat urgent messages requesting action, payment, password reset, or attachment opening with caution." `
                    -RiskPoints 5
            }
        }

        # -------------------------------
        # Phishing Theme Detection
        # -------------------------------

        foreach ($Keyword in $PhishingThemeKeywords) {
            if ($CombinedText -like "*Keyword*") {
                Add-Finding `
                    -Category "Email Phishing Theme" `
                    -RiskLevel "Medium" `
                    -Finding "Common phishing theme keyword detected." `
                    -Evidence "Message ID: $MessageId; SubjectL $Subject; Keyword: $Keyword" `
                    -Recommendation "Review the message context, sender, attachments, and links before taking action." `
                    -RiskPoints 3
            }
        }

        # -------------------------------
        # Ransomware Wording Detection
        # -------------------------------

        foreach ($Keyword in $RansomwareKeywords) {
            if ($CombinedText -like "*$Keyword*") {
                Add-Finding `
                    -Category "Email Ransomware Indicator" `
                    -RiskLevel "High" `
                    -Finding "Ransomware-related wording detected in email message." `
                    -Evidence "Message ID: $MessageId; Subject: $Subject; Keyword: $Keyword" `
                    -Recommendation "Treat ransomware-related wording as high priority. Do not click links or open attachments. Escalate immediately." `
                    -RiskPoints 20
            }
        }

        # -------------------------------
        # Reply-To / Return-Path Mismatch
        # -------------------------------

        if ($SenderEmail -and $ReplyTo -and ($SenderEmail.ToLower() -ne $ReplyTo.ToLower())) {
            Add-Finding `
                -Category "Email Header Indicator" `
                -RiskLevel "Medium" `
                -Finding "Sender email and Reply-To address mismatch detected." `
                -Evidence "Message ID: $MessageId; Sender: $SenderEmail; Reply-To: $ReplyTo" `
                -Recommendation "Review Reply-To mismatches because attackers may use them to redirect responses." `
                -RiskPoints 10
        }

        if ($SenderEmail -and $ReturnPath -and ($SenderEmail.ToLower() -ne $ReturnPath.ToLower())) {
            Add-Finding `
                -Category "Email Header Indicator" `
                -RiskLevel "Medium" `
                -Finding "Sender email and Return-Path mismatch detected" `
                -Evidence "Message ID: $MessageId; Sender: $SenderEmail; Return-Path: $ReturnPath" `
                -Recommendation "Review Return-Path mismatches as part of email header analysis." `
                -RiskPoints 10
        }

        # -------------------------------
        # Authentication Failure Detection
        # -------------------------------

        if ($AuthenticationResults) {
            $AuthLower = $AuthenticationResults.ToLower()

            if ($AuthLower -like "*spf=fail*" -or $AuthLower -like "*dmarc=fail*") {
                Add-Finding `
                    -Category "Email Authentication Indicator" `
                    -RiskLevel "High" `
                    -Finding "Email authentication failure detected." `
                    -Evidence "Message ID: $MessageId; Subject: $Subject; Authentication Results: $AuthenticationResults" `
                    -Recommendation "Review messages with SPF or DMARC failures carefully and confirm legitmacy before interacting." `
                    -RiskPoints 20
            }
            elseif ($AuthLower -like "*spf=softfail*") {
                Add-Finding `
                    -Category "Email Authentication Indicator" `
                    -RiskLevel "Medium" `
                    -Finding "Email authentication softfail detected." `
                    -Evidence "Message ID: $MessageId; Subject: $Subject; Authentication Results: $AuthenticationResults" `
                    -Recommendation "Review softfail messages because they may indicate questionable sender authorization." `
                    -RiskPoints 10
            }
        }
    }

    Add-Finding `
        -Category "Email Phishing Indicator" `
        -RiskLevel "Info" `
        -Finding "Outlook-style CSV phishing indicator scan completed." `
        -Evidence "Email records scanned: $($EmailMessages.Count)" `
        -Recommendation "Review high and medium email findings before interacting with suspicious messages." `
        -RiskPoints 0
}

function Run-StartupPersistenceReviewModule {
    Write-SectionHeader "Startup and Persistence locations..."

    Write-Host "Reviewing common startup and persistence locations..."

    # -------------------------------
    # Startup Folder Checks
    # -------------------------------

    $StartupFolders = @(
        [PSCustomObject]@{
            Scope = "Current User Startup Folder"
            Path  = [Environment]::GetFolderPath("Startup")
        },
        [PSCustomObject]@{
            Scope = "All Users Startup Folder"
            Path  = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        }
    )

    foreach ($StartupFolder in $StartupFolders) {
        if (Test-Path $StartupFolder.Path) {
            $StartupItems = Get-ChildItem -Path $StartupFolder.Path -File -ErrorAction SilentlyContinue

            if ($StartupItems -and $StarupItems.Count -gt 0) {
                foreach ($Item in $StartupItems) {
                    Add-Finding `
                        -Category "Startup Persistence" `
                        -RiskLevel "Medium" `
                        -Finding "Startup folder item detected." `
                        -Evidence "Scope: $($StartupFolder.Scope); File: $($Item.FullName)" `
                        -Recommendation "Review startup folder items to confirm they are expected and trusted." `
                        -RiskPoints 10
                }
            }
            else {
                Add-Finding `
                    -Category "Startup Persistence" `
                    -RiskLevel "Info" `
                    -Finding "$($StartupFolder.Scope) was checked and no startup items were found." `
                    -Evidence "Path checked: $($StartupFolder.Path)" `
                    -Recommendation "No action needed if no unexpected startup items are present." `
                    -RiskPoints 0
            }
        }
        else {
            Add-Finding `
                -Category "Startup Persistence" `
                -RiskLevel "Info" `
                -Finding "$($StartupFolder.Scope) path was not found." `
                -Evidence "Expected path: $($StartupFolder.Path)" `
                -Recommendation "No action needed if the startup folder does not exist on this system." `
                -RiskPoints 0
        }
    }

    # -------------------------------
    # Registry Run Key Checks
    # -------------------------------

    $RunKeyPaths = @(
        [PSCustomObject]@{
            Scope = "Current User Run Key"
            Path  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        },
        [PSCustomObject]@{
            Scope = "Local Machine Run Key"
            Path  = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        },
        [PSCustomObject]@{
            Scope = "Local Machine WOW6432Node Run Key"
            Path  = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" 
        }
    )

    foreach ($RunKey in $RunKeyPaths) {
        if (Test-Path $RunKey.Path) {
            try {
                $RunKeyProperties = Get-ItemProperty -Path $RunKey.Path -ErrorAction Stop
                $PropertyNames = $RunKeyProperties.PSObject.Properties |
                    Where-Object {
                        $_.Name -notlike "PS*" -and
                        $_.Name -ne "VMware User Process"
                    }
                
                if ($PropertyNames -and $PropertyNames.Count -gt 0) {
                    foreach ($Property in $PropertyNames) {
                        Add-Finding `
                            -Category "Registry Persistence" `
                            -RiskLevel "Medium" `
                            -Finding "Registry Run key entry detected." `
                            -Evidence "Scope: $($RunKey.Scope); Name: $($Property.Name); Value: $($Property.Value)" `
                            -Recommednation "Review Run key entries to confirm they are expected and trusted." `
                            -RiskPoints 10
                    }
                }
                else {
                    Add-Finding `
                        -Category "Registry Persistence" `
                        -RiskLevel "Info" `
                        -Finding "$($RunKey.Scope) was checked and no Run key entries were found." `
                        -Evidence "Path checked: $($RunKey.Path) " `
                        -Recommendation "No action needed if no unexpected Run key entries are present." `
                        -RiskPoints 0
                }
            }
            catch {
                Add-Finding `
                    -Category "Registry Persistence" `
                    -RiskLevel "Info" `
                    -Finding "$($RunKey.Scope) could not be fully reviewed." `
                    -Evidence $_.Exception.Message `
                    -Recommendation "Manually review this Run key if needed." `
                    -RiskPoints 0
            }
        }
        else {
            Add-Finding `
                -Category "Registry Persistence" `
                -RiskLevel "Info" `
                -Finding "$($RunKey.Scope) path was not found." `
                -Evidence "Expected Path: $($RunKey.Path)" `
                -Recommendation "No action needed if this Run key does not exist on this system." `
                -RiskPoints 0
        }
    }

    # -------------------------------
    # Scheduled Task Review
    # -------------------------------

    Write-Host "Reviewing scheduled tasks..."

    try {
        $ScheduledTasks = Get-ScheduleTask -ErrorAction Stop

        $UserCreatedTasks = $ScheduledTasks | Where-Object {
            $_.TaskPath -notlike "\Microsoft*" -and
            $_.TaskPath -notlike "OneDrive*" -and
            $_.TaskPath -notlike "GoogleUpdate*" -and
            $_.TaskPath -notlike "Adobe*" -and
            $_.TaskPath -notlike "MicrosoftEdgeUpdate*"
        }

        if ($UserCreatedTasks -and $UserCreatedTasks.Count -gt 0) {
            foreach ($Task in $UserCreatedTasks) {
                Add-Finding `
                    -Category "Scheduled Task Persistence" `
                    -RiskLevel "Medium" `
                    -Finding "Non-Microsoft scheduled task detected." `
                    -Evidence "Task Name: $($Task.TaskName); Task Path: $($Task.TaskPath); State: $($Task.State)" `
                    -Recommendation "Review non-Microsoft scheduled tasks to confirm they are expected and trusted." `
                    -RiskPoints 10
            }
        }
        else {
            Add-Finding `
                -Category "Scheduled Task Persistence" `
                -RiskLevel "Info" `
                -Finding "Scheduled tasks were reviewed and no unusaul non-Microsoft tasks were identified by the scanner." `
                -Evidence "Total scheduled tasks reviewed: $($ScheduledTasks.Count) " `
                -Recommendation "Continue reviewing scheduled tasks during endpoint investigations." `
                -RiskPoints 0
        }

        $DisabledTasks = $ScheduledTasks | Where-Object {
            $_.State -eq "Disabled" 
        }

        Add-Finding `
            -Category "Scheduled Task Review" `
            -RiskLevel "Info" `
            -Finding "Scheduled task inventory summary collected." `
            -Evidence "Total tasks: $($ScheduledTasks.Count); Disabled tasks: $($DisabledTasks.Count)" `
            -Recommendation "Use this summary as context when reviewing persistence and system maintenance tasks." `
            -RiskPoints 0
    }
    catch {
        Add-Finding `
            -Category "Scheduled Task Persistence" `
            -RiskLevel "Info" `
            -Finding "Scheduled task review could not be completed." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually review Task Scheduler if needed." `
            -RiskPoints 0
    }

    Add-Finding `
        -Category "Startup and Persistence Review" `
        -RiskLevel "Info" `
        -Finding "Startup and persistence review completed." `
        -Evidence "Startup folders, Registry Run keys, and scheduled tasks were reviewed." `
        -Recommendation "Investigate unexpected startup entries, Run key values, or scheduled tasks during ransomware response." `
        -RiskPoints 0
}  

function Run-BackupRecoveryReadinessModule {
    Write-SectionHeader "Backup and Recovery Readiness Module"

    Write-Host "Reviewing backup and recovery readiness indicators..."

    # -------------------------------
    # OneDrive Folder Detection
    # -------------------------------

    $OneDrivePaths = @(
        $env:OneDrive,
        "$env:USERPROFILE\OneDrive",
        "$env:USERPROFILE\OneDrive - Personal"
    ) | Where-Object {
        $_ -and $_.Trim() -ne ""
    } | Select-Object -Unique

    $OneDriveDetected = $false
    
    foreach ($path in $OneDrivePaths) {
        if (Test-Path $Path) {
            $OneDriveDetected = $true

            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Info" `
                -Finding "OneDrive folder detected." `
                -Evidence "Detected OneDrive path: $Path" `
                -Recommendation: "Confirm that important folders are syncing correctly and that rasnomware recovery options are understood." `
                -RiskPoints 0 `
        }
    }

    if ($OneDriveDetected -eq $false) {
        Add-Finding `
            -Category "Backup and Recovery Readiness" `
            -RiskLevel "Medium" `
            -Finding "OneDrive folder was not detected by the scanner." `
            -Evidence "Checked common OneDrive paths under the current user profile." `
            -Recommendation "Verify whether cloud backup or file sync is configured for important files." `
            -RiskPoints 10
    }

    # -------------------------------
    # Common Backup Folder Detection
    # -------------------------------

    $CommonBackupFolders = @(
        "$env:USERPROFILE\Backup",
        "$env:USERPROFILE\Backups",
        "$env:USERPROFILE\Documents\Backup",
        "$env:USERPROFILE\Documents\Backups",
        "$env:USERPROFILE\Desktop\Backup",
        "$env:USERPROFILE\Desktop\Backups"
    )

    $BackupFolderDetected = $false

    foreach ($Folder in $CommonBackupFolders) {
        if (Test-Path $Folder) {
            $BackupFolderDetected = $true

            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Info" `
                -Finding "Common backup folder detected." `
                -Evidence "Detected backup folder: $Folder" `
                -Recommendation "Confirm that backup files are current, protected, and recoverable." `
                -RiskPoints 0
        }
    }

    if ($BackupFolderDetected -eq $false) {
        Add-Finding `
            -Category "Backup and Recovery Readiness" `
            -RiskLevel "Medium" `
            -Finding "No common local backup folder was detected." `
            -Evidence "Checked common backup folder paths under the current user profile." `
            -Recommendation "Consider maintaining protected backups for important files. Backups should be tested and isolated from ransomware exposure where possible." `
            -RiskPoints 15
    }

    # -------------------------------
    # File History Service Check
    # -------------------------------

    try {
        $FileHistoryService = Get-Service -Name "fhsvc" -ErrorAction Stop

        if ($FileHistoryService.Status -eq "Running") {
            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Info" `
                -Finding "File History service is running." `
                -Evidence "Service: fhsvc; Status: $($FileHistoryService.Status)" `
                -Recommendation "Confirm File History backup destinations and recovery procedures." `
                -RiskPoints 0
        }
        else {
            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Medium" `
                -Finding "File History service is not running ." `
                -Evidence "Service: fhsvc; Status: $($FileHistoryService.Status)" `
                -Recommendation "If File History is used for backup, verify that it is configured and functioning properly." `
                -RiskPoints 10
        }
    }
    catch {
        Add-Finding `
            -Category "Backup and Recovery Readiness" `
            -RiskLevel "Info" `
            -Finding "File History service could not be checked." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify File History settings if used for backup." `
            -RiskPoints 0
    }

    # -------------------------------
    # Volume Shadow Copy Service Check
    # -------------------------------

    try {
        $VssService = Get-Service -Name "VSS" -ErrorAction Stop

        if ($VssService.Status -eq "Running") {
            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Info" `
                -Finding "Volume Shadow Copy service is running." `
                -Evidence "Service: VSS; Status: $($VssService.Status)" `
                -Recommendation "Confirm restore points or shadow copies are available if this system relies on them for recovery." `
                -RiskPoints 0
        }
        else {
            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Info" `
                -Finding "Volume Shadow Copy service is not currently running." `
                -Evidence "Service: VSS; Status: $($VssService.Status)" `
                -Recommendation "This service may run only when needed. Manually verify restore point and backup configuration." `
                -RiskPoints 0
        }
    }
    catch {
        Add-Finding `
            -Category "Backup and Recovery Readiness" `
            -RiskLevel "Info" `
            -Finding "Volume Shadow Copy service could not be checked." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify Volume Shadow Copy or restore point status if needed." `
            -RiskPoints 0
    }

    # -------------------------------
    # Restore Point Check
    # -------------------------------

    try {
        $RestorePoints = Get-ComputerRestorePoint -ErrorAction Stop 

        if ($RestorePoints -and $RestorePoints.Count -gt 0) {
            $LatestRestorePoint = $RestorePoints | Sort-Object CreationTime -Descending | Select-Object -First 1

            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Info" `
                -Finding "System restore points were detected." `
                -Evidence "Restore points found: $($RestorePoints.Count); Latest restore point: $($LatestRestorePoint.Description)" `
                -Recommendation "Restore Points can help with some system recovery scenarios, but they should not replace offline or cloud backups." `
                -RiskPoints 0
        }
        else {
            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Medium" `
                -Finding "No system restore points were detected." `
                -Evidence "Get-ComputerRestorePoint returned no restore points." `
                -Recommendation "Consider enabling restore protection where appropriate, but maintain separate backups for ransomware recovery." `
                -RiskPoints 10
        }
    }
    catch {
        Add-Finding `
            -Category "Backup and Recovery Readiness" `
            -RiskLevel "Info" `
            -Finding "System restore point check could not be completed." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify System Protection and restore point settings." `
            -RiskPoints 0
    }

    # -------------------------------
    # Shadow Copy Inventory Check
    # -------------------------------

    try {
        $ShadowCopies = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop 

        if ($ShadowCopies -and $ShadowCopies.Count -gt 0) {
            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Info" `
                -Finding "Shadow copy records were detected." `
                -Evidence "Shadow copies found: $($ShadowCopies.Count)" `
                -Recommendation "Review shadow copy availability and confirm whether it supports recovery requirments." `
                -RiskPoints 0
        }
        else {
            Add-Finding `
                -Category "Backup and Recovery Readiness" `
                -RiskLevel "Medium" `
                -Finding "No shadow copy records were detected." `
                -Evidence "Win32_ShadowCopy returned no shadow copy records." `
                -Recommendation "Do not rely on shadow copies alone. Maintain tested backups that are protected from ransomware." `
                -RiskPoints 10
        }
    }
    catch {
        Add-Finding `
            -Category "Backup and Recovery Readiness" `
            -RiskLevel "Info" `
            -Finding "Shadow copy inventory check could not be completed." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify shadow copy status if needed." `
            -RiskPoints 0
    }

    Add-Finding `
        -Category "Backup and Recovery Readiness" `
        -RiskLevel "Info" `
        -Finding "Backup and recovery readiness review completed." `
        -Evidence "OneDrive, common backup folders, File History, VSS, restore points, and shadow copies were reviewed where available." `
        -Recommendation "Use these findings to identify ransomware recovery gaps and backup improvement opportunities." `
        -RiskPoints 0
}  

function Run-UserAccountSecurityModule {
    Write-SectionHeader "User Account Security and Local Admin Review Module"

    Write-Host "Reviewing local user account security indicators..."

    # -------------------------------
    # Current User Admin Status
    # -------------------------------

    try {
        $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
        $IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 

        if ($IsAdmin -eq $true) {
            Add-Finding `
                -Category "User Account Security" `
                -RiskLevel "Medium" `
                -Finding "Current user is running with local administrator priviledges." `
                -Evidence "Current user: $env:USERNAME; Is local admin: $IsAdmin" `
                -Recommendation "Use administrator priviledges only when needed. For daily work, consider using a standard user account where practical." `
                -RiskPoints 10
        }
        else {
            Add-Finding `
                -Category "User Account Security" `
                -RiskLevel "Info" `
                -Finding "Current user is not running with local administrator priviledges." `
                -Evidence "Current user: $env:USERNAME; Is local admin: $IsAdmin" `
                -Recommendation "Continue using least priviledges where possible." `
                -RiskPoints 0
        }
    }
    catch {
        Add-Finding `
            -Category "User Account Security" `
            -RiskLevel "Info" `
            -Finding "Current user administrator status could not be determined." `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually verify whether the current user has local administrator rights." `
            -RiskPoints 0
    }

    # -------------------------------
    # Local User Account Review
    # -------------------------------

    try {
        $LocalUsers = Get-LocalUser -ErrorAction Stop

        $EnabledUsers = $LocalUsers | Where-Object { $_.Enabled -eq $true }
        $DisabledUsers = $LocalUsers | Where-Object { $_.Enabled -eq $false }

        Add-Finding `
            -Category "User Account Security" `
            -RiskLevel "Info" `
            -Finding "Local user account inventory collected." `
            -Evidence "Total local users: $($LocalUsers.Count); Enabled users: $($EnabledUsers.Count); Disabled users: $($DisabledUsers.Count)" `
            -Recommendation "Review enabled local accounts regularly and remove or disable accounts that are no longer needed." `
            -RiskPoints 0

        foreach ($User in $EnabledUsers) {
            Add-Finding `
                -Category "User Account Security" `
                -RiskLevel "Info" `
                -Finding "Enabled local user account detected." `
                -Evidence "Username: $($User.Name); Last logon: $($User.LastLogon); Password required: $($User.PasswordRequired)" `
                -Recommendation "Confirm enabled local accounts are expected and properly secured." `
                -RiskPoints 0
        }

        # Guest account review
        $GuestAccount = $LocalUsers | Where-Object { $_.Name -eq "Guest" }

        if ($GuestAccount) {
            if ($GuestAccount.Enabled -eq $true) {
                Add-Finding `
                    -Category "User Account Security" `
                    -RiskLevel "High" `
                    -Finding "Guest account is enabled." `
                    -Evidence "Guest account enabled: $($GuestAccount.Enabled)" `
                    -Recommendation "Disable the Guest account unless there is an approved business reason." `
                    -RiskPoints 25
            }
            else {
                Add-Finding `
                    -Category "User Account Security" `
                    -RiskLevel "Info" `
                    -Finding "Guest account is disabled." `
                    -Evidence "Guest account enabled: $($GuestAccount.Enabled)" `
                    -Recommendation "Keep the Guest account disabled." `
                    -RiskPoints 0
            }
        }
        else {
            Add-Finding `
                -Category "User Account Security" `
                -RiskLevel "Info" `
                -Finding "Guest account was not found." `
                -Evidence "No local account named Guest was returned by Get-LocalUser." `
                -Recommendation "No action needed if the Guest account is not present." `
                -RiskPoints 0
        }

        # Built-in Administrator account review
        $AdministratorAccount = $LocalUsers | Where-Object {
            $_.Name -eq "Administrator" -or $_.SID.Value.EndsWith("-500")
        }

        if ($AdministratorAccount) {
            if ($AdministratorAccount.Enabled -eq $true) {
                Add-Finding `
                    -Category "User Account Security" `
                    -RiskLevel "Medium" `
                    -Finding "Built-in Administrator account appears enabled." `
                    -Evidence "Administrator account: $($AdministratorAccount.Name); Enabled: $($AdministratorAccount.Enabled)" `
                    -Recommendation "Verify that the built-in Administrator account is required, secured with a strong password, and monitored." `
                    -RiskPoints 15
            }
            else {
                Add-Finding `
                    -Category "User Account Security" `
                    -RiskLevel "Info" `
                    -Finding "Built-in Administrator account appears disabled." `
                    -Evidence "Administrator account: $($AdministratorAccount.Name); Enabled: $($AdministratorAccount.Enabled)" `
                    -Recommendation "Keep the built-in Administrator account disabled unless specifically required." `
                    -RiskPoints 0
            }
        }
        else {
            Add-Finding `
                -Category "User Account Security" `
                -RiskLevel "Info" `
                -Finding "Built-in Administrator account was not clearly identified." `
                -Evidence "No account named Administrator or SID ending in -500 was returned." `
                -Recommednation "Manually verify the built-in Administrator account if required." `
                -RiskPoints 0
        }
    }
    catch {
        Add-Finding `
            -Category "User Account Security" `
            -RiskLevel "Info" `
            -Finding "Local user account review could not be completed." `
            -Evidence $_.Exception.Message `
            -Recommendation "Run PowerShell with appropriate permissions or manually review local users in Computer Management." `
            -RiskPoints 0
    }

    # -------------------------------
    # Local Administrators Group Review
    # -------------------------------
 
    try {
        $AdminMembers = Get-LocalGroupMember -Group "Administartors" -ErrorAction Stop   

        Add-Finding `
            -Category "Local Administrator Review" `
            -RiskLevel "Info" `
            -Finding "Local Administrators group membership collected." `
            -Evidence "Total Administrators group members: $($AdminMembers.Count)" `
            -Recommendation "Review local administrator membership regularly and remove unnecessary priviledged accounts." `
            -RiskPoints 0

        foreach ($Member in $AdminMembers) {
            Add-Finding `
                -Category "Local Administrator Review" `
                -RiskLevel "Medium" `
                -Finding "Local Administrators group member detected." `
                -Evidence "Name: $($Member.Name); ObjectClass: $($Member.ObjectClass); PrincipalSource: $($Member.PrincipalSource)" `
                -Recommendation "Confirm this administrator membership is expected and follows least -priviledge principals." `
                -RiskPoints 10
        }
    }
    catch {
        Add-Finding `
            -Category "Local Administrator Review" `
            -RiskLevel "Info" `
            -Finding "Local Administrators group review could not be completed." `
            -Evidence "$_.Exception.Message" `
            -Recommendation "Manually review the local Administrators group if needed." `
            -RiskPoints 0
    }

    # -------------------------------
    # Basic Password and Lockout Policy Review
    # -------------------------------

    try {
        $NetAccountsOutPut = net accounts
        
        if ($NetAccountsOutPut) {
            $PolicyText = ($NetAccountsOutPut -join " | ")

            Add-Finding `
                -Category "Password and Lockout Policy" `
                -RiskLevel "Info" `
                -Finding "Password and lockout policy information collected." `
                -Evidence $PolicyText `
                -Recommendation "Review password age, minimum length, and lockout policy settings for alignment with security requirements." `
                -RiskPoints 0

            $MinimumPasswordLengthLine = $NetAccountsOutPut | Where-Object { $_ -like "*Minimum password length*" }
            $LockoutThresholdLine = $NetAccountsOutPut | Where-Object { $_ -like "*Lockout threshold*" }

            if ($MinimumPasswordLengthLine -and $MinimumPasswordLengthLine -match "\d+") {
                $MinimumLength = [int]$Matches[0]

                if ($MinimumLength -lt 8) {
                    Add-Finding `
                        -Category "Password and Lockout Policy" `
                        -RiskLevel "Medium" `
                        -Finding "Minimum password length appears lower than recommended." `
                        -Evidence $MinimumPasswordLengthLine `
                        -Recommendation "Consider requiring passwords or at least 8 characters or stronger standards depedning on policy." `
                        -RiskPoints 10 
                }
            }

            if ($LockoutThresholdLine -and $LockoutThresholdLine -like "*Never*") {
                Add-Finding `
                    -Category "Password and Lockout Policy" `
                    -RiskLevel "Medium" `
                    -Finding "Account lockout threshold appears disabled." `
                    -Evidence $LockoutThresholdLine `
                    -Recommendation "Consider enabling an account lockout threshold to reduce brute-force login risk." `
                    -RiskPoints 10
            }
        }
    }
    catch {
        Add-Finding `
            -Category "Password and Lockout Policy" `
            -RiskLevel "Info" `
            -Finding "Password and Lockout Policy" `
            -Evidence $_.Exception.Message `
            -Recommendation "Manually review local password and lockout policies if needed." `
            -RiskPoints 0
    }

    Add-Finding `
        -Category "User Account Security" `
        -RiskLevel "Info" `
        -Finding "User account security and local admin review completed." `
        -Evidence "Current user admin status, local users, Administrators group, Guest account, Administrator account, and password policy were reviewed where available." `
        -Recommendation "Apply least priviledge, disable unused accounts, and review local administrator membership during ransomware readiness assessments." `
        -RiskPoints 0
}

function Run-OutlookDesktopMailboxScanModule {
    Write-SectionHeader "Outlook Desktop Read-Only Mailbox Scan Module"

    Write-Host "This module can scan recent Outlook Desktop Inbox messages in read-only mode." -ForegroundColor Yellow
    Write-Host "It will not open attachments, click links, delete emails, move emails, or send emails."
    Write-Host ""

    $RunOutlookScan = Read-Host "Do you want to run the Outlook Desktop read-only mailbox scan? Type Y to continue or N to skip"

    if ($RunOutlookScan.ToUpper() -ne "Y") {
        Add-Finding `
            -Category "Outlook Desktop Mailbox Scan" `
            -RiskLevel "Info" `
            -Finding "Outlook Desktop mailbox scan was skipped by the user." `
            -Evidence "User did not confirm Outlook Desktop scan." `
            -Recommendation "Run this module only when Outlook Desktop scan approval and scope are clear." `
            -RiskPoints 0
        
        Write-Host "Outlook Desktop mailbox scan skipped." -ForegroundColor Cyan
        return 
    }

    $MessageLimitInput = Read-Host "Enter number of recent Inbox messages to scan, or press Enter for 25"

    if ([string]::IsNullOrWhiteSpace($MessageLimitInput)) {
        $MessageLimit = 25
    }
    elseif ($MessageLimitInput -match "^\d+$") {
        $MessageLimit = [int]$MessageLimitInput
    }
    else {
        $MessageLimit = 25
    }

    if ($MessageLimit -lt 1) {
        $MessageLimit = 25
    }

    if ($MessageLimit -gt 100) {
        Write-Host "Message limit capped at 100 for safety and performance." -ForegroundColor Yellow
        $MessageLimit = 100
    }

    Write-Host "Attempting to connect to Outlook Desktop..."
    Write-Host "Message scan limit: $MessageLimit"

    $RiskyAttachmentExtensions = @(
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".ps1",
        ".zip",
        ".rar",
        ".7z",
        ".iso",
        ".img",
        ".docm",
        ".xlsm",
        ".pptm",
        ".html",
        ".htm",
        ".lnk"
    )

    $UrgentKeywords = @(
        "urgent",
        "immediately",
        "final notice",
        "expires today",
        "required immediately",
        "account locked",
        "verify your account",
        "open attachment",
        "payment is required"
    )

    $PhishingThemeKeywords = @(
        "password",
        "payroll",
        "invoice",
        "payment",
        "wire transfer",
        "account",
        "verify",
        "sign in",
        "login",
        "document shared",
        "unusual sign-in",
        "security alert"
    )

    $RansomwareKeywords = @(
        "restore files",
        "encrypted files",
        "decrypt",
        "recovery",
        "recover files",
        "restore access"
    )

    $UrlShorteners = @(
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly"
    )

    try {
        $Outlook = New-Object -ComObject Outlook.applications
        $Namespace = $Outlook.GetNamespace("MAPI")

        # olFolderInbox = 6
        $Inbox = $Namespace.GetDefaultFolder(6)
        $Items = $Inbox.items

        # Sort newest first
        $Items.Sort("[ReceivedTime]", $true)

        $ScannedCount = 0

        Write-Host "Connected to Outlook Desktop Inbox." -ForegroundColor Green

        foreach ($Message in $Items) {
            if ($ScannedCount -ge $MessageLimit) {
                break
            }

            # Only process normal mail items.
            # Outlook MailItem class = 43.
            if ($Message.Class -ne 43) {
                continue 
            }

            $ScannedCount++

            $Subject = ""
            $SenderName = ""
            $SenderEmail = ""
            $ReceivedTime = ""
            $BodyText = ""
            $HtmlText = ""
            $InternetHeaders = ""
            $ReplyToAddress = ""

            try {
                $Subject = [string]$Message.Subject
            }
            catch {
                $Subject = ""
            }

            try {
                $SenderName = [string]$Message.SenderName
            }
            catch {
                $SenderName = ""
            }

            try {
                $SenderEmail = [string]$Message.SenderEmailAddress
            }
            catch {
                $SenderEmail = ""
            }

            try {
                $ReceivedTime = [string]$Message.ReceivedTime
            }
            catch {
                $ReceivedTime = ""
            }

            try {
                $BodyText = [string]$Message.Body
            }
            catch {
                $BodyText = ""
            }

            try {
                $HtmlText = [string]$Message.HTMLBody
            }
            catch {
                $HtmlText = ""
            }

            # Try to collect transport headers when available.
            try {
                $HeaderSchema = "http://schemas.microsoft.com/mapi/proptag/0x007D001E"
                $InternetHeaders = [string]$Message.PropertyAccessor.GetProperty($HeaderSchema)
            }
            catch {
                $InternetHeaders = ""
            }

            # Try to collect Reply-To if available.
            try {
                if ($Message.ReplyRecipients.Count -gt 0) {
                    $ReplyToAddress = [string]$Message.ReplyRecipients.Item(1).Address
                }
            }
            catch {
                $ReplyToAddress = ""
            }

            $MessageLabel = "Subject: $Subject; Sender: $SenderName <$SenderEmail>; Received: $ReceivedTime" 

            $CombinedText = "$Subject $BodyText $HtmlText $InternetHeaders".ToLower() 

            # -------------------------------
            # Attachment name and extension checks
            # -------------------------------

            try {
                if ($Message.Attachments.Count -gt 0) {
                    for ($i = 1; $i -le $Message.Attachments.Count; $i++) {
                        $Attachment = $Message.Attachments.Item($i)
                        $AttachmentName = [string]$Attachment.FileName 
                        $AttachmentExtension = [System.IO.Path]::GetExtension($AttachmentName).ToLower()

                        if ($RiskyAttachmentExtensions -contains $AttachmentExtension) {
                            $RiskLevel = "Medium" 
                            $RiskPoints = 10

                            if ($AttachmentExtension -in @(".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1")) {
                                $RiskLevel = "High"
                                $RiskPoints = 20
                            }
                            elseif ($AttachmentExtension -in @(".docm", ".xlsm", ".pptm")) {
                                $RiskLevel = "High"
                                $RiskPoints = 20
                            }

                            Add-Finding `
                                -Category "Outlook Desktop Attachment Risk" `
                                -RiskLevel $RiskLevel `
                                -Finding "Risky attachment extension detected in Outlook message." `
                                -Evidence "$MessageLabel; Attachment: $AttachmentName; Extension: $AttachmentExtension" `
                                -Recommendation "Do not open unexpected attachments. Verify the sender and report suspicious attachments to IT/Security." `
                                -RiskPoints $RiskPoints
                        }
                    }
                }
            }
            catch {
                Add-Finding `
                    -Category "Outlook Desktop Attachment Risk" `
                    -RiskLevel "Info" `
                    -Finding "Attachment metadata could not be fully reviewed for one Outlook message." `
                    -Evidence "$MessageLabel; Error: $($_.Exception.Message)" `
                    -Recommendation "Manually review attachment metadata if needed." `
                    -RiskPoints 0
            }

            # -------------------------------
            # Link extraction and suspicious link checks
            # -------------------------------

            $LinkMatches = @()

            try {
                $LinkMatches += [regex]::Matches($BodyText, 'https?://[^\s"<>]+') 
                $LinkMatches += [regex]::Matches($HtmlText, 'https?://[^\s"<>]+') 
            }
            catch {
                $LinkMatches = @()
            }

            $UniqueLinks = @()

            foreach ($Match in $LinkMatches) {
                if ($Match.Value -and ($UniqueLinks -notcontains $Match.Value)) {
                    $UniqueLinks += $Match.Value
                }
            }

            if ($UniqueLinks.Count -gt 5) {
                Add-Finding `
                    -Category "Outlook Desktop Link Risk" `
                    -RiskLevel "Medium" `
                    -Finding "Multiple links detected in Outlook message." `
                    -Evidence "$MessageLabel; Link count: $($UniqueLinks.Count)" `
                    -Recommendation "Review messages with multiple links carefully before clicking." `
                    -RiskPoints 5
            }

            foreach ($Link in $UniqueLinks) {
                $LinkLower = $Link.ToLower()

                if ($LinkLower.StartWith("http://")) {
                    Add-Finding `
                        -Category "Outlook Desktop Link Risk" `
                        -RiskLevel "Medium" `
                        -Finding "HTTP link detected in Outlook message." `
                        -Evidence "$MessageLabel; Link: $Link" `
                        -Recommendation "Use caution with non-HTTPS links. Do not click suspicious links without verification." `
                        -RiskPoints 10
                }

                if ($LinkLower -match '^https?://\d{1,3}(\.\d{1,3}){3}') {
                    Add-Finding `
                        -Category "Outlook Desktop Link Risk" `
                        -RiskLevel "High" `
                        -Finding "IP-address-based link detected in Outlook message." `
                        -Evidence "$MessageLabel; Link: $Link" `
                        -Recommendation "Treat IP-address-based email links as suspicious and report them for review." `
                        -RiskPoints 20
                }

                foreach ($Shortener in $UrlShorteners) {
                    if ($LinkLower -like "*$Shortener*") {
                        Add-Finding `
                            -Category "Outlook Desktop Link Risk" `
                            -RiskLevel "Medium" `
                            -Finding "URL shortener detected in Outlook message." `
                            -Evidence "$MessageLabel; Link: $Link; Shortener: $Shortener" `
                            -Recommendation "Avoid clicking shortened URLs in unexpected emails. Verify the destination with IT/security." `
                            -RiskPoints 10
                    }
                }

                if ($Link.Length -gt 120) {
                    Add-Finding `
                        -Category "Outlook Desktop Link Risk" `
                        -RiskLevel "Medium" `
                        -Finding "Very long URL detected in Outlook message." `
                        -Evidence "$MessageLabel; URL length: $($Link.Length)" `
                        -Recommendation "Review long URLs carefully because they may hide suspicious parameters or redirects." `
                        -RiskPoints 5
                }
            }

            # -------------------------------
            # Urgent language checks
            # -------------------------------

            foreach ($Keyword in $UrgentKeywords) {
                if ($CombinedText -like "*$Keyword*") {
                    Add-Finding `
                        -Category "Outlook Desktop Language Risk" `
                        -RiskLevel "Medium" `
                        -Finding "Urgent or pressure-based language detected in Outlook message." `
                        -Evidence "$MessageLabel; Keyword: $Keyword" `
                        -Recommendation "Treat urgent messages requesting action, payment, password reset, or attachment opening with caution." `
                        -RiskPoints 5
                }
            }

            # -------------------------------
            # Phishing theme checks
            # -------------------------------

            foreach ($Keyword in $PhishingThemeKeywords) {
                if ($CombinedText -like "*$Keyword*") {
                    Add-Finding `
                        -Category "Outlook Desktop Phishing Theme" `
                        -RiskLevel "Medium" `
                        -Finding "Common phishing theme keyword detected in Outlook message." `
                        -Evidence "$MessageLabel; Keyword: $Keyword" `
                        -Recommendation "Review the message context, sender, attachments, and links before taking action." `
                        -RiskPoints 3
                }
            }

            # -------------------------------
            # Ransomware wording checks
            # -------------------------------

            foreach ($Keyword in $RansomwareKeywords) {
                if ($CombinedText -like "*$Keyword*") {
                    Add-Finding `
                        -Category "Outlook Desktop Ransomware Indicator" `
                        -RiskLevel "High" `
                        -Finding "Ransomware-related wording detected in Outlook message." `
                        -Evidence "$MessageLabel; Keyword: $Keyword" `
                        -Recommendation "Treat ransomware-related wording as high priority. Do not click links or open attachments. Escalate Immediately." `
                        -RiskPoints 20
                }
            }

            # -------------------------------
            # Reply-To mismatch check
            # -------------------------------

            if ($SenderEmail -and $ReplyToAddress -and ($SenderEmail.ToLower() -ne $ReplyToAddress.ToLower())) {
                Add-Finding `
                    -Category "Outlook Desktop Header Indicator" `
                    -RiskLevel "Medium" `
                    -Finding "Sender email and Reply-To mismatch detected in Outlook message." `
                    -Evidence "$MessageLabel; Reply-To: $ReplyToAddress" `
                    -Recommendation "Review Reply-To mismatches because attackers may redirect responses." `
                    -RiskPoints 10
            }

            # -------------------------------
            # Header authentication keyword checks
            # -------------------------------

            if ($InternetHeaders) {
                $HeadersLower = $InternetHeaders.ToLower()

                if ($HeadersLower -like "*spf=fail*" -or $HeadersLower -like "*dmarc=fail*") {
                    Add-Finding `
                        -Category "Outlook Desktop Header Indicator" `
                        -RiskLevel "High" `
                        -Finding "Email authentication failure detected in Outlook message headers." `
                        -Evidence "$MessageLabel; Header Indicator included SPF or DMARC failure." `
                        -Recommendation "Review messages with SPF or DMARC failures carefully and confirm legitimacy before interacting." `
                        -RiskPoints 20
                }
                elseif ($HeadersLower -like "*spf=softfail*") {
                    Add-Finding `
                        -Category "Outlook Desktop Header Indicator" `
                        -RiskLevel "Medium" `
                        -Finding "Email authentication softfail detected in Outlook message headers." `
                        -Evidence "$MessageLabel; Header indicator included SPF softfail." `
                        -Recommendation "Review softfail messages because they may indicate questionable sender authorization." `
                        -RiskPoints 10
                }
            }
        }

        Add-Finding `
            -Category "Outlook Desktop Mailbox Scan" `
            -RiskLevel "Info" `
            -Finding "Outlook Desktop read-only mailbox scan completed." `
            -Evidence "Inbox messages scanned: $ScannedCount; Message limit: $MessageLimit" `
            -Recommendation "Review Outlook Desktop findings and validate suspicious messages before taking action." `
            -RiskPoints 0
        
        Write-Host "Outlook Desktop read-only mailbox scan completed." -ForegroundColor Green
        Write-Host "Inbox messages scanned: $ScannedCount"
    }
    catch {
        Add-Finding `
            -Category "Outlook Desktop Mailbox Scan" `
            -RiskLevel "Info" `
            -Finding "Outlook Desktop mailbox scan could not be completed." `
            -Evidence "$_.Exception.Message" `
            -Recommendation "Confirm Outlook Desktop is installed, configured, and accessible. If unavailable, use the CSV phishing scanner module instead." `
            -RiskPoints 0 .\Documentation

        Write-Host "Outlook Desktop mailbox could not be completed." -ForegroundColor Yellow 
        Write-Host $_.Exception.Message
    }
}

# -------------------------------
# Main Scanner Execution
# -------------------------------

Show-ScannerBanner

Start-Transcript -Path $RunLogFile -Append | Out-Null

try {
    Initialize-Report

    Run-SystemInformationModule
    Run-EndpointProtectionDetectionModule
    Run-WindowsDefenderStatusModule
    Run-SophosDetectionModule
    Run-FirewallStatusModule
    Run-SuspiciousFileIndicatorModule
    Run-OutlookCsvPhishingIndicatorModule
    Run-OutlookDesktopMailboxScanModule
    Run-StartupPersistenceReviewModule
    Run-BackupRecoveryReadinessModule
    Run-UserAccountSecurityModule
    Run-ScannerFrameworkTest

    Export-Findings
    Finalize-Report

    Write-SectionHeader "Scan Complete"

    $OverallRiskLevel = Get-RiskLevelFromScore -Score $GlobalRiskScore
    $CriticalCount = Get-FindingCountByRiskLevel -RiskLevel "Critical"
    $HighCount = Get-FindingCountByRiskLevel -RiskLevel "High"
    $MediumCount = Get-FindingCountByRiskLevel -RiskLevel "Medium"
    $LowCount = Get-FindingCountByRiskLevel -RiskLevel "Low"
    $InfoCount = Get-FindingCountByRiskLevel -RiskLevel "Info"

    Write-Host "Overall Risk Score: $GlobalRiskScore"
    Write-Host "Overall Risk Level: $OverallRiskLevel"
    Write-Host "Total Findings: $($Findings.Count)"
    Write-Host "Critical Findings: $CriticalCount"
    Write-Host "High Findings: $HighCount"
    Write-Host "Medium Findings: $MediumCount"
    Write-Host "Low Findings: $LowCount" 
    Write-Host "Informational Findings: $InfoCount"
    Write-Host ""
    Write-Host "TXT Report Created:" -ForegroundColor Green
    Write-Host $ReportFile
    Write-Host ""
    Write-Host "CSV Findings Created:" -ForegroundColor Green
    Write-Host $FindingsCsv
    Write-Host ""
    Write-Host "Run Log Created:" -ForegroundColor Green
    Write-Host $RunLogFile
}
catch {
    Write-Host "An error occurred while running the scanner." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
finally {
    Stop-Transcript | Out-Null
}

            



        
    


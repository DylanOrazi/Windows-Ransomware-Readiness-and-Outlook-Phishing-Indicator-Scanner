WINDOWS RANSOMWARE READINESS AND OUTLOOK PHISHING INDICATOR SCANNER

PROJECT OVERVIEW

The Windows Ransomware Readiness and Outlook Phishing Indicator Scanner is a defensive PowerShell security assessment tool designed to evaluate a Windows computer for ransomware-related weaknesses, suspicious system indicators, phishing risks, and recovery readiness.

The scanner performs a collection of read-only security checks covering endpoint protection, Microsoft Defender settings, Windows Firewall, suspicious files, startup persistence, user accounts, backup and recovery capabilities, Outlook phishing indicators, and other security-related areas.

The project also includes phishing-analysis features that can inspect sample Outlook message data, suspicious links, attachment extensions, and potentially dangerous language patterns.

Results are organized into detailed findings, risk levels, summary statistics, CSV exports, TXT reports, and a complete execution log.

This project was developed in Visual Studio Code using PowerShell.

PROJECT PURPOSE

The purpose of this project is to demonstrate how PowerShell can be used to automate practical cybersecurity assessments on Windows systems.

The scanner was designed to help answer questions such as:

Is antivirus or endpoint protection installed and active?
Is Microsoft Defender real-time protection enabled?
Is Windows Firewall enabled?
Are important ransomware-protection features configured?
Are suspicious file types present in common user folders?
Are unusual startup or persistence indicators present?
Are local administrator accounts properly identified?
Are backups, restore points, or recovery protections available?
Do sample email messages contain common phishing indicators?
Do email attachments use high-risk file extensions?
Are suspicious or misleading links present?
Is classic Outlook available for optional desktop mailbox analysis?
What is the overall security risk level of the computer?

KEY FEATURES
System Information Collection

The scanner collects basic information about the computer being assessed, including:

Computer name
Current username
Windows edition
Windows version
Operating system build
PowerShell version
Scan date and time
Endpoint Protection Detection

The scanner checks for registered antivirus and endpoint-protection products.

It can identify security products such as:

Microsoft Defender Antivirus
Sophos Endpoint
Other antivirus products registered with Windows Security Center

The scanner records whether endpoint protection appears to be installed and available.

Microsoft Defender Security Checks

The scanner evaluates Microsoft Defender settings where available, including:

Antivirus status
Real-time protection
Behavior monitoring
Download scanning
Script scanning
Cloud-delivered protection
Tamper-protection information
Potentially unwanted application protection
Controlled Folder Access status
Defender service availability

Some settings may be controlled by another endpoint-protection platform, organizational policy, or the Windows edition installed on the device.

Sophos Detection

The scanner checks for signs that Sophos security software is installed.

Detection may include:

Installed applications
Windows services
Common Sophos installation directories
Endpoint-protection registration

The module is informational and does not attempt to modify or control Sophos.

Windows Firewall Checks

The scanner checks the status of Windows Firewall profiles, including:

Domain profile
Private profile
Public profile

Disabled firewall profiles are recorded as security findings.

Ransomware Protection Assessment

The scanner evaluates several Windows security features related to ransomware readiness, including:

Microsoft Defender protection status
Controlled Folder Access
Endpoint-protection availability
Firewall status
Backup readiness
Restore-point availability
Shadow-copy information
Recovery-related settings

These checks help identify whether the system has multiple defensive and recovery layers.

Suspicious File Indicator Scan

The scanner searches selected user-accessible locations for files that may require review.

Examples include files with extensions commonly associated with:

Scripts
Executables
Installers
Shortcut abuse
Command files
Registry modifications
Macro-enabled documents
Disk images
Compressed archives
Potential ransomware notes

The scanner does not delete, quarantine, open, or execute files.

A flagged file is not automatically considered malicious. The result only indicates that the file may deserve additional investigation.

Outlook CSV Phishing Analysis

The project includes a phishing-analysis module that examines sample Outlook-style message data stored in CSV format.

The analysis can identify indicators such as:

Urgent or threatening language
Password-reset requests
Account-verification requests
Payment or invoice language
Requests to open an attachment
Requests to click a link
Suspicious sender information
Mismatched sender domains
Unusual attachment extensions
Potential impersonation language
Multiple indicators appearing in one message

Each message can receive a risk rating based on the indicators detected.

Suspicious Link Analysis

The scanner evaluates links and URL examples for common warning signs, including:

IP-address-based links
URL-shortening services
Unusual domain structures
Excessive subdomains
Suspicious keywords
Non-secure HTTP links
Misleading domain names
Encoded or obfuscated characters
Links containing unexpected login or verification terms

The module is intended for defensive awareness and does not visit the links.

Risky Attachment Analysis

The scanner compares attachment names and extensions against a list of potentially dangerous file types.

Examples may include:

.exe
.scr
.bat
.cmd
.com
.js
.vbs
.ps1
.msi
.hta
.lnk
.reg
.iso
.img
.docm
.xlsm

Attachments are analyzed by filename and extension only. The scanner does not open or execute them.

Startup and Persistence Review

The scanner reviews common Windows persistence locations, including:

Current-user startup entries
Local-machine startup entries
Startup folders
Run registry keys
Selected scheduled-task information
Common autorun indicators

Results are intended to support manual security review.

A startup entry is not automatically malicious. Many legitimate applications use startup locations.

Backup and Recovery Readiness

The scanner checks for recovery-related protections where available, including:

Windows restore points
Volume Shadow Copy information
Backup-related services
File History information
Recovery configuration
Available recovery indicators

The module identifies whether recovery options appear to exist but does not create, delete, or modify backups.

User Account Security Review

The scanner evaluates local account information, including:

Local user accounts
Enabled and disabled accounts
Local administrator membership
Password-related account properties
Guest-account information
Potentially unnecessary administrator access

The module is read-only and does not change account settings.

Outlook Desktop Mailbox Module

The project includes an optional Outlook Desktop module that attempts to connect to the locally installed classic Microsoft Outlook application through the Outlook COM interface.

When classic Outlook is available, the module can support read-only mailbox analysis for phishing indicators.

The module does not:

Send email
Reply to messages
Delete messages
Move messages
Download or execute attachments
Change mailbox settings

IMPORTANT OUTLOOK COMPATIBILITY NOTE

The Outlook Desktop module requires classic Microsoft Outlook.

The new Outlook application does not provide the traditional Outlook COM interface used by this scanner.

During testing on a computer using new Outlook, the module returned the following COM registration error:

80040154 Class not registered

This result indicates an Outlook compatibility limitation rather than a failure of the rest of the scanner.

The main scanner continues to operate, and the CSV-based phishing-analysis features remain available.

The Outlook Desktop module may be more fully tested or used on a compatible computer with classic Outlook installed and configured.

Risk Scoring

The scanner assigns risk levels to findings based on their potential security significance.

Possible classifications include:

Low
Informational
Medium
High
Critical

The overall result is calculated from the findings produced during the scan.

Examples of higher-risk findings may include:

No active antivirus protection
Disabled firewall profiles
Disabled real-time protection
Missing recovery options
High-risk phishing indicators
Suspicious attachment types
Multiple security weaknesses occurring together

Informational findings and unsupported features should not automatically be treated as security failures.

Report Generation

The scanner produces organized reports that can be reviewed outside the PowerShell console.

Depending on the completed scan, outputs may include:

Detailed findings CSV
Security summary CSV
TXT security report
Scan execution log
Outlook phishing-analysis results
Suspicious file results
Risk-scoring summary

Reports use timestamped filenames to prevent previous results from being overwritten.

TEST DATA

The project includes controlled test data for safely demonstrating phishing and suspicious-file detection.

Test data may include:

Sample email subjects
Sample sender addresses
Sample message bodies
Safe examples of suspicious-looking links
Safe attachment filenames
High-risk attachment extensions
Benign and suspicious indicator combinations
Empty or low-risk message examples

The test files are intended only to verify detection logic.

No malware, ransomware, credential-stealing software, or executable attack payloads are included.

SAFETY DESIGN

This project was designed as a defensive and read-only security tool.

The scanner does not:

Encrypt files
Delete files
Quarantine files
Modify registry settings
Disable security software
Change firewall settings
Modify Microsoft Defender settings
Create persistence
Execute suspicious files
Open suspicious links
Send email
Delete email
Modify Outlook messages
Change local user accounts
Create or remove administrator accounts
Create or delete restore points
Delete shadow copies
Simulate ransomware behavior

Potentially suspicious items are reported for manual review only.

SYSTEM REQUIREMENTS

Recommended environment:

Windows 10 or Windows 11
Windows PowerShell 5.1 or PowerShell 7
Visual Studio Code
PowerShell extension for Visual Studio Code
Permission to run local PowerShell scripts
Administrator privileges for checks that require elevated access

Optional requirement:

Classic Microsoft Outlook for Outlook Desktop COM mailbox analysis

New Outlook is not supported by the Outlook COM module.

HOW TO RUN THE PROJECT

METHOD 1: RUN FROM VISUAL STUDIO CODE

Open Visual Studio Code.
Open the project folder.
Open the main PowerShell scanner script from the PowerShell folder.
Open a PowerShell terminal in Visual Studio Code.
Run Visual Studio Code as Administrator when performing checks that require elevated permissions.
Navigate to the folder containing the script.

Example:

cd "C:\Path\To\Project\PowerShell"

Run the script.

Example:

.\RansomwareReadinessScanner.ps1

Use the actual script filename if it is different.

Allow the scanner to complete all available modules.
Review the final console summary.
Open the Reports and Exports folders to review the generated output files.

METHOD 2: RUN FROM POWERSHELL

Open Windows PowerShell.
Run PowerShell as Administrator when possible.
Navigate to the PowerShell script folder.
Run the script using:

.\RansomwareReadinessScanner.ps1

POWERSHELL EXECUTION POLICY

If Windows prevents the script from running, the following command can temporarily allow scripts in the current PowerShell session:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

This setting applies only to the current PowerShell process.

After setting the temporary execution policy, run the scanner again.

ADMINISTRATOR PRIVILEGES

The scanner can perform many checks without administrator privileges.

However, some information may be incomplete or unavailable unless PowerShell or Visual Studio Code is run as Administrator.

Elevated access may improve checks involving:

Microsoft Defender
Security services
Firewall configuration
Scheduled tasks
Local accounts
Restore points
Shadow copies
System-wide startup locations
Installed security products

The scanner should report unavailable checks rather than attempting to bypass access controls.

EXPECTED OUTPUT

During execution, the console displays the progress of each security module.

The output may include labels such as:

PASS
INFO
WARNING
HIGH
CRITICAL
SKIPPED
NOT AVAILABLE

At the end of the scan, a summary may display:

Computer name
Scan date
Total findings
Passed checks
Informational findings
Warning count
High-risk findings
Critical findings
Overall risk score
Overall readiness status
Report output locations
REPORT REVIEW

Generated reports should be reviewed as security-assessment evidence rather than as a final malware diagnosis.

A finding may require additional investigation because:

Legitimate software can use script or executable files
Legitimate applications can create startup entries
Organizational policies can disable or replace Windows Defender features
Third-party endpoint protection can manage security settings
Backup features may be handled by an external platform
Some Windows features vary by edition
New Outlook does not support classic Outlook COM automation
Administrator permissions can affect available results

The scanner identifies indicators and configuration concerns. It does not replace professional incident-response tools, endpoint detection and response platforms, antivirus products, or forensic analysis.

TESTING COMPLETED

The project was tested on a Windows computer using Visual Studio Code and PowerShell.

Testing included:

Successful scanner startup
System-information collection
Endpoint-protection detection
Microsoft Defender checks
Sophos-awareness checks
Windows Firewall review
Ransomware-readiness checks
Suspicious-file analysis
CSV-based Outlook phishing analysis
Suspicious-link detection
Risky attachment detection
Startup and persistence review
Backup and recovery checks
Local user-account review
Risk scoring
CSV report generation
TXT report generation
Scan logging
Outlook Desktop COM connection attempt
Safe handling of unsupported or unavailable features
End-to-end report review

The Outlook Desktop module was tested through its COM connection attempt.

The testing computer used new Outlook, which returned error 80040154 because the classic Outlook COM class was not registered.

Full mailbox scanning requires testing on a computer with classic Outlook.

LIMITATIONS

Known limitations include:

Outlook Desktop analysis requires classic Outlook.
New Outlook does not support the COM interface used by the scanner.
Some Microsoft Defender settings may be unavailable when another antivirus product is active.
Some security checks require administrator privileges.
Certain Windows features differ between Windows editions.
Restore points may be disabled by default.
Shadow-copy information may not be available on every system.
Startup entries require manual review to determine whether they are legitimate.
Suspicious file extensions do not prove that a file is malicious.
URL analysis is based on indicators and patterns rather than live reputation services.
The scanner does not perform attachment sandboxing.
The scanner does not perform malware signature scanning.
The scanner does not connect to commercial threat-intelligence services.
Email risk scores are indicators and should be reviewed by a person.
Results represent the system at the time the scan was performed.
PRIVACY CONSIDERATIONS

Before sharing reports or screenshots publicly, review them for sensitive information.

Potentially sensitive information may include:

Computer names
Usernames
Email addresses
Email subjects
Employee names
Organization names
Local file paths
IP addresses
Domain names
Installed software
Local account names
Internal folder names
Security-product details

Portfolio screenshots and sample reports should use test data or redacted information.

SCREENSHOTS

The Screenshots folder contains selected evidence demonstrating the completed project.

Screenshots may include:

Project folder structure
Main PowerShell script
Scanner startup
Windows security checks
Ransomware-readiness findings
Suspicious-file results
Phishing-analysis results
Outlook Desktop compatibility result
Final risk summary
CSV reports
TXT reports
Generated report files
SKILLS DEMONSTRATED

This project demonstrates experience with:

PowerShell scripting
Windows security assessment
Cybersecurity automation
Ransomware-readiness analysis
Microsoft Defender inspection
Windows Firewall inspection
Endpoint-protection detection
Sophos awareness
Suspicious-file analysis
Phishing-indicator detection
Email security concepts
URL analysis
Attachment-risk analysis
Outlook COM automation
Windows startup and persistence review
Local account auditing
Backup and recovery assessment
Risk scoring
Error handling
CSV processing
CSV exports
TXT report generation
Execution logging
Test-data creation
Defensive security design
Technical documentation
Visual Studio Code
Safe tool development

DISCLAIMER

This project is intended for educational, defensive, administrative, and portfolio purposes.

Run the scanner only on computers and accounts that you own or are authorized to assess.

The results should not be treated as proof that a computer is secure, compromised, infected, or free of malware.

Security findings should be reviewed in context by an authorized IT or cybersecurity professional.


# Windows Ransomware Readiness and Outlook Phishing Indicator Scanner

## Overview

A defensive PowerShell security assessment tool designed to evaluate Windows systems for ransomware-related weaknesses, phishing indicators, suspicious files, persistence risks, endpoint protection status, and recovery readiness.

The scanner performs read-only checks and produces structured findings, risk scores, CSV exports, TXT reports, and execution logs.

Built with PowerShell in Visual Studio Code.

---

## Key Features

- Windows system information collection
- Antivirus and endpoint-protection detection
- Microsoft Defender security checks
- Windows Firewall review
- Ransomware-readiness assessment
- Suspicious file indicator scanning
- Startup and persistence review
- Local administrator and user-account auditing
- Backup, restore point, and recovery checks
- Outlook-style phishing analysis using sample CSV data
- Suspicious URL and attachment detection
- Optional classic Outlook COM analysis
- Risk scoring and summary reporting
- CSV and TXT report generation
- Execution logging

---

## Phishing Analysis

The scanner can analyze controlled sample email data for indicators such as:

- Urgent or threatening language
- Password or account-verification requests
- Suspicious sender information
- Mismatched domains
- Risky attachment extensions
- Suspicious URLs
- Payment or invoice language
- Multiple indicators within one message

The scanner does not open links or execute attachments.

---

## Ransomware Readiness Checks

The tool evaluates security and recovery areas including:

- Endpoint protection
- Microsoft Defender configuration
- Windows Firewall
- Controlled Folder Access
- Suspicious files
- Startup persistence
- Local administrator accounts
- Restore points
- Shadow copies
- Backup and recovery indicators

---

## Outlook Compatibility

The optional Outlook Desktop module requires **classic Microsoft Outlook** and uses the Outlook COM interface.

New Outlook does not support this interface.

During testing with new Outlook, the module returned:

`80040154 - Class not registered`

This does not prevent the rest of the scanner from running. CSV-based phishing analysis remains available.

---

## Test Data

This repository includes controlled sample files and sample email data used to demonstrate the scanner's detection logic.

These test findings are for demonstration purposes and do **not** necessarily indicate real threats on the computer running the scanner.

No malware, ransomware, credential-stealing software, or executable attack payloads are included.

---

## Safety Design

The scanner is designed to be defensive and read-only.

It does **not**:

- Delete or quarantine files
- Modify registry settings
- Disable security software
- Change firewall settings
- Modify Microsoft Defender
- Create persistence
- Execute suspicious files
- Open suspicious links
- Modify email messages
- Change user accounts
- Delete restore points or shadow copies
- Simulate ransomware behavior

Suspicious items are reported for manual review only.

---

## Requirements

Recommended environment:

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or PowerShell 7
- Administrator privileges for some system checks

Optional:

- Classic Microsoft Outlook for Outlook COM analysis

---

## How to Run

1. Download and extract the project.
2. Open the `PowerShell` folder.
3. Open PowerShell in that folder by typing in `PowerShell` in the address bar.
4. If script execution is blocked, temporarily allow scripts for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

./ransomware_phishing_scanner.ps1

Then click enter to run.

### PowerShell Compatibility

- Supports Windows 10 and Windows 11.
- Designed for Windows PowerShell 5.1.
- Some system checks may require administrator privileges.
- Run the scanner only on systems you own or are authorized to inspect.

### Outlook Desktop Mailbox Scanning

The optional Outlook Desktop module scans recent Inbox messages in read-only mode using Microsoft Outlook COM automation.

**Requirements:**

- Classic Microsoft Outlook must be installed and configured.
- An accessible Outlook mailbox is required.
- Windows PowerShell 5.1 is recommended for Outlook COM integration.

### Why New Outlook Is Not Supported

Classic Outlook supports COM automation, allowing PowerShell to access mailbox information through the Outlook Object Model.

New Outlook for Windows does not support this legacy COM interface. As a result, direct mailbox scanning currently requires Classic Outlook.

Support for New Outlook could be explored in the future using Microsoft Graph API with appropriate authentication and permissions.

The CSV-based phishing indicator scanner works independently of the installed Outlook version.

### Known Outlook Compatibility Issue

On some systems, the Outlook mailbox module may display:

`0x80040154 - Class not registered`

This indicates that a required COM component could not be initialized.

During compatibility testing, direct PowerShell access to Outlook and the Inbox succeeded, but the scanner's Outlook module still encountered this error. The root cause has not yet been determined.

Users can skip the optional Outlook module and continue with the other scanning features.

### Scheduled Task Inspection

The startup and persistence module may display:

`Scheduled task review could not be completed.`

Possible causes include permission restrictions, system configuration differences, or execution errors. Other startup and registry checks may still complete successfully.

### General Notes

- This project is intended for defensive cybersecurity education and security readiness assessments.
- Detected indicators do not automatically confirm malicious activity.
- The scanner does not automatically remove threats or modify suspicious emails.
- Results may vary depending on Windows configuration, permissions, and installed software.

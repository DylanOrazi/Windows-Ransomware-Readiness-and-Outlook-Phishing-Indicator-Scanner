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


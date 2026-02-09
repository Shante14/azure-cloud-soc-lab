# azure-cloud-soc-lab
Azure-based cloud security operations lab implementing SIEM deployment, threat detection, and incident analysis using Microsoft Sentinel.
Add architecture, detection queries, and incident report
Azure Cloud SOC Lab
Overview

This project demonstrates the deployment of a cloud-based Security Operations Center (SOC) environment using Microsoft Azure and Microsoft Sentinel. The lab simulates real-world attack traffic against a publicly exposed virtual machine and analyzes security events using SIEM capabilities.

The objective was to gain hands-on experience in:

Cloud security monitoring

Log ingestion and normalization

Threat detection using KQL

Brute-force attack analysis

Incident documentation and remediation planning

Architecture Overview
Environment Components

Azure Virtual Machine (Windows)

Public IP Address (RDP enabled for lab testing)

Network Security Group (NSG)

Log Analytics Workspace

Microsoft Sentinel (SIEM)

Data Flow

Internet → Azure Public IP → Windows VM → Security Event Logs → Log Analytics Workspace → Microsoft Sentinel → Detection Queries → Incident Investigation

Detection Scenario: RDP Brute-Force Attack
Objective

Detect high-volume failed login attempts indicative of automated brute-force behavior.

Key Log Source

Event ID 4625 – Failed Login Attempts

Detection Queries
Brute-Force Spike Detection
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 50
| sort by FailedAttempts desc

Top Attacking IP Addresses
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IPAddress
| sort by Attempts desc

Username Targeting Analysis
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by TargetUserName
| sort by Attempts desc

Investigation Findings

Detected over 1,000 failed login attempts within minutes

Observed repeated targeting of administrative usernames

Identified multiple international source IP addresses

Activity consistent with automated brute-force attack behavior

Risk Assessment

High Public-facing RDP endpoints are frequently targeted by automated credential attacks.

Remediation Recommendations

Remove direct public RDP exposure

Implement Azure Bastion for secure remote access

Enforce Multi-Factor Authentication (MFA)

Restrict inbound traffic using NSG rules

Implement account lockout thresholds

Skills Demonstrated

SIEM deployment and configuration

Azure log ingestion and monitoring

KQL query development

Threat detection and event correlation

Incident triage documentation

Cloud security best practices

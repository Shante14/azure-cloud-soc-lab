# Azure Cloud SOC Lab

Azure-based cloud security operations lab implementing SIEM deployment, threat detection, and incident analysis using Microsoft Sentinel.

---

## Overview

This project demonstrates the deployment of a cloud-based Security Operations Center (SOC) environment using Microsoft Azure and Microsoft Sentinel.

The lab simulates real-world attack traffic against a publicly exposed virtual machine and analyzes security events using SIEM capabilities.

### Objectives

- Cloud security monitoring  
- Log ingestion and normalization  
- Threat detection using KQL  
- Brute-force attack analysis  
- Incident documentation and remediation planning  

---

## Architecture Overview

### Environment Components

- Azure Virtual Machine (Windows)
- Public IP Address (RDP enabled for lab testing)
- Network Security Group (NSG)
- Log Analytics Workspace
- Microsoft Sentinel (SIEM)

### Data Flow

Internet → Azure Public IP → Windows VM → Security Event Logs → Log Analytics Workspace → Microsoft Sentinel → Detection Queries → Incident Investigation

---

## Detection Scenario: RDP Brute-Force Attack

### Objective

Detect high-volume failed login attempts indicative of automated brute-force behavior.

### Key Log Source

- Event ID 4625 – Failed Login Attempts

---

## Detection Queries

### Brute-Force Spike Detection

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 50
| sort by FailedAttempts desc

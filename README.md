# SOC Analyst - Log Analysis & Threat Detection Platform

## Overview

SOC Analyst is a cybersecurity-focused Security Operations Center (SOC) simulation platform designed to analyze security logs, detect suspicious authentication activity, and generate actionable security alerts.

### Current Support

- ✅ Linux Authentication Logs

### Planned Support

- 🚧 Web Access Logs *(Coming Soon)*
- 🚧 Firewall Logs *(Coming Soon)*

The current version focuses on Linux SSH authentication logs, parsing login events, detecting authentication-based attacks, and generating alerts mapped to the MITRE ATT&CK framework.

This project was built to demonstrate:

- SOC analyst fundamentals
- Security event parsing
- Threat detection logic
- Alert generation workflows
- MITRE ATT&CK mapping
- Backend security engineering concepts

---

# Features

## Linux Authentication Log Parsing

### Example

```text
May 27 10:15:01 ubuntu sshd[1234]: Failed password for root from 192.168.1.20 port 45522 ssh2
```

### Extracted Fields

- Timestamp
- Hostname
- Service Name
- Process ID (PID)
- Event Type
- Username
- Source IP Address
- Port Number
- Authentication Protocol

---

## Supported Log Sources

| Log Source | Status |
|------------|--------|
| Linux Authentication Logs | ✅ Supported |
| Web Access Logs | 🚧 Planned |
| Firewall Logs | 🚧 Planned |

---

# Detection Rules

| Rule ID | Rule Name | Description | Severity |
|---------|-----------|-------------|----------|
| AUTH-001 | Brute Force Detection | Detects repeated failed login attempts against the same user from a single source IP within a defined time window. | High |
| AUTH-002 | Root Login Attempt | Detects login attempts targeting the local **root** account. | Medium |
| AUTH-003 | Success After Failures | Detects a successful login following multiple failed authentication attempts, indicating a potentially compromised account. | Critical |
| AUTH-004 | Invalid User Scanning | Detects repeated authentication attempts using non-existent usernames, indicating username enumeration or account discovery. | Medium |

---

# Severity Levels

| Detection Rule | Severity |
|----------------|----------|
| Brute Force Detection | High |
| Root Login Attempt | Medium |
| Success After Failures | Critical |
| Invalid User Scanning | Medium |

---

# MITRE ATT&CK Mapping

| Detection Scenario | MITRE ATT&CK ID | Technique |
|--------------------|-----------------|-----------|
| Brute Force Detection (Failed Attempts) | T1110 | Brute Force |
| Distributed Brute Force Detection (Failed Attempts) | T1110 | Brute Force |
| Invalid User Scanning | T1087 | Account Discovery |
| Root Login Attempt | T1078.003 | Valid Accounts: Local Accounts |
| Successful Brute Force Attack (Non-root Account) | T1078 | Valid Accounts |
| Successful Brute Force Attack (Root Account) | T1078.003 | Valid Accounts: Local Accounts |
| Successful Distributed Brute Force Attack (Non-root Account) | T1078 | Valid Accounts |
| Successful Distributed Brute Force Attack (Root Account) | T1078.003 | Valid Accounts: Local Accounts |

---

# Project Architecture

```text
Log File Upload
        ↓
Linux Authentication Parser
        ↓
Event Normalization
        ↓
Detection Engine
        ↓
Threat Correlation
        ↓
Alert Generation
        ↓
SOC Dashboard
```

---

# Example Parsed Event

```json
{
  "raw_log": "May 27 10:15:01 ubuntu sshd[1234]: Failed password for root from 192.168.1.20 port 45522 ssh2",
  "log_type": "LINUX_AUTH",
  "timestamp": "May 27 10:15:01",
  "timestamp_iso": "2026-05-27T10:15:01Z",
  "host": "ubuntu",
  "service": "sshd",
  "pid": 1234,
  "event": "FAILED_LOGIN",
  "user": "root",
  "source_ip": "192.168.1.20",
  "port": 45522,
  "protocol": "ssh2"
}
```

---

# Example Alert Metadata

```json
{
  "key": "192.168.1.20",
  "alert_id": "ALT-1001",
  "alert_type": "BRUTE_FORCE_ATTACK",
  "rule_id": "AUTH-001",
  "rule_name": "Brute Force Detection",
  "severity": "HIGH",
  "risk_score": 85,
  "status": "OPEN",
  "source_ip": "192.168.1.20",
  "user": "root",
  "host": "ubuntu",
  "service": "sshd",
  "pid": 1234,
  "port": 45522,
  "protocol": "ssh2",
  "mitre_technique": "T1110",
  "mitre_name": "Brute Force",
  "created_at": "2026-07-13T09:10:49Z",
  "failed_attempts": 8,
  "starting_time": "2026-07-13T09:10:01Z",
  "ending_time": "2026-07-13T09:10:48Z"
}
```

### Alert Fields

| Field | Description |
|-------|-------------|
| `key` | Correlation key used by the detection engine |
| `alert_id` | Unique identifier for the generated alert |
| `alert_type` | Type of detected security event |
| `rule_id` | Detection rule identifier |
| `rule_name` | Detection rule name |
| `severity` | Alert severity |
| `risk_score` | Calculated risk score based on attack characteristics |
| `status` | Current alert status |
| `source_ip` | Attacker's IP address |
| `user` | Target username |
| `host` | Target host |
| `service` | Service generating the event (e.g., `sshd`) |
| `pid` | Process ID |
| `port` | Network port |
| `protocol` | Authentication protocol |
| `mitre_technique` | MITRE ATT&CK technique ID |
| `mitre_name` | MITRE ATT&CK technique name |
| `created_at` | Alert creation timestamp |
| `failed_attempts` | Number of failed authentication attempts |
| `starting_time` | First observed event in the attack sequence |
| `ending_time` | Last observed event in the attack sequence |

---

# Roadmap

## Phase 1 (Current)

- ✅ Linux Authentication Log Analysis
- ✅ SSH Login Parsing
- ✅ Authentication Event Normalization
- ✅ Brute Force Detection
- ✅ Root Login Detection
- ✅ Username Enumeration Detection
- ✅ Distributed Attack Detection
- ✅ MITRE ATT&CK Mapping

## Phase 2 (Planned)

- 🚧 Web Access Log Parsing
- 🚧 HTTP Request Normalization
- 🚧 Web Attack Detection
- 🚧 Web Security Dashboard

## Phase 3 (Planned)

- 🚧 Firewall Log Parsing
- 🚧 Network Event Normalization
- 🚧 Port Scan Detection
- 🚧 Firewall Threat Detection
- 🚧 Network Security Dashboard

---

# Technologies Used

## Backend

- Python
- FastAPI
- Node.js
- Express
- JWT Authentication
- Regular Expressions (Regex)
- Detection Engine Logic
- Event Correlation

## Frontend

- React
- React Router
- CSS
- Chart.js
- Lucide React

## Database

- MongoDB

---

# Learning Outcomes

This project helped in understanding:

- SOC operations workflows
- Linux authentication log parsing
- Event normalization
- Authentication attack detection
- Detection engineering
- Security alert generation
- MITRE ATT&CK mapping
- Threat hunting fundamentals
- Security monitoring pipelines

---

# Disclaimer

This project is built for educational and portfolio purposes only and is not intended for production use.

**Author:** Amal George
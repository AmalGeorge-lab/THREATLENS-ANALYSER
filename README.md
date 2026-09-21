# SOC Analyst - Log Analysis & Threat Detection Platform

## Overview

SOC Analyst is a cybersecurity-focused Security Operations Center (SOC) simulation platform designed to analyze security logs, detect suspicious activity, correlate security events, and generate actionable security alerts.

The platform currently supports three major log sources:

* ✅ Linux Authentication Logs
* ✅ Web Access Logs
* ✅ Firewall Logs

The system parses raw security logs, normalizes them into structured security events, applies detection rules, correlates suspicious activity, generates alerts, and maps detected threats to the MITRE ATT&CK framework.

This project was built to demonstrate:

* SOC analyst fundamentals
* Security event parsing
* Log normalization
* Threat detection logic
* Event correlation
* Alert generation workflows
* MITRE ATT&CK mapping
* Threat hunting fundamentals
* Security monitoring pipelines
* Backend security engineering concepts

---

# Features

## Supported Log Sources

| Log Source                | Status      |
| ------------------------- | ----------- |
| Linux Authentication Logs | ✅ Supported |
| Web Access Logs           | ✅ Supported |
| Firewall Logs             | ✅ Supported |

---

# 1. Linux Authentication Log Analysis

The Linux authentication module analyzes SSH authentication logs and detects suspicious authentication activity.

### Example Log

```text
May 27 10:15:01 ubuntu sshd[1234]: Failed password for root from 192.168.1.20 port 45522 ssh2
```

### Extracted Fields

* Timestamp
* Hostname
* Service Name
* Process ID (PID)
* Event Type
* Username
* Source IP Address
* Port Number
* Authentication Protocol

---

## Linux Detection Rules

| Rule ID  | Rule Name              | Description                                                                                                        | Severity |
| -------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------ | -------- |
| AUTH-001 | Brute Force Detection  | Detects repeated failed login attempts against the same user from a single source IP within a defined time window. | High     |
| AUTH-002 | Root Login Attempt     | Detects login attempts targeting the `root` account.                                                               | Medium   |
| AUTH-003 | Success After Failures | Detects a successful login following multiple failed authentication attempts.                                      | Critical |
| AUTH-004 | Invalid User Scanning  | Detects repeated authentication attempts using non-existent usernames.                                             | Medium   |

### MITRE ATT&CK Mapping

| Detection Scenario                    | MITRE ATT&CK ID | Technique                      |
| ------------------------------------- | --------------- | ------------------------------ |
| Brute Force Detection                 | T1110           | Brute Force                    |
| Distributed Brute Force Detection     | T1110           | Brute Force                    |
| Invalid User Scanning                 | T1087           | Account Discovery              |
| Root Login Attempt                    | T1078.003       | Valid Accounts: Local Accounts |
| Successful Brute Force Attack         | T1078           | Valid Accounts                 |
| Successful Brute Force Attack - Root  | T1078.003       | Valid Accounts: Local Accounts |
| Distributed Brute Force Attack        | T1078           | Valid Accounts                 |
| Distributed Brute Force Attack - Root | T1078.003       | Valid Accounts: Local Accounts |

---

# 2. Web Access Log Analysis

The Web Access Log module analyzes HTTP access logs and detects suspicious web requests, reconnaissance activity, sensitive file access, SQL injection attempts, and potential web shell activity.

## Web Log Parsing

### Example Log

```text
192.168.1.20 - - [27/May/2026:10:15:01 +0000] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0"
```

### Final Parsed Structure

```json
{
  "raw_log": "192.168.1.20 - - [27/May/2026:10:15:01 +0000] \"GET /admin HTTP/1.1\" 404 512 \"-\" \"Mozilla/5.0\"",
  "log_type": "WEB_ACCESS",
  "timestamp": "27/May/2026:10:15:01 +0000",
  "timestamp_iso": "2026-05-27T10:15:01Z",
  "source_ip": "192.168.1.20",
  "http_method": "GET",
  "request_uri": "/admin",
  "http_version": "HTTP/1.1",
  "status_code": 404,
  "response_size": 512,
  "referrer": "-",
  "user_agent": "Mozilla/5.0"
}
```

### Extracted Fields

* Raw Log
* Log Type
* Timestamp
* Source IP
* HTTP Method
* Request URI
* HTTP Version
* HTTP Status Code
* Response Size
* Referrer
* User Agent

---

## Web Detection Rules

### WEB-001 - Directory Enumeration Detection

Detects repeated requests resulting in `404` responses from the same source IP.

**Detection condition:**

```text
Same IP
    ↓
More than 20 requests
    ↓
404 responses
    ↓
Within 2 minutes
    ↓
Generate Alert
```

### WEB-002 - Sensitive File Access

Detects requests attempting to access potentially sensitive files.

Examples include:

```text
.env
config.php
backup.zip
database.sql
wp-config.php
```

### WEB-003 - SQL Injection Detection

Detects suspicious SQL injection patterns in request URIs.

Examples include:

```text
--
UNION SELECT
OR 1=1
SLEEP(
```

### WEB-004 - Web Shell Access Detection

Detects suspicious requests for web shell files or web shell extensions from unusual locations.

Examples of web shell extensions:

```text
.php
.jsp
.asp
.aspx
.cgi
```

Known web shell filenames include:

```text
cmd.php
shell.php
c99.php
r57.php
ws.php
```

---

## Web Detection Rules Summary

| Rule ID | Rule                       | Description                                                                    | Severity |
| ------- | -------------------------- | ------------------------------------------------------------------------------ | -------- |
| WEB-001 | Directory Enumeration      | Detects repeated 404 requests from the same IP within a defined time window.   | High     |
| WEB-002 | Sensitive File Access      | Detects attempts to access sensitive configuration, backup, or database files. | High     |
| WEB-003 | SQL Injection Attempt      | Detects SQL injection patterns in HTTP request URIs.                           | High     |
| WEB-004 | Web Shell Access Detection | Detects suspicious web shell files and extensions.                             | Critical |

---

## Web MITRE ATT&CK Mapping

| Detection                | MITRE ATT&CK ID | Technique                            |
| ------------------------ | --------------- | ------------------------------------ |
| Directory Enumeration    | T1595           | Active Scanning                      |
| Sensitive File Discovery | T1083           | File and Directory Discovery         |
| SQL Injection            | T1190           | Exploit Public-Facing Application    |
| Web Shell Access         | T1505.003       | Server Software Component: Web Shell |

---

## Example Web Alert Metadata

```json
{
  "alert_id": "ALT-2001",
  "alert_type": "DIRECTORY_ENUMERATION",
  "rule_id": "WEB-001",
  "rule_name": "Directory Enumeration Detection",
  "severity": "HIGH",
  "status": "OPEN",
  "source_ip": "192.168.1.20",
  "failed_requests": 35,
  "time_window": "2 minutes",
  "mitre_technique": "T1595",
  "mitre_name": "Active Scanning",
  "created_at": "2026-05-27T10:20:00Z"
}
```

---

# 3. Firewall Log Analysis

The Firewall Log module analyzes network firewall events and detects network reconnaissance, excessive blocked traffic, SSH targeting, and attempts to access multiple internal hosts.

## Firewall Log Parsing

### Example Log

```text
May 27 14:25:10 firewall01 kernel: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.45 DST=192.168.1.10 LEN=60 PROTO=TCP SPT=54321 DPT=22 ACTION=DROP
```

### Final Parsed Structure

```json
{
  "raw_log": "May 27 14:25:10 firewall01 kernel: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.45 DST=192.168.1.10 LEN=60 PROTO=TCP SPT=54321 DPT=22 ACTION=DROP",
  "log_type": "FIREWALL",
  "timestamp": "May 27 14:25:10",
  "timestamp_iso": "2026-05-27T14:25:10Z",
  "host": "firewall01",
  "service": "kernel",
  "source_ip": "203.0.113.45",
  "destination_ip": "192.168.1.10",
  "protocol": "TCP",
  "source_port": 54321,
  "destination_port": 22,
  "action": "DROP"
}
```

### Extracted Fields

* Raw Log
* Log Type
* Timestamp
* Host
* Service
* Source IP
* Destination IP
* Protocol
* Source Port
* Destination Port
* Firewall Action

---

## Firewall Detection Rules

### FW-001 - Port Scanning Detection

Detects a source IP targeting multiple destination ports within a short time window.

**Detection condition:**

```text
Same Source IP
      ↓
More than 20 different destination ports
      ↓
Within 5 minutes
      ↓
Generate Alert
```

### FW-002 - Excessive Blocked Connections

Detects excessive firewall `DROP` actions originating from the same source IP.

**Detection condition:**

```text
Same Source IP
      ↓
More than 50 DROP actions
      ↓
Within 10 minutes
      ↓
Generate Alert
```

### FW-003 - SSH Targeting Detection

Detects repeated attempts to access SSH services that are blocked by the firewall.

**Detection condition:**

```text
Destination Port = 22
        +
Action = DROP
        +
More than 10 attempts
        +
Within 5 minutes
        ↓
Generate Alert
```

### FW-004 - Internal Network Access Attempt

Detects external source IPs attempting to access multiple internal hosts within a short time window.

**Detection condition:**

```text
External Source IP
       ↓
Multiple Internal Hosts
       ↓
Within 5 minutes
       ↓
Generate Alert
```

---

## Firewall Detection Rules Summary

| Rule ID | Rule                            | Description                                                                              | Severity |
| ------- | ------------------------------- | ---------------------------------------------------------------------------------------- | -------- |
| FW-001  | Port Scanning                   | Detects a source IP targeting more than 20 different destination ports within 5 minutes. | High     |
| FW-002  | Excessive Blocked Connections   | Detects more than 50 blocked connections from the same source IP within 10 minutes.      | Medium   |
| FW-003  | SSH Targeting                   | Detects repeated blocked SSH connection attempts against port 22.                        | Medium   |
| FW-004  | Internal Network Access Attempt | Detects external IPs attempting to access multiple internal hosts.                       | Critical |

---

## Firewall MITRE ATT&CK Mapping

| Detection                       | MITRE ATT&CK ID | Technique                         |
| ------------------------------- | --------------- | --------------------------------- |
| Port Scanning                   | T1595           | Active Scanning                   |
| SSH Targeting                   | T1110           | Brute Force                       |
| Excessive Blocked Connections   | T1190           | Exploit Public-Facing Application |
| Internal Network Access Attempt | T1046           | Network Service Scanning          |

---

## Example Firewall Alert Metadata

```json
{
  "alert_id": "ALT-3001",
  "alert_type": "PORT_SCAN_DETECTED",
  "rule_id": "FW-001",
  "rule_name": "Port Scanning Detection",
  "severity": "HIGH",
  "status": "OPEN",
  "source_ip": "203.0.113.45",
  "ports_targeted": 35,
  "time_window": "5 minutes",
  "mitre_technique": "T1595",
  "mitre_name": "Active Scanning",
  "created_at": "2026-05-27T14:30:00Z"
}
```

---

# Unified Detection Architecture

The platform processes different security log sources through a common detection pipeline.

```text
                    Log File Upload
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
     Linux Auth        Web Access       Firewall
       Parser            Parser           Parser
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                 Event Normalization
                           │
                           ▼
                  Detection Engine
                           │
                           ▼
                   Threat Correlation
                           │
                           ▼
                    Alert Generation
                           │
                           ▼
                    MITRE ATT&CK
                       Mapping
                           │
                           ▼
                     SOC Dashboard
```

---

# Example Parsed Events

## Linux Authentication Event

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

## Web Access Event

```json
{
  "raw_log": "192.168.1.20 - - [27/May/2026:10:15:01 +0000] \"GET /admin HTTP/1.1\" 404 512 \"-\" \"Mozilla/5.0\"",
  "log_type": "WEB_ACCESS",
  "timestamp": "27/May/2026:10:15:01 +0000",
  "timestamp_iso": "2026-05-27T10:15:01Z",
  "source_ip": "192.168.1.20",
  "http_method": "GET",
  "request_uri": "/admin",
  "http_version": "HTTP/1.1",
  "status_code": 404,
  "response_size": 512,
  "referrer": "-",
  "user_agent": "Mozilla/5.0"
}
```

## Firewall Event

```json
{
  "raw_log": "May 27 14:25:10 firewall01 kernel: IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.45 DST=192.168.1.10 LEN=60 PROTO=TCP SPT=54321 DPT=22 ACTION=DROP",
  "log_type": "FIREWALL",
  "timestamp": "May 27 14:25:10",
  "timestamp_iso": "2026-05-27T14:25:10Z",
  "host": "firewall01",
  "service": "kernel",
  "source_ip": "203.0.113.45",
  "destination_ip": "192.168.1.10",
  "protocol": "TCP",
  "source_port": 54321,
  "destination_port": 22,
  "action": "DROP"
}
```

---

# Alert Metadata

Alerts generated by the detection engine contain common metadata fields used for investigation and correlation.

| Field              | Description                                           |
| ------------------ | ----------------------------------------------------- |
| `alert_id`         | Unique identifier for the generated alert             |
| `alert_type`       | Type of detected security event                       |
| `rule_id`          | Detection rule identifier                             |
| `rule_name`        | Detection rule name                                   |
| `severity`         | Alert severity                                        |
| `risk_score`       | Calculated risk score based on attack characteristics |
| `status`           | Current alert status                                  |
| `source_ip`        | Source IP associated with the event                   |
| `destination_ip`   | Destination IP when applicable                        |
| `user`             | Target username when applicable                       |
| `host`             | Target or logging host                                |
| `service`          | Service generating the event                          |
| `pid`              | Process ID when available                             |
| `port`             | Network port when applicable                          |
| `source_port`      | Source network port                                   |
| `destination_port` | Destination network port                              |
| `protocol`         | Network or authentication protocol                    |
| `http_method`      | HTTP request method                                   |
| `request_uri`      | Requested URI                                         |
| `status_code`      | HTTP response status                                  |
| `mitre_technique`  | MITRE ATT&CK technique ID                             |
| `mitre_name`       | MITRE ATT&CK technique name                           |
| `created_at`       | Alert creation timestamp                              |
| `failed_attempts`  | Number of failed authentication attempts              |
| `failed_requests`  | Number of suspicious web requests                     |
| `ports_targeted`   | Number of destination ports targeted                  |
| `time_window`      | Detection time window                                 |
| `starting_time`    | First observed event in an attack sequence            |
| `ending_time`      | Last observed event in an attack sequence             |

---

# Alert Severity Levels

The platform categorizes detected security events into four severity levels:

| Severity | Description                                                                 |
| -------- | --------------------------------------------------------------------------- |
| Medium   | Suspicious activity requiring investigation                                 |
| High     | Significant suspicious activity with elevated security risk                 |
| Critical | Activity requiring immediate investigation due to potentially severe impact |

---

# Project Roadmap

## Phase 1 - Linux Authentication Logs

* ✅ Linux Authentication Log Analysis
* ✅ SSH Login Parsing
* ✅ Authentication Event Normalization
* ✅ Brute Force Detection
* ✅ Root Login Detection
* ✅ Username Enumeration Detection
* ✅ Distributed Attack Detection
* ✅ MITRE ATT&CK Mapping

## Phase 2 - Web Access Logs

* ✅ Web Access Log Parsing
* ✅ HTTP Request Normalization
* ✅ Directory Enumeration Detection
* ✅ Sensitive File Access Detection
* ✅ SQL Injection Detection
* ✅ Web Shell Access Detection
* ✅ MITRE ATT&CK Mapping
* ✅ Web Security Alerts

## Phase 3 - Firewall Logs

* ✅ Firewall Log Parsing
* ✅ Network Event Normalization
* ✅ Port Scan Detection
* ✅ Excessive Blocked Connection Detection
* ✅ SSH Targeting Detection
* ✅ Internal Network Access Detection
* ✅ MITRE ATT&CK Mapping
* ✅ Network Security Alerts

---

# Technologies Used

## Backend

* Python
* FastAPI
* Node.js
* Express
* JWT Authentication
* Regular Expressions (Regex)
* Detection Engine Logic
* Event Correlation

## Frontend

* React
* React Router
* CSS
* Chart.js
* Lucide React

## Database

* MongoDB

## Security Framework

* MITRE ATT&CK

---

# Learning Outcomes

This project helped develop practical understanding of:

* SOC operations and monitoring workflows
* Linux authentication log analysis
* Web access log analysis
* Firewall log analysis
* Log parsing and normalization
* Security event correlation
* Authentication attack detection
* Web attack detection
* Network reconnaissance detection
* Detection engineering
* Security alert generation
* MITRE ATT&CK mapping
* Threat hunting fundamentals
* Security monitoring pipelines
* SOC dashboard development
* Backend security engineering

---

# Disclaimer

This project is built for educational and portfolio purposes only and is not intended for production use.

**Author:** Amal George
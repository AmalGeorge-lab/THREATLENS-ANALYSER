import re
from datetime import datetime, timezone



def calculateRiskScore(status_code):
  if status_code == 200:
    return {
      "risk_score": 95,
      "severity": "CRITICAL"
    }
  elif status_code in [500, 502, 503]:
    return {
      "risk_score": 90,
      "severity": "HIGH"
    }
  elif status_code in [401, 403]:
    return {
      "risk_score": 85,
      "severity": "HIGH"
    }
  elif status_code == 404:
    return {
      "risk_score": 70,
      "severity": "MEDIUM"
    }
  else:
    return {
      "risk_score": 80,
      "severity": "HIGH"
    }



def generate_alert(alert_id,alert_type,rule_id,risk_score,severity,source_ip,request_uri,timestamp,http_method,http_version,status_code,response_size,referrer,user_agent):
  alert = {
    "alert_id": alert_id,
    "alert_type": alert_type,
    "rule_id": rule_id,
    "rule_name": "SQL Injection Attempt",
    "risk_score" : risk_score ,
    "request_uri" : request_uri ,
    "severity": severity,
    "status": "OPEN",
    "source_ip": source_ip,
    "timestamp" : timestamp ,
    "http_method" : http_method ,
    "http_version" : http_version ,
    "status_code" : status_code ,
    "response_size" : response_size ,
    "referrer" : referrer ,
    "user_agent" : user_agent ,
    "mitre_technique": "T1190",
    "mitre_name": "Exploit Public-Facing Application",
    "created_at": datetime.now(timezone.utc).isoformat()
  }
  return alert



def sql_attack(parsedLogs):
  alerts = []
  alertCounter = 5000
  sqliPatterns = [
    r"\binsert\b",
    r"\bupdate\b",
    r"\bdelete\b",
    r"\bdrop\b",
    r"\bhaving\b",
    r"\border\s+by\b",
    r"\bgroup\s+by\b",
    r"concat\s*\(",
    r"ascii\s*\(",
    r"char\s*\(",
    r"substr\s*\(",
    r"substring\s*\(",
    r"database\s*\(",
    r"user\s*\(",
    r"version\s*\(",
    r"@@version",
    r"\bunion\b",
    r"\bselect\b",
    r"\bor\s+1=1\b",
    r"\band\s+1=1\b",
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"waitfor\s+delay",
    r"xp_cmdshell",
    r"information_schema",
    r"load_file\s*\(",
    r"--",
    r"/\*",
    r"\*/",
    r"'"
  ]
  for log in parsedLogs:
    request_uri = log["request_uri"].lower()
    if any(re.search(pattern, request_uri) for pattern in sqliPatterns):
      alertCounter += 1
      riskDetails = calculateRiskScore(log["status_code"])
      alerts.append(generate_alert(
        f"ALT-{alertCounter}",
        "SQL Injection Attempt",
        "WEB-003",
        riskDetails["risk_score"],
        riskDetails["severity"] ,
        log["source_ip"],
        request_uri,
        log["timestamp_iso"],
        log["http_method"],
        log["http_version"],
        log["status_code"],
        log["response_size"],
        log["referrer"],
        log["user_agent"]
      ))
  return alerts
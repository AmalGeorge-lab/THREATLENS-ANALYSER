from datetime import datetime, timezone


def calculateRiskScore(status_code):
  result = { "risk_score" : 85 , "severity" : "HIGH" }
  if status_code == 200:
    result = { "risk_score" : 95 , "severity" : "CRITICAL" }
  return result



def generate_alert(alert_id,alert_type,rule_id,risk_score,severity,source_ip,request_uri,timestamp,http_method,http_version,status_code,response_size,referrer,user_agent):
  alert = {
    "alert_id": alert_id,
    "alert_type": alert_type,
    "rule_id": rule_id,
    "rule_name": "Sensitive File Access",
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
    "mitre_technique": "T1083",
    "mitre_name": "File and Directory Discovery",
    "created_at": datetime.now(timezone.utc).isoformat()
  }
  return alert





def sensitive_file_attack(parsedLogs):
  alerts = []
  SENSITIVE_FILE_PATH = {
    ".env",
    "config.php",
    "wp-config.php",
    "database.sql",
    "backup.sql",
    "backup.zip",
    ".git/config",
    ".git/head",
    "id_rsa",
    ".htaccess",
    "web.config",
    "docker-compose.yml",
    "appsettings.json",
    ".aws/credentials",
    "service-account.json"
  }
  alertCounter = 1000

  for log in parsedLogs:
    request_uri = log["request_uri"].lower()
    if any(file in request_uri for file in SENSITIVE_FILE_PATH):
      alertCounter += 1
      riskDetails = calculateRiskScore(log["status_code"])
      alerts.append(generate_alert(
        f"ALT-{alertCounter}",
        "Sensitive File Access",
        "WEB-002",
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
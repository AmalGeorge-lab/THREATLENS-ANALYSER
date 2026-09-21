from datetime import datetime, timezone


def generate_alert(alert_id,alert_type,rule_id,risk_score,severity,source_ip,request_uri,timestamp,http_method,http_version,status_code,response_size,referrer,user_agent):
  alert = {
    "alert_id": alert_id,
    "alert_type": alert_type,
    "rule_id": rule_id,
    "rule_name": "Web Shell Access Detection",
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
    "mitre_technique": "T1505.003",
    "mitre_name": "Server Software Component: Web Shell",
    "created_at": datetime.now(timezone.utc).isoformat()
  }
  return alert



def calculateRiskScore(status_code):
  result = {
    "risk_score": 90,
    "severity": "HIGH"
  }

  if status_code == 200:
    result = {
      "risk_score": 100,
      "severity": "CRITICAL"
    }
  elif status_code == 403:
    result = {
      "risk_score": 95,
      "severity": "CRITICAL"
    }
  return result



def web_shell_access(parsedLogs):
  WEB_SHELL_EXTENSIONS = [".php", ".jsp", ".asp", ".aspx", ".cgi"]
  KNOWN_WEB_SHELLS = ["cmd.php","shell.php","c99.php","r57.php","ws.php"]
  UNUSUAL_DIRECTORIES = ["/uploads/","/images/","/img/","/assets/","/css/","/js/","/tmp/","/backup/","/files/","/downloads/"]

  alerts = []
  alertCounter = 7000

  for log in parsedLogs:
    request_uri = log["request_uri"].lower()
    attack_detected = False

    if any(shell in request_uri for shell in KNOWN_WEB_SHELLS):
      attack_detected = True

    elif any(request_uri.startswith(directory) for directory in UNUSUAL_DIRECTORIES) and any(request_uri.endswith(ext) for ext in WEB_SHELL_EXTENSIONS):
      attack_detected = True

    if attack_detected:
      alertCounter += 1
      riskDetails = calculateRiskScore(log["status_code"])
      alerts.append(generate_alert(
        f"ALT-{alertCounter}",
        "Web Shell Access Detection" ,
        "WEB-004" ,
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
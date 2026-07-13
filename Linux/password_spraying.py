from datetime import datetime, timedelta, timezone

RULES = {
  "AUTH-001": {
    "name": "Brute Force Detection",
    "mitre_id": "T1110",
    "mitre_name": "Brute Force"
  }
}


def generate_alert(key,alert_id,alert_type,rule_id,source_ip,host,service,pid,port,protocol,severity,risk_score,failed_attempts,users,starting_time,ending_time):
  rule = RULES[rule_id]
  alert = {
    "key" : key ,
    "alert_id": alert_id,
    "alert_type": alert_type,
    "rule_id": rule_id,
    "rule_name": rule["name"],
    "host" : host ,
    "service" : service ,
    "pid" : pid ,
    "port" : port ,
    "protocol" : protocol ,
    "severity": severity,
    "risk_score" : risk_score ,
    "status": "OPEN",
    "source_ip": source_ip,
    "mitre_technique": rule["mitre_id"],
    "mitre_name": rule["mitre_name"],
    "created_at": datetime.now(timezone.utc).isoformat() ,
    "failed_attempts" : failed_attempts ,
    "users" : users ,
    "starting_time" : starting_time ,
    "ending_time" : ending_time
  }
  return alert



def calculateRiskScore(failureCount, usersCount):
  score = 0
  if failureCount > 4:
    score += 20
  if failureCount >= 10:
    score += 20
  if failureCount >= 20:
    score += 20
  if usersCount >= 3:
    score += 20
  if usersCount >= 5:
    score += 10
  if usersCount >= 10:
    score += 10

  if score <= 20:
    severity = "LOW"
  elif score <= 40:
    severity = "MEDIUM"
  elif score <= 60:
    severity = "HIGH"
  else:
    severity = "CRITICAL"

  return {
    "risk_score": score,
    "severity": severity
  }



def passwordSprayingDetector(parsedLogs):
  alerts = []
  passwordSprayingList = {}
  alertCounter = 7000


  # password spraying attack detection
  for log in parsedLogs:
    key = log["source_ip"]
    if key not in passwordSprayingList:
      passwordSprayingList[key] = { "failCount" : 1 , "users" : {log["user"]} , "start_time" : log["timestamp_iso"] , "end_time" : log["timestamp_iso"] }
    else:
      lastTimestamp = datetime.fromisoformat(passwordSprayingList[key]["end_time"].replace("Z" , "+00:00"))
      newTimeStamp = datetime.fromisoformat(log["timestamp_iso"].replace("Z" , "+00:00"))
      timeDiff = newTimeStamp - lastTimestamp

      if timeDiff >= timedelta(minutes=1):
        passwordSprayingList[key]["failCount"] = 1
        passwordSprayingList[key]["users"] = {log["user"]}
        passwordSprayingList[key]["start_time"] = log["timestamp_iso"]
        passwordSprayingList[key]["end_time"] = log["timestamp_iso"]
      else:
        passwordSprayingList[key]["failCount"] += 1
        passwordSprayingList[key]["users"].add(log["user"])
        passwordSprayingList[key]["end_time"] = log["timestamp_iso"]
    


    if len(passwordSprayingList[key]["users"]) > 4:
      matchingAlerts = [a for a in alerts if a["key"] == key]
      keyExists = matchingAlerts[-1] if matchingAlerts else None
      if keyExists:

        lastTimestamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z" , "+00:00"))
        newTimeStamp = datetime.fromisoformat(passwordSprayingList[key]["start_time"].replace("Z" , "+00:00"))
        timeDiff = newTimeStamp - lastTimestamp

        if timeDiff >= timedelta(minutes=1):

          alertCounter += 1
          riskAnalysis = calculateRiskScore(passwordSprayingList[key]["failCount"] , len(passwordSprayingList[key]["users"]))
          alerts.append(generate_alert(
            key ,
            f"ALT-{alertCounter}",
            "Password Spraying Attack",
            "AUTH-001",
            log["source_ip"],
            log["host"] ,
            log["service"] ,
            log["pid"] ,
            log["port"] ,
            log["protocol"] ,
            riskAnalysis["severity"] ,
            riskAnalysis["risk_score"] ,
            passwordSprayingList[key]["failCount"] , 
            list(passwordSprayingList[key]["users"]) ,
            passwordSprayingList[key]["start_time"] ,
            passwordSprayingList[key]["end_time"] 
          ))

        else:

          keyExists["failed_attempts"] = passwordSprayingList[key]["failCount"]
          keyExists["users"] = list(passwordSprayingList[key]["users"])
          result = calculateRiskScore(passwordSprayingList[key]["failCount"],len(passwordSprayingList[key]["users"]))
          keyExists["risk_score"] = result["risk_score"]
          keyExists["severity"] = result["severity"]
          keyExists["ending_time"] = passwordSprayingList[key]["end_time"]

      else:
        alertCounter += 1
        riskAnalysis = calculateRiskScore(passwordSprayingList[key]["failCount"],len(passwordSprayingList[key]["users"]))
        alerts.append(generate_alert(
          key ,
          f"ALT-{alertCounter}",
          "Password Spraying Attack",
          "AUTH-001",
          log["source_ip"],
          log["host"] ,
          log["service"] ,
          log["pid"] ,
          log["port"] ,
          log["protocol"] ,
          riskAnalysis["severity"] ,
          riskAnalysis["risk_score"] ,
          passwordSprayingList[key]["failCount"] , 
          list(passwordSprayingList[key]["users"]) ,
          passwordSprayingList[key]["start_time"] ,
          passwordSprayingList[key]["end_time"] 
        ))
  return alerts
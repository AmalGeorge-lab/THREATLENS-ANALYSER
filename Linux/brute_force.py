from datetime import datetime, timedelta, timezone



RULES = {
  "AUTH-001": {
    "name": "Brute Force Detection",
    "mitre_id": "T1110",
    "mitre_name": "Brute Force"
  },
  "AUTH-002": {
    "name": "Root Login Attempt",
    "mitre_id": "T1078",
    "mitre_name": "Valid Accounts"
  },
  "AUTH-003": {
    "name": "Success After Failures",
    "mitre_id": "T1078",
    "mitre_name": "Valid Accounts"
  }
}


def generate_alert(key,alert_id,alert_type,rule_id,source_ip,user,severity,risk_score,failed_attempts,host,service,pid,port,protocol,starting_time,ending_time):
  rule = RULES[rule_id]
  alert = {
    "key" : key ,
    "alert_id": alert_id,
    "alert_type": alert_type,
    "rule_id": rule_id,
    "rule_name": rule["name"],
    "severity": severity,
    "risk_score" : risk_score ,
    "status": "OPEN",
    "source_ip": source_ip,
    "user" : user ,
    "host" : host ,
    "service" : service ,
    "pid" : pid ,
    "port" : port ,
    "protocol" : protocol ,
    "mitre_technique": rule["mitre_id"],
    "mitre_name": rule["mitre_name"],
    "created_at": datetime.now(timezone.utc).isoformat() ,
    "failed_attempts" : failed_attempts ,
    "starting_time" : starting_time ,
    "ending_time" : ending_time
  }
  return alert


def calculateRiskScore(failureCount, isRoot, successOccurred=False):
  result = {"risk_score": 0,"severity": None}
  # for root
  if isRoot == "root":
    if 4 <= failureCount <= 5:
      result["risk_score"] = 30
    elif 6 <= failureCount <= 10:
      result["risk_score"] = 50
    elif failureCount > 10:
      result["risk_score"] = 80
    # Success after failures
    if successOccurred:
      if 4 <= failureCount <= 5:
        result["risk_score"] += 30
      elif failureCount > 5:
        result["risk_score"] += 40
  # Normal user thresholds
  else:
    if 4 <= failureCount <= 10:
      result["risk_score"] = 20
    elif 11 <= failureCount <= 20:
      result["risk_score"] = 40
    elif 21 <= failureCount <= 50:
      result["risk_score"] = 60
    elif failureCount > 50:
      result["risk_score"] = 80
      # Success after failures
    if successOccurred:
      if 8 <= failureCount <= 10:
        result["risk_score"] += 20
      elif 11 <= failureCount <= 20:
        result["risk_score"] += 30
      elif failureCount > 20:
        result["risk_score"] += 40
  # Cap at 100
  result["risk_score"] = min(result["risk_score"], 100)
  # Determine severity from final score
  score = result["risk_score"]
  if score == 0:
    result["severity"] = None
  elif score < 30:
    result["severity"] = "LOW"
  elif score < 60:
    result["severity"] = "MEDIUM"
  elif score < 80:
    result["severity"] = "HIGH"
  else:
    result["severity"] = "CRITICAL"

  return result



def bruteForceAttackDetector(parsedLogs):
  alerts = []
  successAlerts = []
  bruteForceList = {}
  alertCounter = 1000
  successAlertCounter = 1000

  for log in parsedLogs:
    if log["event"] == "FAILED_LOGIN":
      key = log["source_ip"] + "_" + log["user"]
      if key not in bruteForceList:
        bruteForceList[key] = { "failCount" : 1 , "start_time" : log["timestamp_iso"] , "end_time" : log["timestamp_iso"] }
      else:
        startingTime = datetime.fromisoformat(bruteForceList[key]["start_time"].replace("Z" , "+00:00"))
        currentTime = datetime.fromisoformat(log["timestamp_iso"].replace("Z" , "+00:00"))
        timeDiff = currentTime - startingTime

        if timeDiff >= timedelta(minutes=1):

          endingTime = datetime.fromisoformat(bruteForceList[key]["end_time"].replace("Z" , "+00:00"))
          timeDifference = currentTime - endingTime

          if timeDifference > timedelta(seconds=15):

            bruteForceList[key]["failCount"] = 1
            bruteForceList[key]["start_time"] = log["timestamp_iso"]
            bruteForceList[key]["end_time"] = log["timestamp_iso"]

          else :
            bruteForceList[key]["failCount"] += 1
            bruteForceList[key]["end_time"] = log["timestamp_iso"]

        else:
          bruteForceList[key]["failCount"] += 1
          bruteForceList[key]["end_time"] = log["timestamp_iso"]



      if bruteForceList[key]["failCount"] > 3:
        matchingAlerts = [a for a in alerts if a["key"] == key]
        keyExists = matchingAlerts[-1] if matchingAlerts else None
        if keyExists:
          lastTimestamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z" , "+00:00"))
          newTimeStamp = datetime.fromisoformat(bruteForceList[key]["start_time"].replace("Z" , "+00:00"))
          timeDiff = newTimeStamp - lastTimestamp
          # checking whether it is a new alert or not
          if timeDiff >= timedelta(minutes=1):
            alertCounter += 1
            riskAnalysis = calculateRiskScore(bruteForceList[key]["failCount"],keyExists["user"])
            alerts.append(generate_alert(
              key ,
              f"ALT-{alertCounter}",
              "Classical Brute Force Attack" if keyExists["user"] != "root" else "Root Account Brute Force Attack",
              "AUTH-001" if keyExists["user"] != "root" else "AUTH-002",
              log["source_ip"],
              log["user"] ,
              riskAnalysis["severity"] ,
              riskAnalysis["risk_score"] ,
              bruteForceList[key]["failCount"]  ,
              log["host"] ,
              log["service"] ,
              log["pid"] ,
              log["port"] ,
              log["protocol"] ,
              bruteForceList[key]["start_time"] ,
              bruteForceList[key]["end_time"] 
            ))
          else :
            keyExists["failed_attempts"] = bruteForceList[key]["failCount"]
            result = calculateRiskScore(keyExists["failed_attempts"], keyExists["user"])
            keyExists["risk_score"] = result["risk_score"]
            keyExists["severity"] = result["severity"]
            keyExists["ending_time"] = bruteForceList[key]["end_time"]
        else:
          alertCounter += 1
          riskAnalysis = calculateRiskScore(bruteForceList[key]["failCount"],log["user"])
          alerts.append(generate_alert(
            key ,
            f"ALT-{alertCounter}",
            "Classical Brute Force Attack" if log["user"] != "root" else "Root Account Brute Force Attack",
            "AUTH-001" if log["user"] != "root" else "AUTH-002",
            log["source_ip"],
            log["user"] ,
            riskAnalysis["severity"] ,
            riskAnalysis["risk_score"] ,
            bruteForceList[key]["failCount"] , 
            log["host"] ,
            log["service"] ,
            log["pid"] ,
            log["port"] ,
            log["protocol"] ,
            bruteForceList[key]["start_time"] ,
            bruteForceList[key]["end_time"]
          ))
    else:
      key = log["source_ip"] + "_" + log["user"]
      matchingAlerts = [a for a in alerts if a["key"] == key]
      firstEntry = matchingAlerts[0] if matchingAlerts else None
      if firstEntry:
        alerts = [a for a in alerts if a["key"] != key]
        fail_attempts = sum(a["failed_attempts"] for a in matchingAlerts)
        additional_fail_attempts = bruteForceList[key]["failCount"]
        total_fail_attempts = fail_attempts if additional_fail_attempts > 3 else fail_attempts + additional_fail_attempts
        bruteForceList.pop(key)
        riskAnalysis = calculateRiskScore(total_fail_attempts , firstEntry["user"] , True)
        successAlertCounter += 1
        successAlerts.append({
          "key" : key ,
          "alert_id" : f"SUCC-{successAlertCounter}" ,
          "alert_type" : "Brute Force Account Success" if firstEntry["user"] != "root" else "Root Brute Force Account Success", 
          "rule_id" : "AUTH-003" ,
          "rule_name" : RULES["AUTH-003"]["name"] ,
          "source_ip" : firstEntry["source_ip"] ,
          "target_user" : firstEntry["user"] ,
          "host" : firstEntry["host"] ,
          "service" : firstEntry["service"] ,
          "pid" : firstEntry["pid"] ,
          "port" : firstEntry["port"] ,
          "protocol" : firstEntry["protocol"] ,
          "severity" : riskAnalysis["severity"] ,
          "risk_score" : riskAnalysis["risk_score"] ,
          "failed_attempts" : total_fail_attempts,
          "status" : "OPEN" ,
          "mitre_technique" : "T1078" if firstEntry["user"] != "root" else "T1078.003" ,
          "mitre_name" : "Valid Accounts" if firstEntry["user"] != "root" else "Valid Accounts: Local Accounts",
          "created_at": datetime.now(timezone.utc).isoformat() ,
          "relatedAlerts" : matchingAlerts ,
          "starting_time" : firstEntry["starting_time"] ,
          "ending_time" : log["timestamp_iso"]
        })
  return alerts + successAlerts
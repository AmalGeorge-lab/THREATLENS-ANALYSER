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
  },
}



def generate_alert(key,alert_id,alert_type,rule_id,severity,risk_score,failed_attempts,IPs,host,service,pid,port,protocol,starting_time,ending_time):
  rule = RULES[rule_id]
  alert = {
    "key" : key ,
    "user" : key ,
    "alert_id": alert_id,
    "alert_type": alert_type,
    "rule_id": rule_id,
    "rule_name": rule["name"],
    "severity": severity,
    "risk_score" : risk_score ,
    "status": "OPEN",
    "host" : host ,
    "service" : service ,
    "pid" : pid ,
    "port" : port ,
    "protocol" : protocol ,
    "mitre_technique": rule["mitre_id"],
    "mitre_name": rule["mitre_name"],
    "created_at": datetime.now(timezone.utc).isoformat() ,
    "failed_attempts" : failed_attempts ,
    "IPs" : IPs ,
    "starting_time" : starting_time ,
    "ending_time" : ending_time
  }
  return alert



def calculateRiskScore(failCount, ipCount, isRoot, successOccurred=False):
  #print(failCount, ipCount, isRoot, successOccurred)
  score = 0
  # IP count score
  if ipCount > 3:
    score += 20
  if ipCount >= 5:
    score += 20
  if ipCount >= 10:
    score += 20

  # Failed attempts
  if failCount >= 5:
    score += 10
  if failCount >= 10:
    score += 20
  if failCount >= 20:
    score += 10

  # Root account targeted
  if isRoot == "root":
    score += 30
  # Successful login after attack
  if successOccurred:
    score += 20
    # Additional boost for significant attacks
    if failCount >= 20 or ipCount >= 10:
      score += 10
      
  score = min(score, 100)
  if score <= 20:
    severity = "LOW"
  elif score <= 50:
    severity = "MEDIUM"
  elif score <= 80:
    severity = "HIGH"
  else:
    severity = "CRITICAL"
  return {
    "risk_score": score,
    "severity": severity
  }




def distributedAttackDetector(parsedLogs):
  alerts = []
  successAlerts = []
  distributedAttackList = {}
  alertCounter = 3000
  successAlertCounter = 3000

  for log in parsedLogs:
    if log["event"] == "FAILED_LOGIN":
      key = log["user"]
      if key not in distributedAttackList:
        distributedAttackList[key] = { "failCount" : 1 , "IPs" : {log["source_ip"]} , "start_time" : log["timestamp_iso"] , "end_time" : log["timestamp_iso"] }
      else:
        lastTimestamp = datetime.fromisoformat(distributedAttackList[key]["end_time"].replace("Z" , "+00:00"))
        newTimeStamp = datetime.fromisoformat(log["timestamp_iso"].replace("Z" , "+00:00"))
        timeDiff = newTimeStamp - lastTimestamp

        if timeDiff >= timedelta(minutes=1):
          distributedAttackList[key]["failCount"] = 1
          distributedAttackList[key]["IPs"] = {log["source_ip"]}
          distributedAttackList[key]["start_time"] = log["timestamp_iso"]
          distributedAttackList[key]["end_time"] = log["timestamp_iso"]
        else:
          distributedAttackList[key]["failCount"] += 1
          distributedAttackList[key]["IPs"].add(log["source_ip"])
          distributedAttackList[key]["end_time"] = log["timestamp_iso"]

      if len(distributedAttackList[key]["IPs"]) > 3:
        matchingAlerts = [a for a in alerts if a["key"] == key]
        keyExists = matchingAlerts[-1] if matchingAlerts else None
        if keyExists:
          lastTimestamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z" , "+00:00"))
          newTimeStamp = datetime.fromisoformat(distributedAttackList[key]["start_time"].replace("Z" , "+00:00"))
          timeDiff = newTimeStamp - lastTimestamp

          if timeDiff >= timedelta(minutes=1):
            alertCounter += 1
            riskAnalysis = calculateRiskScore(distributedAttackList[key]["failCount"] , len(distributedAttackList[key]["IPs"]) , keyExists["user"])
            alerts.append(generate_alert(
              key ,
              f"ALT-{alertCounter}",
              "Distributed Brute Force Attack" if keyExists["user"] != "root" else "Root Account Distributed Brute Force Attack",
              "AUTH-001" if keyExists["user"] != "root" else "AUTH-002",
              riskAnalysis["severity"] ,
              riskAnalysis["risk_score"] ,
              distributedAttackList[key]["failCount"] , 
              list(distributedAttackList[key]["IPs"]) ,
              log["host"] ,
              log["service"] ,
              log["pid"] ,
              log["port"] ,
              log["protocol"] ,
              distributedAttackList[key]["start_time"] ,
              distributedAttackList[key]["end_time"] 
            ))
          else:
            keyExists["failed_attempts"] = distributedAttackList[key]["failCount"]
            keyExists["IPs"] = list(distributedAttackList[key]["IPs"])
            result = calculateRiskScore(distributedAttackList[key]["failCount"],len(distributedAttackList[key]["IPs"]) , keyExists["user"])
            keyExists["risk_score"] = result["risk_score"]
            keyExists["severity"] = result["severity"]
            keyExists["ending_time"] = distributedAttackList[key]["end_time"]

        else :
          alertCounter += 1
          riskAnalysis = calculateRiskScore(distributedAttackList[key]["failCount"],len(distributedAttackList[key]["IPs"]),log["user"])
          alerts.append(generate_alert(
            key ,
            f"ALT-{alertCounter}",
            "Distributed Brute Force Attack" if log["user"] != "root" else "Root Account Distributed Brute Force Attack",
            "AUTH-001" if log["user"] != "root" else "AUTH-002",
            riskAnalysis["severity"] ,
            riskAnalysis["risk_score"] ,
            distributedAttackList[key]["failCount"] , 
            list(distributedAttackList[key]["IPs"]) ,
            log["host"] ,
            log["service"] ,
            log["pid"] ,
            log["port"] ,
            log["protocol"] ,
            distributedAttackList[key]["start_time"] ,
            distributedAttackList[key]["end_time"]
          ))
    else:
      key = log["user"]
      matchingAlerts = [a for a in alerts if a["key"] == key]
      firstEntry = matchingAlerts[0] if matchingAlerts else None
      if firstEntry:
        alerts = [a for a in alerts if a["key"] != key]
        fail_attempts = sum(a["failed_attempts"] for a in matchingAlerts)
        IPs = set().union(*(a["IPs"] for a in matchingAlerts))
        total_fail_attempts = fail_attempts if len(distributedAttackList[key]["IPs"]) > 3 else fail_attempts + distributedAttackList[key]["failCount"]
        total_IPs = IPs if len(distributedAttackList[key]["IPs"]) > 3 else IPs.union(distributedAttackList[key]["IPs"])
        distributedAttackList.pop(key)
        riskAnalysis = calculateRiskScore(total_fail_attempts , len(total_IPs) , firstEntry["user"] , True)
        successAlertCounter += 1
        successAlerts.append({
          "key" : key ,
          "alert_id" : f"SUCC-{successAlertCounter}",
          "alert_type" : "Distributed Brute Force Attack Success" if log["user"] != "root" else "Root Account Distributed Brute Force Attack Success",
          "rule_id" : "AUTH-003",
          "success_IP" : log["source_ip"] ,
          "rule_name" : RULES["AUTH-003"]["name"] ,
          "severity" : riskAnalysis["severity"] ,
          "risk_score" : riskAnalysis["risk_score"] ,
          "target_user" : firstEntry["user"] ,
          "failed_attempts" : total_fail_attempts , 
          "IPs" : list(total_IPs) ,
          "host" : firstEntry["host"] ,
          "service" : firstEntry["service"] ,
          "pid" : firstEntry["pid"] ,
          "port" : firstEntry["port"] ,
          "protocol" : firstEntry["protocol"] ,
          "status" : "OPEN" ,
          "mitre_technique" : "T1078" if firstEntry["user"] != "root" else "T1078.003" ,
          "mitre_name" : "Valid Accounts" if firstEntry["user"] != "root" else "Valid Accounts: Local Accounts",
          "created_at": datetime.now(timezone.utc).isoformat() ,
          "relatedAlerts" : matchingAlerts ,
          "starting_time" : firstEntry["starting_time"] ,
          "ending_time" : log["timestamp_iso"]
        })
  return alerts + successAlerts
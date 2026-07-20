from datetime import datetime, timedelta, timezone

def calculateRiskScore(failCount, usersCount):
  score = 0
  # Failed attempts contribution (max 40)
  score += min(failCount * 2, 40)
  # Invalid usernames contribution (max 60)
  score += min(usersCount * 6, 60)
  score = min(score, 100)
  if score >= 80:
    severity = "CRITICAL"
  elif score >= 60:
    severity = "HIGH"
  elif score >= 40:
    severity = "MEDIUM"
  else:
    severity = "LOW"
  return {
    "risk_score": score,
    "severity": severity
  }


def invalidUserDetector(parsed_logs):
  alerts = []
  invalidUserList = {}
  alertCounter = 5000

  for log in parsed_logs:
    key = log["source_ip"]
    if key not in invalidUserList:
      invalidUserList[key] = { "failCount" : 1 , "users" : {log["user"]} , "start_time" : log["timestamp_iso"] , "end_time" : log["timestamp_iso"] }
    else:
      startingTime = datetime.fromisoformat(invalidUserList[key]["start_time"].replace("Z" , "+00:00"))
      currentTime = datetime.fromisoformat(log["timestamp_iso"].replace("Z" , "+00:00"))
      timeDiff = currentTime - startingTime

      if timeDiff >= timedelta(minutes=1):

        endingTime = datetime.fromisoformat(invalidUserList[key]["end_time"].replace("Z" , "+00:00"))
        timeDifference = currentTime - endingTime

        if timeDifference > timedelta(seconds=15):

          invalidUserList[key]["failCount"] = 1
          invalidUserList[key]["users"] = {log["user"]}
          invalidUserList[key]["start_time"] = log["timestamp_iso"]
          invalidUserList[key]["end_time"] = log["timestamp_iso"]

        else :
          invalidUserList[key]["failCount"] += 1
          invalidUserList[key]["users"].add(log["user"])
          invalidUserList[key]["end_time"] = log["timestamp_iso"]

      else:
        invalidUserList[key]["failCount"] += 1
        invalidUserList[key]["users"].add(log["user"])
        invalidUserList[key]["end_time"] = log["timestamp_iso"]


        
    
    if len(invalidUserList[key]["users"]) > 3:
      matchingAlerts = [a for a in alerts if a["key"] == key]
      keyExists = matchingAlerts[-1] if matchingAlerts else None
      if keyExists:
        lastTimestamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z" , "+00:00"))
        newTimeStamp = datetime.fromisoformat(invalidUserList[key]["start_time"].replace("Z" , "+00:00"))
        timeDiff = newTimeStamp - lastTimestamp

        if timeDiff >= timedelta(minutes=1):

          alertCounter += 1
          riskAnalysis = calculateRiskScore(invalidUserList[key]["failCount"] , len(invalidUserList[key]["users"]))
          alerts.append({
            "key" : key ,
            "alert_id" : f"ALT-{alertCounter}",
            "alert_type" : "Username Enumeration Attack",
            "rule_id" : "AUTH-004",
            "rule_name" : "Invalid User Scanning" ,
            "source_ip" : log["source_ip"],
            "host" : log["host"] ,
            "service" : log["service"] ,
            "pid" : log["pid"] ,
            "port" : log["port"] ,
            "protocol" : log["protocol"] ,
            "severity" : riskAnalysis["severity"] ,
            "risk_score" : riskAnalysis["risk_score"] ,
            "failed_attempts" : invalidUserList[key]["failCount"] , 
            "users" : list(invalidUserList[key]["users"]) ,
            "mitre_technique": "T1087",
            "status" : "OPEN" ,
            "mitre_name": "Account Discovery" ,
            "starting_time" : invalidUserList[key]["start_time"] ,
            "ending_time" : invalidUserList[key]["end_time"] ,
            "created_at": datetime.now(timezone.utc).isoformat()
          })
        
        else:

          keyExists["failed_attempts"] = invalidUserList[key]["failCount"]
          keyExists["users"] = list(invalidUserList[key]["users"])
          result = calculateRiskScore(invalidUserList[key]["failCount"],len(invalidUserList[key]["users"]))
          keyExists["risk_score"] = result["risk_score"]
          keyExists["severity"] = result["severity"]
          keyExists["ending_time"] = invalidUserList[key]["end_time"]
      
      else:
        alertCounter += 1
        riskAnalysis = calculateRiskScore(invalidUserList[key]["failCount"],len(invalidUserList[key]["users"]))
        alerts.append({
          "key" : key ,
          "alert_id" : f"ALT-{alertCounter}",
          "alert_type" : "Username Enumeration Attack",
          "rule_id" : "AUTH-004",
          "rule_name" : "Invalid User Scanning" ,
          "source_ip" : log["source_ip"],
          "host" : log["host"] ,
          "service" : log["service"] ,
          "pid" : log["pid"] ,
          "port" : log["port"] ,
          "protocol" : log["protocol"] ,
          "severity" : riskAnalysis["severity"] ,
          "risk_score" : riskAnalysis["risk_score"] ,
          "failed_attempts" : invalidUserList[key]["failCount"] , 
          "users" : list(invalidUserList[key]["users"]) ,
          "mitre_technique": "T1087",
          "mitre_name": "Account Discovery" ,
          "status" : "OPEN" ,
          "starting_time" : invalidUserList[key]["start_time"] ,
          "ending_time" : invalidUserList[key]["end_time"] ,
          "created_at": datetime.now(timezone.utc).isoformat()
        })
  return alerts
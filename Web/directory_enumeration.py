from datetime import datetime, timedelta, timezone


def calculateRiskScore(request_count):
  if request_count > 100:
    return {
      "risk_score": 95,
      "severity": "CRITICAL"
    }
  elif request_count > 50:
    return {
      "risk_score": 85,
      "severity": "HIGH"
    }
  elif request_count > 20:
    return {
      "risk_score": 70,
      "severity": "MEDIUM"
    }
  else:
    return {
      "risk_score": 0,
      "severity": "LOW"
    }



def generate_alert(alert_id,alert_type,rule_id,risk_score,severity,source_ip,logs,request_count,start_time,end_time):
  alert = {
    "key" : source_ip ,
    "alert_id": alert_id,
    "alert_type": alert_type,
    "rule_id": rule_id,
    "rule_name": "Directory Enumeration",
    "risk_score" : risk_score ,
    "severity": severity,
    "status": "OPEN",
    "status_code" : 404 ,
    "source_ip": source_ip,
    "logs" : logs ,
    "request_count" : request_count ,
    "mitre_technique": "T1595",
    "mitre_name": "Active Scanning",
    "starting_time" : start_time ,
    "ending_time" : end_time ,
    "created_at": datetime.now(timezone.utc).isoformat()
  }
  return alert




def directory_enumeration(parsedLogs):
  alerts = []
  attackList = {}
  alertCounter = 3000

  for log in parsedLogs:
    if log["status_code"] == 404:
      key = log["source_ip"]

      if key not in attackList:
        attackList[key] = {
          "request_count" : 1 ,
          "start_time" : log["timestamp_iso"] ,
          "end_time" : log["timestamp_iso"] ,
          "logs" : [log["raw_log"]]
        }
      else:

        startingTime = datetime.fromisoformat(attackList[key]["start_time"].replace("Z" , "+00:00"))
        currentTime = datetime.fromisoformat(log["timestamp_iso"].replace("Z" , "+00:00"))
        timeDiff = currentTime - startingTime

        if timeDiff <= timedelta(minutes=2):

          attackList[key]["request_count"] += 1
          attackList[key]["logs"].append(log["raw_log"])
          attackList[key]["end_time"] = log["timestamp_iso"]
          
          if attackList[key]["request_count"] > 20:
            matchingAlerts = [a for a in alerts if a["key"] == key]
            keyExists = matchingAlerts[-1] if matchingAlerts else None

            if keyExists:

              keyLastTimeStamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z" , "+00:00"))
              timeDifference = currentTime - keyLastTimeStamp

              if timeDifference > timedelta(minutes=2):
                alertCounter += 1
                riskAnalysis = calculateRiskScore(attackList[key]["request_count"])
                alerts.append(generate_alert(
                  f"ALT-{alertCounter}" ,
                  "Directory Enumeration" ,
                  "WEB-001" ,
                  riskAnalysis["risk_score"] ,
                  riskAnalysis["severity"] , 
                  log["source_ip"] ,
                  attackList[key]["logs"] ,
                  attackList[key]["request_count"] ,
                  attackList[key]["start_time"] ,
                  attackList[key]["end_time"]
                ))
              else:
                keyExists["request_count"] = attackList[key]["request_count"]
                riskAnalysis = calculateRiskScore(attackList[key]["request_count"])
                keyExists["risk_score"] = riskAnalysis["risk_score"]
                keyExists["severity"] = riskAnalysis["severity"]
                keyExists["logs"] = attackList[key]["logs"]
                keyExists["ending_time"] = attackList[key]["end_time"]

            else:

              alertCounter += 1
              riskAnalysis = calculateRiskScore(attackList[key]["request_count"])
              alerts.append(generate_alert(
                f"ALT-{alertCounter}" ,
                "Directory Enumeration" ,
                "WEB-001" ,
                riskAnalysis["risk_score"] ,
                riskAnalysis["severity"] , 
                log["source_ip"] ,
                attackList[key]["logs"] ,
                attackList[key]["request_count"] ,
                attackList[key]["start_time"] ,
                attackList[key]["end_time"]
              ))
        
        else:
          matchingAlerts = [a for a in alerts if a["key"] == key]
          keyExists = matchingAlerts[-1] if matchingAlerts else None

          if keyExists:

            lastTimestamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z" , "+00:00"))
            timeDifference = currentTime - lastTimestamp

            if timeDifference > timedelta(minutes=2):

              attackList[key] = {
                "request_count" : 1 ,
                "start_time" : log["timestamp_iso"] ,
                "end_time" : log["timestamp_iso"] ,
                "logs" : [log["raw_log"]]
              }
            
            else :
              attackList[key]["request_count"] += 1
              attackList[key]["logs"].append(log["raw_log"])
              attackList[key]["end_time"] = log["timestamp_iso"]
              
              keyExists["request_count"] = attackList[key]["request_count"]
              riskAnalysis = calculateRiskScore(attackList[key]["request_count"])
              keyExists["risk_score"] = riskAnalysis["risk_score"]
              keyExists["severity"] = riskAnalysis["severity"]
              keyExists["logs"] = attackList[key]["logs"]
              keyExists["ending_time"] = attackList[key]["end_time"]
          
          else:
            attackList[key] = {
              "request_count" : 1 ,
              "start_time" : log["timestamp_iso"] ,
              "end_time" : log["timestamp_iso"] ,
              "logs" : [log["raw_log"]]
            }
  return alerts
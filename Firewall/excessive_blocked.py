from datetime import datetime, timedelta, timezone



def calculateRiskScore(drop_count):
  risk_score = 50

  if drop_count > 50:
    risk_score += 20

  if drop_count >= 75:
    risk_score += 10

  if drop_count >= 100:
    risk_score += 10

  risk_score = min(risk_score, 100)

  if risk_score >= 90:
    severity = "CRITICAL"
  elif risk_score >= 70:
    severity = "HIGH"
  elif risk_score >= 40:
    severity = "MEDIUM"
  else:
    severity = "LOW"
  return risk_score, severity




def generate_alert(alert_id , alert_type , rule_id , risk_score , severity , source_ip , destination_ips , destination_ports , source_ports , drop_count , host , service , start_time , end_time):
  alert = {
    "key" : source_ip ,
    "alert_id" : alert_id ,
    "alert_type" : alert_type ,
    "rule_id" : rule_id ,
    "rule_name" : "Excessive Blocked Connections" ,
    "risk_score" : risk_score ,
    "severity" : severity ,
    "source_ip" : source_ip ,
    "destination_ips" : destination_ips ,
    "destination_ports" : destination_ports ,
    "source_ports" : source_ports ,
    "drop_count" : drop_count ,
    "status" : "OPEN" ,
    "action" : "DROP" ,
    "host" : host ,
    "service" : service ,
    "mitre_name" : "Excessive Blocked Connections" ,
    "mitre_technique" : "T1190" ,
    "starting_time" : start_time ,
    "ending_time" : end_time ,
    "created_at": datetime.now(timezone.utc).isoformat()
  }
  return alert




def excessive_blocked_connections(parsedLogs):
  alerts = []
  attackList = {}
  alertCounter = 3000

  for log in parsedLogs:
    key = log["source_ip"]

    if key not in attackList:
      attackList[key] = {
        "destination_ports" : {log["destination_port"]} ,
        "source_ports" : {log["source_port"]} ,
        "source_ip" : log["source_ip"] ,
        "destination_ips" : {log["destination_ip"]} ,
        "drop_count" : 1 ,
        "start_time" : log["timestamp_iso"] ,
        "end_time" : log["timestamp_iso"]
      }
    else:

      startingTime = datetime.fromisoformat(attackList[key]["start_time"].replace("Z" , "+00:00"))
      currentTime = datetime.fromisoformat(log["timestamp_iso"].replace("Z" , "+00:00"))
      timeDiff = currentTime - startingTime

      if timeDiff <= timedelta(minutes=10):

        attackList[key]["destination_ports"].add(log["destination_port"])
        attackList[key]["source_ports"].add(log["source_port"])
        attackList[key]["destination_ips"].add(log["destination_ip"])
        attackList[key]["drop_count"] += 1
        attackList[key]["end_time"] = log["timestamp_iso"]
        
        if attackList[key]["drop_count"] > 50:
          matchingAlerts = [a for a in alerts if a["key"] == key]
          keyExists = matchingAlerts[-1] if matchingAlerts else None

          if keyExists:

            keyLastTimeStamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z","+00:00"))
            timeDifference = currentTime - keyLastTimeStamp

            if timeDifference > timedelta(minutes=10):
              alertCounter += 1
              risk_score, severity = calculateRiskScore(attackList[key]["drop_count"])
              alerts.append(generate_alert(
                f"ALT-{alertCounter}" ,
                "Excessive Blocked Connections" ,
                "FW-002" ,
                risk_score ,
                severity , 
                attackList[key]["source_ip"] ,
                list(attackList[key]["destination_ips"]) ,
                list(attackList[key]["destination_ports"]) ,
                list(attackList[key]["source_ports"]) ,
                attackList[key]["drop_count"] ,
                log["host"] ,
                log["service"] ,
                attackList[key]["start_time"] ,
                attackList[key]["end_time"]
              ))
            else:

              keyExists["destination_ports"] = list(attackList[key]["destination_ports"])
              keyExists["source_ports"] = list(attackList[key]["source_ports"])
              keyExists["destination_ips"] = list(attackList[key]["destination_ips"])
              keyExists["drop_count"] = attackList[key]["drop_count"]

              risk_score, severity = calculateRiskScore(attackList[key]["drop_count"])

              keyExists["risk_score"] = risk_score
              keyExists["severity"] = severity
              keyExists["ending_time"] = attackList[key]["end_time"]

          else:

            alertCounter += 1
            risk_score, severity = calculateRiskScore(attackList[key]["drop_count"])
            alerts.append(generate_alert(
              f"ALT-{alertCounter}" ,
              "Excessive Blocked Connections" ,
              "FW-002" ,
              risk_score ,
              severity , 
              attackList[key]["source_ip"] ,
              list(attackList[key]["destination_ips"]) ,
              list(attackList[key]["destination_ports"]) ,
              list(attackList[key]["source_ports"]) ,
              attackList[key]["drop_count"] ,
              log["host"] ,
              log["service"] ,
              attackList[key]["start_time"] ,
              attackList[key]["end_time"]
            ))
      
      else:
        matchingAlerts = [a for a in alerts if a["key"] == key]
        keyExists = matchingAlerts[-1] if matchingAlerts else None

        if keyExists:

          lastTimestamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z" , "+00:00"))
          timeDifference = currentTime - lastTimestamp

          if timeDifference > timedelta(minutes=10):

            attackList[key] = {
              "destination_ports" : {log["destination_port"]} ,
              "source_ports" : {log["source_port"]} ,
              "source_ip" : log["source_ip"] ,
              "destination_ips" : {log["destination_ip"]} ,
              "drop_count" : 1 ,
              "start_time" : log["timestamp_iso"] ,
              "end_time" : log["timestamp_iso"]
            }
          
          else :
            attackList[key]["destination_ports"].add(log["destination_port"])
            attackList[key]["source_ports"].add(log["source_port"])
            attackList[key]["destination_ips"].add(log["destination_ip"])
            attackList[key]["drop_count"] += 1
            attackList[key]["end_time"] = log["timestamp_iso"]
            
            keyExists["destination_ports"] = list(attackList[key]["destination_ports"])
            keyExists["source_ports"] = list(attackList[key]["source_ports"])
            keyExists["destination_ips"] = list(attackList[key]["destinations_ips"])
            keyExists["drop_count"] = attackList[key]["drop_count"]

            risk_score, severity = calculateRiskScore(attackList[key]["drop_count"])
            
            keyExists["risk_score"] = risk_score
            keyExists["severity"] = severity
            keyExists["ending_time"] = attackList[key]["end_time"]
        
        else:
          attackList[key] = {
            "destination_ports" : {log["destination_port"]} ,
            "source_ports" : {log["source_port"]} ,
            "source_ip" : log["source_ip"] ,
            "destination_ips" : {log["destination_ip"]} ,
            "drop_count" : 1 ,
            "start_time" : log["timestamp_iso"] ,
            "end_time" : log["timestamp_iso"]
          }
  return alerts
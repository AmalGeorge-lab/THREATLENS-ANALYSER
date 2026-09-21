from datetime import datetime, timedelta, timezone



def calculateRiskScore(unique_ports, action):
  risk_score = 50
  if unique_ports >= 20:
    risk_score += 25
  if unique_ports >= 30:
    risk_score += 10
  if unique_ports >= 50:
    risk_score += 10

  if action == True:
    risk_score += 5
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




def generate_alert(alert_id , alert_type , rule_id , risk_score , severity , source_ip , destination_ip , destination_ports , source_ports , actions , host , service , accepted_ports , start_time , end_time):
  alert = {
    "key" : source_ip ,
    "alert_id" : alert_id ,
    "alert_type" : alert_type ,
    "rule_id" : rule_id ,
    "rule_name" : "Port Scanning" ,
    "risk_score" : risk_score ,
    "severity" : severity ,
    "source_ip" : source_ip ,
    "destination_ip" : destination_ip ,
    "destination_ports" : destination_ports ,
    "source_ports" : source_ports ,
    "actions" : actions ,
    "status" : "OPEN" ,
    "host" : host ,
    "service" : service ,
    "accepted_destination_ports" : accepted_ports ,
    "mitre_name" : "Port Scanning" ,
    "mitre_technique" : "T1595" ,
    "starting_time" : start_time ,
    "ending_time" : end_time ,
    "created_at": datetime.now(timezone.utc).isoformat()
  }
  return alert




def port_scanning(parsedLogs):
  alerts = []
  attackList = {}
  alertCounter = 1000

  for log in parsedLogs:
    key = log["source_ip"]

    if key not in attackList:
      attackList[key] = {
        "destination_ports" : {log["destination_port"]} ,
        "source_ports" : {log["source_port"]} ,
        "source_ip" : log["source_ip"] ,
        "destination_ip" : log["destination_ip"] ,
        "actions" : {log["action"]} ,
        "accepted_destination_ports" : {log["destination_port"]} if log["action"] == "ACCEPT" else set() ,
        "start_time" : log["timestamp_iso"] ,
        "end_time" : log["timestamp_iso"]
      }
    else:

      startingTime = datetime.fromisoformat(attackList[key]["start_time"].replace("Z" , "+00:00"))
      currentTime = datetime.fromisoformat(log["timestamp_iso"].replace("Z" , "+00:00"))
      timeDiff = currentTime - startingTime

      if timeDiff <= timedelta(minutes=5):

        attackList[key]["destination_ports"].add(log["destination_port"])
        attackList[key]["source_ports"].add(log["source_port"])
        attackList[key]["actions"].add(log["action"])
        attackList[key]["end_time"] = log["timestamp_iso"]

        if log["action"] == "ACCEPT":
          attackList[key]["accepted_destination_ports"].add(log["destination_port"])
        
        if len(attackList[key]["destination_ports"]) > 20:
          matchingAlerts = [a for a in alerts if a["key"] == key]
          keyExists = matchingAlerts[-1] if matchingAlerts else None

          if keyExists:

            keyLastTimeStamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z","+00:00"))
            timeDifference = currentTime - keyLastTimeStamp

            if timeDifference > timedelta(minutes=5):
              alertCounter += 1
              accept_action = "ACCEPT" in attackList[key]["actions"]
              risk_score, severity = calculateRiskScore(len(attackList[key]["destination_ports"]) , accept_action)
              alerts.append(generate_alert(
                f"ALT-{alertCounter}" ,
                "Port Scanning Detection" ,
                "FW-001" ,
                risk_score ,
                severity , 
                attackList[key]["source_ip"] ,
                attackList[key]["destination_ip"] ,
                list(attackList[key]["destination_ports"]) ,
                list(attackList[key]["source_ports"]) ,
                list(attackList[key]["actions"]) ,
                log["host"] ,
                log["service"] ,
                list(attackList[key]["accepted_destination_ports"]) if len(attackList[key]["accepted_destination_ports"]) else list() ,
                attackList[key]["start_time"] ,
                attackList[key]["end_time"]
              ))
            else:

              keyExists["destination_ports"] = list(attackList[key]["destination_ports"])
              keyExists["source_ports"] = list(attackList[key]["source_ports"])
              keyExists["actions"] = list(attackList[key]["actions"])
              keyExists["accepted_destination_ports"] = list(attackList[key]["accepted_destination_ports"])

              accept_action = "ACCEPT" in attackList[key]["actions"]
              risk_score, severity = calculateRiskScore(len(attackList[key]["destination_ports"]) , accept_action)

              keyExists["risk_score"] = risk_score
              keyExists["severity"] = severity
              keyExists["ending_time"] = attackList[key]["end_time"]

          else:

            alertCounter += 1
            accept_action = "ACCEPT" in attackList[key]["actions"]
            risk_score, severity = calculateRiskScore(len(attackList[key]["destination_ports"]) , accept_action)
            alerts.append(generate_alert(
              f"ALT-{alertCounter}" ,
              "Port Scanning Detection" ,
              "FW-001" ,
              risk_score ,
              severity , 
              attackList[key]["source_ip"] ,
              attackList[key]["destination_ip"] ,
              list(attackList[key]["destination_ports"]) ,
              list(attackList[key]["source_ports"]) ,
              list(attackList[key]["actions"]) ,
              log["host"] ,
              log["service"] ,
              list(attackList[key]["accepted_destination_ports"]) if len(attackList[key]["accepted_destination_ports"]) else list() ,
              attackList[key]["start_time"] ,
              attackList[key]["end_time"]
            ))
      
      else:
        matchingAlerts = [a for a in alerts if a["key"] == key]
        keyExists = matchingAlerts[-1] if matchingAlerts else None

        if keyExists:

          lastTimestamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z" , "+00:00"))
          timeDifference = currentTime - lastTimestamp

          if timeDifference > timedelta(minutes=5):

            attackList[key] = {
              "destination_ports" : {log["destination_port"]} ,
              "source_ports" : {log["source_port"]} ,
              "source_ip" : log["source_ip"] ,
              "destination_ip" : log["destination_ip"] ,
              "actions" : {log["action"]} ,
              "accepted_destination_ports" : {log["destination_port"]} if log["action"] == "ACCEPT" else set() ,
              "start_time" : log["timestamp_iso"] ,
              "end_time" : log["timestamp_iso"]
            }
          
          else :
            attackList[key]["destination_ports"].add(log["destination_port"])
            attackList[key]["source_ports"].add(log["source_port"])
            attackList[key]["actions"].add(log["action"])
            attackList[key]["end_time"] = log["timestamp_iso"]
    
            if log["action"] == "ACCEPT":
              attackList[key]["accepted_destination_ports"].add(log["destination_port"])
            
            keyExists["destination_ports"] = list(attackList[key]["destination_ports"])
            keyExists["source_ports"] = list(attackList[key]["source_ports"])
            keyExists["actions"] = list(attackList[key]["actions"])
            keyExists["accepted_destination_ports"] = list(attackList[key]["accepted_destination_ports"])

            accept_action = "ACCEPT" in attackList[key]["actions"]
            risk_score, severity = calculateRiskScore(len(attackList[key]["destination_ports"]) , accept_action)
            
            keyExists["risk_score"] = risk_score
            keyExists["severity"] = severity
            keyExists["ending_time"] = attackList[key]["end_time"]
        
        else:
          attackList[key] = {
            "destination_ports" : {log["destination_port"]} ,
            "source_ports" : {log["source_port"]} ,
            "source_ip" : log["source_ip"] ,
            "destination_ip" : log["destination_ip"] ,
            "actions" : {log["action"]} ,
            "accepted_destination_ports" : {log["destination_port"]} if log["action"] == "ACCEPT" else set() ,
            "start_time" : log["timestamp_iso"] ,
            "end_time" : log["timestamp_iso"]
          }
  return alerts
from datetime import datetime, timedelta, timezone
import ipaddress

INTERNAL_NETWORKS = [
  ipaddress.ip_network("192.168.1.0/24"),
  ipaddress.ip_network("10.0.0.0/8"),
  ipaddress.ip_network("172.16.0.0/12")
]

def is_internal(ip):
  ip_obj = ipaddress.ip_address(ip)
  return any(ip_obj in network for network in INTERNAL_NETWORKS)


def is_external(ip):
  return not is_internal(ip)



def calculateRiskScore(destination_ip_count):
  risk_score = 50

  if destination_ip_count > 5:
    risk_score += 20

  if destination_ip_count >= 10:
    risk_score += 10

  if destination_ip_count >= 20:
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




def generate_alert(alert_id , alert_type , rule_id , risk_score , severity , source_ip , destination_ips , host , service , start_time , end_time):
  alert = {
    "key" : source_ip ,
    "alert_id" : alert_id ,
    "alert_type" : alert_type ,
    "rule_id" : rule_id ,
    "rule_name" : "Internal Network Access Attempt" ,
    "risk_score" : risk_score ,
    "severity" : severity ,
    "source_ip" : source_ip ,
    "destination_ips" : destination_ips ,
    "status" : "OPEN" ,
    "host" : host ,
    "service" : service ,
    "mitre_name" : "Internal Network Access Attempt" ,
    "mitre_technique" : "T1046" ,
    "starting_time" : start_time ,
    "ending_time" : end_time ,
    "created_at": datetime.now(timezone.utc).isoformat()
  }
  return alert




def internal_network_access(parsedLogs):
  alerts = []
  attackList = {}
  alertCounter = 7000

  for log in parsedLogs:
    if is_external(log["source_ip"]) and is_internal(log["destination_ip"]):
      key = log["source_ip"]

      if key not in attackList:
        attackList[key] = {
          "source_ip" : log["source_ip"] ,
          "destination_ips" : {log["destination_ip"]} ,
          "start_time" : log["timestamp_iso"] ,
          "end_time" : log["timestamp_iso"]
        }
      else:

        startingTime = datetime.fromisoformat(attackList[key]["start_time"].replace("Z" , "+00:00"))
        currentTime = datetime.fromisoformat(log["timestamp_iso"].replace("Z" , "+00:00"))
        timeDiff = currentTime - startingTime

        if timeDiff <= timedelta(minutes=5):

          attackList[key]["destination_ips"].add(log["destination_ip"])
          attackList[key]["end_time"] = log["timestamp_iso"]
          
          if len(attackList[key]["destination_ips"]) > 5:
            matchingAlerts = [a for a in alerts if a["key"] == key]
            keyExists = matchingAlerts[-1] if matchingAlerts else None

            if keyExists:

              keyLastTimeStamp = datetime.fromisoformat(keyExists["ending_time"].replace("Z","+00:00"))
              timeDifference = currentTime - keyLastTimeStamp

              if timeDifference > timedelta(minutes=5):
                alertCounter += 1
                risk_score, severity = calculateRiskScore(len(attackList[key]["destination_ips"]))
                alerts.append(generate_alert(
                  f"ALT-{alertCounter}" ,
                  "Internal Network Access Attempt" ,
                  "FW-004" ,
                  risk_score ,
                  severity , 
                  attackList[key]["source_ip"] ,
                  list(attackList[key]["destination_ips"]) ,
                  log["host"] ,
                  log["service"] ,
                  attackList[key]["start_time"] ,
                  attackList[key]["end_time"]
                ))
              else:

                keyExists["destination_ips"] = list(attackList[key]["destination_ips"])

                risk_score, severity = calculateRiskScore(len(attackList[key]["destination_ips"]))

                keyExists["risk_score"] = risk_score
                keyExists["severity"] = severity
                keyExists["ending_time"] = attackList[key]["end_time"]

            else:

              alertCounter += 1
              risk_score, severity = calculateRiskScore(len(attackList[key]["destination_ips"]))
              alerts.append(generate_alert(
                f"ALT-{alertCounter}" ,
                "Internal Network Access Attempt" ,
                "FW-004" ,
                risk_score ,
                severity , 
                attackList[key]["source_ip"] ,
                list(attackList[key]["destination_ips"]) ,
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

            if timeDifference > timedelta(minutes=5):

              attackList[key] = {
                "source_ip" : log["source_ip"] ,
                "destination_ips" : {log["destination_ip"]} ,
                "start_time" : log["timestamp_iso"] ,
                "end_time" : log["timestamp_iso"]
              }
            
            else :

              attackList[key]["destination_ips"].add(log["destination_ip"])
              attackList[key]["end_time"] = log["timestamp_iso"]
              
              keyExists["destination_ips"] = list(attackList[key]["destinations_ips"])

              risk_score, severity = calculateRiskScore(len(attackList[key]["destination_ips"]))
              
              keyExists["risk_score"] = risk_score
              keyExists["severity"] = severity
              keyExists["ending_time"] = attackList[key]["end_time"]
          
          else:
            attackList[key] = {
              "source_ip" : log["source_ip"] ,
              "destination_ips" : {log["destination_ip"]} ,
              "start_time" : log["timestamp_iso"] ,
              "end_time" : log["timestamp_iso"]
            }
  return alerts
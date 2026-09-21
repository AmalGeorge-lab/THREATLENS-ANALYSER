import re
from datetime import datetime



logRegex = r"""(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[a-zA-Z0-9._-]+)\s+(?P<service>[a-zA-Z0-9._-]+):\s+(?P<message>.*)"""



def parse_kernel_firewall(message):
  data = {}
  pairs = re.findall(r"([A-Z_]+)=([^\s]*)", message)
  for key, value in pairs:
    if value:
      data[key] = value
  return {
    "interface_in": data.get("IN"),
    "interface_out" : data.get("OUT") if data.get("OUT") else None ,
    "MAC_address" : data.get("MAC") ,
    "source_ip": data.get("SRC"),
    "destination_ip": data.get("DST"),
    "packet_length" : data.get("LEN") ,
    "protocol": data.get("PROTO"),
    "source_port": int(data.get("SPT")) if data.get("SPT") else None,
    "destination_port": int(data.get("DPT")) if data.get("DPT") else None,
    "action": data.get("ACTION")
  }




def parserEngine(logs):
  parsedLogs = []
  for line in logs.splitlines():
    line = line.strip()
    if not line:
      continue
    match = re.search(logRegex, line, re.VERBOSE)
    if not match:
      continue
    data = match.groupdict()
    currentYear = datetime.now().year
    dt = datetime.strptime(f"{currentYear} {data['timestamp']}", "%Y %b %d %H:%M:%S")
    eventData = parse_kernel_firewall(data["message"])
    parsedLog = {
      "raw_log": line,
      "log_type": "FIREWALL",
      "timestamp_iso": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
      "host": data["host"],
      "service": data["service"],
      **eventData
    }
    parsedLogs.append(parsedLog)
  return parsedLogs
import re
from datetime import datetime




logRegex = r"""(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[a-zA-Z0-9._-]+)\s+(?P<service>[a-zA-Z0-9._-]+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)"""



def restData(message):
  failed = re.search(r"Failed password for (?P<user>\w+) from (?P<ip>[\d.]+) port (?P<port>\d+) (?P<protocol>\w+)",message)
  if failed:
    return {
      "event": "FAILED_LOGIN",
      "user": failed.group("user"),
      "source_ip": failed.group("ip"),
      "port": int(failed.group("port")),
      "protocol": failed.group("protocol")
    }
  accepted = re.search(r"Accepted password for (?P<user>\w+) from (?P<ip>[\d.]+) port (?P<port>\d+) (?P<protocol>\w+)",message)
  if accepted:
    return {
      "event": "SUCCESSFUL_LOGIN",
      "user": accepted.group("user"),
      "source_ip": accepted.group("ip"),
      "port": int(accepted.group("port")),
      "protocol": accepted.group("protocol")
    }
  invalid = re.search(r"Failed password for invalid user (?P<user>\w+) from (?P<ip>[\d.]+) port (?P<port>\d+) (?P<protocol>\w+)",message)
  if invalid:
    return {
      "event": "INVALID_USER",
      "user": invalid.group("user"),
      "source_ip": invalid.group("ip"),
      "port": int(invalid.group("port")),
      "protocol" : invalid.group("protocol")
    }
  return {
    "event": "UNKNOWN_SSH_EVENT"
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
    dt = datetime.strptime(f"{currentYear} {data['timestamp']}","%Y %b %d %H:%M:%S")
    eventData = restData(data["message"]);
    parsedLog = {
      "raw_log": line,
      "log_type": "LINUX_AUTH",
      "timestamp_iso": dt.isoformat() + "Z",
      "host": data["host"],
      "service": data["service"],
      "pid": int(data["pid"]),
      **eventData
    }
    parsedLogs.append(parsedLog)
  return parsedLogs
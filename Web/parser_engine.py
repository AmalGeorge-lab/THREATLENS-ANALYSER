import re
from datetime import datetime
from urllib.parse import unquote



def decode_web_log(log_line):
  pattern = r'"([A-Z]+)\s+(.+?)\s+(HTTP/\d\.\d)"'
  match = re.search(pattern, log_line)
  if not match:
    return log_line
  method, uri, version = match.groups()
  decoded_uri = unquote(unquote(uri))
  decoded_request = f'"{method} {decoded_uri} {version}"'
  return re.sub(pattern, decoded_request, log_line, count=1)



logRegex = r'''(?P<source_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<http_method>\S+)\s+(?P<request_uri>.*?)\s+(?P<http_version>HTTP/\d\.\d)"\s+(?P<status_code>\d+)\s+(?P<response_size>\d+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'''



def parserEngine(logs):
  parsedLogs = []
  for line in logs:
    line = line.strip()
    if not line:
      continue
    match = re.search(logRegex, line, re.VERBOSE)
    if not match:
      continue
    data = match.groupdict()
    dt = datetime.strptime(data["timestamp"],"%d/%b/%Y:%H:%M:%S %z")
    parsedLog = {
      "raw_log": line,
      "log_type": "WEB_ACCESS",
      "timestamp_iso": dt.isoformat(),
      "source_ip": data["source_ip"],
      "http_method": data["http_method"],
      "request_uri": data["request_uri"],
      "http_version": data["http_version"],
      "status_code": int(data["status_code"]),
      "response_size": int(data["response_size"]),
      "referrer": data["referrer"],
      "user_agent": data["user_agent"]
    }
    parsedLogs.append(parsedLog)
  return parsedLogs
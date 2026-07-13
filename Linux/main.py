from Linux.parser_engine import parserEngine
from Linux.password_spraying import passwordSprayingDetector
from Linux.invalid_user import invalidUserDetector
from Linux.brute_force import bruteForceAttackDetector
from Linux.distributed_attack import distributedAttackDetector






def linux_log_analyser(logs):
  parsedLogs = parserEngine(logs)
  failed_login_events = []
  invalid_events = []
  for log in parsedLogs:
    if log["event"] != "INVALID_USER" and log["event"] != "UNKNOWN_SSH_EVENT":
      failed_login_events.append(log)
    else:
      continue
  for log in parsedLogs:
    if log["event"] == "INVALID_USER" and log["event"] != "UNKNOWN_SSH_EVENT":
      invalid_events.append(log)
    else:
      continue
  bruteForceAlerts = bruteForceAttackDetector(failed_login_events)
  distributedAttackAlerts = distributedAttackDetector(failed_login_events)
  passwordSprayingAlerts = passwordSprayingDetector(failed_login_events)
  invalidUserAlerts = invalidUserDetector(invalid_events)

  total_alerts = bruteForceAlerts + distributedAttackAlerts + passwordSprayingAlerts + invalidUserAlerts
  return { "alerts" : total_alerts , "parsedLogs" : len(parsedLogs) }
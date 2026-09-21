from Web.directory_enumeration import directory_enumeration
from Web.parser_engine import parserEngine
from Web.sensitive_file import sensitive_file_attack
from Web.sql_attack import sql_attack
from Web.web_shell_access import web_shell_access
from Web.parser_engine import decode_web_log



def web_log_analyser(logs):
  decoded_logs = [decode_web_log(log) for log in logs.splitlines()]
  parsedLogs = parserEngine(decoded_logs)

  directory_enumeration_attacks = directory_enumeration(parsedLogs)
  sensitive_file_attacks = sensitive_file_attack(parsedLogs)
  sql_attacks = sql_attack(parsedLogs)
  web_shell_access_attacks = web_shell_access(parsedLogs)

  total_alerts = directory_enumeration_attacks + sensitive_file_attacks + sql_attacks + web_shell_access_attacks
  return { "alerts" : total_alerts , "parsedLogs" : len(parsedLogs) }
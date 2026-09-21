from Firewall.parser_engine import parserEngine
from Firewall.excessive_blocked import excessive_blocked_connections
from Firewall.internal_network_access import internal_network_access
from Firewall.port_scanning import port_scanning
from Firewall.ssh_targeting import ssh_targeting



def firewall_log_analyser(logs):
  parsedLogs = parserEngine(logs)
  excessive_blocked_connections_attacks = excessive_blocked_connections(parsedLogs)
  internal_network_access_attacks = internal_network_access(parsedLogs)
  port_scanning_attacks = port_scanning(parsedLogs)
  ssh_targeting_attacks = ssh_targeting(parsedLogs)

  total_alerts = excessive_blocked_connections_attacks + internal_network_access_attacks + port_scanning_attacks + ssh_targeting_attacks
  return { "alerts" : total_alerts , "parsedLogs" : len(parsedLogs) }
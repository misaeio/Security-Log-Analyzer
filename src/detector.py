import json
from collections import defaultdict
from typing import List, Dict, Any

class ThreatDetector:
    def __init__(self, rules_path: str = "rules/detection_rules.json"):
        with open(rules_path, 'r') as f:
            self.rules = json.load(f)

    def analyze(self, parsed_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        alerts = []
        failed_attempts = defaultdict(list)
        summary = {
            "total_logs": len(parsed_logs),
            "failed_logins": 0,
            "successful_logins": 0,
            "web_requests": 0,
            "malformed_logs": 0
        }

        for entry in parsed_logs:
            if not entry:
                continue
                
            if entry.get("type") == "MALFORMED":
                summary["malformed_logs"] += 1
                continue

            # SSH Analysis
            if entry.get("type") == "SSH":
                if entry["event_type"] == "FAILED_LOGIN":
                    summary["failed_logins"] += 1
                    failed_attempts[entry["ip"]].append(entry["timestamp"])
                elif entry["event_type"] == "SUCCESSFUL_LOGIN":
                    summary["successful_logins"] += 1

            # Web Log Analysis
            elif entry.get("type") == "WEB":
                summary["web_requests"] += 1
                path = entry.get("path", "")

                # Detect SQL Injection
                for sqli in self.rules["sql_injection_patterns"]:
                    if sqli.lower() in path.lower():
                        alerts.append({
                            "severity": "HIGH",
                            "type": "SQL Injection Attempt",
                            "mitre_id": "T1190",
                            "ip": entry["ip"],
                            "details": f"Payload detected in path: {path}"
                        })

                # Detect Sensitive File Traversal
                for sens_file in self.rules["sensitive_file_access"]:
                    if sens_file in path:
                        alerts.append({
                            "severity": "CRITICAL",
                            "type": "Path Traversal / Sensitive Access",
                            "mitre_id": "T1083",
                            "ip": entry["ip"],
                            "details": f"Attempted access to {path}"
                        })

        # Check SSH Brute Force Thresholds
        max_attempts = self.rules["failed_login_threshold"]["max_attempts"]
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= max_attempts:
                alerts.append({
                    "severity": self.rules["failed_login_threshold"]["severity"],
                    "type": "SSH Brute Force Attack",
                    "mitre_id": self.rules["failed_login_threshold"]["mitre_id"],
                    "ip": ip,
                    "details": f"{len(attempts)} failed login attempts detected from IP."
                })

        return {
            "summary": summary,
            "alerts": alerts
        }
import re
from datetime import datetime
from typing import Dict, Any, Optional

class LogParser:
    # SSH Auth Log Regex: e.g., "Oct 24 14:02:11 hostname sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
    SSH_AUTH_REGEX = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>[\w.-]+)\s+'
        r'(?P<process>[\w\[\]\.]+):\s+'
        r'(?P<message>.*)$'
    )

    # Combined Web Log Regex
    WEB_LOG_REGEX = re.compile(
        r'^(?P<ip>[\d\.]+)\s+-\s+-\s+\[(?P<timestamp>.*?)\]\s+'
        r'"(?P<method>\A[A-Z]+|GET|POST|PUT|DELETE|HEAD)\s+(?P<path>\S+)\s+HTTP/[0-9\.]+"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    )

    def __init__(self):
        self.malformed_count = 0

    def parse_ssh_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None

        match = self.SSH_AUTH_REGEX.match(line)
        if not match:
            self.malformed_count += 1
            return {"type": "MALFORMED", "raw": line}

        data = match.groupdict()
        msg = data['message']
        
        # Extract IP address if present
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', msg)
        ip = ip_match.group(0) if ip_match else "N/A"

        event_type = "UNKNOWN"
        if "Failed password" in msg:
            event_type = "FAILED_LOGIN"
        elif "Accepted password" in msg or "Accepted publickey" in msg:
            event_type = "SUCCESSFUL_LOGIN"
        elif "Invalid user" in msg:
            event_type = "INVALID_USER"

        return {
            "type": "SSH",
            "timestamp": data['timestamp'],
            "hostname": data['hostname'],
            "process": data['process'],
            "event_type": event_type,
            "ip": ip,
            "message": msg
        }

    def parse_web_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.strip()
        if not line:
            return None

        match = self.WEB_LOG_REGEX.match(line)
        if not match:
            self.malformed_count += 1
            return {"type": "MALFORMED", "raw": line}

        data = match.groupdict()
        return {
            "type": "WEB",
            "ip": data["ip"],
            "timestamp": data["timestamp"],
            "method": data["method"],
            "path": data["path"],
            "status": int(data["status"]),
            "bytes": 0 if data["bytes"] == "-" else int(data["bytes"])
        }
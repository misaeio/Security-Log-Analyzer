import pytest
from src.detector import ThreatDetector

def test_sql_injection_detection(tmp_path):
    # Setup test detection rules
    rules_content = """{
        "failed_login_threshold": {"max_attempts": 5, "severity": "HIGH", "mitre_id": "T1110"},
        "sql_injection_patterns": ["UNION SELECT", "' OR '1'='1"],
        "sensitive_file_access": ["/etc/passwd"]
    }"""
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(rules_content)

    detector = ThreatDetector(rules_path=str(rules_file))
    
    parsed_web_log = [{
        "type": "WEB",
        "ip": "10.0.0.50",
        "path": "/login?user=admin' UNION SELECT NULL--",
        "status": 500,
        "bytes": 200
    }]

    analysis = detector.analyze(parsed_web_log)
    
    assert len(analysis["alerts"]) == 1
    assert analysis["alerts"][0]["type"] == "SQL Injection Attempt"
    assert analysis["alerts"][0]["mitre_id"] == "T1190"

def test_sensitive_file_access(tmp_path):
    rules_content = """{
        "failed_login_threshold": {"max_attempts": 5, "severity": "HIGH", "mitre_id": "T1110"},
        "sql_injection_patterns": [],
        "sensitive_file_access": ["/etc/passwd"]
    }"""
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(rules_content)

    detector = ThreatDetector(rules_path=str(rules_file))
    
    parsed_logs = [{
        "type": "WEB",
        "ip": "192.168.1.99",
        "path": "/download?file=/etc/passwd",
        "status": 403,
        "bytes": 0
    }]

    analysis = detector.analyze(parsed_logs)
    
    assert len(analysis["alerts"]) == 1
    assert analysis["alerts"][0]["severity"] == "CRITICAL"
    assert analysis["alerts"][0]["mitre_id"] == "T1083"

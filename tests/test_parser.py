import pytest
from src.parser import LogParser
from src.detector import ThreatDetector

def test_ssh_valid_parse():
    parser = LogParser()
    log = "Oct 27 10:00:01 server sshd[1001]: Failed password for invalid user admin from 192.168.1.105 port 4421 ssh2"
    result = parser.parse_ssh_line(log)
    
    assert result["type"] == "SSH"
    assert result["event_type"] == "FAILED_LOGIN"
    assert result["ip"] == "192.168.1.105"

def test_malformed_input_handling():
    parser = LogParser()
    log = "CORRUPTED DATA LINE NOT MATCHING REGEX"
    result = parser.parse_ssh_line(log)
    
    assert result["type"] == "MALFORMED"
    assert parser.malformed_count == 1

def test_brute_force_detection():
    detector = ThreatDetector()
    logs = [
        {"type": "SSH", "event_type": "FAILED_LOGIN", "ip": "10.0.0.1", "timestamp": f"10:00:0{i}"}
        for i in range(6)
    ]
    analysis = detector.analyze(logs)
    
    assert len(analysis["alerts"]) == 1
    assert analysis["alerts"][0]["type"] == "SSH Brute Force Attack"
    assert analysis["alerts"][0]["mitre_id"] == "T1110"
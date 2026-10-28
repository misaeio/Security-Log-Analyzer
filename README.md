# Python Security Log Analyzer

A Python tool that analyzes authentication and web server logs to identify suspicious activity. It looks for patterns such as repeated failed logins, SQL injection attempts, and path traversal attempts, then generates an HTML report with the results.

## Features

- Parses SSH authentication logs and Apache or Nginx access logs
- Detects repeated failed login attempts that may indicate brute force attacks
- Checks web requests for common attack patterns, including SQL injection and path traversal
- Handles malformed log entries without stopping the entire analysis
- Tracks log counts, failed logins, and detected alerts
- Generates an HTML report summarizing the results
- Maps supported detections to MITRE ATT&CK techniques (T1110, T1190, T1083)

## Example Output

```text
Incident Analysis Summary

Total Logs: 8
Failed Logins: 5
Successful Logins: 1
Web Requests: 3
Malformed Logs: 1

Alerts Triggered: 3
[HIGH] SSH Brute Force Attack (T1110) - 192.168.1.105
[HIGH] SQL Injection Attempt (T1190) - 10.0.0.85
[CRITICAL] Path Traversal Attempt (T1083) - 10.0.0.85
```

This is an example of the analyzer's output. Actual results depend on the input logs and the detection rules configured in `rules/detection_rules.json`.

## Technologies

- Python 3
- Pytest for unit testing
- Jinja2 for HTML report generation
- Regular expressions for log parsing and pattern matching
- MITRE ATT&CK technique mapping

## Running the Project

### 1. Clone the repository

```powershell
git clone YOUR_REPOSITORY_URL
cd security-log-analyzer
```

### 2. Create and activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Generate sample logs and run the analyzer

```powershell
python main.py --generate-samples --auth-log logs/auth_sample.log --web-log logs/web_access.log --output report.html
```

### 5. Run the tests

```powershell
python -m pytest -v
```

## What I Learned

I built this project to get more experience with Python and cybersecurity. Through this project, I worked with log parsing, pattern matching, detection rules, error handling, unit testing, and HTML report generation.

## Future Improvements

- Add detection rules for other attack patterns, such as cross-site scripting and password spraying
- Support more log formats, including Windows Event Logs and AWS CloudTrail
- Add support for processing live log streams
- Export results in JSON format

import argparse
from src.parser import LogParser
from src.detector import ThreatDetector
from src.reporter import ReportGenerator
from src.utils import create_sample_logs

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Log Analyzer & Incident Detection Engine")
    parser.add_argument("--generate-samples", action="store_true", help="Generate sample synthetic log files")
    parser.add_argument("--auth-log", type=str, help="Path to SSH authentication log file")
    parser.add_argument("--web-log", type=str, help="Path to Web access log file")
    parser.add_argument("--output", type=str, default="report.html", help="Output path for HTML report")

    args = parser.parse_args()

    if args.generate_samples:
        create_sample_logs()

    parsed_logs = []
    parser_engine = LogParser()

    if args.auth_log:
        with open(args.auth_log, "r") as f:
            for line in f:
                res = parser_engine.parse_ssh_line(line)
                if res:
                    parsed_logs.append(res)

    if args.web_log:
        with open(args.web_log, "r") as f:
            for line in f:
                res = parser_engine.parse_web_line(line)
                if res:
                    parsed_logs.append(res)

    if not parsed_logs and not args.generate_samples:
        print("[-] No logs provided. Run with --generate-samples first or supply --auth-log / --web-log.")
        return

    # Threat Detection
    detector = ThreatDetector()
    results = detector.analyze(parsed_logs)

    # Output to Console
    print("\n" + "="*50)
    print("Incident Analysis Summary")
    print("="*50)
    for k, v in results["summary"].items():
        print(f"  {k.replace('_', ' ').title()}: {v}")

    print(f"\n Alerts Triggered: {len(results['alerts'])}")
    for alert in results["alerts"]:
        print(f"  [{alert['severity']}] {alert['type']} ({alert['mitre_id']}) - IP: {alert['ip']}")

    # Report Generation
    ReportGenerator.generate_html(results, args.output)

if __name__ == "__main__":
    main()
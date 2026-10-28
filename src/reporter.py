import json
from jinja2 import Template

class ReportGenerator:
    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOC Security Log Analysis Report</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a24; color: #e0e0e0; padding: 20px; }
            h1, h2 { color: #4da6ff; }
            .card-container { display: flex; gap: 20px; margin-bottom: 20px; }
            .card { background: #252538; padding: 15px 25px; border-radius: 8px; flex: 1; border-left: 4px solid #4da6ff; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #252538; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #33334d; }
            th { background: #2d2d44; color: #4da6ff; }
            .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
            .HIGH { background: #ff5555; color: white; }
            .CRITICAL { background: #ff0000; color: white; font-weight: 900; }
            .MEDIUM { background: #ffb86c; color: black; }
        </style>
    </head>
    <body>
        <h1> Security Incident Log Report</h1>
        <p>Generated automated SIEM analysis report.</p>

        <h2>Summary Metrics</h2>
        <div class="card-container">
            <div class="card"><h3>Total Analyzed</h3><p>{{ summary.total_logs }}</p></div>
            <div class="card"><h3>Failed Logins</h3><p>{{ summary.failed_logins }}</p></div>
            <div class="card"><h3>Malformed Logs</h3><p>{{ summary.malformed_logs }}</p></div>
            <div class="card"><h3>Threat Alerts</h3><p>{{ alerts|length }}</p></div>
        </div>

        <h2>Detected Security Incidents</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Incident Type</th>
                <th>MITRE ATT&CK</th>
                <th>Source IP</th>
                <th>Details</th>
            </tr>
            {% for alert in alerts %}
            <tr>
                <td><span class="badge {{ alert.severity }}">{{ alert.severity }}</span></td>
                <td>{{ alert.type }}</td>
                <td><code>{{ alert.mitre_id }}</code></td>
                <td>{{ alert.ip }}</td>
                <td>{{ alert.details }}</td>
            </tr>
            {% else %}
            <tr><td colspan="5">No threat signatures matched.</td></tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """

    @classmethod
    def generate_html(cls, analysis_results: dict, output_filepath: str = "report.html"):
        template = Template(cls.HTML_TEMPLATE)
        rendered = template.render(
            summary=analysis_results["summary"],
            alerts=analysis_results["alerts"]
        )
        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(rendered)
        print(f"[+] Report generated successfully: {output_filepath}")
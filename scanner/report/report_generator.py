import json
import os
import html
from datetime import datetime
from scanner.utils.logger import Logger

class ReportGenerator:
    def __init__(self, target_url, recon_data, vulnerabilities, output_dir="reports"):
        self.target_url = target_url
        self.recon_data = recon_data
        self.vulnerabilities = vulnerabilities
        self.output_dir = output_dir
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        # Create a unique filename based on domain and timestamp
        domain = self.recon_data.get('domain', 'unknown_domain')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_filename = os.path.join(self.output_dir, f"webguard_report_{domain}_{timestamp}")

    def generate_json(self):
        """Generates a JSON version of the scan report."""
        report = {
            "target": self.target_url,
            "scan_date": datetime.now().isoformat(),
            "reconnaissance": self.recon_data,
            "vulnerabilities": self.vulnerabilities
        }
        
        filepath = f"{self.base_filename}.json"
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=4)
        Logger.success(f"JSON Report generated: {filepath}")

    def generate_html(self):
        """Generates a stylized HTML version of the scan report."""
        filepath = f"{self.base_filename}.html"
        
        # Simple HTML template for the professional look
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebGuard Scan Report - {self.target_url}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f4f9; color: #333; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #2980b9; margin-top: 30px; }}
                .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                .vuln-critical {{ border-left: 5px solid #8e44ad; padding-left: 15px; }}
                .vuln-high {{ border-left: 5px solid #e74c3c; padding-left: 15px; }}
                .vuln-medium {{ border-left: 5px solid #f39c12; padding-left: 15px; }}
                .vuln-low {{ border-left: 5px solid #27ae60; padding-left: 15px; }}
                .vuln-info {{ border-left: 5px solid #3498db; padding-left: 15px; }}
                pre {{ background: #eee; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <h1>WebGuard Security Scan Report</h1>
            <div class="card">
                <h2>Target Information</h2>
                <p><strong>URL:</strong> {self.target_url}</p>
                <p><strong>IP Address:</strong> {self.recon_data.get('ip_address', 'Unknown')}</p>
                <p><strong>Server Banner:</strong> {self.recon_data.get('server_banner', 'Unknown')}</p>
                <p><strong>Technologies:</strong> {', '.join(self.recon_data.get('technologies', []))}</p>
            </div>
            
            <h2>Identified Vulnerabilities ({len(self.vulnerabilities)})</h2>
        """
        
        if not self.vulnerabilities:
            html_content += """
            <div class="card">
                <p>No vulnerabilities identified during this scan.</p>
            </div>
            """
        else:
            for vuln in self.vulnerabilities:
                sev_lower = vuln.get('severity', 'info').lower()
                # Bug fix: escape all user-controlled/attacker-controlled fields before
                # inserting into HTML — PoC payloads like <script>alert(1)</script>
                # would otherwise execute in the browser when the report is opened.
                name_escaped = html.escape(vuln.get('name', ''))
                endpoint_escaped = html.escape(vuln.get('endpoint', ''))
                description_escaped = html.escape(vuln.get('description', 'N/A'))
                remediation_escaped = html.escape(vuln.get('remediation', 'N/A'))
                poc_escaped = html.escape(vuln.get('proof_of_concept', 'N/A'))
                html_content += f"""
                <div class="card vuln-{sev_lower}">
                    <h3>[{vuln.get('severity', 'INFO')}] {name_escaped}</h3>
                    <p><strong>Endpoint:</strong> {endpoint_escaped}</p>
                    <p><strong>Description:</strong> {description_escaped}</p>
                    <p><strong>Remediation:</strong> {remediation_escaped}</p>
                    <p><strong>Proof of Concept:</strong></p>
                    <pre>{poc_escaped}</pre>
                </div>
                """
                
        html_content += """
        </body>
        </html>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        Logger.success(f"HTML Report generated: {filepath}")

    def generate_all(self):
        self.generate_json()
        self.generate_html()

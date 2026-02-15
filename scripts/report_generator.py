import json
from datetime import datetime
import pandas as pd
import os

class ReportGenerator:
    def __init__(self, findings, rules):
        self.findings = findings
        self.rules = rules
        
    def generate_json_report(self, output_file):
        """Generate JSON report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_rules': len(self.rules),
                'total_findings': len(self.findings),
                'high_severity': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'medium_severity': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'low_severity': len([f for f in self.findings if f['severity'] == 'LOW'])
            },
            'findings': self.findings,
            'rules_analyzed': self.rules
        }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ JSON report saved to {output_file}")
        return output_file
    
    def generate_excel_report(self, output_file):
        """Generate Excel report with multiple sheets"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = {
                'Metric': ['Total Rules Analyzed', 'Total Findings', 'High Severity Issues', 'Medium Severity Issues', 'Low Severity Issues'],
                'Count': [
                    len(self.rules),
                    len(self.findings),
                    len([f for f in self.findings if f['severity'] == 'HIGH']),
                    len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                    len([f for f in self.findings if f['severity'] == 'LOW'])
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Findings sheet
            if self.findings:
                findings_df = pd.DataFrame(self.findings)
                findings_df.to_excel(writer, sheet_name='Findings', index=False)
            
            # Rules sheet
            if self.rules:
                rules_df = pd.DataFrame(self.rules)
                rules_df.to_excel(writer, sheet_name='All Rules', index=False)
        
        print(f"✓ Excel report saved to {output_file}")
        return output_file
    
    def generate_html_report(self, output_file):
        """Generate HTML report"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        high_count = len([f for f in self.findings if f['severity'] == 'HIGH'])
        medium_count = len([f for f in self.findings if f['severity'] == 'MEDIUM'])
        low_count = len([f for f in self.findings if f['severity'] == 'LOW'])
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Policy Analysis Report</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ 
            color: #333;
            border-bottom: 3px solid #0d47a1;
            padding-bottom: 10px;
        }}
        .summary {{ 
            background: #e3f2fd;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .summary-item {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}
        .summary-item h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
        }}
        .summary-item .number {{
            font-size: 32px;
            font-weight: bold;
            color: #0d47a1;
        }}
        .finding {{ 
            border-left: 4px solid #ff9800;
            padding: 15px;
            margin: 15px 0;
            background: #fafafa;
            border-radius: 4px;
        }}
        .finding.high {{ border-left-color: #f44336; background: #ffebee; }}
        .finding.medium {{ border-left-color: #ff9800; background: #fff3e0; }}
        .finding.low {{ border-left-color: #4caf50; background: #e8f5e9; }}
        .severity-badge {{ 
            padding: 5px 12px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            font-size: 12px;
            display: inline-block;
            margin-bottom: 10px;
        }}
        .high-badge {{ background: #f44336; }}
        .medium-badge {{ background: #ff9800; }}
        .low-badge {{ background: #4caf50; }}
        .finding h3 {{ margin: 10px 0; color: #333; }}
        .finding code {{ 
            background: #263238;
            color: #aed581;
            padding: 10px;
            display: block;
            border-radius: 4px;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .finding p {{ margin: 8px 0; line-height: 1.6; }}
        .finding strong {{ color: #0d47a1; }}
        .timestamp {{
            color: #666;
            font-size: 14px;
            margin: 10px 0;
        }}
        .no-findings {{
            background: #e8f5e9;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            color: #2e7d32;
            font-size: 18px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Policy Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
            <div class="summary-item">
                <h3>Total Rules</h3>
                <div class="number">{len(self.rules)}</div>
            </div>
            <div class="summary-item">
                <h3>Total Findings</h3>
                <div class="number">{len(self.findings)}</div>
            </div>
            <div class="summary-item">
                <h3>High Severity</h3>
                <div class="number" style="color: #f44336;">{high_count}</div>
            </div>
            <div class="summary-item">
                <h3>Medium Severity</h3>
                <div class="number" style="color: #ff9800;">{medium_count}</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
"""
        
        if not self.findings:
            html += """
        <div class="no-findings">
            ✓ No security issues found! Configuration looks good.
        </div>
"""
        else:
            for idx, finding in enumerate(self.findings, 1):
                severity_class = finding['severity'].lower()
                html += f"""
        <div class="finding {severity_class}">
            <span class="severity-badge {severity_class}-badge">{finding['severity']}</span>
            <h3>Finding #{idx}: {finding['issue']}</h3>
            <p><strong>Rule:</strong></p>
            <code>{finding['rule']}</code>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Recommendation:</strong> {finding['recommendation']}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✓ HTML report saved to {output_file}")
        return output_file

# Test the report generator
if __name__ == "__main__":
    from config_parser import FirewallConfigParser
    from security_analyzer import SecurityAnalyzer
    
    # Parse and analyze
    parser = FirewallConfigParser('../configs/sample_asa_config.txt')
    rules = parser.parse()
    
    analyzer = SecurityAnalyzer(rules)
    findings = analyzer.analyze()
    
    # Generate reports
    print("\nGenerating reports...")
    report_gen = ReportGenerator(findings, rules)
    
    report_gen.generate_json_report('../reports/security_report.json')
    report_gen.generate_excel_report('../reports/security_report.xlsx')
    report_gen.generate_html_report('../reports/security_report.html')
    
    print(f"\n✓ All reports generated successfully!")
    print(f"  - Check the 'reports' folder")
    print(f"  - Open security_report.html in your browser to see the visual report")
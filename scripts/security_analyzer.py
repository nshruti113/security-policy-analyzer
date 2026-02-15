class SecurityAnalyzer:
    def __init__(self, rules):
        self.rules = rules
        self.findings = []
        
    def analyze(self):
        """Run all security checks"""
        self.check_overly_permissive()
        self.check_any_any_rules()
        self.check_risky_ports()
        return self.findings
    
    def check_overly_permissive(self):
        """Check for 'permit ip any any' rules"""
        for idx, rule in enumerate(self.rules):
            if (rule['action'] == 'permit' and 
                rule['source'] == 'any' and 
                rule['destination'] == 'any'):
                
                self.findings.append({
                    'severity': 'HIGH',
                    'rule_number': idx + 1,
                    'issue': 'Overly permissive rule',
                    'description': 'Rule permits all traffic from any source to any destination',
                    'recommendation': 'Restrict source/destination to specific networks',
                    'rule': rule['raw_line']
                })
    
    def check_any_any_rules(self):
        """Check for rules with 'any' in source or destination"""
        for idx, rule in enumerate(self.rules):
            if rule['action'] == 'permit' and ('any' in rule['source'] or 'any' in rule['destination']):
                if not (rule['source'] == 'any' and rule['destination'] == 'any'):
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'rule_number': idx + 1,
                        'issue': 'Broad access rule',
                        'description': f"Rule allows traffic from/to 'any'",
                        'recommendation': 'Consider restricting to specific networks',
                        'rule': rule['raw_line']
                    })
    
    def check_risky_ports(self):
        """Check for commonly exploited ports"""
        risky_ports = {
            '22': 'SSH - Should be restricted to management networks',
            '23': 'Telnet - Unencrypted, should be disabled',
            '3389': 'RDP - Should be restricted to management networks',
            '445': 'SMB - Often exploited, should not be exposed'
        }
        
        for idx, rule in enumerate(self.rules):
            for port, warning in risky_ports.items():
                if f'eq {port}' in rule['raw_line'] and rule['source'] == 'any':
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'rule_number': idx + 1,
                        'issue': f'Risky port {port} exposed',
                        'description': warning,
                        'recommendation': f'Restrict access to port {port}',
                        'rule': rule['raw_line']
                    })

# Test it
if __name__ == "__main__":
    from config_parser import FirewallConfigParser
    
    parser = FirewallConfigParser('../configs/sample_asa_config.txt')
    rules = parser.parse()
    
    analyzer = SecurityAnalyzer(rules)
    findings = analyzer.analyze()
    
    print(f"\nSecurity Analysis Results:")
    print(f"Found {len(findings)} issues:\n")
    
    for finding in findings:
        print(f"[{finding['severity']}] Rule {finding['rule_number']}: {finding['issue']}")
        print(f"  Description: {finding['description']}")
        print(f"  Rule: {finding['rule']}")
        print(f"  Recommendation: {finding['recommendation']}\n")
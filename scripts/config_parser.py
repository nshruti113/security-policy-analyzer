import re

class FirewallConfigParser:
    def __init__(self, config_file):
        self.config_file = config_file
        self.rules = []
        
    def parse(self):
        """Parse firewall configuration file"""
        with open(self.config_file, 'r') as f:
            for line in f:
                if 'access-list' in line and 'extended' in line:
                    rule = self.parse_acl_line(line)
                    self.rules.append(rule)
        return self.rules
    
    def parse_acl_line(self, line):
        """Parse individual ACL line"""
        parts = line.split()
        
        rule = {
            'acl_name': parts[1] if len(parts) > 1 else '',
            'action': parts[3] if len(parts) > 3 else '',
            'protocol': parts[4] if len(parts) > 4 else '',
            'source': parts[5] if len(parts) > 5 else '',
            'destination': parts[7] if len(parts) > 7 else '',
            'raw_line': line.strip()
        }
        return rule
    
    def get_rules(self):
        return self.rules

# Test it
if __name__ == "__main__":
    parser = FirewallConfigParser('../configs/sample_asa_config.txt')
    rules = parser.parse()
    
    print(f"Found {len(rules)} rules:")
    for rule in rules:
        print(f"  {rule['action']} {rule['protocol']} from {rule['source']} to {rule['destination']}")
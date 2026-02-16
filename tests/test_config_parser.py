"""
Unit tests for FirewallConfigParser
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from config_parser import FirewallConfigParser


class TestFirewallConfigParser:
    """Test cases for FirewallConfigParser class"""
    
    @pytest.fixture
    def sample_config_file(self, tmp_path):
        """Create a temporary config file for testing"""
        config_content = """
access-list OUTSIDE_IN extended permit tcp any host 192.168.1.10 eq 80
access-list OUTSIDE_IN extended permit tcp any host 192.168.1.10 eq 443
access-list OUTSIDE_IN extended permit tcp any any eq 22
access-list INSIDE_OUT extended permit ip 192.168.1.0 255.255.255.0 any
"""
        config_file = tmp_path / "test_config.txt"
        config_file.write_text(config_content)
        return str(config_file)
    
    def test_parser_initialization(self, sample_config_file):
        """Test parser can be initialized with a config file"""
        parser = FirewallConfigParser(sample_config_file)
        assert parser.config_file == sample_config_file
        assert parser.rules == []
    
    def test_parse_returns_list(self, sample_config_file):
        """Test that parse() returns a list of rules"""
        parser = FirewallConfigParser(sample_config_file)
        rules = parser.parse()
        assert isinstance(rules, list)
        assert len(rules) > 0
    
    def test_parse_correct_count(self, sample_config_file):
        """Test parser finds correct number of rules"""
        parser = FirewallConfigParser(sample_config_file)
        rules = parser.parse()
        assert len(rules) == 4  # Should find 4 ACL lines
    
    def test_parse_acl_structure(self, sample_config_file):
        """Test that parsed rules have correct structure"""
        parser = FirewallConfigParser(sample_config_file)
        rules = parser.parse()
        
        # Check first rule has all required fields
        rule = rules[0]
        assert 'acl_name' in rule
        assert 'action' in rule
        assert 'protocol' in rule
        assert 'source' in rule
        assert 'destination' in rule
        assert 'raw_line' in rule
    
    def test_parse_acl_values(self, sample_config_file):
        """Test that parsed values are correct"""
        parser = FirewallConfigParser(sample_config_file)
        rules = parser.parse()
        
        # Check first rule values
        rule = rules[0]
        assert rule['acl_name'] == 'OUTSIDE_IN'
        assert rule['action'] == 'permit'
        assert rule['protocol'] == 'tcp'
        assert rule['source'] == 'any'
    
    def test_parse_empty_file(self, tmp_path):
        """Test parser handles empty config file"""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")
        
        parser = FirewallConfigParser(str(empty_file))
        rules = parser.parse()
        assert rules == []
    
    def test_parse_no_acl_lines(self, tmp_path):
        """Test parser handles file with no ACL lines"""
        config_file = tmp_path / "no_acl.txt"
        config_file.write_text("""
hostname firewall01
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
""")
        
        parser = FirewallConfigParser(str(config_file))
        rules = parser.parse()
        assert rules == []
    
    def test_get_rules(self, sample_config_file):
        """Test get_rules() method"""
        parser = FirewallConfigParser(sample_config_file)
        parser.parse()
        rules = parser.get_rules()
        
        assert isinstance(rules, list)
        assert len(rules) == 4


class TestParseACLLine:
    """Test cases for parse_acl_line method"""
    
    def test_parse_simple_permit(self):
        """Test parsing a simple permit rule"""
        parser = FirewallConfigParser("dummy.txt")
        line = "access-list TEST extended permit tcp any host 192.168.1.1 eq 80"
        rule = parser.parse_acl_line(line)
        
        assert rule['acl_name'] == 'TEST'
        assert rule['action'] == 'permit'
        assert rule['protocol'] == 'tcp'
        assert rule['source'] == 'any'
    
    def test_parse_deny_rule(self):
        """Test parsing a deny rule"""
        parser = FirewallConfigParser("dummy.txt")
        line = "access-list BLOCK extended deny ip any any"
        rule = parser.parse_acl_line(line)
        
        assert rule['action'] == 'deny'
        assert rule['protocol'] == 'ip'
    
    def test_raw_line_preserved(self):
        """Test that raw line is preserved in parsed rule"""
        parser = FirewallConfigParser("dummy.txt")
        line = "access-list TEST extended permit tcp any any eq 443"
        rule = parser.parse_acl_line(line)
        
        assert rule['raw_line'] == line.strip()
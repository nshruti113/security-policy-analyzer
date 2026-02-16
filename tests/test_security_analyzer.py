"""
Unit tests for SecurityAnalyzer
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from security_analyzer import SecurityAnalyzer


class TestSecurityAnalyzer:
    """Test cases for SecurityAnalyzer class"""
    
    @pytest.fixture
    def sample_rules(self):
        """Create sample rules for testing"""
        return [
            {
                'acl_name': 'TEST',
                'action': 'permit',
                'protocol': 'ip',
                'source': 'any',
                'destination': 'any',
                'raw_line': 'access-list TEST permit ip any any'
            },
            {
                'acl_name': 'TEST',
                'action': 'permit',
                'protocol': 'tcp',
                'source': 'any',
                'destination': 'host 192.168.1.1',
                'raw_line': 'access-list TEST permit tcp any host 192.168.1.1 eq 22'
            },
            {
                'acl_name': 'TEST',
                'action': 'permit',
                'protocol': 'tcp',
                'source': '192.168.1.0',
                'destination': 'any',
                'raw_line': 'access-list TEST permit tcp 192.168.1.0 255.255.255.0 any'
            }
        ]
    
    def test_analyzer_initialization(self, sample_rules):
        """Test analyzer can be initialized with rules"""
        analyzer = SecurityAnalyzer(sample_rules)
        assert analyzer.rules == sample_rules
        assert analyzer.findings == []
    
    def test_analyze_returns_findings(self, sample_rules):
        """Test that analyze() returns a list of findings"""
        analyzer = SecurityAnalyzer(sample_rules)
        findings = analyzer.analyze()
        
        assert isinstance(findings, list)
        assert len(findings) > 0
    
    def test_detect_any_any_rule(self):
        """Test detection of permit any any rules"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'ip',
                'source': 'any',
                'destination': 'any',
                'raw_line': 'access-list TEST permit ip any any'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        findings = analyzer.analyze()
        
        # Should find at least one HIGH severity issue
        high_findings = [f for f in findings if f['severity'] == 'HIGH']
        assert len(high_findings) >= 1
        assert 'Overly permissive' in high_findings[0]['issue']
    
    def test_detect_ssh_exposure(self):
        """Test detection of SSH exposure from any source"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'tcp',
                'source': 'any',
                'destination': 'host 192.168.1.1',
                'raw_line': 'access-list TEST permit tcp any host 192.168.1.1 eq 22'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        findings = analyzer.analyze()
        
        # Should flag SSH exposure
        ssh_findings = [f for f in findings if '22' in str(f.get('issue', ''))]
        assert len(ssh_findings) > 0
        assert ssh_findings[0]['severity'] == 'MEDIUM'
    
    def test_detect_rdp_exposure(self):
        """Test detection of RDP exposure"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'tcp',
                'source': 'any',
                'destination': 'host 10.0.1.5',
                'raw_line': 'access-list DMZ permit tcp any host 10.0.1.5 eq 3389'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        findings = analyzer.analyze()
        
        rdp_findings = [f for f in findings if '3389' in str(f.get('issue', ''))]
        assert len(rdp_findings) > 0
    
    def test_detect_smb_exposure(self):
        """Test detection of SMB exposure"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'tcp',
                'source': 'any',
                'destination': 'host 10.0.1.6',
                'raw_line': 'access-list DMZ permit tcp any host 10.0.1.6 eq 445'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        findings = analyzer.analyze()
        
        smb_findings = [f for f in findings if '445' in str(f.get('issue', ''))]
        assert len(smb_findings) > 0
    
    def test_broad_access_detection(self):
        """Test detection of broad access rules"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'tcp',
                'source': 'any',
                'destination': 'host 192.168.1.10',
                'raw_line': 'access-list TEST permit tcp any host 192.168.1.10 eq 80'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        findings = analyzer.analyze()
        
        # Should find MEDIUM severity broad access issue
        medium_findings = [f for f in findings if f['severity'] == 'MEDIUM']
        assert len(medium_findings) > 0
    
    def test_no_issues_found(self):
        """Test analyzer with secure configuration"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'tcp',
                'source': '192.168.1.0',
                'destination': '10.0.0.0',
                'raw_line': 'access-list SECURE permit tcp 192.168.1.0 255.255.255.0 10.0.0.0 255.255.255.0'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        findings = analyzer.analyze()
        
        # Should not find critical issues
        assert len(findings) == 0 or all(f['severity'] != 'HIGH' for f in findings)
    
    def test_findings_structure(self, sample_rules):
        """Test that findings have correct structure"""
        analyzer = SecurityAnalyzer(sample_rules)
        findings = analyzer.analyze()
        
        for finding in findings:
            assert 'severity' in finding
            assert 'rule_number' in finding
            assert 'issue' in finding
            assert 'description' in finding
            assert 'recommendation' in finding
            assert 'rule' in finding
            assert finding['severity'] in ['HIGH', 'MEDIUM', 'LOW']


class TestCheckMethods:
    """Test individual check methods"""
    
    def test_check_overly_permissive(self):
        """Test check_overly_permissive method"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'ip',
                'source': 'any',
                'destination': 'any',
                'raw_line': 'access-list TEST permit ip any any'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        analyzer.check_overly_permissive()
        
        assert len(analyzer.findings) == 1
        assert analyzer.findings[0]['severity'] == 'HIGH'
    
    def test_check_any_any_rules(self):
        """Test check_any_any_rules method"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'tcp',
                'source': 'any',
                'destination': '192.168.1.0',
                'raw_line': 'access-list TEST permit tcp any 192.168.1.0 255.255.255.0'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        analyzer.check_any_any_rules()
        
        assert len(analyzer.findings) >= 1
        assert analyzer.findings[0]['severity'] == 'MEDIUM'
    
    def test_check_risky_ports_multiple(self):
        """Test detection of multiple risky ports"""
        rules = [
            {
                'action': 'permit',
                'protocol': 'tcp',
                'source': 'any',
                'destination': 'host 192.168.1.1',
                'raw_line': 'access-list TEST permit tcp any host 192.168.1.1 eq 22'
            },
            {
                'action': 'permit',
                'protocol': 'tcp',
                'source': 'any',
                'destination': 'host 192.168.1.2',
                'raw_line': 'access-list TEST permit tcp any host 192.168.1.2 eq 3389'
            }
        ]
        
        analyzer = SecurityAnalyzer(rules)
        analyzer.check_risky_ports()
        
        # Should find 2 risky port exposures
        assert len(analyzer.findings) == 2
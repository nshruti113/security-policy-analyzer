"""
Unit tests for ReportGenerator
"""
import pytest
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from report_generator import ReportGenerator


class TestReportGenerator:
    """Test cases for ReportGenerator class"""
    
    @pytest.fixture
    def sample_data(self):
        """Create sample findings and rules"""
        findings = [
            {
                'severity': 'HIGH',
                'rule_number': 1,
                'issue': 'Overly permissive rule',
                'description': 'Rule permits all traffic',
                'recommendation': 'Restrict access',
                'rule': 'access-list TEST permit ip any any'
            },
            {
                'severity': 'MEDIUM',
                'rule_number': 2,
                'issue': 'SSH exposure',
                'description': 'SSH accessible from any source',
                'recommendation': 'Restrict SSH access',
                'rule': 'access-list TEST permit tcp any host 192.168.1.1 eq 22'
            }
        ]
        
        rules = [
            {
                'acl_name': 'TEST',
                'action': 'permit',
                'protocol': 'ip',
                'source': 'any',
                'destination': 'any',
                'raw_line': 'access-list TEST permit ip any any'
            }
        ]
        
        return findings, rules
    
    def test_report_generator_initialization(self, sample_data):
        """Test report generator can be initialized"""
        findings, rules = sample_data
        report_gen = ReportGenerator(findings, rules)
        
        assert report_gen.findings == findings
        assert report_gen.rules == rules
    
    def test_generate_json_report(self, sample_data, tmp_path):
        """Test JSON report generation"""
        findings, rules = sample_data
        report_gen = ReportGenerator(findings, rules)
        
        output_file = tmp_path / "test_report.json"
        report_gen.generate_json_report(str(output_file))
        
        # Check file was created
        assert output_file.exists()
        
        # Check JSON is valid
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        assert 'timestamp' in data
        assert 'summary' in data
        assert 'findings' in data
        assert data['summary']['total_rules'] == len(rules)
        assert data['summary']['total_findings'] == len(findings)
    
    def test_json_report_structure(self, sample_data, tmp_path):
        """Test JSON report has correct structure"""
        findings, rules = sample_data
        report_gen = ReportGenerator(findings, rules)
        
        output_file = tmp_path / "test_report.json"
        report_gen.generate_json_report(str(output_file))
        
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        # Check summary structure
        assert 'high_severity' in data['summary']
        assert 'medium_severity' in data['summary']
        assert 'low_severity' in data['summary']
        
        # Check severity counts
        assert data['summary']['high_severity'] == 1
        assert data['summary']['medium_severity'] == 1
    
    def test_generate_excel_report(self, sample_data, tmp_path):
        """Test Excel report generation"""
        findings, rules = sample_data
        report_gen = ReportGenerator(findings, rules)
        
        output_file = tmp_path / "test_report.xlsx"
        report_gen.generate_excel_report(str(output_file))
        
        # Check file was created
        assert output_file.exists()
        assert output_file.stat().st_size > 0
    
    def test_generate_html_report(self, sample_data, tmp_path):
        """Test HTML report generation"""
        findings, rules = sample_data
        report_gen = ReportGenerator(findings, rules)
        
        output_file = tmp_path / "test_report.html"
        report_gen.generate_html_report(str(output_file))
        
        # Check file was created
        assert output_file.exists()
        
        # Check HTML content
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert '<!DOCTYPE html>' in content
        assert 'Security Policy Analysis Report' in content
        assert 'HIGH' in content or 'MEDIUM' in content
    
    def test_html_report_contains_findings(self, sample_data, tmp_path):
        """Test HTML report contains finding details"""
        findings, rules = sample_data
        report_gen = ReportGenerator(findings, rules)
        
        output_file = tmp_path / "test_report.html"
        report_gen.generate_html_report(str(output_file))
        
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check findings are in report
        assert 'Overly permissive rule' in content
        assert 'SSH exposure' in content
    
    def test_empty_findings(self, tmp_path):
        """Test report generation with no findings"""
        findings = []
        rules = [{'acl_name': 'TEST', 'action': 'permit', 'protocol': 'tcp', 
                  'source': '192.168.1.0', 'destination': '10.0.0.0',
                  'raw_line': 'access-list TEST permit tcp 192.168.1.0 10.0.0.0'}]
        
        report_gen = ReportGenerator(findings, rules)
        
        # JSON report
        json_file = tmp_path / "empty.json"
        report_gen.generate_json_report(str(json_file))
        
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        assert data['summary']['total_findings'] == 0
        assert data['summary']['high_severity'] == 0
    
    def test_report_creates_directory(self, sample_data, tmp_path):
        """Test that report generator creates output directory"""
        findings, rules = sample_data
        report_gen = ReportGenerator(findings, rules)
        
        # Use non-existent directory
        output_file = tmp_path / "new_dir" / "report.json"
        report_gen.generate_json_report(str(output_file))
        
        assert output_file.exists()
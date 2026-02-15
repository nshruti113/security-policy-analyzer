#!/usr/bin/env python3
"""
Security Policy Automation Framework
Main application for analyzing firewall configurations
"""

import argparse
import sys
import os
from datetime import datetime
from config_parser import FirewallConfigParser
from security_analyzer import SecurityAnalyzer
from report_generator import ReportGenerator


def print_banner():
    """Print application banner"""
    banner = """
    ╔════════════════════════════════════════════════════════════╗
    ║     Security Policy Automation Framework v1.0              ║
    ║     Firewall Configuration Security Analyzer               ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_summary(rules, findings):
    """Print analysis summary to console"""
    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    
    high = len([f for f in findings if f['severity'] == 'HIGH'])
    medium = len([f for f in findings if f['severity'] == 'MEDIUM'])
    low = len([f for f in findings if f['severity'] == 'LOW'])
    
    print(f"\nTotal Rules Analyzed: {len(rules)}")
    print(f"Total Security Findings: {len(findings)}")
    print(f"\nSeverity Breakdown:")
    print(f"  🔴 HIGH:   {high}")
    print(f"  🟡 MEDIUM: {medium}")
    print(f"  🟢 LOW:    {low}")
    
    if findings:
        print("\n" + "-"*60)
        print("TOP ISSUES:")
        print("-"*60)
        
        for idx, finding in enumerate(findings[:5], 1):
            severity_icon = "🔴" if finding['severity'] == 'HIGH' else "🟡" if finding['severity'] == 'MEDIUM' else "🟢"
            print(f"\n{idx}. {severity_icon} [{finding['severity']}] {finding['issue']}")
            print(f"   Rule: {finding['rule'][:80]}...")
            print(f"   Fix: {finding['recommendation']}")
        
        if len(findings) > 5:
            print(f"\n... and {len(findings) - 5} more issues")
    else:
        print("\n✅ No security issues found! Configuration looks good.")
    
    print("\n" + "="*60)


def main():
    """Main application entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Analyze firewall configurations for security issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py config.txt
  python main.py config.txt --output-dir ../reports
  python main.py config.txt --format json
  python main.py config.txt --format all
        """
    )
    
    parser.add_argument(
        'config_file',
        help='Path to firewall configuration file'
    )
    
    parser.add_argument(
        '--output-dir',
        default='../reports',
        help='Output directory for reports (default: ../reports)'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'excel', 'html', 'all'],
        default='all',
        help='Report format (default: all)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress console output, only generate reports'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed output'
    )
    
    args = parser.parse_args()
    
    # Print banner
    if not args.quiet:
        print_banner()
    
    # Validate input file
    if not os.path.exists(args.config_file):
        print(f"❌ Error: Configuration file not found: {args.config_file}")
        sys.exit(1)
    
    try:
        # Step 1: Parse configuration
        if not args.quiet:
            print(f"\n[1/4] Parsing configuration file...")
            print(f"      File: {args.config_file}")
        
        parser_obj = FirewallConfigParser(args.config_file)
        rules = parser_obj.parse()
        
        if not args.quiet:
            print(f"      ✓ Found {len(rules)} access control rules")
        
        if args.verbose:
            print("\n      Rules found:")
            for idx, rule in enumerate(rules[:5], 1):
                print(f"        {idx}. {rule['raw_line'][:70]}...")
            if len(rules) > 5:
                print(f"        ... and {len(rules) - 5} more rules")
        
        # Step 2: Analyze security
        if not args.quiet:
            print(f"\n[2/4] Analyzing security policies...")
        
        analyzer = SecurityAnalyzer(rules)
        findings = analyzer.analyze()
        
        if not args.quiet:
            print(f"      ✓ Completed security analysis")
            print(f"      ✓ Identified {len(findings)} potential issues")
        
        # Step 3: Generate reports
        if not args.quiet:
            print(f"\n[3/4] Generating reports...")
        
        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)
        
        # Timestamp for unique filenames
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        report_gen = ReportGenerator(findings, rules)
        generated_files = []
        
        if args.format in ['json', 'all']:
            json_file = os.path.join(args.output_dir, f'security_report_{timestamp}.json')
            report_gen.generate_json_report(json_file)
            generated_files.append(json_file)
        
        if args.format in ['excel', 'all']:
            excel_file = os.path.join(args.output_dir, f'security_report_{timestamp}.xlsx')
            report_gen.generate_excel_report(excel_file)
            generated_files.append(excel_file)
        
        if args.format in ['html', 'all']:
            html_file = os.path.join(args.output_dir, f'security_report_{timestamp}.html')
            report_gen.generate_html_report(html_file)
            generated_files.append(html_file)
        
        # Step 4: Display summary
        if not args.quiet:
            print(f"\n[4/4] Analysis complete!")
            print_summary(rules, findings)
            
            print("\n📁 REPORTS GENERATED:")
            for filepath in generated_files:
                print(f"   {os.path.basename(filepath)}")
            
            print(f"\n💡 TIP: Open the HTML report in your browser:")
            html_files = [f for f in generated_files if f.endswith('.html')]
            if html_files:
                print(f"   start {html_files[0]}")
        
        # Exit with appropriate code
        if findings and any(f['severity'] == 'HIGH' for f in findings):
            sys.exit(1)  # Exit with error if high severity issues found
        else:
            sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Error during analysis: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
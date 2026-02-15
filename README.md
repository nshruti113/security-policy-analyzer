# 🔒 Security Policy Automation Framework

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A Python-based tool to analyze firewall configurations and identify security issues.

## ✨ Features

- ✅ Parse Cisco ASA firewall configurations
- ✅ Identify security policy violations
- ✅ Detect overly permissive rules
- ✅ Flag risky port exposures (SSH, RDP, Telnet, SMB)
- ✅ Generate professional reports (JSON, Excel, HTML)
- ✅ Beautiful web-based dashboard
- ✅ Command-line interface

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/nshruti113/security-policy-analyzer.git
cd security-policy-analyzer

# Install dependencies
pip install -r requirements.txt
```

### Usage
```bash
# Analyze a configuration file
cd scripts
python main.py ../configs/sample_asa_config.txt

# Generate only HTML report
python main.py ../configs/sample_asa_config.txt --format html

# Verbose output
python main.py ../configs/sample_asa_config.txt --verbose

# See all options
python main.py --help
```

## 📊 Sample Output
```
╔════════════════════════════════════════════════════════════╗
║     Security Policy Automation Framework v1.0              ║
║     Firewall Configuration Security Analyzer               ║
╚════════════════════════════════════════════════════════════╝

[1/4] Parsing configuration file...
      ✓ Found 7 access control rules

[2/4] Analyzing security policies...
      ✓ Identified 6 potential issues

[3/4] Generating reports...
      ✓ JSON, Excel, and HTML reports generated

[4/4] Analysis complete!
```

## 🔍 Security Checks

The tool performs the following security analyses:

| Check | Severity | Description |
|-------|----------|-------------|
| **Overly Permissive Rules** | HIGH | Detects `permit ip any any` rules |
| **Broad Access Rules** | MEDIUM | Identifies rules with `any` in source/destination |
| **Risky Port Exposure** | MEDIUM | Flags SSH (22), Telnet (23), RDP (3389), SMB (445) |
| **Shadow Rules** | LOW | Finds redundant or overlapping rules (planned) |

## 📁 Project Structure
```
security-policy-analyzer/
├── configs/              # Sample firewall configurations
├── scripts/              # Python analysis scripts
│   ├── main.py          # Main CLI application
│   ├── config_parser.py # Configuration parser
│   ├── security_analyzer.py # Security analysis engine
│   └── report_generator.py  # Report generation
├── reports/              # Generated analysis reports
├── ansible-playbooks/    # Automation playbooks (planned)
├── tests/               # Unit tests
└── docs/                # Documentation
```

## 🛠️ Technologies

- **Python 3.9+** - Core language
- **Pandas** - Data analysis and Excel generation
- **Flask** - Web dashboard (planned)
- **Ansible** - Configuration automation (planned)

## 🤝 Contributing

This is a portfolio project, but suggestions are welcome! Feel free to open an issue.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details



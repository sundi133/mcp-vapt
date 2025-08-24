# 🎯 defence - Security Assessment Platform

Welcome to your ExternalAttacker-MCP security assessment platform!

## 📋 Package Information
- **Customer**: defence
- **Email**: test@defence.com
- **Version**: 1.0
- **License**: 30-Day Trial (upgradeable)

## 🚀 Quick Start

### 1. Setup (One-Time)
```bash
# Run the automated setup script (installs tools + activates license)
./CUSTOMER_SETUP.sh

# Or manual setup:
# 1. Install security tools: ./install.sh
# 2. Activate license: ./activate_trial.sh
```

### 2. Start Platform
```bash
# Start both services
python3 startup.py

# Or start individually:
# Terminal 1: python3 ExternalAttacker-App.py
# Terminal 2: python3 ExternalAttacker-MCP.py
```

### 3. Access Platform
- **Web Interface**: http://localhost:6991
- **License Status**: http://localhost:6991/license/status

## 📚 Documentation
- **Licensing Guide**: LICENSING_GUIDE.md
- **Installation Guide**: INSTALLATION.md (if included)
- **Deployment Guide**: INTERNAL_DEPLOYMENT_GUIDE.md (enterprise only)

## 🔐 License Management
```bash
# Check license status
python3 license_manager.py info

# Validate license
python3 license_manager.py validate

# Activate trial (if needed)
python3 license_manager.py activate
```

## 🛠️ Features Included
- **50+ Security Assessment Tools**: Comprehensive penetration testing toolkit
- **NIST 800-53 Compliance Assessment**: Automated compliance validation
- **Stealth Scanning Capabilities**: Evade detection with advanced techniques
- **Advanced Reporting**: Professional documentation and evidence collection
- **API Access**: Full REST API and MCP integration

## 🔧 Installation Details
The `install.sh` script automatically installs:
- **Go-based tools**: subfinder, nuclei, httpx, naabu, ffuf, gobuster
- **Network tools**: nmap, masscan, nikto, hydra, john
- **Web security**: w3af, skipfish, sqlmap, dalfox, ratproxy
- **Exploitation**: metasploit, commix, beef framework
- **Compliance**: GovReady-Q platform for NIST/FedRAMP
- **System setup**: PATH configuration, template updates

## 📞 Support
- **Email**: your-support@company.com
- **Documentation**: Available in package
- **Trial Period**: 30 days from activation

## 💰 Upgrade to Commercial
Contact sales for commercial licensing with:
- Extended limits
- Priority support
- Additional features
- Annual licensing

---
**Package ID**: ExternalAttacker-MCP-defence-v1.0
**Generated**: Thu Aug 21 21:19:02 PDT 2025

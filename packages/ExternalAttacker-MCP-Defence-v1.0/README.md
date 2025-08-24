# ExternalAttacker MCP Server

![ExternalAttacker-MCP](/images/ExternalAttacker-MCP-Banner.png)

## Model Context Protocol (MCP) Server for Security Assessment & Compliance

ExternalAttacker is a comprehensive security assessment platform that combines penetration testing, vulnerability scanning, and compliance validation with a natural language interface. Now featuring **professional licensing** for commercial deployments!

> 🔍 **Complete Security & Compliance Assessment with AI!**  
> Perform security assessments, compliance audits, and generate formal documentation using natural language.

## 📱 Community

Join our Telegram channel for updates, tips, and discussion:
- **Telegram**: [https://t.me/root_sec](https://t.me/root_sec)

## 🚀 **Quick Start**

### **Option 1: One-Command Installation (Recommended)**
```bash
# Download and run the installation script
curl -fsSL https://your-domain.com/install.sh | bash

# Or clone and install locally
git clone https://github.com/your-org/ExternalAttacker-MCP
cd ExternalAttacker-MCP
chmod +x install.sh
./install.sh
```

### **Option 2: Customer Package**
```bash
# Extract customer package
tar -xzf ExternalAttacker-MCP-Customer-v1.0.tar.gz
cd ExternalAttacker-MCP-Customer-v1.0

# Run customer setup
./CUSTOMER_SETUP.sh

# Start platform
python3 startup.py
```

### **Option 3: Manual Installation**
```bash
# Clone repository
git clone https://github.com/your-org/ExternalAttacker-MCP
cd ExternalAttacker-MCP

# Install Python dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Install security tools
./install.sh

# Activate license
python3 license_manager.py activate

# Start services
python3 startup.py
```

## 🔐 **Licensing System**

ExternalAttacker-MCP features a professional licensing system for commercial use:

### **Trial License (FREE)**
- **Duration**: 30 days
- **Features**: All security tools + compliance modules
- **Limits**: 50 targets, 5 concurrent scans
- **Perfect for**: Evaluation and small assessments

### **Commercial License**
- **Duration**: 1 year (renewable)
- **Features**: All features + priority support
- **Limits**: Unlimited targets and scans
- **Perfect for**: Professional security teams

### **License Activation**
```bash
# Interactive trial activation
./activate_trial.sh

# Or command line activation
python3 license_manager.py generate-trial --email "your@email.com" --name "Your Company"

# Check license status
python3 license_manager.py info

# License management via API
curl http://localhost:6991/license/status
```

## ✨ **Features**

### **🔍 Penetration Testing Tools (50+ Tools)**
- **Reconnaissance**: subfinder, dnsx, httpx, katana
- **Network Scanning**: nmap, naabu, masscan
- **Web Security**: nuclei, dalfox, sqlmap, ffuf, gobuster
- **Password Testing**: hydra, john, hashcat
- **Exploitation**: metasploit, commix, beef
- **Analysis**: tlsx, cdncheck, trufflehog

### **🏛️ NIST Compliance & Governance**
- **Frameworks**: NIST 800-53, FedRAMP, SOC 2, ISO 27001
- **Assessment**: Automated control validation
- **Reporting**: OSCAL-compliant documentation
- **Evidence**: Automated collection and validation
- **SSP Generation**: System Security Plans
- **Gap Analysis**: Compliance gap identification

### **🥷 Stealth Scanning Capabilities**
- **Passive Reconnaissance**: Certificate transparency, DNS history
- **Rate Limiting**: Configurable delays and thread limits
- **Evasion**: Random user agents, packet fragmentation
- **Sources**: Multiple passive intelligence sources

### **🌐 Multi-Platform Support**
- **Local**: Direct installation on Linux/macOS
- **Cloud**: Fly.io deployment with scaling
- **Enterprise**: Internal network deployment
- **Container**: Docker-based deployment

## 📦 **Installation Requirements**

### **System Requirements**
- **OS**: Linux (Ubuntu 20+), macOS (11+)
- **Python**: 3.8 or higher
- **Go**: 1.19 or higher (auto-installed)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 10GB free space for tools and databases

### **What install.sh Installs**
The comprehensive installation script (`install.sh`) automatically installs:

#### **Go-Based Security Tools**
```bash
# Reconnaissance
subfinder, httpx, naabu, katana, dnsx, cdncheck, tlsx

# Vulnerability Scanning  
nuclei, dalfox, ffuf, gobuster, kiterunner

# Utilities
trufflehog (secret scanning)
```

#### **Network & Web Security Tools**
```bash
# Network Tools
nmap, masscan, zmap

# Web Security
nikto, skipfish, ratproxy, w3af, wfuzz, burp suite

# Password Testing
hydra, john, hashcat

# Exploitation
metasploit, sqlmap, commix, beef

# OWASP Tools
zap (OWASP ZAP)
```

#### **Compliance Platform**
```bash
# Governance, Risk & Compliance
govready-q (GovReady-Q platform for NIST/FedRAMP compliance)
```

#### **System Configuration**
- Go installation and PATH setup
- Python virtual environment
- Tool verification and health checks
- Startup script creation
- Template updates (nuclei, etc.)

## 🎯 **Usage Examples**

### **Security Assessment**
```bash
# Start the platform
python3 startup.py

# Access web interface
open http://localhost:6991

# Use with Claude/AI
"Scan example.com for subdomains and check for vulnerabilities"
"Perform NIST compliance assessment on internal network 10.0.0.0/24"
```

### **API Usage**
```bash
# Check license
curl http://localhost:6991/license/status

# Run security scan
curl -X POST http://localhost:6991/api/run \
  -H "Content-Type: application/json" \
  -d '{"tool": "scan_subdomains", "args": "example.com"}'

# MCP integration
curl -N -H "Accept: text/event-stream" http://localhost:6991/mcp/sse
```

### **Compliance Assessment**
```bash
# NIST 800-53 assessment
python3 ExternalAttacker-MCP.py start_compliance_assessment \
  --framework nist_800_53 \
  --project "My Security Assessment"

# Generate compliance report
python3 ExternalAttacker-MCP.py generate_compliance_report \
  --format oscal \
  --include-evidence
```

## 🌐 **Deployment Options**

### **Local Development**
```bash
# Quick local setup
./setup_local_license.sh
python3 startup.py
```

### **Cloud Deployment (Fly.io)**
```bash
# Automated cloud deployment with licensing
./fly-licensing-deploy.sh

# Manual cloud deployment
flyctl launch --dockerfile Dockerfile.complete
flyctl secrets set CUSTOMER_EMAIL="customer@company.com"
flyctl deploy
```

### **Enterprise Internal Deployment**
```bash
# Internal network deployment
./deploy-internal.sh

# Docker deployment
docker build -t external-attacker-mcp -f Dockerfile.complete .
docker run -p 6991:6991 -p 8000:8000 external-attacker-mcp
```

## 📚 **Documentation**

- **[Licensing Guide](LICENSING_GUIDE.md)**: Complete licensing information
- **[Installation Guide](INSTALLATION.md)**: Detailed installation instructions
- **[Internal Deployment](INTERNAL_DEPLOYMENT_GUIDE.md)**: Enterprise deployment
- **[Fly.io Guide](FLY_LICENSING_GUIDE.md)**: Cloud deployment guide
- **[NIST Compliance](HIGH_CONFIDENCE_NIST_GUIDE.md)**: High-confidence assessments
- **[Red Team Examples](RED_TEAM_EXAMPLES.md)**: Advanced usage examples

## 🔧 **Development**

### **Project Structure**
```
ExternalAttacker-MCP/
├── ExternalAttacker-MCP.py     # MCP server with tools
├── ExternalAttacker-App.py     # Flask API backend
├── license_manager.py          # Licensing system
├── install.sh                  # Tool installation script
├── startup.py                  # Multi-service launcher
├── requirements.txt            # Python dependencies
├── templates/                  # Web interface
├── Dockerfile.complete         # Full Docker image
└── docs/                       # Documentation
```

### **Adding New Tools**
1. Define tool function in `ExternalAttacker-MCP.py`
2. Add corresponding `_direct` function in `ExternalAttacker-App.py`
3. Update `ALLOWED_TOOLS` and `MCP_TOOLS_LIST`
4. Add installation steps to `install.sh`
5. Test and document

### **License Features**
```python
# Check license in your code
if license_manager and license_manager.check_feature_access('compliance_modules'):
    # Feature enabled
    run_compliance_scan()
else:
    # Feature requires license
    return error_response()
```

## 📦 **Customer Distribution**

### **Creating Customer Packages**
```bash
# Generate customer package
./package_for_customer.sh

# Package types:
# 1. Trial Package (Basic - Self-Service)
# 2. Enterprise Package (Full - Internal Deployment)  
# 3. Cloud Package (SaaS - Vendor Managed)
# 4. Developer Package (Complete - For Integration)
```

### **Package Contents**
- ✅ Core application files
- ✅ Licensing system
- ✅ Installation scripts (`install.sh`)
- ✅ Customer setup script
- ✅ Documentation
- ✅ Web interface templates
- ✅ Docker configurations

## 🛡️ **Security Considerations**

### **Local Installation**
- Tools run with user privileges (not root)
- Virtual environment isolation
- License hardware binding
- Encrypted license storage

### **Cloud Deployment**
- HTTPS-only communication
- Environment variable secrets
- Persistent volume encryption
- License API protection

### **Enterprise Deployment**
- Network segmentation support
- Internal credential management
- Audit logging
- Compliance evidence collection

## 📞 **Support & Commercial Licensing**

### **Community Support**
- **Telegram**: [https://t.me/root_sec](https://t.me/root_sec)
- **GitHub Issues**: Bug reports and feature requests
- **Documentation**: Comprehensive guides included

### **Commercial Support**
- **Trial Support**: Best-effort community support
- **Commercial License**: Priority email support
- **Enterprise**: Dedicated support channel, custom features

### **Sales & Licensing**
- **Email**: sales@your-company.com
- **Trial**: 30 days free with all features
- **Commercial**: Annual licensing with support
- **Enterprise**: Custom deployment and features

## 🎉 **Getting Started**

1. **Choose Your Installation Method**:
   - Quick: `curl -fsSL https://your-domain.com/install.sh | bash`
   - Customer Package: Extract and run `CUSTOMER_SETUP.sh`
   - Manual: Clone repo and run `install.sh`

2. **Activate License**:
   - Trial: `./activate_trial.sh`
   - Commercial: Contact sales

3. **Start Platform**:
   - `python3 startup.py`
   - Open http://localhost:6991

4. **Begin Assessment**:
   - Use web interface or integrate with Claude/AI
   - Run security scans and compliance assessments
   - Generate professional reports

---

**🔐 Licensed Security Assessment Platform** | **🌐 Cloud & On-Premise** | **🎯 NIST Compliant** | **🤖 AI-Powered**
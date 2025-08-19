# ExternalAttacker-MCP Installation Guide

## 🚀 Quick Start

### Automated Installation (Recommended)

```bash
# Make the install script executable
chmod +x install.sh

# Run the installation script
./install.sh
```

### Manual Installation

If you prefer to install manually, follow these steps:

## 📋 Prerequisites

- **Python 3.8+** with pip
- **Go 1.19+** (for security tools)
- **Git** (for cloning repositories)

### macOS Prerequisites
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install basic tools
brew install python3 go git
```

### Linux Prerequisites (Ubuntu/Debian)
```bash
# Update package lists
sudo apt update

# Install basic tools  
sudo apt install python3 python3-pip git curl wget
```

## 🔧 Step-by-Step Installation

### 1. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Install Security Tools

#### Go-based Tools
```bash
# Recon tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# Vulnerability scanners
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest

# API tools
go install github.com/assetnote/kiterunner@latest
```

#### Other Tools

**SQLMap** (SQL injection testing):
```bash
# macOS
brew install sqlmap

# Linux
sudo apt install sqlmap
```

**TruffleHog** (Secret scanning):
```bash
# macOS
brew install trufflehog

# Linux
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

**OWASP ZAP** (Web application security):
```bash
# macOS
brew install --cask owasp-zap

# Linux
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh
chmod +x ZAP_2_14_0_unix.sh
sudo ./ZAP_2_14_0_unix.sh -q
```

**Commix** (Command injection testing):
```bash
# macOS
brew install commix

# Linux
git clone https://github.com/commixproject/commix.git
cd commix
sudo python3 setup.py install
```

**BeEF** (Browser Exploitation Framework):
```bash
# macOS
brew install ruby
gem install bundler
git clone https://github.com/beefproject/beef ~/tools/beef
cd ~/tools/beef && bundle install

# Linux
sudo apt-get install ruby-full build-essential
gem install bundler
git clone https://github.com/beefproject/beef ~/tools/beef
cd ~/tools/beef && bundle install
```

**Nessus** (Professional vulnerability scanner):
```bash
# Download from: https://www.tenable.com/downloads/nessus
# Install according to platform-specific instructions
# Requires commercial license for full functionality
# Free version available for home use with limitations
```

### 3. Update PATH
Add Go binary directory to your PATH:

```bash
# For zsh (macOS default)
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
source ~/.zshrc

# For bash (Linux default)
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 4. Update Nuclei Templates
```bash
nuclei -update-templates
```

## 🏃‍♂️ Running the Application

### Option 1: Using the Startup Script (Recommended)
```bash
./start_external_attacker.sh
```

### Option 2: Manual Startup
```bash
# Terminal 1: Start Flask app
python3 ExternalAttacker-App.py

# Terminal 2: Start MCP server  
python3 ExternalAttacker-MCP.py
```

## 🔍 Verification

### Check Tool Installation
```bash
# Test each tool
subfinder -version
httpx -version
naabu -version
katana -version
nuclei -version
sqlmap --version
trufflehog --version
```

### Test Web Interface
1. Open your browser to `http://localhost:6991`
2. Try running a simple scan like: `subfinder -domain example.com`

### Test API Endpoint
```bash
curl -X POST http://localhost:6991/api/run \
  -H "Content-Type: application/json" \
  -d '{"tool": "subfinder", "args": "-domain example.com -silent"}'
```

## 🎯 Tool Categories

| **Category** | **Tools** | **Purpose** |
|-------------|-----------|-------------|
| **Recon** | subfinder, httpx, katana, naabu | Domain enum, web crawling, port scanning |
| **Vulns** | nuclei, ffuf, sqlmap, dalfox, commix | Template scanning, fuzzing, SQLi, XSS, command injection |
| **Professional** | Nessus | Enterprise-grade vulnerability assessment |
| **Exploitation** | BeEF | Browser exploitation and client-side attacks |
| **APIs** | kiterunner, ZAP | API discovery, web app security |
| **Secrets** | trufflehog | Secret detection across multiple sources |
| **Reporting** | DefectDojo, Dradis | Vulnerability management and reporting |

## 🐛 Troubleshooting

### Common Issues

**Go tools not found:**
```bash
# Check Go installation
go version

# Check PATH
echo $PATH | grep go

# Manually add to PATH
export PATH=$PATH:$HOME/go/bin
```

**Permission errors:**
```bash
# Fix Go directory permissions
sudo chown -R $(whoami) $HOME/go
```

**Python module not found:**
```bash
# Reinstall requirements
pip3 install --upgrade -r requirements.txt
```

**Flask app won't start:**
```bash
# Check if port 6991 is in use
lsof -i :6991

# Kill existing process
kill $(lsof -t -i:6991)
```

### Tool-Specific Issues

**Nuclei templates outdated:**
```bash
nuclei -update-templates -silent
```

**ZAP not in PATH (macOS):**
```bash
echo 'export PATH=$PATH:/Applications/OWASP\ ZAP.app/Contents/Java' >> ~/.zshrc
source ~/.zshrc
```

## 🔧 Configuration

### Environment Variables
```bash
# Optional: Set Flask secret key
export FLASK_SECRET_KEY="your-secret-key-here"

# Optional: Enable API key protection
export API_KEY="your-api-key-here"
```

### Custom Tool Paths
If tools are installed in custom locations, update the `ALLOWED_TOOLS` list in `ExternalAttacker-App.py`.

## 📖 Usage Examples

### MCP Integration
The MCP server provides these main functions:

**Reconnaissance:**
- `scan_subdomains` - Subdomain enumeration
- `scan_ports` - Port scanning
- `analyze_http_services` - HTTP service analysis
- `crawl_website` - Web crawling with katana

**Vulnerability Testing:**
- `scan_vulnerabilities` - Nuclei vulnerability scanning
- `test_sql_injection` - SQLMap testing
- `scan_xss` - XSS vulnerability scanning
- `test_command_injection` - Command injection testing with Commix
- `scan_with_zap` - OWASP ZAP scanning

**Professional & Advanced:**
- `scan_with_nessus` - Professional Nessus vulnerability scanning
- `get_nessus_results` - Retrieve Nessus scan results
- `exploit_with_beef` - Browser exploitation with BeEF

**API & Endpoint Discovery:**
- `enumerate_apis` - API endpoint discovery
- `fuzz_endpoints` - Directory/endpoint fuzzing

**Secret Detection:**
- `scan_secrets` - Secret scanning with TruffleHog

**Reporting:**
- `upload_to_defectdojo` - DefectDojo integration
- `create_dradis_project` - Dradis project management

### Web Interface
Access the web interface at `http://localhost:6991` for manual tool execution.

## 🔒 Security Notes

- The Flask app runs with API key protection (when configured)
- Input validation prevents command injection
- Tools run in isolated subprocess environments
- No root privileges required for operation

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Verify all tools are properly installed with `./install.sh`
3. Check the Flask app logs for error messages
4. Ensure all dependencies are up to date 
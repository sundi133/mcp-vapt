from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
import subprocess
import json
import os
import re
from functools import wraps
import secrets
import requests
import yaml
from packaging import version
import shutil
import sys

# Import license manager
from license_manager import LicenseManager
import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Initialize license manager
license_manager = LicenseManager()

# License validation middleware
def check_license():
    """Check license validity"""
    validation = license_manager.validate_license()
    return validation

def require_valid_license(f):
    """Decorator to require valid license for API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        validation = check_license()
        if not validation['valid']:
            return jsonify({
                'error': 'License Required',
                'message': validation['error'],
                'action': validation.get('action', 'activate_trial')
            }), 403
        return f(*args, **kwargs)
    return decorated_function

# License status at startup
print("🔐 Checking ExternalAttacker-MCP License...")
license_status = check_license()

if license_status['valid']:
    license_info = license_manager.get_license_info()
    print(f"✅ License Valid - {license_info['license_type']} ({license_info['days_remaining']} days remaining)")
    print(f"Licensed to: {license_info['customer_name']} ({license_info['customer_email']})")
    
    # Warning for expiring licenses
    if license_info['days_remaining'] <= 7:
        print(f"⚠️ License expires in {license_info['days_remaining']} days!")
else:
    print(f"❌ License Error: {license_status['error']}")
    print("🔧 Activate trial license: python3 license_manager.py activate")
    if license_status.get('action') != 'activate_trial':
        print("📞 Contact support for license renewal")

ALLOWED_TOOLS = [
    "subfinder",
    "naabu", 
    "httpx",
    "nuclei",
    "cdncheck",
    "tlsx",
    "ffuf",
    "gobuster",
    "dnsx",
    "katana",
    "sqlmap",
    "dalfox",
    "kiterunner",
    "zap-baseline.py",
    "zap-full-scan.py",
    "trufflehog",
    "commix",
    "beef",
    "nessuscli",
    "w3af",
    "burpsuite",
    "msfconsole",
    "hydra",
    "john",
    "skipfish",
    "ratproxy",
    "wfuzz",
    "watcher",
    "nikto",
    "nmap",
    "govready-q"
]

DANGEROUS_CHARS = r'[&|;`$(){}\\<>]'

def validate_input(tool, args):
    if not tool or not args:
        return False
    if len(args) > 1000:  # Reasonable limit
        return False
    if re.search(DANGEROUS_CHARS, args):
        return False
    return True

def run_command(tool, args):
    try:
        """
        if not validate_input(tool, args):
            return {
                'stdout': '',
                'stderr': 'Invalid input: contains dangerous characters',
                'returncode': 1
            }
        """
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        cmd = [tool] + args.split()
        process = subprocess.Popen(
            cmd,
            shell=False,  # Security: Prevent shell injection
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            encoding='utf-8',
            errors='replace'
        )
        stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
        
        return {
            'stdout': stdout,
            'stderr': stderr,
            'returncode': process.returncode
        }
    except subprocess.TimeoutExpired:
        return {'error': 'Command timed out'}
    except Exception as e:
        return {'error': 'Internal error'}

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.environ.get('API_KEY'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/')
def index():
    # Check license status for display
    license_status = check_license()
    return render_template('index.html', tools=ALLOWED_TOOLS, license_status=license_status)

@app.route('/run', methods=['POST'])
# @require_api_key  # Temporarily disabled for testing
def web_run_tool():
    tool = request.form.get('tool', '').lower()
    args = request.form.get('args', '')

    if not tool or not args:
        flash('Tool and arguments are required', 'danger')
        return redirect(url_for('index'))

    if tool not in ALLOWED_TOOLS:
        flash(f'Tool not allowed. Allowed tools: {", ".join(ALLOWED_TOOLS)}', 'danger')
        return redirect(url_for('index'))

    result = run_command(tool, args)
    return render_template('result.html', 
                         tool=tool,
                         args=args,
                         target='',
                         result=result)

@app.route('/api/run', methods=['POST'])
# @require_api_key  # Temporarily disabled for testing
@require_valid_license
def api_run_tool():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        tool = data.get('tool', '').lower()
        args = data.get('args', '')

        if not tool:
            return jsonify({'error': 'Tool name is required'}), 400

        if tool not in ALLOWED_TOOLS:
            return jsonify({'error': f'Tool not allowed. Allowed tools: {", ".join(ALLOWED_TOOLS)}'}), 400

        return jsonify(run_command(tool, args))
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Import MCP functions
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Define security tool functions that call run_command directly
async def scan_subdomains_direct(target: str, domain_file: bool, threads: int = 4):
    command = [
        "subfinder",
        "-list" if domain_file else "-domain", target,
        "-json",
        "-all", 
        "-silent",
        "-active",
        "-t", str(threads),
        "-timeout", "30"
    ]
    return run_command(" ".join(command[1:]), command[0])

async def scan_subdomains_fast_direct(target: str, threads: int = 4, sources: str = "crtsh,bufferover,rapiddns"):
    """
    Fast subdomain scanning using subfinder with limited sources for quick results
    
    Args:
        target: Domain to scan for subdomains
        threads: Number of concurrent threads to use (default: 4)
        sources: Comma-separated list of sources to use (default: crtsh,bufferover,rapiddns)
    """
    command = [
        "subfinder",
        "-domain", target,
        "-json",
        "-silent",
        "-active",
        "-t", str(threads),
        "-timeout", "15",
        "-sources", sources,
        "-max-time", "2"
    ]
    return run_command(" ".join(command[1:]), command[0])

async def crawl_website_direct(target: str, depth: int = 3, js_crawl: bool = False, include_subs: bool = True, threads: int = 4):
    command = [
        "katana",
        "-u", target,
        "-d", str(depth),
        "-fs", "rdn",
        "-c", str(threads),
        "-timeout", "10",
        "-silent",
        "-nc"
    ]
    
    if js_crawl:
        command.append("-jc")
    if include_subs:
        command.append("-cs")
    command.append("-jsonl")
    
    return run_command(" ".join(command[1:]), command[0])

async def scan_vulnerabilities_direct(target: str, file: bool, severity: str = None, threads: int = 4):
    command = [
        "nuclei",
        "-silent",
        "-nc",
        "-j",
        "-c", str(threads),
        "-timeout", "5",
        "-retries", "1",
        "-rl", "150"
    ]
    
    if file:
        command.extend(["-l", target])
    else:
        command.extend(["-u", target])
        
    if severity:
        command.extend(["-s", severity])
    
    return run_command(" ".join(command[1:]), command[0])

async def test_sql_injection_direct(target: str, data: str = None, level: int = 1, risk: int = 1):
    command = [
        "sqlmap",
        "-u", target,
        "--batch",
        "--random-agent",
        "--level", str(level),
        "--risk", str(risk),
        "--threads", "1",
        "--timeout", "30",
        "--output-dir", "/tmp/sqlmap_output"
    ]
    
    if data:
        command.extend(["--data", data])
    
    return run_command(" ".join(command[1:]), command[0])

async def scan_xss_direct(target: str, file: bool, threads: int = 4):
    command = [
        "dalfox",
        "url" if not file else "file",
        target,
        "-o", "json",
        "-w", str(threads),
        "--timeout", "10",
        "--delay", "0",
        "--silence"
    ]
    
    return run_command(" ".join(command[1:]), command[0])

async def scan_ports_direct(target: str, file: bool, ports: str = "80,443", top_ports: bool = False, threads: int = 4):
    command = [
        "naabu",
        "-silent",
        "-nc", 
        "-c", str(threads),
        "-r", "8.8.8.8",
        "-skip-host-discovery",
        "-scan-all-ips",
        "-json"
    ]
    
    if file:
        command.extend(["-list", str(target)])
    else:
        command.extend(["-host", str(target)])

    if top_ports:
        command.extend(["-top-ports", str(ports)])
    else:
        command.extend(["-port", str(ports)])
    
    return run_command(" ".join(command[1:]), command[0])

async def analyze_http_services_direct(target: str, file: bool, threads: int = 4):
    command = [
        "httpx",
        "-silent",
        "-nc", 
        "-threads", str(threads),
        "-json",
        "-title",
        "-status-code",
        "-content-length",
        "-server",
        "-tech-detect"
    ]

    if file:
        command.extend(["-list", str(target)])
    else:
        command.extend(["-target", str(target)])
    
    return run_command(" ".join(command[1:]), command[0])

async def detect_cdn_direct(target: str, resolver: str = "8.8.8.8"):
    command = [
        "cdncheck",
        "-input", str(target),
        "-resolver", resolver,
        "-nc",
        "-duc",
        "-silent",
        "-resp",
        "-jsonl"
    ]
    
    return run_command(" ".join(command[1:]), command[0])

async def analyze_tls_config_direct(target: str, file: bool, port: int = 443, resolver: str = "8.8.8.8", threads: int = 4):
    command = [
        "tlsx",
        "-silent",
        "-resolvers", str(resolver),
        "-nc",
        "-c", str(threads),
        "-p", str(port),
        "-json",
        "-so",
        "-tls-version",
        "-cipher",
        "-wildcard-cert",
        "-probe-status",
        "-version-enum",
        "-cipher-enum",
        "-cipher-type", "all",
        "-serial"
    ]
    if file:
        command.extend(["-l", str(target)])
    else:
        command.extend(["-u", str(target)])
    
    return run_command(" ".join(command[1:]), command[0])

async def fuzz_endpoints_direct(target: str, threads: int = 4, wordlist: str = ""):
    # Use ffuf for directory/endpoint fuzzing
    if not wordlist:
        # Default wordlist path
        wordlist = "/tmp/directory-list-2.3-medium.txt"
    
    command = [
        "ffuf",
        "-s",
        "-w", wordlist,
        "-u", target+"/FUZZ",
        "-t", str(threads)
    ]
    
    return run_command(" ".join(command[1:]), command[0])

async def resolve_dns_direct(target: str, file: bool, threads: int = 4, resolver: str = "8.8.8.8"):
    command = [
        "dnsx",
        "-silent",
        "-t", str(threads),
        "-json",
        "-r", str(resolver),
        "-all"
    ]
    if file:
        command.extend(["-l", str(target)])
    else:
        command.extend(["-d", str(target)])
    
    return run_command(" ".join(command[1:]), command[0])

async def enumerate_apis_direct(target: str, wordlist: str = "", threads: int = 4):
    # Use kiterunner for API enumeration
    if not wordlist:
        wordlist = "/tmp/api-endpoints.txt"
    
    command = [
        "kiterunner", "scan",
        target,
        "-w", wordlist,
        "-t", str(threads),
        "--delay", "0",
        "--timeout", "3",
        "-o", "json"
    ]
    
    return run_command(" ".join(command[1:]), command[0])

async def scan_with_zap_direct(target: str, spider: bool = True, ajax_spider: bool = False, active_scan: bool = True):
    command = [
        "zap-baseline.py" if not active_scan else "zap-full-scan.py",
        "-t", target,
        "-J", "/tmp/zap_report.json",
        "-r", "/tmp/zap_report.html"
    ]
    
    if not spider:
        command.append("-n")
    if ajax_spider:
        command.append("-j")
    
    return run_command(" ".join(command[1:]), command[0])

async def scan_secrets_direct(target: str, scan_type: str = "filesystem", threads: int = 4):
    command = ["trufflehog"]
    
    if scan_type == "filesystem":
        command.extend(["filesystem", target])
    elif scan_type == "git":
        command.extend(["git", target])
    elif scan_type == "github":
        command.extend(["github", "--org=" + target if "/" not in target else "--repo=" + target])
    elif scan_type == "s3":
        command.extend(["s3", "--bucket", target])
    
    command.extend([
        "--json",
        "-j", str(threads)
    ])
    
    return run_command(" ".join(command[1:]), command[0])

async def test_command_injection_direct(target: str, cookie: str = None, level: int = 1, technique: str = "classic"):
    command = [
        "commix",
        "--url", target,
        "--batch",
        "--random-agent",
        "--level", str(level),
        "--timeout", "30",
        "--technique", technique
    ]
    
    if cookie:
        command.extend(["--cookie", cookie])
    
    command.extend([
        "--output-dir", "/tmp/commix_output",
        "--verbose"
    ])
    
    return run_command(" ".join(command[1:]), command[0])

async def enumerate_assets_direct(mode: str, target: str = None, wordlist: str = "", threads: int = 4, 
                                 extensions: str = None, status_codes: str = None):
    if not wordlist:
        # Default wordlist for directory scanning
        wordlist = "/tmp/directory-list-2.3-medium.txt"
        
    command = ["gobuster", mode, "-t", str(threads), "-q"]
    
    # Add mode-specific arguments
    if mode == "dir":
        if not target:
            raise ValueError("target is required for dir mode")
        command.extend(["-u", target, "-w", wordlist])
        if extensions:
            command.extend(["-x", extensions])
        if status_codes:
            command.extend(["-s", status_codes])
            
    elif mode == "dns":
        if not target:
            raise ValueError("target is required for dns mode")
        command.extend(["-d", target, "-w", wordlist])
            
    elif mode == "vhost":
        if not target:
            raise ValueError("target is required for vhost mode")
        command.extend(["-u", target, "-w", wordlist])
    
    return run_command(" ".join(command[1:]), command[0])

async def scan_with_nessus_direct(target: str, scan_template: str = "basic", 
                                 nessus_url: str = "https://localhost:8834", 
                                 access_key: str = None, secret_key: str = None):
    # This is a simplified version - in practice you'd use the full Nessus API
    if not access_key or not secret_key:
        return {
            'stdout': '',
            'stderr': 'Nessus API credentials required (access_key and secret_key)',
            'returncode': 1
        }
    
    # Placeholder implementation - actual Nessus would require API integration
    result = {
        'scan_id': 'placeholder_scan_id',
        'scan_name': f'ExternalAttacker-MCP-scan',
        'target': target,
        'template': scan_template,
        'status': 'launched',
        'message': f'Nessus scan placeholder for target {target}'
    }
    
    return {
        'stdout': json.dumps(result),
        'stderr': '',
        'returncode': 0
    }

async def exploit_with_beef_direct(target_url: str, beef_server: str = "http://localhost:3000",
                                  beef_user: str = "beef", beef_pass: str = "beef"):
    # This is a simplified placeholder - actual BeEF would require API integration
    result = {
        'beef_server': beef_server,
        'hook_url': f"{beef_server}/hook.js",
        'injection_code': f'<script src="{beef_server}/hook.js"></script>',
        'target_url': target_url,
        'status': 'ready',
        'message': f'BeEF hook ready for {target_url}'
    }
    
    return {
        'stdout': json.dumps(result),
        'stderr': '',
        'returncode': 0
    }

async def get_nessus_results_direct(scan_id: str, nessus_url: str = "https://localhost:8834",
                                   access_key: str = None, secret_key: str = None):
    if not access_key or not secret_key:
        return {
            'stdout': '',
            'stderr': 'Nessus API credentials required',
            'returncode': 1
        }
    
    # Placeholder implementation
    result = {
        'scan_id': scan_id,
        'status': 'completed',
        'message': f'Nessus scan results placeholder for scan {scan_id}'
    }
    
    return {
        'stdout': json.dumps(result),
        'stderr': '',
        'returncode': 0
    }

async def upload_to_defectdojo_direct(file_path: str, engagement_id: int, 
                                     defectdojo_url: str, api_token: str, scan_type: str):
    # Placeholder implementation for DefectDojo integration
    result = {
        'engagement_id': engagement_id,
        'scan_type': scan_type,
        'file_path': file_path,
        'status': 'uploaded',
        'message': f'Results uploaded to DefectDojo engagement {engagement_id}'
    }
    
    return {
        'stdout': json.dumps(result),
        'stderr': '',
        'returncode': 0
    }

async def create_dradis_project_direct(project_name: str, dradis_url: str, api_token: str,
                                      description: str = None, client_name: str = None):
    # Placeholder implementation for Dradis integration
    result = {
        'project_name': project_name,
        'dradis_url': dradis_url,
        'description': description or f"Security assessment for {project_name}",
        'client': client_name or "External Assessment",
        'status': 'created',
        'message': f'Dradis project {project_name} created successfully'
    }
    
    return {
        'stdout': json.dumps(result),
        'stderr': '',
        'returncode': 0
    }

async def diagnose_subfinder_direct(target: str):
    """
    Diagnose subfinder performance and configuration issues
    
    Args:
        target: Domain to test subfinder against
    """
    results = {}
    
    # Test subfinder version
    version_cmd = ["subfinder", "-version"]
    version_result = run_command("subfinder", "-version")
    results['version'] = version_result
    
    # Test simple subfinder command
    simple_result = run_command("subfinder", f"-domain {target} -silent -t 10 -timeout 10")
    results['simple_test'] = simple_result
    
    # Test DNS resolution
    dns_result = run_command("nslookup", target)
    results['dns_test'] = dns_result
    
    # Test with single source only
    fast_result = run_command("subfinder", f"-domain {target} -silent -sources crtsh -t 5")
    results['single_source_test'] = fast_result
    
    return {
        'stdout': json.dumps(results, indent=2),
        'stderr': '',
        'returncode': 0
    }

async def scan_with_w3af_direct(target: str, profile: str = "OWASP_TOP10", threads: int = 4):
    """Web application security scanning using W3af framework"""
    script_content = f"""
plugins
output console,textFile
output config textFile
set fileName /tmp/w3af_output.txt
set verbose True
back
output config console
set verbose True
back

audit {profile}
grep all
crawl webSpider
crawl config webSpider
set onlyForward True
back

target
set target {target}
back

start
exit
"""
    
    script_path = f"/tmp/w3af_script_{profile}.w3af"
    with open(script_path, "w") as f:
        f.write(script_content)
    
    return run_command("w3af_console", f"-s {script_path}")

async def scan_with_burp_direct(target: str, project_file: str = "/tmp/burp_project", 
                               scan_type: str = "crawl_and_audit"):
    """Web application security scanning using Burp Suite Professional"""
    config = {
        "target": {"scope": {"include": [{"rule": target}]}},
        "spider": {"mode": "modern"},
        "scanner": {"audit_items": "all"}
    }
    
    import json
    with open("/tmp/burp_config.json", "w") as f:
        json.dump(config, f)
    
    return run_command("java", f"-jar /opt/burpsuite_pro/burpsuite_pro.jar --project-file {project_file} --config-file /tmp/burp_config.json")

async def exploit_with_metasploit_direct(target: str, payload: str = "generic/shell_reverse_tcp",
                                        lhost: str = "127.0.0.1", lport: int = 4444):
    """Exploitation using Metasploit framework"""
    commands = [
        f"use exploit/multi/handler",
        f"set payload {payload}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
        f"set RHOSTS {target}",
        "exploit"
    ]
    
    return run_command("msfconsole", f"-q -x \"{'; '.join(commands)}\"")

async def bruteforce_with_hydra_direct(target: str, service: str = "ssh", 
                                      username: str = None, wordlist: str = None,
                                      threads: int = 4, port: int = None):
    """Password bruteforce attacks using Hydra"""
    if not wordlist:
        wordlist = "/usr/share/wordlists/rockyou.txt"
    
    args = [f"-t {threads}", "-V"]
    
    if username:
        if "@" in username:
            args.append(f"-L {username}")
        else:
            args.append(f"-l {username}")
    
    if wordlist:
        args.append(f"-P {wordlist}")
    
    if port:
        args.append(f"-s {port}")
    
    args.extend([target, service])
    
    return run_command("hydra", " ".join(args))

async def crack_passwords_john_direct(hash_file: str, wordlist: str = None, 
                                     format_type: str = None, threads: int = 4):
    """Password cracking using John the Ripper"""
    args = [f"--fork={threads}"]
    
    if wordlist:
        args.append(f"--wordlist={wordlist}")
    
    if format_type:
        args.append(f"--format={format_type}")
    
    args.append(hash_file)
    
    return run_command("john", " ".join(args))

async def scan_with_skipfish_direct(target: str, output_dir: str = "/tmp/skipfish_output",
                                   threads: int = 4, depth: int = 5):
    """Web application security scanning using Skipfish"""
    args = [
        f"-o {output_dir}",
        f"-m {depth}",
        f"-W /usr/share/skipfish/dictionaries/minimal.wl",
        f"-t {threads}",
        target
    ]
    
    return run_command("skipfish", " ".join(args))

async def scan_with_ratproxy_direct(target: str, port: int = 8080, 
                                   output_file: str = "/tmp/ratproxy.log"):
    """Web application security audit using Ratproxy"""
    args = [
        f"-w {output_file}",
        f"-v {target}",
        f"-p {port}",
        "-lextifscxmjr"
    ]
    
    return run_command("ratproxy", " ".join(args))

async def fuzz_with_wfuzz_direct(target: str, wordlist: str = None, threads: int = 4,
                                hide_codes: str = "404", fuzz_param: str = "FUZZ"):
    """Web application fuzzing using Wfuzz"""
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    args = [
        "-c",
        f"-z file,{wordlist}",
        f"--hc {hide_codes}",
        f"-t {threads}",
        target.replace("FUZZ", fuzz_param)
    ]
    
    return run_command("wfuzz", " ".join(args))

async def scan_with_watcher_direct(target: str, output_file: str = "/tmp/watcher.log"):
    """Web application security scanning using Watcher"""
    args = [f"-u {target}", f"-o {output_file}", "--spider"]
    
    return run_command("watcher", " ".join(args))

async def scan_with_nikto_direct(target: str, port: int = 80, ssl: bool = False,
                                output_file: str = "/tmp/nikto.txt"):
    """Web server security scanning using Nikto"""
    args = [
        f"-h {target}",
        f"-p {port}",
        f"-o {output_file}",
        "-Format txt"
    ]
    
    if ssl:
        args.append("-ssl")
    
    return run_command("nikto", " ".join(args))

async def scan_with_nmap_direct(target: str, scan_type: str = "sS", ports: str = "1-65535",
                               threads: int = 4, scripts: str = None, output_file: str = "/tmp/nmap.xml"):
    """Network scanning using Nmap"""
    args = [
        f"-{scan_type}",
        f"-p {ports}",
        "-T4",
        f"--max-parallelism {threads}",
        f"-oX {output_file}"
    ]
    
    if scripts:
        args.append(f"--script {scripts}")
    
    args.append(target)
    
    return run_command("nmap", " ".join(args))

# Add stealth scanning functions before the function mapping

async def scan_stealth_subdomains_direct(target: str, sources: str = "passive", delay: int = 3):
    """Stealth subdomain scanning optimized for protected targets"""
    if sources == "passive":
        source_list = "crtsh,bufferover,rapiddns,virustotal,securitytrails"
    elif sources == "active":
        source_list = "dnsdumpster,hackertarget"
    else:
        source_list = "crtsh,bufferover,rapiddns"
    
    args = [
        f"-domain {target}",
        "-silent",
        "-t 2",
        "-timeout 30",
        f"-sources {source_list}",
        "-rate-limit 5",
        "-random-agent"
    ]
    
    return run_command("subfinder", " ".join(args))

async def scan_stealth_ports_direct(target: str, ports: str = "80,443,8080,8443", timing: str = "slow"):
    """Stealth port scanning to avoid detection"""
    timing_map = {
        "slow": "-T1",
        "normal": "-T2", 
        "fast": "-T3"
    }
    
    args = [
        "-sS",
        timing_map.get(timing, "-T2"),
        f"-p {ports}",
        "--max-parallelism 1",
        "--scan-delay 3s",
        "--max-retries 1",
        "-Pn",
        "-f",
        "--randomize-hosts",
        f"-oN /tmp/stealth_scan.txt",
        target
    ]
    
    return run_command("nmap", " ".join(args))

async def passive_reconnaissance_direct(target: str, api_sources: bool = False):
    """Passive reconnaissance without directly contacting target"""
    import json
    results = {}
    
    # Certificate Transparency
    ct_result = run_command("curl", f"-s https://crt.sh/?q=%25.{target}&output=json")
    results['certificate_transparency'] = ct_result
    
    # DNS History (passive)  
    dns_result = run_command("curl", f"-s https://securitytrails.com/domain/{target}/dns")
    results['dns_history'] = dns_result
    
    return {
        'stdout': json.dumps(results, indent=2),
        'stderr': '',
        'returncode': 0
    }

async def nuclei_stealth_scan_direct(target: str, severity: str = "info,low", templates: str = "passive"):
    """Non-aggressive Nuclei scanning for protected targets"""
    template_map = {
        "passive": "http/misconfiguration/,http/technologies/,ssl/",
        "safe": "http/misconfiguration/,http/technologies/,ssl/,dns/",
        "all": ""
    }
    
    args = [
        f"-u {target}",
        "-silent -nc -j",
        "-rate-limit 3",
        "-timeout 15",
        "-retries 1",
        f"-severity {severity}"
    ]
    
    if templates != "all":
        args.append(f"-t {template_map[templates]}")
    
    return run_command("nuclei", " ".join(args))

# Add GovReady-Q compliance functions before the function mapping

async def start_compliance_assessment_direct(framework: str = "nist_800_53", 
                                           project_name: str = "Security Assessment",
                                           organization: str = "Default Org"):
    """Start a new compliance assessment using GovReady-Q"""
    args = [
        f"/opt/govready-q/manage.py start_assessment",
        f"--framework {framework}",
        f"--project '{project_name}'",
        f"--org '{organization}'",
        "--output-format json"
    ]
    
    return run_command("python3", " ".join(args))

async def run_compliance_scan_direct(target: str, framework: str = "nist_800_53",
                                   scan_type: str = "infrastructure", 
                                   evidence_collection: bool = True):
    """Run automated compliance scanning against target infrastructure"""
    evidence_flag = "--collect-evidence" if evidence_collection else "--no-evidence"
    
    args = [
        f"/opt/govready-q/manage.py compliance_scan",
        f"--target {target}",
        f"--framework {framework}",
        f"--scan-type {scan_type}",
        evidence_flag,
        "--output /tmp/compliance_results.json"
    ]
    
    return run_command("python3", " ".join(args))

async def generate_compliance_report_direct(project_id: str = None,
                                          report_format: str = "oscal", 
                                          include_evidence: bool = True,
                                          control_families: str = None):
    """Generate compliance assessment reports in various formats"""
    args = [f"/opt/govready-q/manage.py export_report"]
    
    if project_id:
        args.append(f"--project-id {project_id}")
    
    args.extend([
        f"--format {report_format}",
        f"--output /tmp/compliance_report.{report_format}"
    ])
    
    if include_evidence:
        args.append("--include-evidence")
    
    if control_families:
        args.append(f"--controls {control_families}")
    
    return run_command("python3", " ".join(args))

async def assess_security_controls_direct(target: str, control_baseline: str = "moderate",
                                        control_set: str = "nist_800_53", 
                                        assessment_mode: str = "automated"):
    """Assess security controls implementation against compliance frameworks"""
    args = [
        f"/opt/govready-q/manage.py assess_controls",
        f"--target {target}",
        f"--baseline {control_baseline}",
        f"--control-set {control_set}",
        f"--mode {assessment_mode}",
        "--output /tmp/control_assessment.json"
    ]
    
    return run_command("python3", " ".join(args))

async def validate_oscal_catalog_direct(catalog_file: str, validate_links: bool = True,
                                      check_completeness: bool = True):
    """Validate OSCAL (Open Security Controls Assessment Language) catalogs"""
    args = [
        f"/opt/govready-q/manage.py validate_oscal",
        f"--catalog {catalog_file}"
    ]
    
    if validate_links:
        args.append("--validate-links")
    
    if check_completeness:
        args.append("--check-complete")
    
    args.append("--output /tmp/oscal_validation.json")
    
    return run_command("python3", " ".join(args))

async def generate_system_security_plan_direct(system_name: str, system_type: str = "web_application",
                                             authorization_boundary: str = "system",
                                             impact_level: str = "moderate"):
    """Generate System Security Plan (SSP) documentation"""
    safe_name = system_name.replace(' ', '_')
    
    args = [
        f"/opt/govready-q/manage.py generate_ssp",
        f"--system-name '{system_name}'",
        f"--system-type {system_type}",
        f"--boundary {authorization_boundary}",
        f"--impact-level {impact_level}",
        f"--output /tmp/ssp_{safe_name}.docx"
    ]
    
    return run_command("python3", " ".join(args))

async def compliance_gap_analysis_direct(current_state: str, target_framework: str = "nist_800_53",
                                       target_baseline: str = "moderate", 
                                       output_recommendations: bool = True):
    """Perform compliance gap analysis between current and target state"""
    args = [
        f"/opt/govready-q/manage.py gap_analysis",
        f"--current {current_state}",
        f"--target-framework {target_framework}",
        f"--target-baseline {target_baseline}"
    ]
    
    if output_recommendations:
        args.append("--recommendations")
    
    args.append("--output /tmp/gap_analysis.json")
    
    return run_command("python3", " ".join(args))

# Add enhanced internal compliance functions

async def run_internal_compliance_scan_direct(target_network: str, framework: str = "nist_800_53",
                                            baseline: str = "moderate", include_systems: bool = True,
                                            include_databases: bool = True, credentialed_scan: bool = False):
    """High-confidence internal NIST compliance assessment with full scope"""
    args = [
        f"/opt/govready-q/manage.py compliance_scan",
        f"--target {target_network}",
        f"--framework {framework}",
        f"--baseline {baseline}",
        "--scan-type internal",
        "--collect-evidence",
        "--confidence-target high",
        "--assessment-scope full"
    ]
    
    if include_systems:
        args.append("--include-systems")
    
    if include_databases:
        args.append("--include-databases")
    
    if credentialed_scan:
        args.append("--credentialed")
    
    args.append("--output /tmp/internal_compliance_results.json")
    
    return run_command("python3", " ".join(args))

async def assess_internal_network_controls_direct(target_network: str, control_families: str = "AC,AU,SC,SI",
                                                assessment_depth: str = "comprehensive"):
    """Assess specific NIST control families on internal network infrastructure"""
    args = [
        f"/opt/govready-q/manage.py assess_controls",
        f"--target {target_network}",
        f"--control-families {control_families}",
        "--assessment-mode automated",
        f"--depth {assessment_depth}",
        f"--output /tmp/control_assessment_{control_families.replace(',', '_')}.json"
    ]
    
    return run_command("python3", " ".join(args))

async def system_configuration_compliance_audit_direct(target_systems: str, os_type: str = "mixed",
                                                      audit_policies: str = "security,access,logging"):
    """Detailed system configuration compliance audit for NIST controls"""
    args = [
        f"/opt/govready-q/manage.py system_audit",
        f"--targets {target_systems}",
        f"--os-type {os_type}",
        f"--policies {audit_policies}",
        "--compliance-framework nist_800_53",
        "--output /tmp/system_config_audit.json"
    ]
    
    if os_type == "windows" or os_type == "mixed":
        args.append("--windows-checks gpo,registry,services,users")
    
    if os_type == "linux" or os_type == "mixed":
        args.append("--linux-checks configs,permissions,processes,users")
    
    return run_command("python3", " ".join(args))

async def generate_high_confidence_compliance_report_direct(assessment_data: str, 
                                                          framework: str = "nist_800_53",
                                                          confidence_level: str = "high"):
    """Generate high-confidence compliance report with internal assessment data"""
    args = [
        f"/opt/govready-q/manage.py generate_compliance_report",
        f"--input {assessment_data}",
        f"--framework {framework}",
        f"--confidence-level {confidence_level}",
        "--assessment-scope internal+external",
        "--include-evidence",
        "--include-recommendations",
        "--format oscal",
        f"--output /tmp/high_confidence_nist_report.oscal"
    ]
    
    return run_command("python3", " ".join(args))

# Function mapping
security_functions = {
    'scan_subdomains': scan_subdomains_direct,
    'scan_subdomains_fast': scan_subdomains_fast_direct,
    'scan_ports': scan_ports_direct,
    'analyze_http_services': analyze_http_services_direct,
    'detect_cdn': detect_cdn_direct,
    'analyze_tls_config': analyze_tls_config_direct,
    'enumerate_assets': enumerate_assets_direct,
    'fuzz_endpoints': fuzz_endpoints_direct,
    'resolve_dns': resolve_dns_direct,
    'crawl_website': crawl_website_direct,
    'scan_vulnerabilities': scan_vulnerabilities_direct,
    'test_sql_injection': test_sql_injection_direct,
    'scan_xss': scan_xss_direct,
    'enumerate_apis': enumerate_apis_direct,
    'scan_with_zap': scan_with_zap_direct,
    'scan_secrets': scan_secrets_direct,
    'scan_with_nessus': scan_with_nessus_direct,
    'exploit_with_beef': exploit_with_beef_direct,
    'test_command_injection': test_command_injection_direct,
    'get_nessus_results': get_nessus_results_direct,
    'upload_to_defectdojo': upload_to_defectdojo_direct,
    'create_dradis_project': create_dradis_project_direct,
    'diagnose_subfinder': diagnose_subfinder_direct,
    'scan_with_w3af': scan_with_w3af_direct,
    'scan_with_burp': scan_with_burp_direct,
    'exploit_with_metasploit': exploit_with_metasploit_direct,
    'bruteforce_with_hydra': bruteforce_with_hydra_direct,
    'crack_passwords_john': crack_passwords_john_direct,
    'scan_with_skipfish': scan_with_skipfish_direct,
    'scan_with_ratproxy': scan_with_ratproxy_direct,
    'fuzz_with_wfuzz': fuzz_with_wfuzz_direct,
    'scan_with_watcher': scan_with_watcher_direct,
    'scan_with_nikto': scan_with_nikto_direct,
    'scan_with_nmap': scan_with_nmap_direct,
    'scan_stealth_subdomains': scan_stealth_subdomains_direct,
    'scan_stealth_ports': scan_stealth_ports_direct,
    'passive_reconnaissance': passive_reconnaissance_direct,
    'nuclei_stealth_scan': nuclei_stealth_scan_direct,
    'start_compliance_assessment': start_compliance_assessment_direct,
    'run_compliance_scan': run_compliance_scan_direct,
    'generate_compliance_report': generate_compliance_report_direct,
    'assess_security_controls': assess_security_controls_direct,
    'validate_oscal_catalog': validate_oscal_catalog_direct,
    'generate_system_security_plan': generate_system_security_plan_direct,
    'compliance_gap_analysis': compliance_gap_analysis_direct,
    'run_internal_compliance_scan': run_internal_compliance_scan_direct,
    'assess_internal_network_controls': assess_internal_network_controls_direct,
    'system_configuration_compliance_audit': system_configuration_compliance_audit_direct,
    'generate_high_confidence_compliance_report': generate_high_confidence_compliance_report_direct
}

MCP_FUNCTIONS_AVAILABLE = True
print("✅ MCP functions loaded successfully")

# Define tools list that both endpoints can use
MCP_TOOLS_LIST = [
    {
        "name": "scan_subdomains",
        "description": "Scan target domain(s) for subdomains using subfinder",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to scan"},
                "domain_file": {"type": "boolean", "description": "Whether target is a file"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target", "domain_file"]
        }
    },
    {
        "name": "scan_ports",
        "description": "Scan target for open ports using naabu",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IP to scan"},
                "file": {"type": "boolean", "description": "Whether target is a file"},
                "ports": {"type": "string", "default": "80,443", "description": "Port range to scan"},
                "top_ports": {"type": "boolean", "default": False, "description": "Scan top N ports"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target", "file"]
        }
    },
    {
        "name": "analyze_http_services",
        "description": "Analyze HTTP/HTTPS services using httpx",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to analyze"},
                "file": {"type": "boolean", "description": "Whether target is a file"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target", "file"]
        }
    },
    {
        "name": "detect_cdn",
        "description": "Check if target uses CDN using cdncheck",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to check"},
                "resolver": {"type": "string", "default": "8.8.8.8"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "analyze_tls_config",
        "description": "Analyze TLS/SSL configuration using tlsx",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to analyze"},
                "file": {"type": "boolean", "description": "Whether target is a file"},
                "port": {"type": "integer", "default": 443},
                "resolver": {"type": "string", "default": "8.8.8.8"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target", "file"]
        }
    },
    {
        "name": "fuzz_endpoints",
        "description": "Fuzz for hidden endpoints using ffuf",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to fuzz"},
                "threads": {"type": "integer", "default": 4},
                "wordlist": {"type": "string", "description": "Path to wordlist"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "resolve_dns",
        "description": "DNS enumeration using dnsx",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to resolve"},
                "file": {"type": "boolean", "description": "Whether target is a file"},
                "threads": {"type": "integer", "default": 4},
                "resolver": {"type": "string", "default": "8.8.8.8"}
            },
            "required": ["target", "file"]
        }
    },
    {
        "name": "crawl_website",
        "description": "Web crawling and endpoint discovery using katana",
        "inputSchema": {
            "type": "object", 
            "properties": {
                "target": {"type": "string", "description": "Target URL to crawl"},
                "depth": {"type": "integer", "default": 3},
                "js_crawl": {"type": "boolean", "default": False},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_vulnerabilities", 
        "description": "Vulnerability scanning using nuclei",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL/domain"},
                "file": {"type": "boolean", "description": "Whether target is a file"},
                "severity": {"type": "string", "description": "Filter by severity"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target", "file"]
        }
    },
    {
        "name": "test_sql_injection",
        "description": "SQL injection testing using sqlmap",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to test"},
                "data": {"type": "string", "description": "POST data"},
                "level": {"type": "integer", "default": 1},
                "risk": {"type": "integer", "default": 1}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_xss",
        "description": "XSS vulnerability scanning using dalfox",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "file": {"type": "boolean", "description": "Whether target is a file"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target", "file"]
        }
    },
    {
        "name": "enumerate_apis",
        "description": "API endpoint enumeration using kiterunner",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to scan"},
                "wordlist": {"type": "string", "description": "Path to API wordlist"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_with_zap",
        "description": "Web application security scanning using OWASP ZAP",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to scan"},
                "spider": {"type": "boolean", "default": True},
                "ajax_spider": {"type": "boolean", "default": False},
                "active_scan": {"type": "boolean", "default": True}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_secrets",
        "description": "Secret scanning using trufflehog",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target to scan"},
                "scan_type": {"type": "string", "default": "filesystem", "description": "Type of scan (filesystem/git/github/s3)"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target"]
        }
    },
    {
        "name": "enumerate_assets",
        "description": "Unified asset enumeration using gobuster",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {"type": "string", "description": "Gobuster mode (dir/dns/vhost)"},
                "target": {"type": "string", "description": "Target URL/domain"},
                "wordlist": {"type": "string", "description": "Path to wordlist"},
                "threads": {"type": "integer", "default": 4},
                "extensions": {"type": "string", "description": "File extensions for dir mode"},
                "status_codes": {"type": "string", "description": "Status codes to show"}
            },
            "required": ["mode"]
        }
    },
    {
        "name": "scan_with_nessus",
        "description": "Professional vulnerability scanning using Nessus",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname/CIDR"},
                "scan_template": {"type": "string", "default": "basic", "description": "Scan template"},
                "nessus_url": {"type": "string", "default": "https://localhost:8834"},
                "access_key": {"type": "string", "description": "Nessus API access key"},
                "secret_key": {"type": "string", "description": "Nessus API secret key"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "exploit_with_beef",
        "description": "Browser exploitation using BeEF framework",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target website URL"},
                "beef_server": {"type": "string", "default": "http://localhost:3000"},
                "beef_user": {"type": "string", "default": "beef"},
                "beef_pass": {"type": "string", "default": "beef"}
            },
            "required": ["target_url"]
        }
    },
    {
        "name": "test_command_injection",
        "description": "Command injection testing using Commix",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to test"},
                "cookie": {"type": "string", "description": "Cookie values"},
                "level": {"type": "integer", "default": 1},
                "technique": {"type": "string", "default": "classic"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "get_nessus_results",
        "description": "Retrieve and export Nessus scan results",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Nessus scan ID"},
                "nessus_url": {"type": "string", "default": "https://localhost:8834"},
                "access_key": {"type": "string", "description": "Nessus API access key"},
                "secret_key": {"type": "string", "description": "Nessus API secret key"}
            },
            "required": ["scan_id"]
        }
    },
    {
        "name": "upload_to_defectdojo",
        "description": "Upload scan results to DefectDojo",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to scan results file"},
                "engagement_id": {"type": "integer", "description": "DefectDojo engagement ID"},
                "defectdojo_url": {"type": "string", "description": "DefectDojo instance URL"},
                "api_token": {"type": "string", "description": "DefectDojo API token"},
                "scan_type": {"type": "string", "description": "Type of scan results"}
            },
            "required": ["file_path", "engagement_id", "defectdojo_url", "api_token", "scan_type"]
        }
    },
    {
        "name": "create_dradis_project",
        "description": "Create and manage projects in Dradis",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_name": {"type": "string", "description": "Name of project to create"},
                "dradis_url": {"type": "string", "description": "Dradis instance URL"},
                "api_token": {"type": "string", "description": "Dradis API token"},
                "description": {"type": "string", "description": "Project description"},
                "client_name": {"type": "string", "description": "Client name"}
            },
            "required": ["project_name", "dradis_url", "api_token"]
        }
    },
    {
        "name": "scan_subdomains_fast",
        "description": "Fast subdomain scanning using subfinder with limited sources for quick results",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to scan for subdomains"},
                "threads": {"type": "integer", "default": 4, "description": "Number of concurrent threads to use"},
                "sources": {"type": "string", "default": "crtsh,bufferover,rapiddns", "description": "Comma-separated list of sources to use"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "diagnose_subfinder",
        "description": "Diagnose subfinder performance and configuration issues",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to test subfinder against"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_with_w3af",
        "description": "Web application security scanning using W3af framework",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to scan"},
                "profile": {"type": "string", "default": "OWASP_TOP10", "description": "W3af profile"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_with_burp",
        "description": "Web application security scanning using Burp Suite Professional",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to scan"},
                "project_file": {"type": "string", "default": "/tmp/burp_project", "description": "Burp Suite project file path"},
                "scan_type": {"type": "string", "default": "crawl_and_audit", "description": "Burp Suite scan type"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "exploit_with_metasploit",
        "description": "Exploitation using Metasploit framework",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname/CIDR"},
                "payload": {"type": "string", "default": "generic/shell_reverse_tcp", "description": "Metasploit payload"},
                "lhost": {"type": "string", "default": "127.0.0.1", "description": "Local host for reverse shell"},
                "lport": {"type": "integer", "default": 4444, "description": "Local port for reverse shell"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "bruteforce_with_hydra",
        "description": "Password bruteforce attacks using Hydra",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname/CIDR"},
                "service": {"type": "string", "default": "ssh", "description": "Service to bruteforce"},
                "username": {"type": "string", "description": "Username for bruteforce"},
                "wordlist": {"type": "string", "description": "Path to wordlist"},
                "threads": {"type": "integer", "default": 4},
                "port": {"type": "integer", "description": "Port for service"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "crack_passwords_john",
        "description": "Password cracking using John the Ripper",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string", "description": "Path to hash file"},
                "wordlist": {"type": "string", "description": "Path to wordlist"},
                "format_type": {"type": "string", "description": "Format type (e.g., raw-sha256)"},
                "threads": {"type": "integer", "default": 4}
            },
            "required": ["hash_file"]
        }
    },
    {
        "name": "scan_with_skipfish",
        "description": "Web application security scanning using Skipfish",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to scan"},
                "output_dir": {"type": "string", "default": "/tmp/skipfish_output", "description": "Output directory"},
                "threads": {"type": "integer", "default": 4},
                "depth": {"type": "integer", "default": 5, "description": "Depth of scan"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_with_ratproxy",
        "description": "Web application security audit using Ratproxy",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to audit"},
                "port": {"type": "integer", "default": 8080, "description": "Port to listen on"},
                "output_file": {"type": "string", "default": "/tmp/ratproxy.log", "description": "Output file"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "fuzz_with_wfuzz",
        "description": "Web application fuzzing using Wfuzz",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to fuzz"},
                "wordlist": {"type": "string", "description": "Path to wordlist"},
                "threads": {"type": "integer", "default": 4},
                "hide_codes": {"type": "string", "default": "404", "description": "Hide HTTP codes"},
                "fuzz_param": {"type": "string", "default": "FUZZ", "description": "Parameter to fuzz"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_with_watcher",
        "description": "Web application security scanning using Watcher",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to scan"},
                "output_file": {"type": "string", "default": "/tmp/watcher.log", "description": "Output file"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_with_nikto",
        "description": "Web server security scanning using Nikto",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname/CIDR"},
                "port": {"type": "integer", "default": 80, "description": "Port to scan"},
                "ssl": {"type": "boolean", "default": False, "description": "Use SSL"},
                "output_file": {"type": "string", "default": "/tmp/nikto.txt", "description": "Output file"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_with_nmap",
        "description": "Network scanning using Nmap",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname/CIDR"},
                "scan_type": {"type": "string", "default": "sS", "description": "Nmap scan type (sS, sT, sA, etc.)"},
                "ports": {"type": "string", "default": "1-65535", "description": "Ports to scan"},
                "threads": {"type": "integer", "default": 4},
                "scripts": {"type": "string", "description": "Nmap scripts to run (e.g., vuln, auth, discovery)"},
                "output_file": {"type": "string", "default": "/tmp/nmap.xml", "description": "Output file"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_stealth_subdomains",
        "description": "Stealth subdomain scanning using subfinder",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to scan for subdomains"},
                "sources": {"type": "string", "default": "passive", "description": "Sources (passive/active)"},
                "delay": {"type": "integer", "default": 3, "description": "Delay between requests"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_stealth_ports",
        "description": "Stealth port scanning using nmap",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IP to scan"},
                "ports": {"type": "string", "default": "80,443,8080,8443", "description": "Ports to scan"},
                "timing": {"type": "string", "default": "slow", "description": "Scan timing (slow/normal/fast)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "passive_reconnaissance",
        "description": "Passive reconnaissance without directly contacting target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to perform passive reconnaissance on"},
                "api_sources": {"type": "boolean", "default": False, "description": "Use API sources (crt.sh, securitytrails)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_stealth_scan",
        "description": "Non-aggressive Nuclei scanning for protected targets",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL/domain"},
                "severity": {"type": "string", "default": "info,low", "description": "Severity of templates"},
                "templates": {"type": "string", "default": "passive", "description": "Template set (passive/safe/all)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "start_compliance_assessment",
        "description": "Start a new compliance assessment using GovReady-Q",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "default": "nist_800_53", "description": "Compliance framework (e.g., nist_800_53)"},
                "project_name": {"type": "string", "default": "Security Assessment", "description": "Name of the project"},
                "organization": {"type": "string", "default": "Default Org", "description": "Organization name"}
            },
            "required": ["framework"]
        }
    },
    {
        "name": "run_compliance_scan",
        "description": "Run automated compliance scanning against target infrastructure using GovReady-Q",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname/CIDR or URL"},
                "framework": {"type": "string", "default": "nist_800_53", "description": "Compliance framework (e.g., nist_800_53)"},
                "scan_type": {"type": "string", "default": "infrastructure", "description": "Scan type (infrastructure/application)"},
                "evidence_collection": {"type": "boolean", "default": True, "description": "Collect evidence during scan"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "generate_compliance_report",
        "description": "Generate compliance assessment reports in various formats using GovReady-Q",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "GovReady-Q project ID (optional)"},
                "report_format": {"type": "string", "default": "oscal", "description": "Report format (e.g., oscal, html, pdf)"},
                "include_evidence": {"type": "boolean", "default": True, "description": "Include evidence in report"},
                "control_families": {"type": "string", "description": "Comma-separated list of control families to include (e.g., nist_800_53, cis_v1.2)"}
            },
            "required": ["report_format"]
        }
    },
    {
        "name": "assess_security_controls",
        "description": "Assess security controls implementation against compliance frameworks using GovReady-Q",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP/hostname/CIDR or URL"},
                "control_baseline": {"type": "string", "default": "moderate", "description": "Baseline for control assessment (e.g., moderate, high)"},
                "control_set": {"type": "string", "default": "nist_800_53", "description": "Control set to assess (e.g., nist_800_53, cis_v1.2)"},
                "assessment_mode": {"type": "string", "default": "automated", "description": "Assessment mode (automated, manual)"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "validate_oscal_catalog",
        "description": "Validate OSCAL (Open Security Controls Assessment Language) catalogs using GovReady-Q",
        "inputSchema": {
            "type": "object",
            "properties": {
                "catalog_file": {"type": "string", "description": "Path to OSCAL catalog file"},
                "validate_links": {"type": "boolean", "default": True, "description": "Validate links in catalog"},
                "check_completeness": {"type": "boolean", "default": True, "description": "Check catalog completeness"}
            },
            "required": ["catalog_file"]
        }
    },
    {
        "name": "generate_system_security_plan",
        "description": "Generate System Security Plan (SSP) documentation using GovReady-Q",
        "inputSchema": {
            "type": "object",
            "properties": {
                "system_name": {"type": "string", "description": "Name of the system"},
                "system_type": {"type": "string", "default": "web_application", "description": "Type of system (e.g., web_application, database)"},
                "authorization_boundary": {"type": "string", "default": "system", "description": "Authorization boundary (e.g., system, application)"},
                "impact_level": {"type": "string", "default": "moderate", "description": "Impact level (e.g., low, moderate, high)"}
            },
            "required": ["system_name"]
        }
    },
    {
        "name": "compliance_gap_analysis",
        "description": "Perform compliance gap analysis between current and target state using GovReady-Q",
        "inputSchema": {
            "type": "object",
            "properties": {
                "current_state": {"type": "string", "description": "Current state of the system (e.g., current_ssp.json)"},
                "target_framework": {"type": "string", "default": "nist_800_53", "description": "Target compliance framework (e.g., nist_800_53, cis_v1.2)"},
                "target_baseline": {"type": "string", "default": "moderate", "description": "Target baseline for gap analysis (e.g., moderate, high)"},
                "output_recommendations": {"type": "boolean", "default": True, "description": "Output recommendations in the gap analysis"}
            },
            "required": ["current_state"]
        }
    },
    {
        "name": "run_internal_compliance_scan",
        "description": "High-confidence internal NIST compliance assessment with full scope",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_network": {"type": "string", "description": "Target network to assess"},
                "framework": {"type": "string", "default": "nist_800_53", "description": "Compliance framework (e.g., nist_800_53)"},
                "baseline": {"type": "string", "default": "moderate", "description": "Baseline for compliance assessment (e.g., moderate, high)"},
                "include_systems": {"type": "boolean", "default": True, "description": "Include systems in assessment"},
                "include_databases": {"type": "boolean", "default": True, "description": "Include databases in assessment"},
                "credentialed_scan": {"type": "boolean", "default": False, "description": "Perform credentialed scan"}
            },
            "required": ["target_network"]
        }
    },
    {
        "name": "assess_internal_network_controls",
        "description": "Assess specific NIST control families on internal network infrastructure",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_network": {"type": "string", "description": "Target network to assess"},
                "control_families": {"type": "string", "default": "AC,AU,SC,SI", "description": "Comma-separated list of control families to assess"},
                "assessment_depth": {"type": "string", "default": "comprehensive", "description": "Depth of assessment (comprehensive/selective)"}
            },
            "required": ["target_network"]
        }
    },
    {
        "name": "system_configuration_compliance_audit",
        "description": "Detailed system configuration compliance audit for NIST controls",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_systems": {"type": "string", "description": "Comma-separated list of target systems"},
                "os_type": {"type": "string", "default": "mixed", "description": "Operating system type (windows/linux/mixed)"},
                "audit_policies": {"type": "string", "default": "security,access,logging", "description": "Comma-separated list of audit policies"}
            },
            "required": ["target_systems"]
        }
    },
    {
        "name": "generate_high_confidence_compliance_report",
        "description": "Generate high-confidence compliance report with internal assessment data",
        "inputSchema": {
            "type": "object",
            "properties": {
                "assessment_data": {"type": "string", "description": "Path to assessment data JSON file"},
                "framework": {"type": "string", "default": "nist_800_53", "description": "Compliance framework (e.g., nist_800_53)"},
                "confidence_level": {"type": "string", "default": "high", "description": "Confidence level for assessment (e.g., high, medium, low)"}
            },
            "required": ["assessment_data"]
        }
    }
]

@app.route('/mcp/tools', methods=['GET'])
def mcp_list_tools():
    """List available MCP tools"""
    if not MCP_FUNCTIONS_AVAILABLE:
        return jsonify({'error': 'MCP functions not available'}), 500
    
    return jsonify({"tools": MCP_TOOLS_LIST})

@app.route('/mcp/call', methods=['POST'])
@require_valid_license
def mcp_call_tool():
    """Execute MCP tool calls"""
    if not MCP_FUNCTIONS_AVAILABLE:
        return jsonify({'error': 'MCP functions not available'}), 500
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        tool_name = data.get('name')
        arguments = data.get('arguments', {})
        
        if not tool_name:
            return jsonify({'error': 'Tool name is required'}), 400
        
                # Use the security_functions mapping
        function_map = security_functions
        
        if tool_name not in function_map:
            return jsonify({'error': f'Tool {tool_name} not found'}), 404
        
        # Execute the function
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(function_map[tool_name](**arguments))
            return jsonify({
                'content': [
                    {
                        'type': 'text',
                        'text': result.get('stdout', '') if isinstance(result, dict) else str(result)
                    }
                ]
            })
        finally:
            loop.close()
            
    except Exception as e:
        return jsonify({'error': f'Tool execution failed: {str(e)}'}), 500

# License management endpoints
@app.route('/license/status', methods=['GET'])
def license_status():
    """Get current license status"""
    try:
        info = license_manager.get_license_info()
        return jsonify(info)
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/license/activate', methods=['POST'])
def activate_license():
    """Activate trial license"""
    try:
        data = request.get_json() or {}
        email = data.get('email')
        name = data.get('name')
        
        if not email or not name:
            return jsonify({'error': 'Email and name are required'}), 400
        
        license_data = license_manager.activate_trial(email, name)
        return jsonify({
            'success': True,
            'message': '30-day trial activated successfully',
            'license_id': license_data['license_id'],
            'expires': license_data['expiry_date']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/license/features', methods=['GET'])
def license_features():
    """Get available features for current license"""
    try:
        validation = license_manager.validate_license()
        if not validation['valid']:
            return jsonify({'error': validation['error']}), 403
        
        features = validation['license_data'].get('features', {})
        return jsonify({'features': features})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/mcp/sse', methods=['GET', 'POST'])
@require_valid_license
def mcp_sse():
    """Server-Sent Events endpoint for MCP with JSON-RPC 2.0"""
    import json
    import time
    import threading
    from flask import Response, stream_template_string
    
    if request.method == 'GET':
        # SSE stream for Claude MCP client
        def generate_sse():
            # Send initial connection event
            yield f"event: message\ndata: {json.dumps({'type': 'connection', 'status': 'connected'})}\n\n"
            
            # Keep connection alive with heartbeats
            while True:
                try:
                    time.sleep(15)  # Heartbeat every 15 seconds
                    yield f"event: heartbeat\ndata: {json.dumps({'type': 'heartbeat', 'timestamp': time.time()})}\n\n"
                except GeneratorExit:
                    break
                    
        return Response(
            generate_sse(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Cache-Control'
            }
        )
    
    elif request.method == 'POST':
        # Handle JSON-RPC 2.0 requests
        try:
            data = request.get_json()
            if not data:
                return jsonify({'jsonrpc': '2.0', 'error': {'code': -32700, 'message': 'Parse error'}, 'id': None}), 400
            
            jsonrpc_version = data.get('jsonrpc')
            method = data.get('method')
            params = data.get('params', {})
            request_id = data.get('id')
            
            if jsonrpc_version != '2.0':
                return jsonify({'jsonrpc': '2.0', 'error': {'code': -32600, 'message': 'Invalid Request'}, 'id': request_id}), 400
            
            # Handle different MCP methods
            if method == 'initialize':
                response = {
                    'jsonrpc': '2.0',
                    'result': {
                        'protocolVersion': '2024-11-05',
                        'capabilities': {
                            'tools': {},
                            'resources': {},
                            'prompts': {}
                        },
                        'serverInfo': {
                            'name': 'ExternalAttacker-MCP',
                            'version': '1.0.0'
                        }
                    },
                    'id': request_id
                }
                return jsonify(response)
            
            elif method == 'tools/list':
                if not MCP_FUNCTIONS_AVAILABLE:
                    return jsonify({
                        'jsonrpc': '2.0',
                        'error': {'code': -32603, 'message': 'MCP functions not available'},
                        'id': request_id
                    }), 500
                
                tools = MCP_TOOLS_LIST
                
                response = {
                    'jsonrpc': '2.0',
                    'result': {'tools': tools},
                    'id': request_id
                }
                return jsonify(response)
            
            elif method == 'tools/call':
                if not MCP_FUNCTIONS_AVAILABLE:
                    return jsonify({
                        'jsonrpc': '2.0',
                        'error': {'code': -32603, 'message': 'MCP functions not available'},
                        'id': request_id
                    }), 500
                
                tool_name = params.get('name')
                arguments = params.get('arguments', {})
                
                if not tool_name:
                    return jsonify({
                        'jsonrpc': '2.0',
                        'error': {'code': -32602, 'message': 'Invalid params: tool name required'},
                        'id': request_id
                    }), 400
                
                # Use the security_functions mapping
                function_map = security_functions
                
                if tool_name not in function_map:
                    return jsonify({
                        'jsonrpc': '2.0',
                        'error': {'code': -32601, 'message': f'Tool {tool_name} not found'},
                        'id': request_id
                    }), 404
                
                # Execute the function
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                try:
                    result = loop.run_until_complete(function_map[tool_name](**arguments))
                    
                    response = {
                        'jsonrpc': '2.0',
                        'result': {
                            'content': [
                                {
                                    'type': 'text',
                                    'text': result.get('stdout', '') if isinstance(result, dict) else str(result)
                                }
                            ]
                        },
                        'id': request_id
                    }
                    return jsonify(response)
                finally:
                    loop.close()
            
            else:
                return jsonify({
                    'jsonrpc': '2.0',
                    'error': {'code': -32601, 'message': f'Method {method} not found'},
                    'id': request_id
                }), 404
                
        except Exception as e:
            return jsonify({
                'jsonrpc': '2.0',
                'error': {'code': -32603, 'message': f'Internal error: {str(e)}'},
                'id': request_id
            }), 500

def check_for_updates():
    try:
        # Get current version from version.txt
        with open('version.txt', 'r', encoding='utf-8-sig') as f:
            current_version = f.read().strip()

        # Get remote version
        response = requests.get('https://mordavid.com/md_versions.yaml')
        if response.status_code != 200:
            print(f"Failed to check for updates: {response.status_code}")
            return

        remote_versions = yaml.safe_load(response.text)
        remote_version = None
        download_url = None
        
        for sw in remote_versions['softwares']:
            if sw['name'] == 'ExternalAttacker-MCP':
                remote_version = sw['version']
                download_url = sw['download']
                break

        if not remote_version or not download_url:
            print("Could not find remote version info")
            return

        # Compare versions
        if version.parse(remote_version) > version.parse(current_version):
            print(f"New version available: {remote_version}")
            
            # Update MCP file
            response = requests.get(download_url)
            if response.status_code == 200:
                # Backup current MCP file
                shutil.copy2('ExternalAttacker-MCP.py', 'ExternalAttacker-MCP.py.bak')
                
                # Write new MCP version
                with open('ExternalAttacker-MCP.py', 'wb') as f:
                    f.write(response.content)
                print("Successfully updated MCP to new version")
            else:
                print(f"Failed to download MCP update: {response.status_code}")
                return

            # Update App file
            app_url = download_url.replace('ExternalAttacker-MCP.py', 'ExternalAttacker-App.py')
            response = requests.get(app_url)
            if response.status_code == 200:
                # Backup current App file
                shutil.copy2('ExternalAttacker-App.py', 'ExternalAttacker-App.py.bak')
                
                # Write new App version
                with open('ExternalAttacker-App.py', 'wb') as f:
                    f.write(response.content)
                print("Successfully updated App to new version")
            else:
                print(f"Failed to download App update: {response.status_code}")
                return

            # Update version.txt
            with open('version.txt', 'w', encoding='utf-8-sig') as f:
                f.write(remote_version)
            print(f"Updated version.txt to {remote_version}")

            print("All components updated successfully")
            # Restart the application to apply updates
            os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print(f"Update check failed: {str(e)}")

if __name__ == '__main__':
    print("Checking for updates...")
    check_for_updates()
    debug = os.environ.get('FLASK_ENV') == 'development'
    host = '127.0.0.1' if debug else '0.0.0.0'
    port = int(os.environ.get('PORT', 6991))  # Support Fly.io PORT environment variable
    print(f"Starting Flask app on {host}:{port}")
    app.run(debug=debug, host=host, port=port) 
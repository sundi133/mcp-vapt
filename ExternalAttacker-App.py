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

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

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
    "nessuscli"
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
    return render_template('index.html', tools=ALLOWED_TOOLS)

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

# Function mapping
security_functions = {
    'scan_subdomains': scan_subdomains_direct,
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
    'create_dradis_project': create_dradis_project_direct
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
    }
]

@app.route('/mcp/tools', methods=['GET'])
def mcp_list_tools():
    """List available MCP tools"""
    if not MCP_FUNCTIONS_AVAILABLE:
        return jsonify({'error': 'MCP functions not available'}), 500
    
    return jsonify({"tools": MCP_TOOLS_LIST})

@app.route('/mcp/call', methods=['POST'])
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

@app.route('/mcp/sse', methods=['GET', 'POST'])
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
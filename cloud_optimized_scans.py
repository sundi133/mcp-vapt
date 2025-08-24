#!/usr/bin/env python3
"""
Cloud-optimized scanning functions for better results against protected targets
"""

import asyncio
import time
import random

async def stealth_subdomain_scan(target: str, delay_range: tuple = (2, 5)):
    """
    Stealth subdomain scanning with randomized delays and user agents
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ]
    
    command = [
        "subfinder",
        "-domain", target,
        "-silent",
        "-active",
        "-t", "2",  # Reduce threads to avoid rate limiting
        "-timeout", "30",
        "-sources", "crtsh,bufferover,rapiddns,virustotal",  # Passive sources only
        "-rate-limit", "10",  # 10 requests per second max
        "-random-agent"
    ]
    
    return {
        'scan_type': 'stealth_subdomains',
        'target': target,
        'command': ' '.join(command),
        'notes': 'Optimized for protected targets with rate limiting'
    }

async def passive_reconnaissance(target: str):
    """
    Passive reconnaissance that doesn't directly contact the target
    """
    recon_sources = {
        'certificate_transparency': f"curl -s 'https://crt.sh/?q=%25.{target}&output=json'",
        'dns_dumpster': f"curl -s 'https://dnsdumpster.com/api/?domain={target}'",
        'security_trails': f"curl -s 'https://securitytrails.com/domain/{target}/dns'",
        'virustotal': f"curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_API&domain={target}'"
    }
    
    return {
        'scan_type': 'passive_recon',
        'target': target,
        'sources': recon_sources,
        'notes': 'Passive data gathering - no direct target contact'
    }

async def slow_port_scan(target: str, ports: str = "80,443,8080,8443"):
    """
    Slow, stealthy port scanning to avoid detection
    """
    command = [
        "nmap",
        "-sS",  # SYN scan
        "-T2",  # Slow timing (polite)
        "-p", ports,
        "--max-parallelism", "1",  # One port at a time
        "--scan-delay", "2s",  # 2 second delay between probes
        "--max-retries", "1",
        "-Pn",  # Skip host discovery
        "--randomize-hosts",
        "-f",  # Fragment packets
        target
    ]
    
    return {
        'scan_type': 'stealth_port_scan',
        'target': target,
        'command': ' '.join(command),
        'notes': 'Slow scan to avoid IDS/IPS detection'
    }

async def web_technology_detection(target: str):
    """
    Identify web technologies without aggressive scanning
    """
    command = [
        "httpx",
        "-target", target,
        "-silent",
        "-follow-redirects",
        "-tech-detect",
        "-title",
        "-server",
        "-status-code",
        "-content-length",
        "-threads", "1",  # Single thread
        "-timeout", "30",
        "-retries", "1",
        "-random-agent"
    ]
    
    return {
        'scan_type': 'web_tech_detection',
        'target': target,
        'command': ' '.join(command),
        'notes': 'Gentle web technology fingerprinting'
    }

async def nuclei_passive_templates(target: str):
    """
    Run only passive Nuclei templates that don't trigger WAF
    """
    command = [
        "nuclei",
        "-u", target,
        "-t", "http/misconfiguration/",
        "-t", "http/technologies/",
        "-t", "ssl/",
        "-silent",
        "-nc",
        "-j",
        "-rate-limit", "5",  # 5 requests per second
        "-timeout", "10",
        "-retries", "1",
        "-severity", "info,low,medium"  # Avoid aggressive high-severity templates
    ]
    
    return {
        'scan_type': 'passive_nuclei',
        'target': target,
        'command': ' '.join(command),
        'notes': 'Non-intrusive vulnerability detection'
    }

# Configuration recommendations for cloud scanning
CLOUD_SCAN_CONFIG = {
    'recommendations': {
        'timing': 'Use slow timing (-T2 or -T1) to avoid rate limiting',
        'threads': 'Limit concurrent threads (1-4 max) for stealthy scanning',
        'delays': 'Add delays between requests (2-5 seconds)',
        'user_agents': 'Rotate user agents to appear like normal browsing',
        'fragmentation': 'Use packet fragmentation (-f in nmap) to evade IDS',
        'passive_first': 'Always start with passive reconnaissance',
        'api_keys': 'Use API keys for better data from passive sources'
    },
    'aws_specific': {
        'global_accelerator': 'Targets behind AWS GA are heavily protected',
        'rate_limits': 'AWS enforces strict rate limiting on scanning',
        'cloudflare': 'If behind CloudFlare, expect additional protection',
        'waf_bypass': 'Use different scan patterns to avoid WAF signatures'
    }
} 
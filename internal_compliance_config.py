#!/usr/bin/env python3
"""
Internal NIST Compliance Assessment Configuration
Enables full-scope compliance scanning for High confidence levels
"""

import json
import os

# Internal Assessment Configuration
INTERNAL_ASSESSMENT_CONFIG = {
    "assessment_scope": {
        "external_only": False,          # Enable internal scope
        "internal_network": True,        # Scan internal networks
        "system_configuration": True,    # Check system configs
        "database_access": True,         # Database security assessment
        "file_system_access": True,      # File/directory permissions
        "process_validation": True,      # Running process validation
        "user_access_review": True,      # User account assessment
        "network_segmentation": True     # Internal network topology
    },
    
    "network_ranges": {
        "internal_cidrs": [
            "10.0.0.0/8",           # Private Class A
            "172.16.0.0/12",        # Private Class B  
            "192.168.0.0/16",       # Private Class C
            "10.1.0.0/24",          # Example: Production network
            "10.2.0.0/24",          # Example: Development network
            "10.3.0.0/24"           # Example: Management network
        ],
        "dmz_networks": [
            "203.0.113.0/24"        # Example: DMZ network
        ]
    },
    
    "system_access": {
        "ssh_enabled": True,
        "wmi_enabled": True,            # Windows Management
        "snmp_enabled": True,           # Network device management
        "agent_based": True,            # Install assessment agents
        "credentialed_scans": True      # Use system credentials
    },
    
    "compliance_frameworks": {
        "nist_800_53": {
            "baseline": "moderate",     # low/moderate/high
            "control_families": [
                "AC",   # Access Control
                "AU",   # Audit and Accountability  
                "AT",   # Awareness and Training
                "CM",   # Configuration Management
                "CP",   # Contingency Planning
                "IA",   # Identification and Authentication
                "IR",   # Incident Response
                "MA",   # Maintenance
                "MP",   # Media Protection
                "PS",   # Personnel Security
                "PE",   # Physical and Environmental Protection
                "PL",   # Planning
                "PM",   # Program Management
                "RA",   # Risk Assessment
                "CA",   # Security Assessment and Authorization
                "SC",   # System and Communications Protection
                "SI",   # System and Information Integrity
                "SA"    # System and Services Acquisition
            ],
            "confidence_target": "high"
        }
    },
    
    "assessment_methods": {
        "automated_scanning": True,
        "configuration_review": True,
        "interview_based": False,       # Set to True if including interviews
        "document_review": True,
        "penetration_testing": True,
        "vulnerability_assessment": True
    }
}

def generate_internal_assessment_script(target_network: str = "10.0.0.0/24"):
    """Generate GovReady-Q script for internal assessment"""
    
    script = f"""
# Internal NIST 800-53 Compliance Assessment Script
# Target: {target_network}
# Scope: Internal + External
# Confidence Target: High

# 1. Network Discovery and Asset Inventory
nmap -sn {target_network} -oA /tmp/network_discovery
nmap -sS -sV -O -A {target_network} -oA /tmp/internal_scan

# 2. Internal Service Analysis  
nuclei -target {target_network} -t /opt/nuclei-templates/technologies/ -silent -json -o /tmp/internal_tech.json
nuclei -target {target_network} -t /opt/nuclei-templates/cves/ -severity medium,high,critical -silent -json -o /tmp/internal_vulns.json

# 3. Configuration Assessment
# AC Family - Access Control
nmap --script smb-enum-users,smb-enum-shares {target_network}
nmap --script ssh-auth-methods,ssh-hostkey {target_network}

# AU Family - Audit and Accountability
nmap --script ms-sql-info,mysql-info,oracle-sid-brute {target_network}

# CM Family - Configuration Management
nuclei -target {target_network} -t /opt/nuclei-templates/misconfiguration/ -silent -json

# SC Family - System and Communications Protection
nmap --script ssl-enum-ciphers,ssl-cert {target_network}
nuclei -target {target_network} -t /opt/nuclei-templates/ssl/ -silent -json

# 4. Compliance Control Validation
python3 /opt/govready-q/manage.py compliance_scan \\
    --target {target_network} \\
    --framework nist_800_53 \\
    --baseline moderate \\
    --scan-type internal \\
    --collect-evidence \\
    --confidence-target high \\
    --output /tmp/nist_internal_assessment.json

# 5. Generate High-Confidence Report
python3 /opt/govready-q/manage.py generate_compliance_report \\
    --format oscal \\
    --include-evidence \\
    --assessment-scope internal \\
    --confidence-level high \\
    --output /tmp/nist_high_confidence_report.oscal
"""
    
    return script

def create_internal_scan_functions():
    """Create enhanced internal scanning functions for MCP"""
    
    functions = {
        "internal_nist_assessment": {
            "description": "High-confidence internal NIST 800-53 compliance assessment",
            "parameters": {
                "target_network": "Internal network CIDR (e.g., 10.0.0.0/24)",
                "baseline": "NIST baseline (low/moderate/high)",
                "control_families": "Specific control families to assess",
                "include_systems": "Include system configuration assessment",
                "include_databases": "Include database security assessment",
                "credentialed_scan": "Use system credentials for detailed assessment"
            }
        },
        
        "system_configuration_audit": {
            "description": "Detailed system configuration compliance audit",
            "parameters": {
                "target_systems": "List of systems to audit",
                "os_type": "Operating system type (windows/linux/mixed)",
                "audit_policies": "Security policies to validate",
                "baseline_configs": "Baseline configurations to compare against"
            }
        },
        
        "network_segmentation_assessment": {
            "description": "Internal network segmentation compliance review",
            "parameters": {
                "network_zones": "Network zones to assess",
                "firewall_rules": "Firewall rule analysis",
                "vlan_segmentation": "VLAN segmentation review"
            }
        }
    }
    
    return functions

# Save configuration
if __name__ == "__main__":
    # Write configuration file
    with open("/tmp/internal_compliance_config.json", "w") as f:
        json.dump(INTERNAL_ASSESSMENT_CONFIG, f, indent=2)
    
    # Generate assessment script
    script = generate_internal_assessment_script("10.0.0.0/24")
    with open("/tmp/internal_nist_assessment.sh", "w") as f:
        f.write(script)
    
    print("✅ Internal compliance assessment configuration created")
    print("📁 Files created:")
    print("   - /tmp/internal_compliance_config.json")
    print("   - /tmp/internal_nist_assessment.sh") 
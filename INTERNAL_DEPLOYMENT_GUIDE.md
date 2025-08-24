# 🏢 Internal Network Deployment Guide
## High-Confidence NIST Compliance Assessment

## 🎯 **Why Internal Deployment?**

For **High Confidence** NIST compliance assessment, you need:
- ✅ Access to internal network segments
- ✅ System-level configuration auditing
- ✅ Database security assessment
- ✅ Network segmentation validation
- ✅ Active Directory/LDAP enumeration

**External scanning only = Medium Confidence (60% coverage)**
**Internal deployment = High Confidence (85%+ coverage)**

## 🏗️ **Deployment Architecture Options**

### **Option 1: Dedicated Internal Server** ⭐ **Recommended**

```
┌─────────────────────────────────────────────────────────────┐
│                    Internal Network                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Production  │    │ Development │    │ Management  │     │
│  │ 10.1.0.0/24 │    │ 10.2.0.0/24 │    │ 10.3.0.0/24 │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│          │                   │                   │          │
│          └───────────────────┼───────────────────┘          │
│                              │                              │
│              ┌─────────────────────────────┐                │
│              │   Assessment Server         │                │
│              │   10.1.0.100               │                │
│              │                            │                │
│              │ ExternalAttacker-MCP       │                │
│              │ + All Security Tools       │                │
│              │ + GovReady-Q              │                │
│              └─────────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

### **Option 2: VPN-Connected Assessment**

```
┌─────────────────┐    VPN    ┌─────────────────────────────────┐
│ External Cloud  │◄─────────►│        Internal Network        │
│ Assessment Host │           │                                 │
│                 │           │  ┌─────────┐  ┌─────────────┐   │
│ ExternalAttacker│           │  │Production│  │Development │   │
│ -MCP            │           │  │Network   │  │Network      │   │
│                 │           │  └─────────┘  └─────────────┘   │
└─────────────────┘           └─────────────────────────────────┘
```

## 📋 **Internal Server Requirements**

### **Minimum Hardware:**
- **CPU:** 4 cores
- **RAM:** 8GB (16GB recommended)
- **Storage:** 100GB SSD
- **Network:** Gigabit Ethernet

### **Operating System:**
- **Ubuntu 20.04/22.04 LTS** (recommended)
- **CentOS/RHEL 8+**
- **Windows Server 2019+** (with WSL2)

### **Network Access Requirements:**
```bash
# Required Internal Network Access:
✅ SSH (22) to Linux systems
✅ RDP (3389) to Windows systems  
✅ HTTPS (443) to web applications
✅ Database ports (1433, 3306, 5432, etc.)
✅ SNMP (161) to network devices
✅ DNS (53) resolution
✅ LDAP (389/636) to domain controllers
```

## 🚀 **Internal Deployment Steps**

### **Step 1: Prepare Internal Server**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Git
sudo apt install git -y

# Clone repository
git clone https://github.com/your-repo/ExternalAttacker-MCP.git
cd ExternalAttacker-MCP
```

### **Step 2: Network Discovery**

```bash
# Discover internal network ranges
ip route show
nmap -sn 10.0.0.0/8 | grep "Nmap scan report"
nmap -sn 172.16.0.0/12 | grep "Nmap scan report"  
nmap -sn 192.168.0.0/16 | grep "Nmap scan report"
```

### **Step 3: Deploy Assessment Platform**

```bash
# Option A: Docker Deployment (Recommended)
docker build -f Dockerfile.complete -t external-attacker-internal .

# Run with internal network access
docker run -d \
  --name external-attacker-internal \
  --network host \
  -v /tmp/assessment-results:/tmp \
  -e FLASK_APP_URL=http://127.0.0.1:6991 \
  -e INTERNAL_NETWORKS="10.1.0.0/24,10.2.0.0/24,10.3.0.0/24" \
  external-attacker-internal

# Option B: Direct Installation
./install.sh
source .venv/bin/activate
python3 ExternalAttacker-App.py
```

### **Step 4: Configure Network Scanning**

```bash
# Create internal network configuration
cat > internal_networks.txt << EOF
10.1.0.0/24    # Production Network
10.2.0.0/24    # Development Network  
10.3.0.0/24    # Management Network
192.168.1.0/24 # WiFi Network
EOF
```

## 🛡️ **Security Considerations**

### **Network Segmentation:**
```bash
# Ensure assessment server can reach all required networks
# But limit its exposure to external networks

# Firewall rules (example)
sudo ufw allow from 10.0.0.0/8 to any port 22      # SSH from internal
sudo ufw allow from 172.16.0.0/12 to any port 22   # SSH from internal
sudo ufw deny from 0.0.0.0/0 to any port 22        # Block external SSH
```

### **Credential Management:**
```bash
# Store scanning credentials securely
mkdir -p ~/.config/assessment-creds

# Windows domain credentials (for credentialed scans)
echo "domain\\username:password" > ~/.config/assessment-creds/windows.txt

# Database credentials
echo "dbuser:dbpass" > ~/.config/assessment-creds/database.txt

# Set secure permissions
chmod 600 ~/.config/assessment-creds/*
```

## 📊 **Internal Assessment Workflow**

### **Phase 1: Network Discovery**
```bash
# Discover all internal systems
run_internal_compliance_scan({
    target_network: "10.0.0.0/8",
    framework: "nist_800_53",
    baseline: "moderate",
    include_systems: true
})
```

### **Phase 2: Control Family Assessment**
```bash
# Deep dive into specific controls
assess_internal_network_controls({
    target_network: "10.1.0.0/24",  # Production network
    control_families: "AC,AU,SC,SI,CM,IA",
    assessment_depth: "comprehensive"
})
```

### **Phase 3: System Configuration Audit**
```bash
# Detailed system auditing
system_configuration_compliance_audit({
    target_systems: "10.1.0.10,10.1.0.11,10.1.0.12",
    os_type: "mixed",
    audit_policies: "security,access,logging,baseline"
})
```

### **Phase 4: High-Confidence Reporting**
```bash
# Generate final compliance report
generate_high_confidence_compliance_report({
    assessment_data: "/tmp/internal_compliance_results.json",
    confidence_level: "high"
})
```

## 🔧 **Troubleshooting Internal Deployment**

### **Common Issues:**

1. **Network Access Problems:**
```bash
# Test connectivity to internal networks
nmap -sn 10.1.0.0/24
ping 10.1.0.1
telnet 10.1.0.10 22
```

2. **Permission Issues:**
```bash
# Ensure assessment server has proper permissions
sudo usermod -aG adm assessment-user
sudo usermod -aG sudo assessment-user
```

3. **Firewall Blocking:**
```bash
# Check internal firewalls
nmap -sS -O 10.1.0.10
nmap --script firewall-bypass 10.1.0.10
```

## 📈 **Expected Results with Internal Deployment**

| **Assessment Scope** | **Confidence Level** | **Control Coverage** |
|----------------------|----------------------|----------------------|
| External Only | 🟡 Medium (60%) | Limited evidence |
| Internal Network | 🟢 High (85%) | Strong evidence |
| + Credentialed | 🔵 Very High (95%) | Complete evidence |

## 🎯 **Recommended Internal Setup**

```bash
# Ideal internal deployment
Assessment Server: 10.1.0.100
├── Network Access: All internal VLANs
├── Credentials: Domain admin, DB admin  
├── Tools: Full ExternalAttacker-MCP suite
├── Storage: 500GB for scan results
└── Compliance: GovReady-Q integration

# Network segments to assess:
Production: 10.1.0.0/24
Development: 10.2.0.0/24  
Management: 10.3.0.0/24
DMZ: 203.0.113.0/24
```

---

**🎉 Result: High-Confidence NIST 800-53 compliance assessment with complete internal network coverage!** 
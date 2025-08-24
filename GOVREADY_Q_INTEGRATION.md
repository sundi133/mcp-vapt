# 🏛️ GovReady-Q Compliance Integration

## Overview

ExternalAttacker-MCP now includes **[GovReady-Q](https://github.com/GovReady/govready-q)**, a powerful open-source **Governance, Risk & Compliance (GRC)** platform that automates security assessments and compliance documentation.

## 🎯 What GovReady-Q Adds

### **Compliance Frameworks Supported:**
- **NIST 800-53** (Federal Information Systems)
- **FedRAMP** (Cloud Security Authorization)  
- **SOC 2** (Service Organization Controls)
- **ISO 27001** (Information Security Management)
- **CIS Controls** (Center for Internet Security)
- **PCI DSS** (Payment Card Industry)

### **Key Capabilities:**
- **🔍 Automated Compliance Scanning** - Assess infrastructure against controls
- **📋 Control Assessment** - Validate security control implementation  
- **📄 Report Generation** - OSCAL, PDF, DOCX compliance reports
- **🔗 OSCAL Integration** - NIST Open Security Controls Assessment Language
- **📊 Gap Analysis** - Identify compliance gaps and remediation steps
- **📝 SSP Generation** - System Security Plan documentation

## 🚀 Available Functions

### 1. **Start Compliance Assessment**
```javascript
// Initialize a new compliance project
start_compliance_assessment({
    framework: "nist_800_53",           // or "fedramp", "iso27001", "soc2"
    project_name: "Web App Assessment",  
    organization: "ACME Corp"
})
```

### 2. **Run Compliance Scan**
```javascript
// Automated compliance scanning
run_compliance_scan({
    target: "https://example.com",
    framework: "nist_800_53",
    scan_type: "infrastructure",        // or "application", "network", "cloud"
    evidence_collection: true
})
```

### 3. **Assess Security Controls**
```javascript
// Validate control implementation
assess_security_controls({
    target: "192.168.1.100",
    control_baseline: "moderate",       // "low", "moderate", "high"
    control_set: "nist_800_53",        // or "iso27001", "cis"
    assessment_mode: "automated"        // or "manual", "hybrid"
})
```

### 4. **Generate Compliance Reports**  
```javascript
// Create compliance documentation
generate_compliance_report({
    project_id: "proj_12345",
    report_format: "oscal",            // "oscal", "docx", "pdf", "json"
    include_evidence: true,
    control_families: "AC,AU,SC,SI"    // Access Control, Audit, System & Comms, System & Info Integrity
})
```

### 5. **System Security Plan (SSP)**
```javascript
// Generate SSP documentation
generate_system_security_plan({
    system_name: "E-commerce Platform",
    system_type: "web_application",     // "database", "network", "cloud"
    authorization_boundary: "system",
    impact_level: "moderate"            // "low", "moderate", "high"
})
```

### 6. **Gap Analysis**
```javascript
// Identify compliance gaps
compliance_gap_analysis({
    current_state: "/tmp/current_ssp.json",
    target_framework: "nist_800_53",
    target_baseline: "moderate",
    output_recommendations: true
})
```

### 7. **OSCAL Validation**
```javascript
// Validate OSCAL catalogs
validate_oscal_catalog({
    catalog_file: "/tmp/security_catalog.json",
    validate_links: true,
    check_completeness: true
})
```

## 🔄 Complete Compliance Workflow

### **Phase 1: Discovery & Assessment**
```bash
# 1. Start compliance project
start_compliance_assessment({
    framework: "nist_800_53",
    project_name: "Production System Assessment"
})

# 2. Scan target infrastructure  
run_compliance_scan({
    target: "https://api.example.com",
    framework: "nist_800_53",
    scan_type: "infrastructure"
})

# 3. Assess specific controls
assess_security_controls({
    target: "api.example.com",
    control_baseline: "moderate"
})
```

### **Phase 2: Gap Analysis & Planning**
```bash
# 4. Perform gap analysis
compliance_gap_analysis({
    current_state: "/tmp/current_assessment.json",
    target_framework: "nist_800_53",
    output_recommendations: true
})
```

### **Phase 3: Documentation & Reporting**
```bash
# 5. Generate System Security Plan
generate_system_security_plan({
    system_name: "Production API",
    system_type: "web_application",
    impact_level: "moderate"
})

# 6. Create compliance reports
generate_compliance_report({
    report_format: "oscal",
    include_evidence: true
})
```

## 📊 Integration with Penetration Testing

### **Combined Security Assessment:**
1. **🔍 Recon**: `scan_stealth_subdomains` → Discover attack surface
2. **🛡️ Compliance**: `run_compliance_scan` → Assess control implementation
3. **⚡ Pentesting**: `scan_vulnerabilities` → Find security vulnerabilities  
4. **📋 Gap Analysis**: `compliance_gap_analysis` → Identify compliance gaps
5. **📄 Reporting**: `generate_compliance_report` → Unified compliance report

### **Example Workflow:**
```bash
# Discovery phase
scan_stealth_subdomains({target: "example.com"})
scan_stealth_ports({target: "example.com"})

# Security testing
scan_vulnerabilities({target: "https://example.com"})
scan_xss({target: "https://example.com"})

# Compliance assessment  
run_compliance_scan({target: "https://example.com"})
assess_security_controls({target: "example.com"})

# Documentation
generate_system_security_plan({system_name: "Example System"})
generate_compliance_report({report_format: "oscal"})
```

## 🏢 Enterprise Use Cases

### **DevSecOps Integration**
- **CI/CD Pipeline**: Automated compliance checks in deployment
- **Infrastructure as Code**: Validate Terraform/CloudFormation compliance
- **Container Security**: Assess Docker/K8s deployments

### **Audit Preparation**  
- **Control Evidence**: Automated evidence collection
- **Documentation**: OSCAL-compliant security documentation
- **Gap Remediation**: Prioritized remediation roadmap

### **Multi-Framework Support**
- **Government**: FedRAMP, FISMA, NIST 800-53
- **Commercial**: SOC 2, ISO 27001, PCI DSS
- **Industry**: HIPAA, PCI DSS, GDPR alignment

## 📁 Output Files

GovReady-Q generates compliance artifacts in `/tmp/`:

- **`compliance_results.json`** - Scan results with control mappings
- **`control_assessment.json`** - Security control validation results
- **`compliance_report.oscal`** - OSCAL-formatted compliance report
- **`gap_analysis.json`** - Gap analysis with remediation recommendations
- **`ssp_SystemName.docx`** - System Security Plan document
- **`oscal_validation.json`** - OSCAL catalog validation results

## 🚀 Getting Started

### **Quick Compliance Check:**
```bash
# Basic NIST 800-53 assessment
run_compliance_scan({
    target: "https://yourapp.com",
    framework: "nist_800_53"
})
```

### **Full Enterprise Assessment:**
```bash
# Comprehensive compliance workflow
start_compliance_assessment({framework: "nist_800_53"})
→ run_compliance_scan({target: "prod.company.com"})
→ assess_security_controls({control_baseline: "moderate"})  
→ compliance_gap_analysis({output_recommendations: true})
→ generate_system_security_plan({system_name: "Production"})
→ generate_compliance_report({report_format: "oscal"})
```

## 🔗 Resources

- **GovReady-Q Documentation**: [govready-q.readthedocs.io](https://govready-q.readthedocs.io)
- **NIST OSCAL**: [pages.nist.gov/OSCAL](https://pages.nist.gov/OSCAL/)  
- **NIST 800-53**: [csrc.nist.gov/publications/detail/sp/800-53/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- **FedRAMP**: [fedramp.gov](https://fedramp.gov)

---

**🎯 Perfect for:** Government contractors, cloud providers, fintech, healthcare, and any organization requiring formal compliance documentation alongside security testing. 
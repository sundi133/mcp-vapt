# 🔐 ExternalAttacker-MCP Licensing Guide
## 30-Day Trial & Commercial Licensing

## 🎯 **Overview**

ExternalAttacker-MCP uses a hardware-bound licensing system to protect intellectual property while providing flexible trial and commercial options for customers.

## 📋 **License Types**

### **🆓 30-Day Free Trial**
- **Duration:** 30 days from activation
- **Features:** Full feature access with limits
- **Targets:** Up to 50 targets per scan
- **Concurrent Scans:** Up to 5 simultaneous scans
- **Compliance Modules:** ✅ Included
- **Stealth Scanning:** ✅ Included
- **Reporting:** ✅ Included
- **API Access:** ✅ Included

### **💼 Commercial License**
- **Duration:** 1 year (renewable)
- **Features:** All features unlocked
- **Targets:** Up to 1,000 targets per scan
- **Concurrent Scans:** Up to 20 simultaneous scans
- **Enterprise Features:** ✅ Included
- **Priority Support:** ✅ Included
- **Custom Integration:** ✅ Available

## 🚀 **Customer Trial Activation**

### **Quick Start (Recommended)**
```bash
# 1. Download ExternalAttacker-MCP
git clone <repository-url>
cd ExternalAttacker-MCP

# 2. Run the trial activation script
./activate_trial.sh

# Follow the interactive prompts to activate your trial
```

### **Manual Activation**
```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Activate trial license
python3 license_manager.py activate --email "your@email.com" --name "Your Company"

# 3. Verify activation
python3 license_manager.py info
```

## 🔧 **License Management Commands**

### **Check License Status**
```bash
python3 license_manager.py validate
python3 license_manager.py info
```

### **Activate Trial**
```bash
python3 license_manager.py activate
# Interactive mode - prompts for email/name

python3 license_manager.py activate --email "customer@company.com" --name "Company Name"
# Non-interactive mode
```

### **Generate Licenses (Vendor Only)**
```bash
# Generate trial license
python3 license_manager.py generate-trial --email "customer@company.com" --name "Customer Name"

# Generate commercial license
python3 license_manager.py generate-commercial --email "customer@company.com" --name "Customer Name"
```

## 🏢 **Customer Deployment Scenarios**

### **Scenario 1: Trial Evaluation**
```bash
# Customer downloads and runs trial activation
./activate_trial.sh

# 30-day evaluation period begins
# Customer can test all features with trial limits
```

### **Scenario 2: Internal Network Assessment**
```bash
# Customer deploys on internal server
./deploy-internal.sh

# Select deployment mode based on network requirements
# License validates on target hardware
```

### **Scenario 3: Cloud Deployment**
```bash
# Customer deploys to cloud (AWS/Azure/GCP)
# License binds to cloud instance hardware fingerprint
flyctl deploy  # or equivalent cloud deployment
```

## 🛡️ **Security Features**

### **Hardware Binding**
- License tied to specific hardware fingerprint
- Prevents unauthorized copying/sharing
- Based on: hostname, platform, processor, machine type

### **Encryption**
- All license data encrypted with AES-256
- Hardware-specific encryption keys
- Tamper-resistant license files

### **Validation**
- Real-time license validation
- Automatic expiry checking
- Feature-based access control

## 🌐 **Web Interface Integration**

### **License Status API**
```bash
# Check license status
curl http://localhost:6991/license/status

# Get available features
curl http://localhost:6991/license/features

# Activate trial (POST)
curl -X POST http://localhost:6991/license/activate \
  -H "Content-Type: application/json" \
  -d '{"email": "customer@company.com", "name": "Customer Name"}'
```

### **Web Dashboard**
- License status displayed on main dashboard
- Expiry warnings for approaching deadlines
- Trial activation interface
- Feature access indicators

## 📊 **License Enforcement**

### **Feature Restrictions**
```python
# Compliance modules require valid license
if not license_manager.check_feature_access('compliance_modules'):
    return error("Compliance features require valid license")

# Target limits enforced
limits = license_manager.enforce_limits(current_targets=75)
if not limits['allowed']:
    return error(f"Target limit exceeded: {limits['error']}")
```

### **API Protection**
- All MCP calls protected by license validation
- API endpoints require valid license
- Graceful degradation for expired licenses

## 🎯 **Commercial Licensing Process**

### **For Customers:**
1. **Trial Period:** Evaluate with 30-day trial
2. **Purchase Decision:** Contact sales for commercial license
3. **License Generation:** Vendor generates commercial license
4. **Deployment:** Replace trial license with commercial license
5. **Support:** Access to priority support and updates

### **For Vendors:**
1. **Lead Qualification:** Customer requests trial
2. **Trial Generation:** Generate 30-day trial license
3. **Follow-up:** Monitor trial usage and support
4. **Commercial Sale:** Generate commercial license upon purchase
5. **Support Delivery:** Provide ongoing support and updates

## 📈 **License Analytics**

### **Trial Tracking**
- Monitor trial activations
- Track usage patterns
- Identify conversion opportunities

### **Commercial Monitoring**
- License expiry tracking
- Feature usage analytics
- Support request correlation

## 🔧 **Technical Integration**

### **Application Startup**
```python
# Both ExternalAttacker-MCP.py and ExternalAttacker-App.py
from license_manager import LicenseManager

license_manager = LicenseManager()
license_status = license_manager.validate_license()

if license_status['valid']:
    print(f"✅ License Valid ({license_status['days_remaining']} days)")
else:
    print(f"❌ License Error: {license_status['error']}")
```

### **Function Protection**
```python
# Protect premium functions
@require_valid_license
def premium_function():
    # Implementation
    pass

# Check specific features
if license_manager.check_feature_access('stealth_scanning'):
    # Allow stealth scanning
    pass
```

## 🚨 **Troubleshooting**

### **Common Issues**

1. **"License not valid for this hardware"**
   - License tied to different hardware
   - Solution: Contact support for license transfer

2. **"License expired X days ago"**
   - Trial or commercial license expired
   - Solution: Renew license or contact sales

3. **"No license file found"**
   - License file missing or corrupted
   - Solution: Re-activate trial or restore license file

4. **"Cryptography module not found"**
   - Missing dependency
   - Solution: `pip3 install cryptography>=3.4.8`

### **Error Recovery**
```bash
# Reset corrupted license
rm license.key
python3 license_manager.py activate

# Check system compatibility
python3 -c "from license_manager import LicenseManager; print('License system OK')"

# Verify all dependencies
pip3 install -r requirements.txt
```

## 📞 **Support Contacts**

### **Trial Support**
- **Email:** trial-support@your-company.com
- **Documentation:** Available in repository
- **Response Time:** Best effort

### **Commercial Support**
- **Email:** support@your-company.com
- **Phone:** +1-XXX-XXX-XXXX
- **Response Time:** 24 hours (priority customers)
- **Escalation:** Available for critical issues

## 💰 **Pricing Information**

### **Trial License**
- **Cost:** FREE
- **Duration:** 30 days
- **Features:** Full access with limits
- **Support:** Community support

### **Commercial License**
- **Contact Sales** for pricing
- **Duration:** 1 year (renewable)
- **Features:** Full enterprise access
- **Support:** Priority support included

---

## 🎯 **Quick Reference**

| **Task** | **Command** |
|----------|-------------|
| Activate Trial | `./activate_trial.sh` |
| Check Status | `python3 license_manager.py info` |
| Validate License | `python3 license_manager.py validate` |
| Start Application | `python3 ExternalAttacker-App.py` |
| Web Interface | `http://localhost:6991` |
| License API | `http://localhost:6991/license/status` |

**🎉 Ready for customer deployments with professional licensing!** 
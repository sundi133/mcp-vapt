# 🚁 Fly.io Licensing Deployment Guide
## ExternalAttacker-MCP Cloud Licensing

## 🎯 **Overview**

Deploy ExternalAttacker-MCP to Fly.io with integrated licensing system for customer trial and commercial deployments.

## 🚀 **Quick Start - Customer Trial Deployment**

### **Prerequisites**
```bash
# 1. Install flyctl
curl -L https://fly.io/install.sh | sh

# 2. Login to Fly.io
flyctl auth login

# 3. Clone repository
git clone <repository-url>
cd ExternalAttacker-MCP
```

### **Deploy with 30-Day Trial**
```bash
# One-command deployment with trial license
./fly-licensing-deploy.sh

# Select option 1: Trial License
# Enter customer email and company name
# Automatic deployment with pre-configured trial
```

## 🏢 **Deployment Scenarios**

### **Scenario 1: Customer Trial (Self-Service)**
```bash
# Customer gets pre-configured trial deployment
./fly-licensing-deploy.sh
# Select: 1. Trial License
# Enter: customer@company.com, "Company Name"
# Result: 30-day trial automatically activated
```

### **Scenario 2: Commercial Customer**
```bash
# Deploy with commercial license
./fly-licensing-deploy.sh
# Select: 2. Commercial License
# Enter: customer@company.com, "Company Name"
# Result: 1-year commercial license activated
```

### **Scenario 3: Post-Deployment Activation**
```bash
# Deploy without license, activate later
./fly-licensing-deploy.sh
# Select: 3. No License
# Customer activates via API after deployment
```

## 🔧 **Manual Deployment Steps**

### **Step 1: Configure Fly.io App**
```bash
# Create new Fly.io app
flyctl launch --dockerfile Dockerfile.complete --name external-attacker-mcp-trial

# Configure secrets for licensing
flyctl secrets set CUSTOMER_EMAIL="customer@company.com"
flyctl secrets set CUSTOMER_NAME="Customer Company"
flyctl secrets set LICENSE_TYPE="trial"
flyctl secrets set FLASK_SECRET_KEY="$(openssl rand -hex 32)"
```

### **Step 2: Create Persistent Volume**
```bash
# Create volume for license storage
flyctl volumes create license_data --region iad --size 1

# Update fly.toml with volume mount
cp fly-license.toml fly.toml
```

### **Step 3: Deploy Application**
```bash
# Deploy with licensing
flyctl deploy --dockerfile Dockerfile.complete

# Check deployment
flyctl logs
flyctl status
```

### **Step 4: Verify License**
```bash
# Check license status
curl https://your-app.fly.dev/license/status

# Expected response for trial:
{
  "valid": true,
  "license_type": "trial",
  "customer_name": "Customer Company",
  "days_remaining": 30,
  "features": {
    "max_targets": 50,
    "max_concurrent_scans": 5,
    "compliance_modules": true
  }
}
```

## 🌐 **Cloud Licensing Features**

### **Cloud-Specific Hardware Fingerprinting**
```python
# Uses stable cloud identifiers
cloud_info = {
    'fly_app': os.environ.get('FLY_APP_NAME'),
    'fly_region': os.environ.get('FLY_REGION'),
    'hostname': socket.gethostname(),
    'customer_email': os.environ.get('CUSTOMER_EMAIL')
}
```

### **Persistent License Storage**
- Licenses stored in Fly.io volumes (`/app/license_data/`)
- Survives app restarts and deployments
- Encrypted with cloud-specific keys

### **Environment Variable Configuration**
| Variable | Purpose | Example |
|----------|---------|---------|
| `CUSTOMER_EMAIL` | License binding | `customer@company.com` |
| `CUSTOMER_NAME` | Customer identification | `Company Name` |
| `LICENSE_TYPE` | License type | `trial` or `commercial` |
| `FLASK_SECRET_KEY` | Security | Auto-generated |

## 📋 **Customer Access Workflow**

### **Trial Customer Journey**
1. **Receive deployment URL** from vendor
2. **Access immediately** - trial pre-activated
3. **Use for 30 days** with full features (limited targets)
4. **Purchase commercial license** for continued access

### **Commercial Customer Journey**
1. **Purchase license** from vendor
2. **Receive deployment URL** with commercial license
3. **Full access** to all features and limits
4. **Annual renewal** for continued service

## 🔐 **License Management APIs**

### **Check License Status**
```bash
GET https://your-app.fly.dev/license/status

Response:
{
  "valid": true,
  "license_type": "trial",
  "customer_name": "Customer Company",
  "customer_email": "customer@company.com",
  "license_id": "uuid",
  "expires": "2024-10-20T12:00:00",
  "days_remaining": 25,
  "features": {...}
}
```

### **Activate Trial (Post-Deployment)**
```bash
POST https://your-app.fly.dev/license/activate
Content-Type: application/json

{
  "email": "customer@company.com",
  "name": "Customer Company"
}

Response:
{
  "success": true,
  "message": "30-day trial activated successfully",
  "license_id": "uuid",
  "expires": "2024-10-20T12:00:00"
}
```

### **Get Available Features**
```bash
GET https://your-app.fly.dev/license/features

Response:
{
  "features": {
    "max_targets": 50,
    "max_concurrent_scans": 5,
    "compliance_modules": true,
    "stealth_scanning": true,
    "reporting": true,
    "api_access": true
  }
}
```

## 🎛️ **Fly.io Management**

### **Monitor Deployment**
```bash
# Check application status
flyctl status

# View real-time logs
flyctl logs

# Check machine status
flyctl machine status

# Scale application
flyctl scale count 2
```

### **License Management**
```bash
# Update license environment variables
flyctl secrets set CUSTOMER_EMAIL="new@customer.com"
flyctl secrets set LICENSE_TYPE="commercial"

# Restart application to apply changes
flyctl machine restart

# Connect to console for debugging
flyctl ssh console
```

### **Volume Management**
```bash
# List volumes
flyctl volumes list

# Create backup
flyctl volumes snapshot create license_data

# Restore from backup
flyctl volumes restore <snapshot-id>
```

## 🚨 **Troubleshooting**

### **Common Issues**

1. **"License not valid for this hardware"**
   ```bash
   # Check environment variables
   flyctl ssh console
   env | grep CUSTOMER
   
   # Reset license
   rm /app/license_data/license.key
   restart application
   ```

2. **"No license file found"**
   ```bash
   # Check volume mount
   flyctl ssh console
   ls -la /app/license_data/
   
   # Verify environment variables
   flyctl secrets list
   ```

3. **License API not responding**
   ```bash
   # Check application health
   flyctl status
   flyctl logs
   
   # Test license endpoint
   curl https://your-app.fly.dev/license/status
   ```

4. **Volume not mounted**
   ```bash
   # Check fly.toml configuration
   cat fly.toml | grep -A5 mounts
   
   # Recreate volume if needed
   flyctl volumes destroy license_data
   flyctl volumes create license_data --region iad --size 1
   ```

## 💰 **Pricing Considerations**

### **Fly.io Costs**
- **Small apps**: ~$5-10/month
- **Medium apps**: ~$20-30/month  
- **Storage**: ~$0.15/GB/month (minimal for licenses)
- **Bandwidth**: Included in base pricing

### **License Tiers**
- **Trial**: FREE (30 days)
- **Commercial**: Contact sales
- **Enterprise**: Custom pricing

## 🔧 **Advanced Configuration**

### **Custom Health Checks**
```toml
# fly.toml
[[http_service.checks]]
  method = "get"
  path = "/license/status"
  interval = 15000
  timeout = 10000
  headers = {"Accept" = "application/json"}
```

### **Auto-Scaling**
```toml
# fly.toml
[[vm]]
  cpu_kind = "shared"
  cpus = 2
  memory_mb = 4096

[metrics]
  port = 9091
  path = "/metrics"
```

### **Multiple Regions**
```bash
# Deploy to multiple regions
flyctl regions add lax
flyctl regions add fra
flyctl scale count 3
```

## 📞 **Customer Support Integration**

### **Support Information in License**
```json
{
  "support": {
    "trial": {
      "email": "trial-support@company.com",
      "docs": "https://docs.company.com",
      "response_time": "best_effort"
    },
    "commercial": {
      "email": "support@company.com",
      "phone": "+1-XXX-XXX-XXXX",
      "response_time": "24_hours",
      "priority": true
    }
  }
}
```

### **Automated Notifications**
- License expiry warnings (7, 3, 1 days)
- Usage limit notifications
- Upgrade prompts for trial users

## 🎯 **Customer Deployment Examples**

### **Quick Trial for Prospect**
```bash
# Sales team deploys trial for prospect
./fly-licensing-deploy.sh
# Customer email: prospect@bigcorp.com
# Company: Big Corp Security Team
# License: 30-day trial
# URL: https://bigcorp-trial.fly.dev
```

### **Commercial Customer Setup**
```bash
# Deploy for paying customer
./fly-licensing-deploy.sh
# Customer: customer@enterprise.com
# Company: Enterprise Corp
# License: Commercial (1 year)
# URL: https://enterprise-security.fly.dev
```

### **Multi-Customer SaaS**
```bash
# Deploy multiple instances
for customer in customer1 customer2 customer3; do
    flyctl launch --name "external-attacker-$customer"
    flyctl secrets set CUSTOMER_EMAIL="$customer@company.com"
    flyctl deploy
done
```

---

## 🎯 **Quick Reference**

| **Task** | **Command** |
|----------|-------------|
| Deploy Trial | `./fly-licensing-deploy.sh` (option 1) |
| Deploy Commercial | `./fly-licensing-deploy.sh` (option 2) |
| Check License | `curl https://app.fly.dev/license/status` |
| View Logs | `flyctl logs` |
| Scale App | `flyctl scale count 2` |
| SSH Console | `flyctl ssh console` |
| Update Secrets | `flyctl secrets set KEY=value` |

**🎉 Ready for professional cloud deployment with integrated licensing!** 
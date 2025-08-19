# Deploy ExternalAttacker-MCP to Fly.io

Complete guide to deploy your security testing platform to the cloud.

## 🚀 **Prerequisites**

### 1. Install Fly CLI
```bash
# macOS
curl -L https://fly.io/install.sh | sh

# Linux
curl -L https://fly.io/install.sh | sh

# Windows (PowerShell)
iwr https://fly.io/install.ps1 -useb | iex
```

### 2. Create Fly.io Account
```bash
# Sign up and authenticate
fly auth signup
# OR login if you have an account
fly auth login
```

## 📦 **Deployment Steps**

### Step 1: Prepare Your Application
```bash
# Navigate to your project
cd /Users/jyotirmoysundi/git/ExternalAttacker-MCP

# Verify all files are present
ls -la
# Should see: Dockerfile, fly.toml, ExternalAttacker-App.py, ExternalAttacker-MCP.py
```

### Step 2: Launch Application on Fly.io
```bash
# Launch your app (this will create it on Fly.io)
fly launch

# Follow the prompts:
# - App name: external-attacker-mcp (or your preferred name)
# - Region: Choose closest to you (sjc for San Jose, ord for Chicago, etc.)
# - Database: No (we don't need one for this app)
# - Redis: No
```

### Step 3: Create Volume for Scan Results (Optional)
```bash
# Create persistent volume for scan results
fly volumes create scan_results --size 10 --region sjc

# Update fly.toml if needed (already configured)
```

### Step 4: Set Environment Variables/Secrets
```bash
# Set API key for Flask app protection
fly secrets set API_KEY="your_secure_api_key_here"

# Set Flask secret key
fly secrets set FLASK_SECRET_KEY="your_flask_secret_key_here"

# Optional: Set Nessus credentials if you have them
fly secrets set NESSUS_ACCESS_KEY="your_nessus_access_key"
fly secrets set NESSUS_SECRET_KEY="your_nessus_secret_key"
fly secrets set NESSUS_URL="https://your-nessus-server:8834"

# Optional: Set BeEF credentials
fly secrets set BEEF_USER="beef_admin"
fly secrets set BEEF_PASS="secure_password"
```

### Step 5: Deploy Application
```bash
# Deploy your application
fly deploy

# Monitor deployment
fly logs

# Check status
fly status
```

### Step 6: Scale Resources (If Needed)
```bash
# Scale to higher memory if needed for large scans
fly scale memory 4096

# Scale CPU cores
fly scale count 2

# Check current scaling
fly scale show
```

## 🌐 **Access Your Application**

### Web Interface
```bash
# Get your app URL
fly info

# Example: https://external-attacker-mcp.fly.dev
```

### API Endpoint
```bash
# Test API endpoint
curl -X POST https://external-attacker-mcp.fly.dev/api/run \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{"tool": "subfinder", "args": "-domain example.com -silent"}'
```

### MCP Server Connection
```bash
# Your MCP server will be available at:
# https://external-attacker-mcp.fly.dev

# Use this URL in your MCP client configuration
```

## 🔧 **Configuration Options**

### Update fly.toml
```toml
# Modify resources in fly.toml
[vm]
  cpu_kind = "shared"    # or "performance" for more power
  cpus = 2               # 1, 2, 4, 8
  memory_mb = 2048       # 512, 1024, 2048, 4096, 8192

# Auto-scaling
[http_service]
  auto_stop_machines = true     # Stop when idle
  auto_start_machines = true    # Start when needed
  min_machines_running = 0      # Always-on instances
```

### Environment Variables
```bash
# List current secrets
fly secrets list

# Update a secret
fly secrets set API_KEY="new_secure_key"

# Remove a secret
fly secrets unset OLD_SECRET
```

## 🛡️ **Security Configuration**

### 1. API Key Protection
```bash
# Set strong API key
fly secrets set API_KEY="$(openssl rand -base64 32)"

# Use in API calls
curl -H "X-API-Key: your_api_key" https://your-app.fly.dev/api/run
```

### 2. Network Security
```bash
# Fly.io provides HTTPS by default
# Your app is accessible at: https://your-app-name.fly.dev

# Custom domain (optional)
fly certs add your-domain.com
```

### 3. Firewall Rules
Fly.io handles this automatically, but you can configure:
```bash
# View current app info
fly info

# Check networking
fly ips list
```

## 📊 **Monitoring & Logs**

### View Logs
```bash
# Real-time logs
fly logs

# Historical logs
fly logs --search "error"

# Specific time range
fly logs --since 1h
```

### Monitor Performance
```bash
# Resource usage
fly metrics

# Machine status
fly status

# App info
fly info
```

### Health Checks
The Dockerfile includes health checks. Monitor with:
```bash
# Check health status
fly checks list
```

## 🔄 **Updates & Maintenance**

### Deploy Updates
```bash
# After making code changes
git add .
git commit -m "Update security tools"

# Deploy changes
fly deploy

# Quick deployment (skip build cache)
fly deploy --no-cache
```

### Restart Application
```bash
# Restart all instances
fly restart

# Restart specific machine
fly restart MACHINE_ID
```

### Scale Down/Up
```bash
# Scale down when not in use
fly scale count 0

# Scale up for heavy testing
fly scale count 2 memory 4096
```

## 💰 **Cost Management**

### Fly.io Pricing (as of 2024)
- **Free Tier**: 3 shared-cpu-1x machines with 256MB RAM
- **Paid**: ~$0.02/hour for shared-cpu-1x (1GB RAM)
- **Storage**: ~$0.15/GB/month for volumes

### Cost Optimization
```bash
# Auto-stop when idle (already configured)
auto_stop_machines = true

# Minimum running instances
min_machines_running = 0

# Monitor usage
fly billing show
```

## 🚨 **Security Considerations**

### ⚠️ **Important Security Notes**

1. **API Key Protection**: Always use strong API keys
2. **Rate Limiting**: Built into the Flask app
3. **Target Authorization**: Only scan authorized targets
4. **Log Management**: Monitor scan activities
5. **Network Access**: App can reach any internet host

### 🔒 **Best Practices**

```bash
# 1. Use environment variables for all secrets
fly secrets set SECRET_NAME="value"

# 2. Monitor logs for suspicious activity
fly logs --search "failed"

# 3. Regular security updates
fly deploy  # Deploy latest security patches

# 4. Backup important scan results
fly ssh console -C "tar -czf /tmp/backup.tar.gz /app/results"
```

## 🛠️ **Troubleshooting**

### Common Issues

**1. Build Failures**
```bash
# Check build logs
fly logs --app external-attacker-mcp

# Force rebuild
fly deploy --no-cache
```

**2. Memory Issues**
```bash
# Increase memory
fly scale memory 4096

# Check current usage
fly metrics
```

**3. Tool Installation Issues**
```bash
# SSH into container to debug
fly ssh console

# Check tool availability
which nuclei subfinder httpx
```

**4. Network Connectivity**
```bash
# Test from container
fly ssh console -C "curl -I https://example.com"

# Check DNS resolution
fly ssh console -C "nslookup google.com"
```

### Debug Commands
```bash
# SSH into running container
fly ssh console

# Execute specific commands
fly ssh console -C "nuclei -version"

# View filesystem
fly ssh console -C "ls -la /app"

# Check running processes
fly ssh console -C "ps aux"
```

## 🎯 **Usage Examples**

### Test Your Deployed App
```bash
# 1. Basic health check
curl https://external-attacker-mcp.fly.dev/

# 2. API test
curl -X POST https://external-attacker-mcp.fly.dev/api/run \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{"tool": "httpx", "args": "-target example.com -silent"}'

# 3. MCP integration
# Use https://external-attacker-mcp.fly.dev as your MCP server URL
```

### Sample MCP Client Configuration
```json
{
  "mcpServers": {
    "external-attacker": {
      "command": "node",
      "args": ["path/to/mcp-client.js"],
      "env": {
        "MCP_SERVER_URL": "https://external-attacker-mcp.fly.dev"
      }
    }
  }
}
```

## 🎉 **Success!**

Your ExternalAttacker-MCP is now running on Fly.io! You have:

✅ **Cloud-hosted security testing platform**  
✅ **HTTPS-secured endpoints**  
✅ **Auto-scaling capabilities**  
✅ **Persistent storage for results**  
✅ **Professional-grade tools** (nuclei, sqlmap, etc.)  
✅ **API and MCP server access**  

Access your platform at: `https://your-app-name.fly.dev`

---

## 📞 **Support**

- **Fly.io Documentation**: https://fly.io/docs/
- **Fly.io Community**: https://community.fly.io/
- **Status Page**: https://status.fly.io/ 
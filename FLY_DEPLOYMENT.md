# 🚀 ExternalAttacker-MCP Fly.io Deployment Guide

This guide provides complete instructions for deploying ExternalAttacker-MCP to Fly.io with all security tool dependencies.

## 📋 Prerequisites

1. **Fly.io Account**: Sign up at [fly.io](https://fly.io)
2. **Fly CLI**: Install flyctl
   ```bash
   curl -L https://fly.io/install.sh | sh
   ```
3. **Authentication**: Log in to Fly.io
   ```bash
   flyctl auth login
   ```

## 🐳 Dockerfile Options

We provide three deployment options with different security tool sets:

### 1. Complete Build (`Dockerfile.complete`) - **Recommended for Full Features**
- **All 20+ security tools** including:
  - ProjectDiscovery suite (subfinder, httpx, naabu, nuclei, katana, dnsx, etc.)
  - Traditional tools (nmap, nikto, hydra, john, sqlmap, wfuzz)
  - Advanced tools (w3af, skipfish, ratproxy, metasploit installer)
- **Size**: ~2-3GB
- **Build time**: 15-20 minutes
- **Memory**: 4GB recommended

### 2. Standard Build (`Dockerfile`) - **Balanced Option**
- **Core security tools** (15+ tools)
- Includes ProjectDiscovery suite + essential tools
- **Size**: ~1-2GB  
- **Build time**: 10-15 minutes
- **Memory**: 2GB minimum

### 3. Light Build (`Dockerfile.light`) - **Fast & Minimal**
- **Essential tools only** (8 core tools)
- Fastest build and smallest size
- **Size**: ~500MB-1GB
- **Build time**: 5-10 minutes
- **Memory**: 2GB minimum

## 📦 Complete Dependency List

### Core Go-Based Tools (ProjectDiscovery Suite)
```
✅ subfinder    - Subdomain discovery
✅ httpx        - HTTP toolkit  
✅ naabu        - Port scanner
✅ nuclei       - Vulnerability scanner
✅ katana       - Web crawler
✅ dnsx         - DNS toolkit
✅ cdncheck     - CDN detection
✅ tlsx         - TLS data scanner
✅ dalfox       - XSS scanner
✅ ffuf         - Web fuzzer
✅ gobuster     - Directory/DNS bruter
✅ kiterunner   - API endpoint scanner
```

### System Security Tools
```
✅ sqlmap       - SQL injection tool
✅ nmap         - Network mapper
✅ nikto        - Web server scanner
✅ hydra        - Login brute-forcer
✅ john         - Password cracker
✅ wfuzz        - Web fuzzer
✅ trufflehog   - Secret scanner
✅ commix       - Command injection tool
```

### Advanced Tools (Complete Build Only)
```
✅ w3af         - Web application attack framework
✅ skipfish     - Web application security scanner
✅ ratproxy     - Web security audit tool
✅ metasploit   - Exploitation framework (installer)
✅ beef         - Browser exploitation framework
```

## 🚀 Quick Deployment

### Option 1: Automated Script (Recommended)
```bash
chmod +x deploy-to-fly.sh
./deploy-to-fly.sh
```

The script will:
1. Check prerequisites
2. Let you choose build option
3. Configure fly.toml automatically
4. Create the app and deploy
5. Set up persistent storage

### Option 2: Manual Deployment

1. **Choose your Dockerfile**:
   ```bash
   # For complete build
   cp Dockerfile.complete Dockerfile.deploy
   
   # For standard build  
   cp Dockerfile Dockerfile.deploy
   
   # For light build
   cp Dockerfile.light Dockerfile.deploy
   ```

2. **Update fly.toml**:
   ```toml
   app = 'your-app-name'
   primary_region = 'sjc'

   [build]
     dockerfile = 'Dockerfile.deploy'

   [env]
     FLASK_ENV = 'production'
     PYTHONUNBUFFERED = '1'

   [http_service]
     internal_port = 6991
     force_https = true

   [[vm]]
     cpu_kind = 'shared'
     cpus = 2
     memory_mb = 4096
   ```

3. **Deploy**:
   ```bash
   flyctl apps create your-app-name
   flyctl deploy
   ```

## 🔧 Configuration Details

### Environment Variables
- `PORT`: Automatically set by Fly.io (defaults to 6991)
- `FLASK_ENV`: Set to 'production'
- `PYTHONUNBUFFERED`: Set to '1' for proper logging

### Resource Requirements

| Build Type | CPU | Memory | Disk | Build Time |
|------------|-----|--------|------|------------|
| Complete   | 2   | 4GB    | 20GB | 15-20 min |
| Standard   | 2   | 2GB    | 15GB | 10-15 min |
| Light      | 1   | 2GB    | 10GB | 5-10 min  |

### Persistent Storage
- Volume: `scan_data` (10GB)
- Mount: `/app/scan_results`
- Purpose: Store scan results and temporary files

## 🌐 Access Your Deployment

After successful deployment, your app will be available at:
- **Web Interface**: `https://your-app-name.fly.dev/`
- **MCP Tools Endpoint**: `https://your-app-name.fly.dev/mcp/tools`
- **MCP Call Endpoint**: `https://your-app-name.fly.dev/mcp/call`

## 🔍 Health Checks & Monitoring

### Built-in Health Check
- Endpoint: `/`
- Interval: 30s
- Timeout: 10s
- Grace period: 15s

### Monitoring Commands
```bash
# View logs
flyctl logs -a your-app-name

# Check status
flyctl status -a your-app-name

# Scale resources
flyctl scale memory 4096 -a your-app-name
flyctl scale count 2 -a your-app-name

# Open dashboard
flyctl dashboard your-app-name
```

## 🛠️ Troubleshooting

### Common Issues

1. **Build Timeout**
   ```bash
   # Increase build timeout
   flyctl deploy --build-timeout 1800
   ```

2. **Out of Memory During Build**
   ```bash
   # Use light build or increase machine size
   flyctl scale memory 8192 -a your-app-name
   ```

3. **Tool Not Found**
   - Check which Dockerfile you're using
   - Some tools are only in the complete build
   - Verify tool installation in build logs

4. **Port Issues**
   - Fly.io automatically sets PORT environment variable
   - App listens on 0.0.0.0:$PORT (not 127.0.0.1)
   - Internal port should be 6991 in fly.toml

### Build Logs
```bash
# View build progress
flyctl logs -a your-app-name

# Follow logs in real-time
flyctl logs -a your-app-name -f
```

## 🔐 Security Considerations

1. **Tool Access**: All security tools run in isolated container
2. **Network**: Only HTTP/HTTPS traffic allowed through Fly.io
3. **Storage**: Scan results stored in persistent volume
4. **Updates**: Redeploy to update tools and dependencies

## 📊 Cost Optimization

### Recommended Settings
- **Development**: Light build, 1 CPU, 2GB RAM
- **Production**: Complete build, 2 CPU, 4GB RAM
- **High-load**: Scale horizontally with multiple instances

### Auto-scaling
```toml
[http_service]
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 0
```

## 🔄 Updates & Maintenance

### Update Deployment
```bash
# Pull latest changes
git pull

# Redeploy
flyctl deploy -a your-app-name
```

### Update Security Tools
Security tools are updated during each deployment build.

### Database/Volume Backup
```bash
# Create volume snapshot
flyctl volumes snapshots create vol_xyz -a your-app-name
```

## 📞 Support

- **Issues**: Check the GitHub repository
- **Fly.io Docs**: [fly.io/docs](https://fly.io/docs)
- **Community**: Fly.io community forum

---

## Quick Start Summary

1. Install flyctl and authenticate
2. Run `./deploy-to-fly.sh`
3. Choose build option (Complete recommended)
4. Wait 15-20 minutes for deployment
5. Access at `https://your-app-name.fly.dev`

Your complete security testing platform is now live on Fly.io! 🎉 
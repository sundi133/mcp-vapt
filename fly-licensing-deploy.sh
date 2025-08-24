#!/bin/bash

# 🚁 ExternalAttacker-MCP Fly.io Licensing Deployment
# Deploy with licensing to Fly.io cloud platform

set -e

echo "🚁 ExternalAttacker-MCP Fly.io Licensing Deployment"
echo "=================================================="

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if flyctl is installed
if ! command -v flyctl &> /dev/null; then
    print_error "flyctl is required but not installed"
    echo "Install from: https://fly.io/docs/flyctl/install/"
    exit 1
fi

# Check if logged in to fly.io
if ! flyctl auth whoami &> /dev/null; then
    print_error "Please log in to fly.io first"
    echo "Run: flyctl auth login"
    exit 1
fi

# Check required files
for file in "license_manager.py" "Dockerfile.complete" "fly.toml"; do
    if [[ ! -f "$file" ]]; then
        print_error "Required file missing: $file"
        exit 1
    fi
done

echo
print_step "Cloud Licensing Deployment Options"
echo "1. Trial License (Customer self-service)"
echo "2. Commercial License (Pre-configured)"
echo "3. No License (License activation required post-deployment)"
echo
read -p "Select deployment type (1-3): " DEPLOY_TYPE

# Get customer information for pre-configured licenses
if [[ "$DEPLOY_TYPE" == "1" ]] || [[ "$DEPLOY_TYPE" == "2" ]]; then
    echo
    print_step "Customer License Information"
    read -p "Customer email: " CUSTOMER_EMAIL
    read -p "Customer name/company: " CUSTOMER_NAME
    
    if [[ -z "$CUSTOMER_EMAIL" ]] || [[ -z "$CUSTOMER_NAME" ]]; then
        print_error "Customer email and name are required for pre-configured licensing"
        exit 1
    fi
fi

# Generate license locally for embedding
if [[ "$DEPLOY_TYPE" == "1" ]]; then
    print_step "Generating trial license for cloud deployment..."
    python3 license_manager.py generate-trial --email "$CUSTOMER_EMAIL" --name "$CUSTOMER_NAME"
    LICENSE_TYPE="trial"
elif [[ "$DEPLOY_TYPE" == "2" ]]; then
    print_step "Generating commercial license for cloud deployment..."
    python3 license_manager.py generate-commercial --email "$CUSTOMER_EMAIL" --name "$CUSTOMER_NAME"
    LICENSE_TYPE="commercial"
else
    LICENSE_TYPE="none"
fi

# Create fly.io specific environment variables
print_step "Configuring Fly.io environment..."

# Set environment variables for fly.io
if [[ "$DEPLOY_TYPE" != "3" ]]; then
    flyctl secrets set CUSTOMER_EMAIL="$CUSTOMER_EMAIL" 2>/dev/null || print_warning "Failed to set CUSTOMER_EMAIL secret"
    flyctl secrets set CUSTOMER_NAME="$CUSTOMER_NAME" 2>/dev/null || print_warning "Failed to set CUSTOMER_NAME secret"
    flyctl secrets set LICENSE_TYPE="$LICENSE_TYPE" 2>/dev/null || print_warning "Failed to set LICENSE_TYPE secret"
fi

flyctl secrets set FLASK_SECRET_KEY="$(openssl rand -hex 32)" 2>/dev/null || print_warning "Failed to set FLASK_SECRET_KEY"

# Update fly.toml for licensing
print_step "Updating fly.toml configuration..."

# Create backup of fly.toml
cp fly.toml fly.toml.backup

# Update fly.toml with licensing configuration
cat > fly.toml << EOF
app = "external-attacker-mcp"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile.complete"

[env]
  PORT = "8080"
  FLASK_ENV = "production"
  PYTHONUNBUFFERED = "1"
  FLASK_APP_URL = "http://127.0.0.1:6991"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 0
  processes = ["app"]

  [[http_service.checks]]
    method = "get"
    path = "/license/status"
    interval = 15000
    timeout = 10000
    grace_period = "5s"

[mounts]
  source = "license_data"
  destination = "/app/license_data"

[[vm]]
  cpu_kind = "shared"
  cpus = 2
  memory_mb = 4096

EOF

print_success "fly.toml updated with licensing configuration"

# Create cloud-specific license manager
print_step "Creating cloud license manager..."

cat > cloud_license_manager.py << 'EOF'
#!/usr/bin/env python3
"""
Cloud-specific license manager for Fly.io deployment
Handles cloud environment licensing considerations
"""

import os
import json
import hashlib
import platform
import socket
from license_manager import LicenseManager

class CloudLicenseManager(LicenseManager):
    def __init__(self):
        # Use persistent storage for license file
        self.license_file = "/app/license_data/license.key"
        self.config_file = "/app/license_data/license_config.json"
        
        # Ensure license directory exists
        os.makedirs("/app/license_data", exist_ok=True)
        
        # Initialize parent class
        super().__init__()
    
    def _get_hardware_fingerprint(self):
        """Generate cloud-specific hardware fingerprint"""
        # In cloud environments, use more stable identifiers
        cloud_info = {
            'fly_app': os.environ.get('FLY_APP_NAME', 'unknown'),
            'fly_region': os.environ.get('FLY_REGION', 'unknown'),
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'customer_email': os.environ.get('CUSTOMER_EMAIL', 'unknown')
        }
        
        fingerprint_str = json.dumps(cloud_info, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
    
    def activate_cloud_license(self):
        """Activate license in cloud environment using environment variables"""
        customer_email = os.environ.get('CUSTOMER_EMAIL')
        customer_name = os.environ.get('CUSTOMER_NAME')
        license_type = os.environ.get('LICENSE_TYPE', 'trial')
        
        if not customer_email or not customer_name:
            print("⚠️ No license environment variables found")
            return False
        
        print(f"🔐 Activating {license_type} license for {customer_name}")
        
        if license_type == 'trial':
            self.generate_trial_license(customer_email, customer_name)
        elif license_type == 'commercial':
            self.generate_commercial_license(customer_email, customer_name)
        else:
            print(f"❌ Unknown license type: {license_type}")
            return False
        
        print(f"✅ {license_type.title()} license activated successfully")
        return True

# Cloud license manager instance
cloud_license_manager = CloudLicenseManager()

if __name__ == "__main__":
    # Auto-activate license on cloud startup
    if os.environ.get('CUSTOMER_EMAIL'):
        cloud_license_manager.activate_cloud_license()
    else:
        print("⚠️ No license configuration found in environment")
EOF

# Update Dockerfile.complete for cloud licensing
print_step "Updating Dockerfile for cloud licensing..."

# Create cloud-specific startup script
cat > cloud_startup.py << 'EOF'
#!/usr/bin/env python3
"""
Cloud startup script for Fly.io with licensing
"""

import os
import sys
import time
import threading
from multiprocessing import Process

def activate_cloud_license():
    """Activate license using cloud environment variables"""
    try:
        from cloud_license_manager import cloud_license_manager
        
        # Check if license already exists
        validation = cloud_license_manager.validate_license()
        if validation['valid']:
            print(f"✅ Existing license valid ({validation['days_remaining']} days remaining)")
            return True
        
        # Try to activate using environment variables
        if os.environ.get('CUSTOMER_EMAIL'):
            return cloud_license_manager.activate_cloud_license()
        else:
            print("⚠️ No license configuration - will run in limited mode")
            return False
            
    except Exception as e:
        print(f"❌ License activation failed: {e}")
        return False

def start_flask_app():
    """Start the Flask application"""
    print("🚀 Starting Flask app...")
    os.environ['FLASK_APP_URL'] = 'http://127.0.0.1:6991'
    os.system("python3 ExternalAttacker-App.py")

def start_mcp_server():
    """Start the MCP server"""
    print("🔧 Starting MCP server...")
    time.sleep(5)  # Wait for Flask to start
    os.environ['PORT'] = '8000'
    os.system("python3 ExternalAttacker-MCP.py")

def main():
    """Main cloud startup function"""
    print("☁️ ExternalAttacker-MCP Cloud Startup (Fly.io)")
    print("=" * 50)
    
    # Activate license first
    license_activated = activate_cloud_license()
    if not license_activated:
        print("⚠️ Continuing without license - functionality will be limited")
    
    # Start services
    flask_process = Process(target=start_flask_app)
    flask_process.start()
    
    mcp_process = Process(target=start_mcp_server)
    mcp_process.start()
    
    try:
        flask_process.join()
        mcp_process.join()
    except KeyboardInterrupt:
        print("🛑 Shutting down services...")
        flask_process.terminate()
        mcp_process.terminate()
        flask_process.join()
        mcp_process.join()

if __name__ == "__main__":
    main()
EOF

# Update the Dockerfile to use cloud startup
print_step "Updating Dockerfile startup command..."

# Replace the startup command in Dockerfile.complete
sed -i.bak 's/exec python3 startup.py/exec python3 cloud_startup.py/' Dockerfile.complete

# Add cloud license files to Dockerfile
cat >> Dockerfile.complete << 'EOF'

# Add cloud licensing support
COPY cloud_license_manager.py /app/
COPY cloud_startup.py /app/

# Create persistent license directory
RUN mkdir -p /app/license_data

# Set cloud startup as entrypoint
EOF

# Update the startup script in Dockerfile
sed -i.bak 's/exec python3 startup.py/exec python3 cloud_startup.py/' Dockerfile.complete

print_success "Dockerfile updated for cloud licensing"

# Create Fly.io volume for license persistence
print_step "Creating persistent volume for license data..."
flyctl volumes create license_data --region iad --size 1 2>/dev/null || print_warning "Volume may already exist"

# Deploy to Fly.io
print_step "Deploying to Fly.io..."
flyctl deploy --dockerfile Dockerfile.complete

if [[ $? -eq 0 ]]; then
    print_success "🎉 Deployment successful!"
    
    # Get app URL
    APP_URL=$(flyctl info --json | jq -r '.Hostname' 2>/dev/null || echo "your-app.fly.dev")
    
    echo
    echo "📋 Deployment Summary:"
    echo "====================="
    echo "App URL: https://$APP_URL"
    echo "License API: https://$APP_URL/license/status"
    echo "MCP Endpoint: https://$APP_URL/mcp/sse"
    
    if [[ "$DEPLOY_TYPE" != "3" ]]; then
        echo "License Type: $LICENSE_TYPE"
        echo "Customer: $CUSTOMER_NAME ($CUSTOMER_EMAIL)"
    fi
    
    echo
    echo "🔧 Post-Deployment Commands:"
    echo "• Check logs: flyctl logs"
    echo "• Check license: curl https://$APP_URL/license/status"
    echo "• Scale app: flyctl scale count 2"
    
    if [[ "$DEPLOY_TYPE" == "3" ]]; then
        echo
        print_warning "License activation required:"
        echo "curl -X POST https://$APP_URL/license/activate \\"
        echo "  -H 'Content-Type: application/json' \\"
        echo "  -d '{\"email\":\"customer@company.com\",\"name\":\"Customer Name\"}'"
    fi
    
    # Test the deployment
    print_step "Testing deployment..."
    sleep 10
    
    if curl -s "https://$APP_URL/license/status" > /dev/null; then
        print_success "✅ License API is responding"
    else
        print_warning "⚠️ License API may still be starting up"
    fi
    
else
    print_error "❌ Deployment failed"
    echo "Check logs with: flyctl logs"
    exit 1
fi

# Cleanup
print_step "Cleaning up temporary files..."
rm -f cloud_license_manager.py cloud_startup.py
mv fly.toml.backup fly.toml

print_success "🎉 Fly.io licensing deployment complete!"
echo
echo "📞 Customer Access:"
echo "• Trial/Commercial users can immediately use the platform"
echo "• API access via: https://$APP_URL"
echo "• License management via web interface"
echo
echo "🔧 Management:"
echo "• Monitor: flyctl logs --app external-attacker-mcp"
echo "• Scale: flyctl scale count <num>"
echo "• Update: Re-run this script for updates" 
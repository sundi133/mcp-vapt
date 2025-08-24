#!/bin/bash

set -e

echo "🚀 ExternalAttacker-MCP Fly.io Deployment Script"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
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
    print_error "flyctl is not installed. Please install it first:"
    echo "curl -L https://fly.io/install.sh | sh"
    exit 1
fi

# Check if user is logged in
if ! flyctl auth whoami &> /dev/null; then
    print_warning "You are not logged in to Fly.io"
    print_status "Please log in first: flyctl auth login"
    exit 1
fi

# Ask user which Dockerfile to use
echo
echo "Choose deployment option:"
echo "1) Complete build (all security tools) - Dockerfile.complete"
echo "2) Standard build (most tools) - Dockerfile"
echo "3) Light build (essential tools only) - Dockerfile.light"
echo "4) Custom Dockerfile"
echo
read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        DOCKERFILE="Dockerfile.complete"
        APP_NAME="externalattacker-complete"
        print_status "Using complete build with all security tools"
        ;;
    2)
        DOCKERFILE="Dockerfile"
        APP_NAME="externalattacker-standard"
        print_status "Using standard build"
        ;;
    3)
        DOCKERFILE="Dockerfile.light"
        APP_NAME="externalattacker-light"
        print_status "Using light build with essential tools only"
        ;;
    4)
        read -p "Enter custom Dockerfile name: " DOCKERFILE
        read -p "Enter app name: " APP_NAME
        if [ ! -f "$DOCKERFILE" ]; then
            print_error "Dockerfile $DOCKERFILE not found!"
            exit 1
        fi
        ;;
    *)
        print_error "Invalid choice!"
        exit 1
        ;;
esac

# Update fly.toml with correct app name
print_status "Updating fly.toml configuration..."
cat > fly.toml << EOF
# fly.toml app configuration file for ExternalAttacker-MCP
# See https://fly.io/docs/reference/configuration/ for information about how to use this file.

app = '$APP_NAME'
primary_region = 'sjc'

[build]
  dockerfile = '$DOCKERFILE'

[env]
  FLASK_ENV = 'production'
  PYTHONUNBUFFERED = '1'

[http_service]
  internal_port = 6991
  force_https = true
  auto_stop_machines = false
  auto_start_machines = true
  min_machines_running = 1

  [[http_service.checks]]
    interval = '30s'
    timeout = '10s'
    grace_period = '15s'
    method = 'GET'
    path = '/'

[[vm]]
  cpu_kind = 'shared'
  cpus = 2
  memory_mb = 4096

# Increase disk space for security tools and scan results
[mounts]
  source = "scan_data"
  destination = "/app/scan_results"
  
[[statics]]
  guest_path = "/app/static"
  url_prefix = "/static/"
EOF

print_success "fly.toml updated for $APP_NAME using $DOCKERFILE"

# Check if app already exists
print_status "Checking if app $APP_NAME already exists..."
if flyctl apps list | grep -q "$APP_NAME"; then
    print_warning "App $APP_NAME already exists"
    read -p "Do you want to continue with deployment? (y/N): " continue_deploy
    if [[ ! $continue_deploy =~ ^[Yy]$ ]]; then
        print_status "Deployment cancelled"
        exit 0
    fi
else
    print_status "Creating new app: $APP_NAME"
    flyctl apps create "$APP_NAME" --org personal
fi

# Create volume for persistent data (if it doesn't exist)
print_status "Setting up persistent storage..."
if ! flyctl volumes list -a "$APP_NAME" | grep -q "scan_data"; then
    print_status "Creating volume for scan data..."
    flyctl volumes create scan_data --region sjc --size 10 -a "$APP_NAME"
else
    print_status "Volume scan_data already exists"
fi

# Deploy the application
print_status "Starting deployment to Fly.io..."
print_warning "This may take 10-20 minutes depending on the build option chosen"

flyctl deploy -a "$APP_NAME" --dockerfile "$DOCKERFILE" --strategy rolling

if [ $? -eq 0 ]; then
    print_success "Deployment completed successfully!"
    echo
    print_status "Your ExternalAttacker-MCP is now running at:"
    echo "https://$APP_NAME.fly.dev"
    echo
    print_status "Available endpoints:"
    echo "- Web Interface: https://$APP_NAME.fly.dev/"
    echo "- MCP Tools: https://$APP_NAME.fly.dev/mcp/tools"
    echo "- MCP Call: https://$APP_NAME.fly.dev/mcp/call"
    echo
    print_status "To view logs: flyctl logs -a $APP_NAME"
    print_status "To scale: flyctl scale count 2 -a $APP_NAME"
    print_status "To open dashboard: flyctl dashboard $APP_NAME"
else
    print_error "Deployment failed!"
    print_status "Check logs with: flyctl logs -a $APP_NAME"
    exit 1
fi 
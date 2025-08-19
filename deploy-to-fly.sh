#!/bin/bash

# ExternalAttacker-MCP - Fly.io Deployment Script
# This script automates the deployment process to Fly.io

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
if ! command -v fly &> /dev/null; then
    print_error "Fly CLI is not installed. Please install it first:"
    echo "curl -L https://fly.io/install.sh | sh"
    exit 1
fi

print_status "🚀 Starting ExternalAttacker-MCP deployment to Fly.io..."

# Check if user is logged in
if ! fly auth whoami &> /dev/null; then
    print_warning "Not logged in to Fly.io. Please authenticate:"
    fly auth login
fi

print_success "✅ Fly.io authentication verified"

# Generate secure API key if not provided
if [ -z "$API_KEY" ]; then
    API_KEY=$(openssl rand -base64 32)
    print_status "Generated secure API key"
fi

if [ -z "$FLASK_SECRET_KEY" ]; then
    FLASK_SECRET_KEY=$(openssl rand -base64 32)
    print_status "Generated Flask secret key"
fi

# Check if app already exists
APP_NAME=${1:-external-attacker-mcp}
print_status "App name: $APP_NAME"

if fly apps list | grep -q "$APP_NAME"; then
    print_warning "App $APP_NAME already exists. Deploying update..."
    EXISTING_APP=true
else
    print_status "Creating new app: $APP_NAME"
    EXISTING_APP=false
fi

# Deploy or create app
if [ "$EXISTING_APP" = false ]; then
    print_status "Launching new app..."
    fly launch --name "$APP_NAME" --region sjc --no-deploy
    
    print_status "Creating persistent volume for scan results..."
    fly volumes create scan_results --size 10 --region sjc --app "$APP_NAME"
else
    print_status "Deploying to existing app..."
fi

# Set secrets
print_status "Setting application secrets..."
fly secrets set --app "$APP_NAME" \
    API_KEY="$API_KEY" \
    FLASK_SECRET_KEY="$FLASK_SECRET_KEY" \
    FLASK_ENV="production"

print_success "✅ Secrets configured"

# Deploy the application
print_status "Deploying application... (this may take several minutes)"
fly deploy --app "$APP_NAME"

# Check deployment status
print_status "Checking deployment status..."
fly status --app "$APP_NAME"

# Get app URL
APP_URL=$(fly info --app "$APP_NAME" | grep "^Hostname" | awk '{print $2}')
FULL_URL="https://$APP_URL"

print_success "🎉 Deployment successful!"
echo ""
echo "📋 Deployment Summary:"
echo "======================"
echo "App Name: $APP_NAME"
echo "URL: $FULL_URL"
echo "API Key: $API_KEY"
echo ""
echo "🔧 Next Steps:"
echo "1. Test your deployment:"
echo "   curl $FULL_URL"
echo ""
echo "2. Test API endpoint:"
echo "   curl -X POST $FULL_URL/api/run \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -H 'X-API-Key: $API_KEY' \\"
echo "     -d '{\"tool\": \"httpx\", \"args\": \"-target example.com -silent\"}'"
echo ""
echo "3. MCP Server URL:"
echo "   $FULL_URL"
echo ""
echo "📊 Monitoring:"
echo "- View logs: fly logs --app $APP_NAME"
echo "- Check status: fly status --app $APP_NAME"
echo "- Scale resources: fly scale memory 4096 --app $APP_NAME"
echo ""
echo "🔐 Security:"
echo "- Your API key: $API_KEY"
echo "- Store this key securely!"
echo ""

# Optional: Test deployment
read -p "Would you like to test the deployment now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Testing deployment..."
    
    echo "Testing health check..."
    if curl -f -s "$FULL_URL" > /dev/null; then
        print_success "✅ Health check passed"
    else
        print_error "❌ Health check failed"
    fi
    
    echo "Testing API endpoint..."
    if curl -f -s -X POST "$FULL_URL/api/run" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d '{"tool": "httpx", "args": "-version"}' > /dev/null; then
        print_success "✅ API endpoint working"
    else
        print_warning "⚠️  API test inconclusive (may need time to fully start)"
    fi
fi

print_success "🚀 ExternalAttacker-MCP is now live on Fly.io!"
print_status "Access your security testing platform at: $FULL_URL" 
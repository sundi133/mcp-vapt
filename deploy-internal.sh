#!/bin/bash

# 🏢 ExternalAttacker-MCP Internal Deployment Script
# For High-Confidence NIST Compliance Assessment

set -e

echo "🚀 ExternalAttacker-MCP Internal Deployment"
echo "============================================="

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

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "Please do not run this script as root"
   exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_status "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    print_warning "Please log out and log back in for Docker permissions to take effect"
    print_warning "Then run this script again"
    exit 1
fi

# Get internal network information
print_status "Detecting internal networks..."
echo
echo "Available network interfaces:"
ip route show | grep -E "(10\.|172\.|192\.168\.)" | head -10

echo
read -p "Enter your internal network range (e.g., 192.168.1.0/24): " INTERNAL_NETWORK
if [[ -z "$INTERNAL_NETWORK" ]]; then
    print_error "Internal network range is required"
    exit 1
fi

# Build Docker image for internal deployment
print_status "Building ExternalAttacker-MCP for internal deployment..."
docker build -f Dockerfile.complete -t external-attacker-internal . --no-cache

# Create results directory
mkdir -p ./assessment-results
chmod 755 ./assessment-results

# Ask for deployment mode
echo
echo "Deployment Options:"
echo "1. Quick Test (Flask app only)"
echo "2. Full Internal Assessment (Flask + MCP server)"
echo "3. Cloud + Internal Hybrid"
echo
read -p "Select deployment mode (1-3): " DEPLOY_MODE

case $DEPLOY_MODE in
    1)
        print_status "Starting Quick Test deployment..."
        docker run -d \
          --name external-attacker-test \
          --network host \
          -v $(pwd)/assessment-results:/tmp/assessment-results \
          -e FLASK_APP_URL=http://127.0.0.1:6991 \
          -e INTERNAL_NETWORKS="$INTERNAL_NETWORK" \
          external-attacker-internal python3 ExternalAttacker-App.py
        
        print_success "Quick test deployment started!"
        print_status "Flask app running on: http://$(hostname -I | awk '{print $1}'):6991"
        ;;
    
    2)
        print_status "Starting Full Internal Assessment deployment..."
        docker run -d \
          --name external-attacker-internal \
          --network host \
          -v $(pwd)/assessment-results:/tmp/assessment-results \
          -e FLASK_APP_URL=http://127.0.0.1:6991 \
          -e INTERNAL_NETWORKS="$INTERNAL_NETWORK" \
          -e PORT=8000 \
          external-attacker-internal
        
        print_success "Full internal deployment started!"
        print_status "Flask app: http://$(hostname -I | awk '{print $1}'):6991"
        print_status "MCP server: http://$(hostname -I | awk '{print $1}'):8000"
        ;;
    
    3)
        print_status "Starting Hybrid deployment..."
        # Start local Flask for internal network access
        docker run -d \
          --name external-attacker-internal-flask \
          --network host \
          -v $(pwd)/assessment-results:/tmp/assessment-results \
          -e INTERNAL_NETWORKS="$INTERNAL_NETWORK" \
          external-attacker-internal python3 ExternalAttacker-App.py
        
        print_success "Hybrid deployment started!"
        print_status "Local Flask (internal): http://$(hostname -I | awk '{print $1}'):6991"
        print_warning "Configure your cloud MCP server to use: http://$(hostname -I | awk '{print $1}'):6991"
        ;;
    
    *)
        print_error "Invalid deployment mode selected"
        exit 1
        ;;
esac

# Wait for services to start
print_status "Waiting for services to start..."
sleep 5

# Test connectivity
print_status "Testing deployment..."
LOCAL_IP=$(hostname -I | awk '{print $1}')

if curl -s http://$LOCAL_IP:6991/ > /dev/null; then
    print_success "Flask app is running successfully"
else
    print_error "Flask app failed to start"
fi

if [[ $DEPLOY_MODE == "2" ]]; then
    if curl -s http://$LOCAL_IP:8000/ > /dev/null; then
        print_success "MCP server is running successfully"
    else
        print_warning "MCP server may still be starting..."
    fi
fi

# Network connectivity test
print_status "Testing internal network connectivity..."
if ping -c 1 $(echo $INTERNAL_NETWORK | cut -d'/' -f1 | sed 's/0$/1/') &> /dev/null; then
    print_success "Internal network is reachable"
else
    print_warning "Internal network may not be reachable from this host"
fi

echo
print_success "🎉 Internal deployment completed!"
echo
echo "📋 Deployment Summary:"
echo "====================="
echo "Network Range: $INTERNAL_NETWORK"
echo "Flask App: http://$LOCAL_IP:6991"
if [[ $DEPLOY_MODE == "2" ]]; then
    echo "MCP Server: http://$LOCAL_IP:8000"
fi
echo "Results: $(pwd)/assessment-results"
echo
echo "📖 Next Steps:"
echo "1. Configure Claude MCP to connect to: http://$LOCAL_IP:8000"
echo "2. Test with: run_internal_compliance_scan({target_network: \"$INTERNAL_NETWORK\"})"
echo "3. Review results in: $(pwd)/assessment-results"
echo
echo "🔧 Management Commands:"
echo "- View logs: docker logs external-attacker-internal"
echo "- Stop: docker stop external-attacker-internal"
echo "- Remove: docker rm external-attacker-internal"
echo

print_warning "Remember: For high-confidence assessments, ensure this server has:"
print_warning "- Network access to all internal VLANs"
print_warning "- Administrative credentials for target systems"
print_warning "- Firewall rules allowing assessment traffic" 
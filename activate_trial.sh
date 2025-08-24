#!/bin/bash

# 🚀 ExternalAttacker-MCP Trial License Activation
# Customer-Friendly 30-Day Trial Setup

clear
echo "🛡️  ExternalAttacker-MCP - Security Assessment & Compliance Platform"
echo "=================================================================="
echo
echo "🎉 Welcome to your 30-Day FREE Trial!"
echo

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
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required but not installed"
    echo "Please install Python 3 and try again"
    exit 1
fi

# Check if we're in the right directory
if [[ ! -f "license_manager.py" ]]; then
    print_error "license_manager.py not found"
    echo "Please run this script from the ExternalAttacker-MCP directory"
    exit 1
fi

print_step "Installing required dependencies..."
pip3 install -r requirements.txt --quiet || {
    print_warning "Attempting to install with user permissions..."
    pip3 install -r requirements.txt --user --quiet
}

echo
print_step "Trial License Activation"
echo "Enter your information to activate your 30-day free trial:"
echo

# Get customer information
while true; do
    read -p "📧 Your email address: " EMAIL
    if [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        print_error "Please enter a valid email address"
    fi
done

read -p "🏢 Your name/company: " NAME
if [[ -z "$NAME" ]]; then
    NAME="Trial User"
fi

read -p "🌍 Your organization type (optional): " ORG_TYPE

echo
print_step "Activating your trial license..."

# Activate the trial license
python3 license_manager.py activate --email "$EMAIL" --name "$NAME" 2>/dev/null

if [[ $? -eq 0 ]]; then
    echo
    print_success "🎉 Your 30-Day Trial License has been activated!"
    echo
    echo "📋 Trial License Details:"
    echo "========================"
    python3 license_manager.py info 2>/dev/null | grep -E "(Type|Customer|Email|Expires|Days remaining)"
    echo
    echo "🚀 What's included in your trial:"
    echo "• Full security assessment toolkit (50+ tools)"
    echo "• NIST 800-53 compliance assessment"
    echo "• Up to 50 targets per scan"
    echo "• Up to 5 concurrent scans"
    echo "• Stealth scanning capabilities"
    echo "• Advanced reporting"
    echo "• API access"
    echo
    echo "🔧 Getting Started:"
    echo "1. Start the Flask app: python3 ExternalAttacker-App.py"
    echo "2. Start the MCP server: python3 ExternalAttacker-MCP.py"
    echo "3. Access web interface: http://localhost:6991"
    echo
    echo "📚 Documentation:"
    echo "• Installation Guide: INSTALLATION.md"
    echo "• High-Confidence NIST: HIGH_CONFIDENCE_NIST_GUIDE.md"
    echo "• Internal Deployment: INTERNAL_DEPLOYMENT_GUIDE.md"
    echo
    echo "💬 Support:"
    echo "• Email: support@your-company.com"
    echo "• Documentation: https://your-docs-site.com"
    echo
    print_warning "Your trial will expire in 30 days. Contact sales for commercial licensing."
    
else
    print_error "Failed to activate trial license"
    echo "Please check your information and try again, or contact support"
    exit 1
fi

echo
read -p "🚀 Would you like to start the applications now? (y/n): " START_NOW

if [[ "$START_NOW" =~ ^[Yy] ]]; then
    echo
    print_step "Starting ExternalAttacker-MCP..."
    
    # Check if virtual environment exists
    if [[ -d ".venv" ]]; then
        print_warning "Activating virtual environment..."
        source .venv/bin/activate
    fi
    
    # Start in background
    echo "Starting Flask application..."
    python3 ExternalAttacker-App.py &
    FLASK_PID=$!
    
    sleep 3
    
    echo "Flask app started (PID: $FLASK_PID)"
    echo "Access the web interface at: http://localhost:6991"
    echo
    echo "🔧 To stop the application:"
    echo "kill $FLASK_PID"
    echo
    print_success "ExternalAttacker-MCP is now running!"
    echo "Your 30-day trial has started. Enjoy exploring our security assessment platform!"
fi

echo
echo "🎯 Next Steps:"
echo "• Run your first scan: http://localhost:6991"
echo "• Try internal compliance assessment with the new functions"
echo "• Review the documentation for advanced features"
echo
print_success "Thank you for trying ExternalAttacker-MCP!" 
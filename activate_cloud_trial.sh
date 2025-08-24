#!/bin/bash

# 🌐 Cloud Trial License Activation
# Customer self-service trial activation for cloud deployment

clear
echo "🌐 ExternalAttacker-MCP Cloud Trial Activation"
echo "============================================="
echo
echo "🎉 Activate your 30-Day FREE Trial on our cloud platform!"
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

# Get deployment URL
echo "Please provide your cloud deployment URL:"
read -p "🌐 URL (e.g., https://your-app.fly.dev): " APP_URL

# Remove trailing slash if present
APP_URL="${APP_URL%/}"

# Validate URL format
if [[ ! "$APP_URL" =~ ^https?:// ]]; then
    print_error "Please provide a valid URL starting with http:// or https://"
    exit 1
fi

echo
print_step "Checking deployment status..."

# Test if deployment is accessible
if ! curl -s "$APP_URL/license/status" > /dev/null; then
    print_error "Unable to connect to deployment at $APP_URL"
    echo "Please check:"
    echo "• URL is correct"
    echo "• Deployment is running"
    echo "• You have internet connectivity"
    exit 1
fi

print_success "Deployment is accessible"

# Check current license status
echo
print_step "Checking current license status..."
LICENSE_STATUS=$(curl -s "$APP_URL/license/status" | jq -r '.valid // "false"' 2>/dev/null || echo "false")

if [[ "$LICENSE_STATUS" == "true" ]]; then
    DAYS_REMAINING=$(curl -s "$APP_URL/license/status" | jq -r '.days_remaining // "unknown"' 2>/dev/null || echo "unknown")
    LICENSE_TYPE=$(curl -s "$APP_URL/license/status" | jq -r '.license_type // "unknown"' 2>/dev/null || echo "unknown")
    
    print_warning "License already active:"
    echo "• Type: $LICENSE_TYPE"
    echo "• Days remaining: $DAYS_REMAINING"
    echo
    read -p "Do you want to continue anyway? (y/n): " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Yy] ]]; then
        echo "Trial activation cancelled"
        exit 0
    fi
fi

echo
print_step "Trial License Activation"
echo "Enter your information to activate your 30-day free trial:"
echo

# Get customer information with validation
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
    print_error "Name/company is required"
    exit 1
fi

read -p "🌍 Organization type (optional): " ORG_TYPE

echo
print_step "Activating your trial license..."

# Activate trial via API
ACTIVATION_RESPONSE=$(curl -s -X POST "$APP_URL/license/activate" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"name\":\"$NAME\"}" 2>/dev/null)

# Check if activation was successful
if echo "$ACTIVATION_RESPONSE" | jq -r '.success' 2>/dev/null | grep -q "true"; then
    LICENSE_ID=$(echo "$ACTIVATION_RESPONSE" | jq -r '.license_id' 2>/dev/null)
    EXPIRES=$(echo "$ACTIVATION_RESPONSE" | jq -r '.expires' 2>/dev/null)
    
    echo
    print_success "🎉 Your 30-Day Trial License has been activated!"
    echo
    echo "📋 Trial License Details:"
    echo "========================"
    echo "• Customer: $NAME"
    echo "• Email: $EMAIL"
    echo "• License ID: $LICENSE_ID"
    echo "• Expires: $EXPIRES"
    echo "• Platform: $APP_URL"
    echo
    
    # Get updated license information
    echo "🚀 What's included in your trial:"
    LICENSE_INFO=$(curl -s "$APP_URL/license/status" 2>/dev/null)
    
    if [[ -n "$LICENSE_INFO" ]]; then
        MAX_TARGETS=$(echo "$LICENSE_INFO" | jq -r '.features.max_targets // "50"' 2>/dev/null)
        MAX_SCANS=$(echo "$LICENSE_INFO" | jq -r '.features.max_concurrent_scans // "5"' 2>/dev/null)
        
        echo "• Full security assessment toolkit (50+ tools)"
        echo "• NIST 800-53 compliance assessment"
        echo "• Up to $MAX_TARGETS targets per scan"
        echo "• Up to $MAX_SCANS concurrent scans"
        echo "• Stealth scanning capabilities"
        echo "• Advanced reporting"
        echo "• API access"
    fi
    
    echo
    echo "🔧 Getting Started:"
    echo "1. Access your platform: $APP_URL"
    echo "2. Start your first scan"
    echo "3. Try the compliance assessment features"
    echo
    echo "📚 Resources:"
    echo "• Documentation: $APP_URL/docs (if available)"
    echo "• License status: $APP_URL/license/status"
    echo "• Support: trial-support@your-company.com"
    echo
    print_warning "Your trial will expire in 30 days. Contact sales for commercial licensing."
    
else
    # Parse error message
    ERROR_MSG=$(echo "$ACTIVATION_RESPONSE" | jq -r '.error // "Unknown error"' 2>/dev/null || echo "Unknown error")
    
    print_error "Trial activation failed: $ERROR_MSG"
    echo
    echo "🔧 Troubleshooting:"
    echo "• Check your internet connection"
    echo "• Verify the deployment URL is correct"
    echo "• Contact support if the problem persists"
    echo "• Support email: trial-support@your-company.com"
    exit 1
fi

echo
print_step "Testing platform access..."

# Test a few key endpoints
sleep 2

if curl -s "$APP_URL/" > /dev/null; then
    print_success "✅ Web interface accessible"
else
    print_warning "⚠️ Web interface may still be starting"
fi

if curl -s "$APP_URL/license/features" > /dev/null; then
    print_success "✅ License API working"
else
    print_warning "⚠️ License API may still be initializing"
fi

echo
echo "🎯 Next Steps:"
echo "• Visit your platform: $APP_URL"
echo "• Run your first security scan"
echo "• Explore compliance assessment features"
echo "• Review documentation and tutorials"
echo
print_success "🎉 Welcome to ExternalAttacker-MCP! Your 30-day trial is now active."
echo
echo "💬 Need Help?"
echo "• Email: trial-support@your-company.com"
echo "• Documentation: Available in your platform"
echo "• License questions: Check $APP_URL/license/status" 
#!/bin/bash

# 🏠 Local License Setup and Run Guide
# Complete guide for setting up and running ExternalAttacker-MCP locally

clear
echo "🏠 ExternalAttacker-MCP Local Setup with Licensing"
echo "================================================="
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

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if virtual environment exists
print_step "Checking virtual environment..."
if [[ ! -d ".venv" ]]; then
    print_error "Virtual environment not found. Please create it first:"
    echo "python3 -m venv .venv"
    echo "source .venv/bin/activate"
    echo "pip install -r requirements.txt"
    exit 1
fi

print_success "Virtual environment found"

# Activate virtual environment
source .venv/bin/activate

# Check if license_manager.py exists
print_step "Checking license manager..."
if [[ ! -f "license_manager.py" ]]; then
    print_error "license_manager.py not found!"
    exit 1
fi

print_success "License manager found"

# Check current license status
print_step "Checking current license status..."
if python3 license_manager.py validate > /dev/null 2>&1; then
    LICENSE_INFO=$(python3 license_manager.py info 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        print_success "License already exists and is valid!"
        echo "Current license details:"
        echo "$LICENSE_INFO"
        echo
        read -p "Do you want to create a new license anyway? (y/n): " CREATE_NEW
        if [[ ! "$CREATE_NEW" =~ ^[Yy] ]]; then
            print_info "Using existing license"
            SKIP_LICENSE=true
        fi
    fi
fi

# Create license if needed
if [[ "$SKIP_LICENSE" != "true" ]]; then
    echo
    print_step "License Creation Options"
    echo "1. Trial License (30 days) - Free"
    echo "2. Commercial License (1 year) - Full features"
    echo "3. Interactive activation"
    echo
    read -p "Select option (1-3): " LICENSE_OPTION
    
    case $LICENSE_OPTION in
        1)
            print_step "Creating trial license..."
            read -p "Enter your email: " EMAIL
            read -p "Enter your name/company: " NAME
            python3 license_manager.py generate-trial --email "$EMAIL" --name "$NAME"
            ;;
        2)
            print_step "Creating commercial license..."
            read -p "Enter your email: " EMAIL
            read -p "Enter your name/company: " NAME
            python3 license_manager.py generate-commercial --email "$EMAIL" --name "$NAME"
            ;;
        3)
            print_step "Starting interactive activation..."
            python3 license_manager.py activate
            ;;
        *)
            print_error "Invalid option selected"
            exit 1
            ;;
    esac
    
    # Verify license creation
    if python3 license_manager.py validate > /dev/null 2>&1; then
        print_success "License created successfully!"
    else
        print_error "License creation failed"
        exit 1
    fi
fi

# Show license information
echo
print_step "License Information"
python3 license_manager.py info

echo
print_step "Starting Services"
echo "Choose how to run the system:"
echo "1. Run both Flask App and MCP Server (recommended)"
echo "2. Run only Flask App (for testing)"
echo "3. Run only MCP Server (for Claude integration)"
echo "4. Show manual commands"
echo

read -p "Select option (1-4): " RUN_OPTION

case $RUN_OPTION in
    1)
        print_info "Starting both services..."
        echo
        echo "🌐 Flask App will run on: http://localhost:6991"
        echo "🔧 MCP Server will be available for Claude"
        echo
        echo "Press Ctrl+C to stop both services"
        echo
        sleep 2
        
        # Check if startup.py exists
        if [[ -f "startup.py" ]]; then
            python3 startup.py
        else
            print_error "startup.py not found. Starting services manually..."
            echo "Please run these commands in separate terminals:"
            echo "Terminal 1: python3 ExternalAttacker-App.py"
            echo "Terminal 2: python3 ExternalAttacker-MCP.py"
        fi
        ;;
    2)
        print_info "Starting Flask App only..."
        echo "🌐 Access at: http://localhost:6991"
        echo "📊 License status: http://localhost:6991/license/status"
        python3 ExternalAttacker-App.py
        ;;
    3)
        print_info "Starting MCP Server only..."
        echo "🔧 MCP Server ready for Claude integration"
        python3 ExternalAttacker-MCP.py
        ;;
    4)
        echo
        print_info "Manual Commands:"
        echo "================"
        echo
        echo "🔐 License Management:"
        echo "• Check status: python3 license_manager.py info"
        echo "• Validate: python3 license_manager.py validate"
        echo "• Create trial: python3 license_manager.py generate-trial --email 'your@email.com' --name 'Your Name'"
        echo
        echo "🚀 Start Services:"
        echo "• Flask App: python3 ExternalAttacker-App.py"
        echo "• MCP Server: python3 ExternalAttacker-MCP.py"
        echo "• Both services: python3 startup.py"
        echo
        echo "🌐 URLs:"
        echo "• Web Interface: http://localhost:6991"
        echo "• License API: http://localhost:6991/license/status"
        echo "• License Features: http://localhost:6991/license/features"
        echo
        echo "🔧 Testing:"
        echo "• curl http://localhost:6991/license/status"
        echo "• curl http://localhost:6991/license/features"
        ;;
    *)
        print_error "Invalid option selected"
        exit 1
        ;;
esac

print_success "Setup complete!" 
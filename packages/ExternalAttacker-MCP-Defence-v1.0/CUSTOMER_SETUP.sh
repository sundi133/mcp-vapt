#!/bin/bash

# 🎯 defence - ExternalAttacker-MCP Setup
# Customer: test@defence.com
# Package Version: 1.0

clear
echo "🎯 Welcome defence!"
echo "ExternalAttacker-MCP Security Assessment Platform"
echo "================================================="
echo

echo "📧 Licensed to: test@defence.com"
echo "📦 Package version: 1.0"
echo

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    echo "Please install Python 3.8+ and try again"
    exit 1
fi

# Install dependencies and security tools
echo "📥 Installing dependencies and security tools..."
if [[ -f "install.sh" ]]; then
    chmod +x install.sh
    echo "Running comprehensive installation (this may take a few minutes)..."
    ./install.sh
else
    echo "Install script not found, installing Python dependencies only..."
    python3 -m pip install -r requirements.txt
fi

# Activate trial license
echo
echo "🔐 Activating your 30-day trial license..."
if [[ -f "activate_trial.sh" ]]; then
    chmod +x activate_trial.sh
    ./activate_trial.sh
else
    echo "⚠️ Manual license activation required"
    echo "Run: python3 license_manager.py activate"
fi

echo
echo "🚀 Setup complete! Your security platform is ready."
echo
echo "🎯 Next steps:"
echo "1. Start the platform: python3 startup.py"
echo "2. Access web interface: http://localhost:6991"
echo "3. Check license status: python3 license_manager.py info"
echo
echo "📞 Support: your-support@company.com"
echo "📚 Documentation: See LICENSING_GUIDE.md"

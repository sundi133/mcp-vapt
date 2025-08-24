#!/bin/bash

# 📦 Customer Package Builder
# Creates distribution packages for different customer types

clear
echo "📦 ExternalAttacker-MCP Customer Package Builder"
echo "================================================"

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

# Package types
echo "📦 Select Customer Package Type:"
echo "1. Trial Package (Basic - Self-Service)"
echo "2. Enterprise Package (Full - Internal Deployment)"
echo "3. Cloud Package (SaaS - Vendor Managed)"
echo "4. Developer Package (Complete - For Integration)"
echo

read -p "Select package type (1-4): " PACKAGE_TYPE

# Get customer information
echo
print_step "Customer Information"
read -p "Customer name/company: " CUSTOMER_NAME
read -p "Customer email: " CUSTOMER_EMAIL
read -p "Package version (default: 1.0): " PACKAGE_VERSION
PACKAGE_VERSION=${PACKAGE_VERSION:-1.0}

# Create package directory
PACKAGE_NAME="ExternalAttacker-MCP-${CUSTOMER_NAME// /-}-v${PACKAGE_VERSION}"
PACKAGE_DIR="packages/${PACKAGE_NAME}"

print_step "Creating package directory: $PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# Core files (always included)
CORE_FILES=(
    "ExternalAttacker-MCP.py"
    "ExternalAttacker-App.py"
    "license_manager.py"
    "requirements.txt"
    "startup.py"
    "install.sh"
)

# Documentation files
DOC_FILES=(
    "README.md"
    "LICENSING_GUIDE.md"
)

# Template files
TEMPLATE_FILES=(
    "templates/base.html"
    "templates/index.html"
    "templates/result.html"
)

# Copy core files
print_step "Copying core application files..."
for file in "${CORE_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        cp "$file" "$PACKAGE_DIR/"
        echo "  ✅ $file"
    else
        print_error "Missing core file: $file"
    fi
done

# Copy documentation
print_step "Copying documentation..."
for file in "${DOC_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        cp "$file" "$PACKAGE_DIR/"
        echo "  ✅ $file"
    fi
done

# Copy templates
print_step "Copying web templates..."
mkdir -p "$PACKAGE_DIR/templates"
for file in "${TEMPLATE_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        cp "$file" "$PACKAGE_DIR/templates/"
        echo "  ✅ $file"
    fi
done

# Package-specific files
case $PACKAGE_TYPE in
    1) # Trial Package
        print_step "Adding trial-specific files..."
        TRIAL_FILES=(
            "activate_trial.sh"
            "setup_local_license.sh"
        )
        for file in "${TRIAL_FILES[@]}"; do
            if [[ -f "$file" ]]; then
                cp "$file" "$PACKAGE_DIR/"
                echo "  ✅ $file"
            fi
        done
        ;;
    
    2) # Enterprise Package
        print_step "Adding enterprise-specific files..."
        ENTERPRISE_FILES=(
            "deploy-internal.sh"
            "INTERNAL_DEPLOYMENT_GUIDE.md"
            "HIGH_CONFIDENCE_NIST_GUIDE.md"
            "internal_compliance_config.py"
            "install.sh"
            "activate_trial.sh"
            "setup_local_license.sh"
        )
        for file in "${ENTERPRISE_FILES[@]}"; do
            if [[ -f "$file" ]]; then
                cp "$file" "$PACKAGE_DIR/"
                echo "  ✅ $file"
            fi
        done
        ;;
    
    3) # Cloud Package
        print_step "Adding cloud deployment files..."
        CLOUD_FILES=(
            "fly-licensing-deploy.sh"
            "fly-license.toml"
            "FLY_LICENSING_GUIDE.md"
            "activate_cloud_trial.sh"
            "Dockerfile.complete"
        )
        for file in "${CLOUD_FILES[@]}"; do
            if [[ -f "$file" ]]; then
                cp "$file" "$PACKAGE_DIR/"
                echo "  ✅ $file"
            fi
        done
        ;;
    
    4) # Developer Package
        print_step "Adding all files for developers..."
        # Copy everything except sensitive files
        rsync -av --exclude='.git' --exclude='__pycache__' --exclude='.venv' \
              --exclude='*.pyc' --exclude='license.key' --exclude='packages' \
              ./ "$PACKAGE_DIR/"
        ;;
esac

# Create customer-specific activation script
print_step "Creating customer activation script..."
cat > "$PACKAGE_DIR/CUSTOMER_SETUP.sh" << EOF
#!/bin/bash

# 🎯 ${CUSTOMER_NAME} - ExternalAttacker-MCP Setup
# Customer: ${CUSTOMER_EMAIL}
# Package Version: ${PACKAGE_VERSION}

clear
echo "🎯 Welcome ${CUSTOMER_NAME}!"
echo "ExternalAttacker-MCP Security Assessment Platform"
echo "================================================="
echo

echo "📧 Licensed to: ${CUSTOMER_EMAIL}"
echo "📦 Package version: ${PACKAGE_VERSION}"
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
EOF

chmod +x "$PACKAGE_DIR/CUSTOMER_SETUP.sh"

# Create customer README
print_step "Creating customer README..."
cat > "$PACKAGE_DIR/CUSTOMER_README.md" << EOF
# 🎯 ${CUSTOMER_NAME} - Security Assessment Platform

Welcome to your ExternalAttacker-MCP security assessment platform!

## 📋 Package Information
- **Customer**: ${CUSTOMER_NAME}
- **Email**: ${CUSTOMER_EMAIL}
- **Version**: ${PACKAGE_VERSION}
- **License**: 30-Day Trial (upgradeable)

## 🚀 Quick Start

### 1. Setup (One-Time)
\`\`\`bash
# Run the automated setup script (installs tools + activates license)
./CUSTOMER_SETUP.sh

# Or manual setup:
# 1. Install security tools: ./install.sh
# 2. Activate license: ./activate_trial.sh
\`\`\`

### 2. Start Platform
\`\`\`bash
# Start both services
python3 startup.py

# Or start individually:
# Terminal 1: python3 ExternalAttacker-App.py
# Terminal 2: python3 ExternalAttacker-MCP.py
\`\`\`

### 3. Access Platform
- **Web Interface**: http://localhost:6991
- **License Status**: http://localhost:6991/license/status

## 📚 Documentation
- **Licensing Guide**: LICENSING_GUIDE.md
- **Installation Guide**: INSTALLATION.md (if included)
- **Deployment Guide**: INTERNAL_DEPLOYMENT_GUIDE.md (enterprise only)

## 🔐 License Management
\`\`\`bash
# Check license status
python3 license_manager.py info

# Validate license
python3 license_manager.py validate

# Activate trial (if needed)
python3 license_manager.py activate
\`\`\`

## 🛠️ Features Included
- **50+ Security Assessment Tools**: Comprehensive penetration testing toolkit
- **NIST 800-53 Compliance Assessment**: Automated compliance validation
- **Stealth Scanning Capabilities**: Evade detection with advanced techniques
- **Advanced Reporting**: Professional documentation and evidence collection
- **API Access**: Full REST API and MCP integration

## 🔧 Installation Details
The \`install.sh\` script automatically installs:
- **Go-based tools**: subfinder, nuclei, httpx, naabu, ffuf, gobuster
- **Network tools**: nmap, masscan, nikto, hydra, john
- **Web security**: w3af, skipfish, sqlmap, dalfox, ratproxy
- **Exploitation**: metasploit, commix, beef framework
- **Compliance**: GovReady-Q platform for NIST/FedRAMP
- **System setup**: PATH configuration, template updates

## 📞 Support
- **Email**: your-support@company.com
- **Documentation**: Available in package
- **Trial Period**: 30 days from activation

## 💰 Upgrade to Commercial
Contact sales for commercial licensing with:
- Extended limits
- Priority support
- Additional features
- Annual licensing

---
**Package ID**: ${PACKAGE_NAME}
**Generated**: $(date)
EOF

# Create package archive
print_step "Creating package archive..."
cd packages
tar -czf "${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
zip -r "${PACKAGE_NAME}.zip" "${PACKAGE_NAME}" > /dev/null 2>&1
cd ..

# Package summary
echo
print_success "📦 Customer package created successfully!"
echo
echo "📋 Package Summary:"
echo "==================="
echo "• Customer: ${CUSTOMER_NAME}"
echo "• Email: ${CUSTOMER_EMAIL}"
echo "• Package: ${PACKAGE_NAME}"
echo "• Type: $(case $PACKAGE_TYPE in 1) echo "Trial";; 2) echo "Enterprise";; 3) echo "Cloud";; 4) echo "Developer";; esac)"
echo "• Files: $(find "$PACKAGE_DIR" -type f | wc -l | tr -d ' ') files"
echo "• Size: $(du -sh "$PACKAGE_DIR" | cut -f1)"
echo

echo "📁 Package Location:"
echo "• Directory: $PACKAGE_DIR"
echo "• Archive: packages/${PACKAGE_NAME}.tar.gz"
echo "• ZIP file: packages/${PACKAGE_NAME}.zip"
echo

echo "📤 Distribution Options:"
echo "• Send archive: packages/${PACKAGE_NAME}.tar.gz"
echo "• Send ZIP: packages/${PACKAGE_NAME}.zip"
echo "• Upload to cloud storage"
echo "• Create git repository"
echo

echo "🎯 Customer Instructions:"
echo "1. Extract package: tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "2. Enter directory: cd ${PACKAGE_NAME}"
echo "3. Run setup: ./CUSTOMER_SETUP.sh"
echo "4. Start platform: python3 startup.py"

print_success "Package ready for distribution! 🎉" 
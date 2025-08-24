#!/bin/bash

# ExternalAttacker-MCP Installation Script
# This script installs all required security tools and dependencies

set -e  # Exit on any error

echo "🚀 ExternalAttacker-MCP Installation Script"
echo "============================================"

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

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

print_status "Detected OS: $OS"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Go if not present
install_go() {
    if command_exists go; then
        print_success "Go is already installed"
        return
    fi
    
    print_status "Installing Go..."
    if [[ "$OS" == "macos" ]]; then
        if command_exists brew; then
            brew install go
        else
            print_error "Please install Homebrew first: https://brew.sh/"
            exit 1
        fi
    else
        # Linux installation
        GO_VERSION="1.21.3"
        wget -q "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
        rm "go${GO_VERSION}.linux-amd64.tar.gz"
    fi
    print_success "Go installed successfully"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Check if pip exists
    if ! command_exists pip3 && ! command_exists pip; then
        print_error "pip is not installed. Please install Python and pip first."
        exit 1
    fi
    
    # Use pip3 if available, otherwise pip
    PIP_CMD="pip3"
    if ! command_exists pip3; then
        PIP_CMD="pip"
    fi
    
    # Install requirements
    $PIP_CMD install -r requirements.txt
    print_success "Python dependencies installed"
}

# Install security tools
install_security_tools() {
    print_status "Installing security tools..."
    
    # Create tools directory
    mkdir -p ~/tools
    cd ~/tools
    
    # Install Go-based tools
    print_status "Installing Go-based security tools..."
    
    # Recon tools
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
    go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
    
    # Vulnerability scanners
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/hahwul/dalfox/v2@latest
    go install -v github.com/ffuf/ffuf/v2@latest
    go install -v github.com/OJ/gobuster/v3@latest
    
    # API tools
    go install github.com/assetnote/kiterunner@latest
    
    print_success "Go-based tools installed"
    
    # Install other tools
    print_status "Installing additional security tools..."
    
    # Install sqlmap
    if ! command_exists sqlmap; then
        if [[ "$OS" == "macos" ]]; then
            brew install sqlmap
        else
            sudo apt-get update && sudo apt-get install -y sqlmap
        fi
    fi
    
    # Install trufflehog
    if ! command_exists trufflehog; then
        if [[ "$OS" == "macos" ]]; then
            brew install trufflehog
        else
            curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
        fi
    fi
    
    # Install Commix (Command Injection Exploiter)
    if ! command_exists commix; then
        print_status "Installing Commix..."
        if [[ "$OS" == "macos" ]]; then
            brew install commix
        else
            # Install from source on Linux
            cd ~/tools
            git clone https://github.com/commixproject/commix.git
            cd commix
            sudo python3 setup.py install
            sudo ln -sf $(pwd)/commix.py /usr/local/bin/commix
        fi
    fi
    
    # Install BeEF (Browser Exploitation Framework)
    if ! command_exists beef; then
        print_status "Installing BeEF Framework..."
        if [[ "$OS" == "macos" ]]; then
            # Install Ruby and dependencies
            brew install ruby
            gem install bundler
            
            # Clone and setup BeEF
            cd ~/tools
            git clone https://github.com/beefproject/beef
            cd beef
            bundle install
            echo 'alias beef="cd ~/tools/beef && ./beef"' >> ~/.zshrc
        else
            # Linux installation
            sudo apt-get update
            sudo apt-get install -y curl git ruby-full build-essential zlib1g-dev liblzma-dev
            
            # Install RVM and Ruby
            curl -sSL https://get.rvm.io | bash -s stable
            source ~/.rvm/scripts/rvm
            rvm install 3.0.0
            rvm use 3.0.0 --default
            gem install bundler
            
            # Clone and setup BeEF
            cd ~/tools
            git clone https://github.com/beefproject/beef
            cd beef
            bundle install
            echo 'alias beef="cd ~/tools/beef && ./beef"' >> ~/.bashrc
        fi
    fi
    
    # Install OWASP ZAP
    if [[ "$OS" == "macos" ]]; then
        if ! command_exists zap-baseline.py; then
            print_status "Installing OWASP ZAP..."
            brew install --cask owasp-zap
            # Add ZAP scripts to PATH
            echo 'export PATH=$PATH:/Applications/OWASP\ ZAP.app/Contents/Java' >> ~/.zshrc
        fi
    else
        if ! command_exists zap-baseline.py; then
            print_status "Installing OWASP ZAP..."
            wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh
            chmod +x ZAP_2_14_0_unix.sh
            sudo ./ZAP_2_14_0_unix.sh -q
            rm ZAP_2_14_0_unix.sh
        fi
    fi
    
    print_success "Additional tools installed"
    
    # Install network and web security tools
    print_status "Installing network and web security tools..."
    
    # Install Nmap
    if ! command_exists nmap; then
        print_status "Installing Nmap..."
        if [[ "$OS" == "macos" ]]; then
            brew install nmap
        else
            sudo apt-get update && sudo apt-get install -y nmap
        fi
    fi
    
    # Install Nikto
    if ! command_exists nikto; then
        print_status "Installing Nikto..."
        if [[ "$OS" == "macos" ]]; then
            brew install nikto
        else
            sudo apt-get install -y nikto
        fi
    fi
    
    # Install Hydra
    if ! command_exists hydra; then
        print_status "Installing Hydra..."
        if [[ "$OS" == "macos" ]]; then
            brew install hydra
        else
            sudo apt-get install -y hydra
        fi
    fi
    
    # Install John the Ripper
    if ! command_exists john; then
        print_status "Installing John the Ripper..."
        if [[ "$OS" == "macos" ]]; then
            brew install john
        else
            sudo apt-get install -y john
        fi
    fi
    
    # Install Wfuzz
    if ! command_exists wfuzz; then
        print_status "Installing Wfuzz..."
        if [[ "$OS" == "macos" ]]; then
            brew install wfuzz
        else
            pip3 install wfuzz
        fi
    fi
    
    # Install W3AF
    if ! command_exists w3af_console; then
        print_status "Installing W3AF..."
        if [[ "$OS" == "macos" ]]; then
            print_warning "W3AF installation on macOS requires manual setup:"
            print_warning "1. Visit: https://github.com/andresriancho/w3af"
            print_warning "2. Follow macOS installation instructions"
        else
            # Install dependencies
            sudo apt-get install -y git python3-pip python3-setuptools
            cd ~/tools
            git clone --depth 1 https://github.com/andresriancho/w3af.git
            cd w3af
            ./w3af_dependency_install.sh
            sudo ln -sf $(pwd)/w3af_console /usr/local/bin/w3af_console
            sudo ln -sf $(pwd)/w3af_gui /usr/local/bin/w3af_gui
        fi
    fi
    
    # Install Skipfish
    if ! command_exists skipfish; then
        print_status "Installing Skipfish..."
        if [[ "$OS" == "macos" ]]; then
            brew install skipfish
        else
            sudo apt-get install -y skipfish
        fi
    fi
    
    # Install Ratproxy
    if ! command_exists ratproxy; then
        print_status "Installing Ratproxy..."
        cd ~/tools
        if [[ "$OS" == "macos" ]]; then
            # Compile from source on macOS
            git clone https://github.com/spinkham/ratproxy.git
            cd ratproxy
            make
            sudo cp ratproxy /usr/local/bin/
        else
            # Compile from source on Linux
            git clone https://github.com/spinkham/ratproxy.git
            cd ratproxy
            make
            sudo cp ratproxy /usr/local/bin/
        fi
    fi
    
    # Install Watcher (if available)
    if ! command_exists watcher; then
        print_status "Installing Watcher..."
        print_warning "Watcher installation requires manual setup:"
        print_warning "Visit: https://github.com/felix-schwarz/watcher for installation instructions"
    fi
    
    # Install Metasploit Framework
    if ! command_exists msfconsole; then
        print_status "Installing Metasploit Framework..."
        if [[ "$OS" == "macos" ]]; then
            # Install via curl installer
            curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
            chmod 755 msfinstall
            ./msfinstall
            rm msfinstall
        else
            # Install on Linux
            curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
            chmod 755 msfinstall
            sudo ./msfinstall
            rm msfinstall
        fi
    fi
    
    # Install GovReady-Q Compliance Platform
    if ! test -f ~/tools/govready-q/manage.py; then
        print_status "Installing GovReady-Q Compliance Platform..."
        
        # Install system dependencies
        if [[ "$OS" == "macos" ]]; then
            brew install postgresql libpq || print_warning "PostgreSQL installation failed - may need manual setup"
        else
            sudo apt-get update
            sudo apt-get install -y postgresql-client libpq-dev python3-dev || print_warning "PostgreSQL dependencies installation failed"
        fi
        
        # Clone and install GovReady-Q
        mkdir -p ~/tools
        cd ~/tools
        git clone --depth 1 https://github.com/GovReady/govready-q.git || print_error "Failed to clone GovReady-Q repository"
        
        if [[ -d "govready-q" ]]; then
            cd govready-q
            
            # Install Python dependencies
            pip3 install --user -r requirements.txt || print_warning "Some Python dependencies may have failed to install"
            
            # Basic setup (skip database migration for now)
            mkdir -p local-examples
            python3 manage.py collectstatic --noinput --clear || print_warning "Static files collection failed"
            
            # Create symlink for easy access
            if command -v sudo >/dev/null 2>&1; then
                sudo ln -sf $(pwd)/manage.py /usr/local/bin/govready-q || print_warning "Failed to create govready-q symlink"
            else
                ln -sf $(pwd)/manage.py /usr/local/bin/govready-q || print_warning "Failed to create govready-q symlink"
            fi
            
            print_success "GovReady-Q compliance platform installed"
            print_status "Note: Full configuration requires database setup - see documentation"
        else
            print_error "GovReady-Q installation failed"
        fi
    else
        print_success "GovReady-Q already installed"
    fi
    
    print_success "Network and web security tools installed"
    
    # Commercial/Enterprise tools notes
    print_warning "Commercial Tool Installation Notes:"
    print_warning ""
    print_warning "Burp Suite Professional:"
    print_warning "1. Download from: https://portswigger.net/burp/pro"
    print_warning "2. Install to /opt/burpsuite_pro/"
    print_warning "3. Update path in ExternalAttacker-MCP functions"
    print_warning ""
    
    # Nessus installation note
    print_warning "Nessus Installation Required:"
    print_warning "Nessus is a commercial scanner that requires separate installation:"
    print_warning "1. Download from: https://www.tenable.com/downloads/nessus"
    print_warning "2. Follow platform-specific installation instructions"
    print_warning "3. Create an API access key and secret key"
    print_warning "4. Configure the MCP functions with your Nessus credentials"
}

# Add Go bin to PATH
setup_path() {
    print_status "Setting up PATH..."
    
    # Add Go bin to PATH
    GO_BIN_PATH="$HOME/go/bin"
    
    # Determine shell config file
    if [[ "$SHELL" == *"zsh"* ]]; then
        SHELL_CONFIG="$HOME/.zshrc"
    else
        SHELL_CONFIG="$HOME/.bashrc"
    fi
    
    # Check if already in PATH
    if [[ ":$PATH:" != *":$GO_BIN_PATH:"* ]]; then
        echo "export PATH=\$PATH:$GO_BIN_PATH" >> "$SHELL_CONFIG"
        export PATH="$PATH:$GO_BIN_PATH"
        print_success "Added $GO_BIN_PATH to PATH"
    fi
    
    print_warning "Please restart your terminal or run: source $SHELL_CONFIG"
}

# Update nuclei templates
update_nuclei_templates() {
    print_status "Updating Nuclei templates..."
    if command_exists nuclei; then
        nuclei -update-templates -silent
        print_success "Nuclei templates updated"
    fi
}

# Verify installations
verify_installations() {
    print_status "Verifying tool installations..."
    
    tools=(
        "subfinder"
        "httpx" 
        "naabu"
        "katana"
        "dnsx"
        "cdncheck"
        "tlsx"
        "nuclei"
        "dalfox"
        "ffuf"
        "gobuster"
        "kiterunner"
        "sqlmap"
        "trufflehog"
        "commix"
        "nmap"
        "nikto"
        "hydra"
        "john"
        "wfuzz"
        "w3af_console"
        "skipfish"
        "ratproxy"
        "msfconsole"
        "govready-q"
    )
    
    missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            print_success "$tool ✓"
        else
            print_error "$tool ✗"
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -eq 0 ]]; then
        print_success "All tools installed successfully!"
    else
        print_warning "Missing tools: ${missing_tools[*]}"
        print_warning "You may need to restart your terminal and/or install missing tools manually"
    fi
}

# Create startup script
create_startup_script() {
    print_status "Creating startup script..."
    
    cat > start_external_attacker.sh << 'EOF'
#!/bin/bash

echo "🚀 Starting ExternalAttacker-MCP Services..."

# Start Flask app in background
echo "Starting Flask app on port 6991..."
python3 ExternalAttacker-App.py &
FLASK_PID=$!

# Wait for Flask to start
sleep 3

# Start MCP server
echo "Starting MCP server..."
echo "Flask PID: $FLASK_PID"
echo "Use 'kill $FLASK_PID' to stop the Flask app"

python3 ExternalAttacker-MCP.py

# Cleanup
kill $FLASK_PID 2>/dev/null
EOF
    
    chmod +x start_external_attacker.sh
    print_success "Startup script created: start_external_attacker.sh"
}

# Main installation flow
main() {
    print_status "Starting installation process..."
    
    # Install Go
    install_go
    
    # Install Python dependencies
    install_python_deps
    
    # Install security tools
    install_security_tools
    
    # Setup PATH
    setup_path
    
    # Update nuclei templates
    update_nuclei_templates
    
    # Create startup script
    create_startup_script
    
    # Verify installations
    verify_installations
    
    echo ""
    echo "🎉 Installation completed!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Restart your terminal or run: source ~/.zshrc (or ~/.bashrc)"
    echo "2. Run the services: ./start_external_attacker.sh"
    echo "3. The Flask app will run on http://localhost:6991"
    echo "4. The MCP server will be available for integration"
    echo ""
    echo "🔧 Usage:"
    echo "• Web interface: http://localhost:6991"
    echo "• API endpoint: http://localhost:6991/api/run"
    echo "• MCP integration: Use with your preferred MCP client"
    echo ""
}

# Run main function
main "$@" 
#!/bin/bash

# ExternalAttacker-MCP Local Security Stack Setup
# This script installs Nessus, BeEF, DefectDojo, and Dradis locally for development

set -e

print_status() {
    echo "🔧 $1"
}

print_success() {
    echo "✅ $1"
}

print_error() {
    echo "❌ $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

print_status "Setting up Local Security Stack for ExternalAttacker-MCP..."

# Create tools directory
mkdir -p ~/security-tools
cd ~/security-tools

# 1. Install BeEF Framework
print_status "Installing BeEF Framework..."
if [ ! -d "beef" ]; then
    git clone https://github.com/beefproject/beef.git
    cd beef
    
    # Install Ruby dependencies
    if command -v brew >/dev/null 2>&1; then
        # macOS
        brew install ruby
    elif command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian
        sudo apt-get update
        sudo apt-get install -y ruby-full build-essential
    fi
    
    gem install bundler
    bundle install
    
    print_success "BeEF installed - Start with: cd ~/security-tools/beef && ./beef"
    cd ..
else
    print_success "BeEF already installed"
fi

# 2. Setup DefectDojo with Docker
print_status "Setting up DefectDojo..."
if [ ! -d "django-DefectDojo" ]; then
    # Check if Docker is installed
    if ! command -v docker >/dev/null 2>&1; then
        print_error "Docker is required for DefectDojo. Please install Docker first."
        print_status "Install Docker: https://docs.docker.com/get-docker/"
    else
        git clone https://github.com/DefectDojo/django-DefectDojo.git
        cd django-DefectDojo
        
        # Create local settings
        cat > local_settings.py << EOF
# DefectDojo Local Configuration
DEBUG = True
ALLOWED_HOSTS = ['localhost', '127.0.0.1']
DATABASE_URL = 'sqlite:///defectdojo.db'
SECRET_KEY = 'local-development-key-change-in-production'
EOF
        
        print_success "DefectDojo setup - Start with: cd ~/security-tools/django-DefectDojo && docker-compose up -d"
        cd ..
    fi
else
    print_success "DefectDojo already setup"
fi

# 3. Setup Dradis Community Edition
print_status "Setting up Dradis Community Edition..."
if [ ! -d "dradis-ce" ]; then
    git clone https://github.com/dradis/dradis-ce.git
    cd dradis-ce
    
    # Install Ruby if not present
    if ! command -v ruby >/dev/null 2>&1; then
        if command -v brew >/dev/null 2>&1; then
            brew install ruby
        elif command -v apt-get >/dev/null 2>&1; then
            sudo apt-get install -y ruby-full
        fi
    fi
    
    gem install bundler
    bundle install
    
    # Setup database
    bundle exec rails db:create db:migrate
    
    print_success "Dradis installed - Start with: cd ~/security-tools/dradis-ce && bundle exec rails server"
    cd ..
else
    print_success "Dradis already installed"
fi

# 4. Nessus Installation Instructions
print_status "Nessus Installation..."
print_status "Nessus requires manual download from Tenable:"
echo ""
echo "📥 Download Nessus Essentials (Free for home use):"
echo "   https://www.tenable.com/downloads/nessus"
echo ""
echo "🔧 Installation:"
echo "   macOS: Download .dmg and install"
echo "   Linux: Download .deb/.rpm and install with package manager"
echo ""
echo "🌐 Access: https://localhost:8834"
echo "👤 Create admin account during first setup"
echo ""

# Create startup script
cat > start_security_stack.sh << 'EOF'
#!/bin/bash

echo "🚀 Starting Local Security Stack..."

# Start BeEF
echo "Starting BeEF..."
cd ~/security-tools/beef
./beef &
BEEF_PID=$!

# Start DefectDojo (if Docker is available)
if command -v docker >/dev/null 2>&1; then
    echo "Starting DefectDojo..."
    cd ~/security-tools/django-DefectDojo
    docker-compose up -d
fi

# Start Dradis
echo "Starting Dradis..."
cd ~/security-tools/dradis-ce
bundle exec rails server -p 3001 &
DRADIS_PID=$!

echo ""
echo "🌐 Security Stack URLs:"
echo "   BeEF:       http://localhost:3000"
echo "   DefectDojo: http://localhost:8080 (if Docker running)"
echo "   Dradis:     http://localhost:3001"
echo "   Nessus:     https://localhost:8834 (if installed)"
echo ""
echo "🛑 Stop with: kill $BEEF_PID $DRADIS_PID"
echo "📝 PIDs: BeEF=$BEEF_PID, Dradis=$DRADIS_PID"

wait
EOF

chmod +x start_security_stack.sh

print_success "Local Security Stack setup complete!"
echo ""
echo "🚀 Quick Start:"
echo "   ./start_security_stack.sh    # Start all services"
echo ""
echo "🔧 Individual Services:"
echo "   BeEF:       cd ~/security-tools/beef && ./beef"
echo "   DefectDojo: cd ~/security-tools/django-DefectDojo && docker-compose up -d"
echo "   Dradis:     cd ~/security-tools/dradis-ce && bundle exec rails server"
echo ""
echo "📋 Default Credentials:"
echo "   BeEF:       beef/beef"
echo "   DefectDojo: admin/admin"
echo "   Dradis:     Create during first run"
echo ""
echo "⚙️  Update ExternalAttacker-MCP URLs to use localhost endpoints" 
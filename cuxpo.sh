#!/bin/bash

#===============================================================================
# CUXPO: Comprehensive Bug Bounty Reconnaissance Tool
# Author: AI Assistant
# Version: 1.0
# Description: Multi-faceted reconnaissance automation for ethical bug bounty hunting
#===============================================================================

# DISCLAIMER AND ETHICAL USAGE WARNING
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                 DISCLAIMER                                   ║
║                                                                              ║
║ This tool (Cuxpo) is intended SOLELY for authorized and ethical security    ║
║ research and legitimate bug bounty hunting activities. By using this tool,   ║
║ you agree to:                                                                ║
║                                                                              ║
║ 1. Only use this tool on systems you own or have explicit permission to     ║
║    test from the system owner.                                               ║
║ 2. Comply with all applicable laws and regulations in your jurisdiction.     ║
║ 3. Follow responsible disclosure practices for any vulnerabilities found.    ║
║ 4. Never use this tool for unauthorized access, malicious activities, or     ║
║    any illegal purposes.                                                     ║
║                                                                              ║
║ The authors and contributors of this tool are not responsible for any        ║
║ misuse, damage, or legal consequences resulting from the use of this tool.   ║
║                                                                              ║
║ USE AT YOUR OWN RISK AND RESPONSIBILITY.                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF

echo -e "\n\033[1;33mPress Enter to acknowledge and continue, or Ctrl+C to exit...\033[0m"
read -r

# Clear screen and show banner
clear

# ASCII Art Banner
show_banner() {
    if command -v figlet >/dev/null 2>&1; then
        if command -v lolcat >/dev/null 2>&1; then
            figlet -f big "CUXPO" | lolcat
            echo "Comprehensive Bug Bounty Reconnaissance Tool" | lolcat
        else
            echo -e "\033[1;36m"
            figlet -f big "CUXPO"
            echo "Comprehensive Bug Bounty Reconnaissance Tool"
            echo -e "\033[0m"
        fi
    else
        echo -e "\033[1;36m"
        echo "  ▄████▄   ▄   ▄█   ▄  ▄██████▄  "
        echo " ██▀  ▀██  ██  ██ ▄█▀  ██▀  ▀██▄ "
        echo " ██    ██  ██  ██▀    ██▀    ▀██ "
        echo " ▀██▄▄██▀  ██  ██     ██▄    ▄██ "
        echo "  ▀████▀   ▀▀  ▀▀      ▀██████▀  "
        echo ""
        echo "Comprehensive Bug Bounty Reconnaissance Tool"
        echo -e "\033[0m"
    fi
}

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global variables
TARGET=""
OUTPUT_DIR=""
TIMESTAMP=""
LOG_FILE=""
VENV_PATH=""
PARALLEL_PROCESSES=10
WORDLIST_PATH="/usr/share/seclists"

# Logging functions
log_info() {
    local message="$1"
    echo -e "${BLUE}[INFO]${NC} $message" | tee -a "$LOG_FILE"
}

log_success() {
    local message="$1"
    echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "$LOG_FILE"
}

log_error() {
    local message="$1"
    echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE"
}

log_warning() {
    local message="$1"
    echo -e "${YELLOW}[WARNING]${NC} $message" | tee -a "$LOG_FILE"
}

# Progress indicator
show_progress() {
    local phase="$1"
    local tool="$2"
    echo -e "\n${PURPLE}[PHASE]${NC} $phase"
    echo -e "${CYAN}[TOOL]${NC} Executing $tool..."
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Setup Python virtual environment
setup_python_venv() {
    if [ ! -d "$VENV_PATH" ]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv "$VENV_PATH" || {
            log_error "Failed to create Python virtual environment"
            return 1
        }
    fi
    
    # Activate virtual environment
    source "$VENV_PATH/bin/activate" || {
        log_error "Failed to activate Python virtual environment"
        return 1
    }
    
    # Upgrade pip
    pip install --upgrade pip >/dev/null 2>&1
    log_success "Python virtual environment ready"
}

# Install Go tools
install_go_tool() {
    local tool_name="$1"
    local install_path="$2"
    
    if ! command_exists go; then
        log_error "Go is not installed. Please install Go first."
        return 1
    fi
    
    log_info "Installing Go tool: $tool_name"
    go install "$install_path@latest" || {
        log_error "Failed to install $tool_name"
        return 1
    }
    
    # Check if GOPATH/bin is in PATH
    if [[ ":$PATH:" != *":$(go env GOPATH)/bin:"* ]]; then
        log_warning "$(go env GOPATH)/bin is not in PATH. Add it with: export PATH=\$PATH:\$(go env GOPATH)/bin"
    fi
    
    log_success "Installed $tool_name"
}

# Install Rust tools
install_rust_tool() {
    local tool_name="$1"
    
    if ! command_exists cargo; then
        log_error "Rust/Cargo is not installed. Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        return 1
    fi
    
    log_info "Installing Rust tool: $tool_name"
    cargo install "$tool_name" || {
        log_error "Failed to install $tool_name"
        return 1
    }
    
    log_success "Installed $tool_name"
}

# Install Python tools in virtual environment
install_python_tool() {
    local tool_name="$1"
    local pip_package="$2"
    
    setup_python_venv || return 1
    
    log_info "Installing Python tool: $tool_name"
    pip install "$pip_package" || {
        log_error "Failed to install $tool_name"
        return 1
    }
    
    log_success "Installed $tool_name"
}

# Install Node.js tools
install_nodejs_tool() {
    local tool_name="$1"
    local npm_package="$2"
    
    if ! command_exists nvm; then
        log_error "nvm is not installed. Install with: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash"
        log_error "Then restart your terminal or source your shell profile"
        return 1
    fi
    
    # Source nvm
    [ -s "$HOME/.nvm/nvm.sh" ] && \. "$HOME/.nvm/nvm.sh"
    
    # Ensure Node.js is installed
    if ! command_exists node; then
        log_info "Installing Node.js..."
        nvm install node
        nvm use node
    fi
    
    log_info "Installing Node.js tool: $tool_name"
    npm install -g "$npm_package" || {
        log_error "Failed to install $tool_name"
        return 1
    }
    
    log_success "Installed $tool_name"
}

# Install system packages
install_system_package() {
    local package="$1"
    
    log_info "Installing system package: $package"
    sudo apt update >/dev/null 2>&1
    sudo apt install -y "$package" || {
        log_error "Failed to install $package"
        return 1
    }
    
    log_success "Installed $package"
}

# Tool installation and execution functions
check_and_install_tool() {
    local tool_name="$1"
    local install_type="$2"
    local install_param="$3"
    
    if command_exists "$tool_name"; then
        return 0
    fi
    
    log_warning "$tool_name not found, attempting installation..."
    
    case "$install_type" in
        "go")
            install_go_tool "$tool_name" "$install_param"
            ;;
        "rust")
            install_rust_tool "$install_param"
            ;;
        "python")
            install_python_tool "$tool_name" "$install_param"
            ;;
        "nodejs")
            install_nodejs_tool "$tool_name" "$install_param"
            ;;
        "system")
            install_system_package "$install_param"
            ;;
        *)
            log_error "Unknown installation type: $install_type"
            return 1
            ;;
    esac
}

# Execute tool with proper error handling
execute_tool() {
    local tool_name="$1"
    local command="$2"
    local output_file="$3"
    
    if ! command_exists "$tool_name"; then
        log_error "$tool_name is not available, skipping..."
        return 1
    fi
    
    log_info "Executing $tool_name..."
    
    # Execute command and capture output
    if eval "$command" > "$output_file" 2>&1; then
        log_success "$tool_name completed successfully"
        return 0
    else
        log_error "$tool_name failed to execute"
        return 1
    fi
}

# Phase 1: Subdomain Enumeration
phase1_subdomain_enumeration() {
    show_progress "1/10" "Subdomain Enumeration"
    local phase_dir="$OUTPUT_DIR/01_subdomain_enumeration"
    mkdir -p "$phase_dir"
    
    # Sublist3r
    check_and_install_tool "sublist3r" "python" "sublist3r"
    execute_tool "sublist3r" "python3 -m sublist3r -d $TARGET -o $phase_dir/sublist3r.txt" "$phase_dir/sublist3r_log.txt"
 
    # Subfinder
    check_and_install_tool "subfinder" "go" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    execute_tool "subfinder" "subfinder -d $TARGET -o $phase_dir/subfinder.txt" "$phase_dir/subfinder_log.txt"
    
    # Assetfinder
    check_and_install_tool "assetfinder" "go" "github.com/tomnomnom/assetfinder"
    execute_tool "assetfinder" "assetfinder --subs-only $TARGET > $phase_dir/assetfinder.txt" "$phase_dir/assetfinder_log.txt"
    
    # Findomain
    check_and_install_tool "findomain" "rust" "findomain"
    execute_tool "findomain" "findomain -t $TARGET --output $phase_dir/" "$phase_dir/findomain_log.txt"
    
    # DNSx for validation
    check_and_install_tool "dnsx" "go" "github.com/projectdiscovery/dnsx/cmd/dnsx"
    
    # Combine and deduplicate subdomains
    log_info "Combining and deduplicating subdomains..."
    cat "$phase_dir"/*.txt 2>/dev/null | sort -u > "$phase_dir/all_subdomains.txt"
    
    # Validate live subdomains
    if command_exists dnsx; then
        log_info "Validating live subdomains..."
        cat "$phase_dir/all_subdomains.txt" | dnsx -silent > "$phase_dir/live_subdomains.txt"
        log_success "Found $(wc -l < "$phase_dir/live_subdomains.txt") live subdomains"
    fi
}

# Phase 2: Port Scanning
phase2_port_scanning() {
    show_progress "2/10" "Port Scanning"
    local phase_dir="$OUTPUT_DIR/02_port_scanning"
    mkdir -p "$phase_dir"
    
    local targets_file="$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt"
    if [ ! -f "$targets_file" ]; then
        targets_file="$OUTPUT_DIR/01_subdomain_enumeration/all_subdomains.txt"
    fi
    
    if [ ! -f "$targets_file" ]; then
        log_error "No subdomain file found for port scanning"
        return 1
    fi
    
    # Naabu
    check_and_install_tool "naabu" "go" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
    execute_tool "naabu" "naabu -list $targets_file -o $phase_dir/naabu_ports.txt" "$phase_dir/naabu_log.txt"
    
    # RustScan
    check_and_install_tool "rustscan" "rust" "rustscan"
    if command_exists rustscan; then
        log_info "Running RustScan on top ports..."
        rustscan -a "$targets_file" --ulimit 5000 > "$phase_dir/rustscan.txt" 2>&1
    fi
    
    # Masscan (if available)
    if command_exists masscan; then
        log_info "Running Masscan..."
        sudo masscan -iL "$targets_file" -p1-65535 --rate=1000 > "$phase_dir/masscan.txt" 2>&1
    fi
    
    # Nmap detailed scan on discovered ports
    if command_exists nmap && [ -f "$phase_dir/naabu_ports.txt" ]; then
        log_info "Running detailed Nmap scan..."
        nmap -sV -sC -iL "$phase_dir/naabu_ports.txt" -oA "$phase_dir/nmap_detailed" > "$phase_dir/nmap_log.txt" 2>&1
    fi
}

# Phase 3: Screenshots
phase3_screenshots() {
    show_progress "3/10" "Screenshots"
    local phase_dir="$OUTPUT_DIR/03_screenshots"
    mkdir -p "$phase_dir"
    
    local targets_file="$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt"
    if [ ! -f "$targets_file" ]; then
        log_error "No live subdomains file found for screenshots"
        return 1
    fi
    
    # Gowitness
    check_and_install_tool "gowitness" "go" "github.com/sensepost/gowitness"
    execute_tool "gowitness" "gowitness file -f $targets_file -P $phase_dir/" "$phase_dir/gowitness_log.txt"
    
    # Aquatone
    check_and_install_tool "aquatone" "go" "github.com/michenriksen/aquatone"
    if command_exists aquatone; then
        cd "$phase_dir" || return 1
        cat "$targets_file" | aquatone -out aquatone_results > aquatone_log.txt 2>&1
        cd - || return 1
    fi
    
    # EyeWitness (Python)
    if [ -d "/opt/EyeWitness" ]; then
        log_info "Running EyeWitness..."
        python3 /opt/EyeWitness/Python/EyeWitness.py -f "$targets_file" -d "$phase_dir/eyewitness" > "$phase_dir/eyewitness_log.txt" 2>&1
    fi
}

# Phase 4: Technology Detection
phase4_technology_detection() {
    show_progress "4/10" "Technology Detection"
    local phase_dir="$OUTPUT_DIR/04_technology_detection"
    mkdir -p "$phase_dir"
    
    local targets_file="$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt"
    if [ ! -f "$targets_file" ]; then
        log_error "No live subdomains file found for technology detection"
        return 1
    fi
    
    # HTTPx
    check_and_install_tool "httpx" "go" "github.com/projectdiscovery/httpx/cmd/httpx"
    execute_tool "httpx" "httpx -list $targets_file -tech-detect -o $phase_dir/httpx_tech.txt" "$phase_dir/httpx_log.txt"
    
    # Webanalyze
    check_and_install_tool "webanalyze" "go" "github.com/rverton/webanalyze"
    execute_tool "webanalyze" "webanalyze -hosts $targets_file -output csv > $phase_dir/webanalyze.csv" "$phase_dir/webanalyze_log.txt"
    
    # WhatWeb
    check_and_install_tool "whatweb" "system" "whatweb"
    if command_exists whatweb; then
        log_info "Running WhatWeb..."
        while read -r url; do
            whatweb "$url" >> "$phase_dir/whatweb.txt" 2>&1
        done < "$targets_file"
    fi
    
    # Retire.js
    check_and_install_tool "retire" "nodejs" "retire"
    if command_exists retire; then
        log_info "Running Retire.js..."
        while read -r url; do
            retire --url "$url" >> "$phase_dir/retirejs.txt" 2>&1
        done < "$targets_file"
    fi
}

# Phase 5: Content Discovery
phase5_content_discovery() {
    show_progress "5/10" "Content Discovery"
    local phase_dir="$OUTPUT_DIR/05_content_discovery"
    mkdir -p "$phase_dir"
    
    local targets_file="$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt"
    if [ ! -f "$targets_file" ]; then
        log_error "No live subdomains file found for content discovery"
        return 1
    fi
    
    # Gobuster
    check_and_install_tool "gobuster" "go" "github.com/OJ/gobuster/v3"
    if command_exists gobuster && [ -f "$WORDLIST_PATH/Discovery/Web-Content/common.txt" ]; then
        log_info "Running Gobuster directory enumeration..."
        while read -r url; do
            gobuster dir -u "$url" -w "$WORDLIST_PATH/Discovery/Web-Content/common.txt" -o "$phase_dir/gobuster_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g').txt" 2>&1
        done < "$targets_file"
    fi
    
    # Feroxbuster
    check_and_install_tool "feroxbuster" "rust" "feroxbuster"
    if command_exists feroxbuster && [ -f "$WORDLIST_PATH/Discovery/Web-Content/common.txt" ]; then
        log_info "Running Feroxbuster..."
        feroxbuster -u "file://$targets_file" -w "$WORDLIST_PATH/Discovery/Web-Content/common.txt" -o "$phase_dir/feroxbuster.txt" > "$phase_dir/feroxbuster_log.txt" 2>&1
    fi
    
    # Dirsearch
    check_and_install_tool "dirsearch" "python" "dirsearch"
    if command_exists dirsearch; then
        log_info "Running Dirsearch..."
        while read -r url; do
            dirsearch -u "$url" -o "$phase_dir/dirsearch_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g').txt" 2>&1
        done < "$targets_file"
    fi
    
    # Gospider
    check_and_install_tool "gospider" "go" "github.com/jaeles-project/gospider"
    execute_tool "gospider" "gospider -S $targets_file -o $phase_dir/gospider/" "$phase_dir/gospider_log.txt"
    
    # Katana
    check_and_install_tool "katana" "go" "github.com/projectdiscovery/katana/cmd/katana"
    execute_tool "katana" "katana -list $targets_file -o $phase_dir/katana.txt" "$phase_dir/katana_log.txt"
}

# Phase 6: Link Discovery
phase6_link_discovery() {
    show_progress "6/10" "Link Discovery"
    local phase_dir="$OUTPUT_DIR/06_link_discovery"
    mkdir -p "$phase_dir"
    
    # Waybackurls
    check_and_install_tool "waybackurls" "go" "github.com/tomnomnom/waybackurls"
    execute_tool "waybackurls" "echo $TARGET | waybackurls > $phase_dir/waybackurls.txt" "$phase_dir/waybackurls_log.txt"
    
    # GAU (Get All URLs)
    check_and_install_tool "gau" "go" "github.com/lc/gau/v2/cmd/gau"
    execute_tool "gau" "gau $TARGET > $phase_dir/gau.txt" "$phase_dir/gau_log.txt"
    
    # URLGrab
    check_and_install_tool "urlgrab" "go" "github.com/IAmStoxe/urlgrab"
    execute_tool "urlgrab" "urlgrab -url $TARGET > $phase_dir/urlgrab.txt" "$phase_dir/urlgrab_log.txt"
    
    # LinkFinder
    check_and_install_tool "linkfinder" "python" "linkfinder"
    if [ -d "$OUTPUT_DIR/03_screenshots" ]; then
        log_info "Running LinkFinder on discovered pages..."
        find "$OUTPUT_DIR/03_screenshots" -name "*.html" -exec python3 -m linkfinder -i {} -o cli \; >> "$phase_dir/linkfinder.txt" 2>&1
    fi
    
    # Combine all URLs
    log_info "Combining all discovered URLs..."
    cat "$phase_dir"/*.txt 2>/dev/null | sort -u > "$phase_dir/all_urls.txt"
    log_success "Found $(wc -l < "$phase_dir/all_urls.txt") unique URLs"
}

# Phase 7: Parameter Discovery
phase7_parameter_discovery() {
    show_progress "7/10" "Parameter Discovery"
    local phase_dir="$OUTPUT_DIR/07_parameter_discovery"
    mkdir -p "$phase_dir"
    
    local urls_file="$OUTPUT_DIR/06_link_discovery/all_urls.txt"
    if [ ! -f "$urls_file" ]; then
        log_error "No URLs file found for parameter discovery"
        return 1
    fi
    
    # Arjun
    check_and_install_tool "arjun" "python" "arjun"
    if command_exists arjun; then
        log_info "Running Arjun parameter discovery..."
        head -100 "$urls_file" | while read -r url; do
            arjun -u "$url" -o "$phase_dir/arjun_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g').txt" 2>&1
        done
    fi
    
    # ParamSpider
    check_and_install_tool "paramspider" "python" "paramspider"
    execute_tool "paramspider" "paramspider -d $TARGET -o $phase_dir/paramspider.txt" "$phase_dir/paramspider_log.txt"
    
    # x8
    check_and_install_tool "x8" "rust" "x8"
    if command_exists x8 && [ -f "$WORDLIST_PATH/Discovery/Web-Content/burp-parameter-names.txt" ]; then
        log_info "Running x8 parameter discovery..."
        head -50 "$urls_file" | x8 -w "$WORDLIST_PATH/Discovery/Web-Content/burp-parameter-names.txt" -o "$phase_dir/x8.txt" > "$phase_dir/x8_log.txt" 2>&1
    fi
}

# Phase 8: Fuzzing
phase8_fuzzing() {
    show_progress "8/10" "Fuzzing"
    local phase_dir="$OUTPUT_DIR/08_fuzzing"
    mkdir -p "$phase_dir"
    
    local urls_file="$OUTPUT_DIR/06_link_discovery/all_urls.txt"
    if [ ! -f "$urls_file" ]; then
        log_error "No URLs file found for fuzzing"
        return 1
    fi
    
    # FFUF
    check_and_install_tool "ffuf" "go" "github.com/ffuf/ffuf"
    if command_exists ffuf && [ -f "$WORDLIST_PATH/Discovery/Web-Content/common.txt" ]; then
        log_info "Running FFUF fuzzing..."
        head -10 "$urls_file" | while read -r url; do
            ffuf -u "${url}/FUZZ" -w "$WORDLIST_PATH/Discovery/Web-Content/common.txt" -o "$phase_dir/ffuf_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g').json" -of json 2>&1
        done
    fi
    
    # Wfuzz
    check_and_install_tool "wfuzz" "python" "wfuzz"
    if command_exists wfuzz && [ -f "$WORDLIST_PATH/Discovery/Web-Content/common.txt" ]; then
        log_info "Running Wfuzz..."
        head -5 "$urls_file" | while read -r url; do
            wfuzz -c -z file,"$WORDLIST_PATH/Discovery/Web-Content/common.txt" --hc 404 "${url}/FUZZ" > "$phase_dir/wfuzz_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g').txt" 2>&1
        done
    fi
}

# Phase 9: Vulnerability Scanning
phase9_vulnerability_scanning() {
    show_progress "9/10" "Vulnerability Scanning"
    local phase_dir="$OUTPUT_DIR/09_vulnerability_scanning"
    mkdir -p "$phase_dir"
    
    local targets_file="$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt"
    if [ ! -f "$targets_file" ]; then
        log_error "No live subdomains file found for vulnerability scanning"
        return 1
    fi
    
    # Nuclei
    check_and_install_tool "nuclei" "go" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    if command_exists nuclei; then
        log_info "Running Nuclei vulnerability scanner..."
        nuclei -list "$targets_file" -o "$phase_dir/nuclei.txt" -severity critical,high,medium > "$phase_dir/nuclei_log.txt" 2>&1
    fi
    
    # SQLMap for SQL injection testing
    check_and_install_tool "sqlmap" "python" "sqlmap"
    if command_exists sqlmap && [ -f "$OUTPUT_DIR/07_parameter_discovery/paramspider.txt" ]; then
        log_info "Running SQLMap on discovered parameters..."
        head -10 "$OUTPUT_DIR/07_parameter_discovery/paramspider.txt" | while read -r url; do
            sqlmap -u "$url" --batch --risk=1 --level=1 --output-dir="$phase_dir/sqlmap/" 2>&1
        done
    fi
    
    # XSStrike for XSS testing
    check_and_install_tool "xsstrike" "python" "xsstrike"
    if command_exists xsstrike; then
        log_info "Running XSStrike for XSS detection..."
        head -10 "$OUTPUT_DIR/06_link_discovery/all_urls.txt" | while read -r url; do
            xsstrike -u "$url" >> "$phase_dir/xsstrike.txt" 2>&1
        done
    fi
    
    # Nikto
    check_and_install_tool "nikto" "system" "nikto"
    if command_exists nikto; then
        log_info "Running Nikto web scanner..."
        while read -r url; do
            nikto -h "$url" -output "$phase_dir/nikto_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g').txt" 2>&1
        done < <(head -5 "$targets_file")
    fi
}

# Phase 10: Additional Reconnaissance
phase10_additional_recon() {
    show_progress "10/10" "Additional Reconnaissance"
    local phase_dir="$OUTPUT_DIR/10_additional_recon"
    mkdir -p "$phase_dir"
    
    # Git repository discovery
    check_and_install_tool "gitdorker" "python" "gitdorker"
    execute_tool "gitdorker" "python3 -m gitdorker -d $TARGET -o $phase_dir/gitdorker.txt" "$phase_dir/gitdorker_log.txt"
    
    # Secret scanning with Gitleaks
    check_and_install_tool "gitleaks" "go" "github.com/gitleaks/gitleaks/v8"
    if [ -d "$OUTPUT_DIR/05_content_discovery" ]; then
        log_info "Running Gitleaks on discovered content..."
        find "$OUTPUT_DIR/05_content_discovery" -type f -name "*.txt" -exec gitleaks detect --source {} --report-path "$phase_dir/gitleaks_$(basename {}).json" \; 2>&1
    fi
    
    # TruffleHog for secret detection
    check_and_install_tool "trufflehog" "go" "github.com/trufflesecurity/trufflehog/v3"
    if command_exists trufflehog; then
        log_info "Running TruffleHog for secret detection..."
        echo "$TARGET" | trufflehog --json > "$phase_dir/trufflehog.json" 2>&1
    fi
    
    # S3 Bucket discovery
    check_and_install_tool "s3scanner" "python" "s3scanner"
    execute_tool "s3scanner" "s3scanner -d $TARGET > $phase_dir/s3scanner.txt" "$phase_dir/s3scanner_log.txt"
    
    # Subdomain takeover detection
    check_and_install_tool "subjack" "go" "github.com/haccer/subjack"
    if [ -f "$OUTPUT_DIR/01_subdomain_enumeration/all_subdomains.txt" ]; then
        execute_tool "subjack" "subjack -w $OUTPUT_DIR/01_subdomain_enumeration/all_subdomains.txt -o $phase_dir/subjack.txt" "$phase_dir/subjack_log.txt"
    fi
    
    # CMS detection and scanning
    check_and_install_tool "wpscan" "system" "wpscan"
    if command_exists wpscan; then
        log_info "Running WPScan for WordPress detection..."
        while read -r url; do
            if [[ "$url" == *"wordpress"* ]] || [[ "$url" == *"wp-"* ]]; then
                wpscan --url "$url" --enumerate u,p,t --output "$phase_dir/wpscan_$(echo "$url" | sed 's|[^a-zA-Z0-9]|_|g').txt" 2>&1
            fi
        done < "$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt"
    fi
    
    # JWT token analysis
    check_and_install_tool "jwt_tool" "python" "pyjwt"
    if [ -f "$OUTPUT_DIR/06_link_discovery/all_urls.txt" ]; then
        log_info "Checking for JWT tokens in URLs..."
        grep -i "jwt\|token" "$OUTPUT_DIR/06_link_discovery/all_urls.txt" > "$phase_dir/potential_jwt_urls.txt" 2>/dev/null || true
    fi
}

# Generate comprehensive report
generate_report() {
    log_info "Generating comprehensive reconnaissance report..."
    local report_file="$OUTPUT_DIR/RECON_REPORT.md"
    
    cat << EOF > "$report_file"
# Cuxpo Reconnaissance Report

**Target:** $TARGET  
**Scan Date:** $(date)  
**Output Directory:** $OUTPUT_DIR  

## Executive Summary

This report contains the results of comprehensive reconnaissance performed against $TARGET using the Cuxpo toolkit.

## Discovered Assets

### Subdomains
EOF
    
    if [ -f "$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt" ]; then
        echo "**Live Subdomains Found:** $(wc -l < "$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt")" >> "$report_file"
        echo "" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        head -20 "$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt" >> "$report_file" 2>/dev/null
        echo "\`\`\`" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    cat << EOF >> "$report_file"

### Port Scanning Results
EOF
    
    if [ -f "$OUTPUT_DIR/02_port_scanning/naabu_ports.txt" ]; then
        echo "**Open Ports Found:** $(wc -l < "$OUTPUT_DIR/02_port_scanning/naabu_ports.txt")" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    cat << EOF >> "$report_file"

### Technology Stack
EOF
    
    if [ -f "$OUTPUT_DIR/04_technology_detection/httpx_tech.txt" ]; then
        echo "**Technologies Detected:**" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        head -10 "$OUTPUT_DIR/04_technology_detection/httpx_tech.txt" >> "$report_file" 2>/dev/null
        echo "\`\`\`" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    cat << EOF >> "$report_file"

### Discovered URLs
EOF
    
    if [ -f "$OUTPUT_DIR/06_link_discovery/all_urls.txt" ]; then
        echo "**Total URLs Found:** $(wc -l < "$OUTPUT_DIR/06_link_discovery/all_urls.txt")" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    cat << EOF >> "$report_file"

### Vulnerability Assessment
EOF
    
    if [ -f "$OUTPUT_DIR/09_vulnerability_scanning/nuclei.txt" ]; then
        echo "**Nuclei Findings:**" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        head -20 "$OUTPUT_DIR/09_vulnerability_scanning/nuclei.txt" >> "$report_file" 2>/dev/null
        echo "\`\`\`" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    cat << EOF >> "$report_file"

## File Structure

The following directories contain detailed results:

- **01_subdomain_enumeration/**: All subdomain discovery results
- **02_port_scanning/**: Port scan results and service detection
- **03_screenshots/**: Website screenshots and visual reconnaissance
- **04_technology_detection/**: Technology stack identification
- **05_content_discovery/**: Directory and file enumeration
- **06_link_discovery/**: URL and endpoint discovery
- **07_parameter_discovery/**: Parameter identification
- **08_fuzzing/**: Fuzzing results
- **09_vulnerability_scanning/**: Security vulnerability assessment
- **10_additional_recon/**: Secret scanning, bucket discovery, etc.

## Recommendations

1. **Immediate Actions:**
   - Review high-severity findings from Nuclei scan
   - Investigate any exposed sensitive files or directories
   - Check for subdomain takeover vulnerabilities

2. **Security Improvements:**
   - Implement proper security headers
   - Ensure all subdomains are properly configured
   - Regular security assessments

3. **Monitoring:**
   - Set up continuous monitoring for new subdomains
   - Implement alerting for configuration changes

---

*Report generated by Cuxpo v1.0*  
*For authorized security testing purposes only*
EOF
    
    log_success "Report generated: $report_file"
}

# Cleanup function
cleanup() {
    log_info "Performing cleanup..."
    
    # Deactivate Python virtual environment if active
    if [[ "$VIRTUAL_ENV" != "" ]]; then
        deactivate 2>/dev/null || true
    fi
    
    # Remove temporary files
    find "$OUTPUT_DIR" -name "*.tmp" -delete 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Signal handlers
trap cleanup EXIT
trap 'log_error "Script interrupted by user"; exit 1' INT TERM

# Main execution function
main() {
    # Validate arguments
    if [ $# -ne 1 ]; then
        echo -e "${RED}Usage: $0 <target_domain>${NC}"
        echo -e "${YELLOW}Example: $0 example.com${NC}"
        exit 1
    fi
    
    TARGET="$1"
    
    # Validate domain format
    if [[ ! "$TARGET" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Invalid domain format: $TARGET"
        exit 1
    fi
    
    # Setup directories and logging
    TIMESTAMP=$(date +"%Y-%m-%d-%H%M%S")
    OUTPUT_DIR="${TARGET}/${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"
    
    LOG_FILE="$OUTPUT_DIR/recon_log.txt"
    VENV_PATH="$OUTPUT_DIR/cuxpo_venv"
    
    # Show banner
    show_banner
    
    # Log start of reconnaissance
    log_info "Starting reconnaissance for target: $TARGET"
    log_info "Output directory: $OUTPUT_DIR"
    log_info "Log file: $LOG_FILE"
    
    # Install essential system tools first
    log_info "Checking and installing essential system tools..."
    check_and_install_tool "figlet" "system" "figlet"
    check_and_install_tool "lolcat" "system" "lolcat"
    check_and_install_tool "jq" "system" "jq"
    check_and_install_tool "curl" "system" "curl"
    check_and_install_tool "wget" "system" "wget"
    check_and_install_tool "git" "system" "git"
    
    # Check for SecLists wordlist
    if [ ! -d "$WORDLIST_PATH" ]; then
        log_warning "SecLists not found at $WORDLIST_PATH"
        log_info "Installing SecLists..."
        sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || {
            log_error "Failed to install SecLists. Some tools may not work properly."
            WORDLIST_PATH="/usr/share/wordlists"
        }
    fi
    
    # Execute reconnaissance phases
    local start_time=$(date +%s)
    
    phase1_subdomain_enumeration
    phase2_port_scanning
    phase3_screenshots
    phase4_technology_detection
    phase5_content_discovery
    phase6_link_discovery
    phase7_parameter_discovery
    phase8_fuzzing
    phase9_vulnerability_scanning
    phase10_additional_recon
    
    # Generate report
    generate_report
    
    # Calculate execution time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    local seconds=$((duration % 60))
    
    # Final summary
    echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                          RECONNAISSANCE COMPLETE                             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    log_success "Reconnaissance completed for $TARGET"
    log_success "Total execution time: ${hours}h ${minutes}m ${seconds}s"
    log_success "Results saved in: $OUTPUT_DIR"
    log_success "Report available at: $OUTPUT_DIR/RECON_REPORT.md"
    
    # Display summary statistics
    echo -e "\n${CYAN}Summary Statistics:${NC}"
    
    if [ -f "$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt" ]; then
        echo -e "${WHITE}• Live Subdomains:${NC} $(wc -l < "$OUTPUT_DIR/01_subdomain_enumeration/live_subdomains.txt")"
    fi
    
    if [ -f "$OUTPUT_DIR/06_link_discovery/all_urls.txt" ]; then
        echo -e "${WHITE}• Total URLs:${NC} $(wc -l < "$OUTPUT_DIR/06_link_discovery/all_urls.txt")"
    fi
    
    if [ -f "$OUTPUT_DIR/02_port_scanning/naabu_ports.txt" ]; then
        echo -e "${WHITE}• Open Ports:${NC} $(wc -l < "$OUTPUT_DIR/02_port_scanning/naabu_ports.txt")"
    fi
    
    echo -e "\n${YELLOW}Next Steps:${NC}"
    echo -e "1. Review the generated report: ${CYAN}$OUTPUT_DIR/RECON_REPORT.md${NC}"
    echo -e "2. Examine high-priority vulnerabilities in: ${CYAN}$OUTPUT_DIR/09_vulnerability_scanning/${NC}"
    echo -e "3. Analyze screenshots for interesting targets: ${CYAN}$OUTPUT_DIR/03_screenshots/${NC}"
    echo -e "4. Check for sensitive information in: ${CYAN}$OUTPUT_DIR/10_additional_recon/${NC}"
    
    echo -e "\n${GREEN}Happy hunting! 🎯${NC}"
}

# Script information
show_info() {
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                               CUXPO v1.0                                    ║
║                    Comprehensive Bug Bounty Reconnaissance                  ║
║                                                                              ║
║ Features:                                                                    ║
║ • 10-Phase reconnaissance methodology                                        ║
║ • 80+ integrated security tools                                             ║
║ • Intelligent tool installation and management                              ║
║ • Organized output with timestamped results                                 ║
║ • Comprehensive reporting                                                    ║
║ • Parallel processing for improved performance                              ║
║                                                                              ║
║ Phases:                                                                      ║
║ 1. Subdomain Enumeration    6. Link Discovery                               ║
║ 2. Port Scanning           7. Parameter Discovery                           ║
║ 3. Screenshots             8. Fuzzing                                        ║
║ 4. Technology Detection    9. Vulnerability Scanning                        ║
║ 5. Content Discovery      10. Additional Reconnaissance                     ║
║                                                                              ║
║ Usage: ./cuxpo.sh <target_domain>                                           ║
║ Example: ./cuxpo.sh example.com                                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
}

# Help function
show_help() {
    show_info
    cat << "EOF"

INSTALLATION REQUIREMENTS:
• Go programming language
• Python 3.x with pip
• Rust and Cargo
• Node.js and npm (via nvm recommended)
• Git
• Basic system tools (curl, wget, etc.)

SUPPORTED ENVIRONMENTS:
• Kali Linux (recommended)
• Ubuntu/Debian
• Other Linux distributions (with package manager support)

CONFIGURATION:
• WordLists: Script attempts to install SecLists to /usr/share/seclists
• API Keys: Configure Amass with Shodan/VirusTotal keys in ~/.config/amass/
• Parallel Processes: Default 10, adjustable in script variables

ETHICAL USAGE:
This tool is designed for authorized security testing only. Always ensure you have
proper permission before scanning any target. Unauthorized scanning may be illegal
in your jurisdiction.

For support and updates, visit: https://github.com/cuxpo/cuxpo-recon
EOF
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -i|--info)
        show_info
        exit 0
        ;;
    "")
        show_help
        exit 1
        ;;
    *)
        main "$@"
        ;;
esac
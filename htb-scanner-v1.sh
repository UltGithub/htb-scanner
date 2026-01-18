#!/bin/bash
# HTB Master Scanner - Interactive Vulnerability Scanner for HackTheBox
# Author: Auto-generated
# Version: 2.0

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Global variables
TARGET=""
OUTPUT_DIR=""
SCAN_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CURRENT_DIR=$(pwd)

# Banner
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                 HTB MASTER SCANNER v2.0                  ║"
    echo "║        Comprehensive Vulnerability Assessment Tool        ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Usage: Select options from the menu below${NC}"
    echo -e "${YELLOW}==========================================${NC}\n"
}

# Check for required tools
check_tools() {
    local missing_tools=()
    
    # Essential tools
    essential_tools=("nmap" "ping" "curl" "grep" "cut")
    
    # Optional but recommended tools
    recommended_tools=("gobuster" "nikto" "whatweb" "enum4linux" "smbclient" "searchsploit" "hydra")
    
    echo -e "${BLUE}[*] Checking for required tools...${NC}"
    
    for tool in "${essential_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[-] Missing essential tool: $tool${NC}"
            missing_tools+=("$tool")
        fi
    done
    
    for tool in "${recommended_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${YELLOW}[!] Recommended tool not found: $tool${NC}"
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}[!] Please install missing tools before continuing.${NC}"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}[+] All essential tools are installed${NC}"
    fi
}

# Setup directories
setup_directories() {
    if [ -z "$TARGET" ]; then
        read -p "Enter target IP/hostname: " TARGET
    fi
    
    OUTPUT_DIR="scans/${TARGET}_${SCAN_TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR/nmap"
    mkdir -p "$OUTPUT_DIR/web"
    mkdir -p "$OUTPUT_DIR/enumeration"
    mkdir -p "$OUTPUT_DIR/exploits"
    
    echo -e "${GREEN}[+] Output directory created: ${OUTPUT_DIR}${NC}"
}

# Quick Scan (Basic Recon)
quick_scan() {
    echo -e "${BLUE}[*] Starting Quick Scan${NC}"
    
    # Host discovery
    echo -e "${CYAN}[1] Checking if host is alive...${NC}"
    ping -c 3 "$TARGET" > "$OUTPUT_DIR/ping.txt" 2>&1
    
    # Quick TCP scan
    echo -e "${CYAN}[2] Running quick TCP scan (top 1000 ports)...${NC}"
    nmap -sC -sV -T4 -oA "$OUTPUT_DIR/nmap/quick_tcp" "$TARGET"
    
    # Check for web services
    echo -e "${CYAN}[3] Checking for web services...${NC}"
    nmap -p 80,443,8000,8080,8443,3000 --open -oG "$OUTPUT_DIR/nmap/web_ports.txt" "$TARGET"
    
    # Quick UDP scan (top 100)
    echo -e "${CYAN}[4] Quick UDP scan (top 100 ports)...${NC}"
    nmap -sU --top-ports 100 -T4 -oA "$OUTPUT_DIR/nmap/quick_udp" "$TARGET"
    
    echo -e "${GREEN}[+] Quick scan completed${NC}"
}

# Full Scan (Comprehensive)
full_scan() {
    echo -e "${BLUE}[*] Starting Full Comprehensive Scan${NC}"
    
    # Full TCP port scan
    echo -e "${CYAN}[1] Running full TCP port scan (all 65535 ports)...${NC}"
    nmap -p- -T4 --min-rate=1000 -oA "$OUTPUT_DIR/nmap/full_tcp" "$TARGET" &
    TCP_PID=$!
    
    # Full UDP scan (top 1000)
    echo -e "${CYAN}[2] Running UDP scan (top 1000 ports)...${NC}"
    nmap -sU --top-ports 1000 -T4 -oA "$OUTPUT_DIR/nmap/full_udp" "$TARGET" &
    UDP_PID=$!
    
    # Wait for TCP scan
    wait $TCP_PID
    
    # Service detection on open ports
    echo -e "${CYAN}[3] Service detection on open ports...${NC}"
    open_ports=$(grep -oP '\d+/open' "$OUTPUT_DIR/nmap/full_tcp.nmap" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    
    if [ ! -z "$open_ports" ]; then
        nmap -sC -sV -p "$open_ports" -oA "$OUTPUT_DIR/nmap/service_detection" "$TARGET"
    fi
    
    # Wait for UDP scan
    wait $UDP_PID
    
    # Vulnerability scan
    echo -e "${CYAN}[4] Running vulnerability scan...${NC}"
    nmap --script vuln -oA "$OUTPUT_DIR/nmap/vulnerability_scan" "$TARGET"
    
    # NSE script scan
    echo -e "${CYAN}[5] Running safe script scan...${NC}"
    nmap --script safe -oA "$OUTPUT_DIR/nmap/safe_scripts" "$TARGET"
    
    echo -e "${GREEN}[+] Full scan completed${NC}"
}

# Web Application Scan
web_scan() {
    echo -e "${BLUE}[*] Starting Web Application Scan${NC}"
    
    # Detect web ports
    echo -e "${CYAN}[1] Detecting web ports...${NC}"
    web_ports=()
    
    for port in 80 443 8080 8443 8000 3000 8888; do
        if timeout 2 nc -z "$TARGET" "$port" 2>/dev/null; then
            web_ports+=("$port")
            echo -e "${GREEN}[+] Web service found on port $port${NC}"
        fi
    done
    
    if [ ${#web_ports[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No web ports detected${NC}"
        return
    fi
    
    # Scan each web port
    for port in "${web_ports[@]}"; do
        echo -e "${PURPLE}[*] Scanning port $port...${NC}"
        
        local protocol="http"
        if [ "$port" -eq 443 ] || [ "$port" -eq 8443 ]; then
            protocol="https"
        fi
        
        local url="$protocol://$TARGET:$port"
        local port_dir="$OUTPUT_DIR/web/port_$port"
        mkdir -p "$port_dir"
        
        # Technology detection
        echo -e "${CYAN}  [a] Technology detection...${NC}"
        whatweb "$url" > "$port_dir/whatweb.txt"
        
        # Directory brute-forcing
        echo -e "${CYAN}  [b] Directory brute-forcing...${NC}"
        if command -v gobuster &> /dev/null; then
            gobuster dir -u "$url" -w /usr/share/wordlists/dirb/common.txt -o "$port_dir/gobuster_common.txt" -t 50 &
            gobuster dir -u "$url" -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o "$port_dir/gobuster_medium.txt" -t 30 &
        fi
        
        # Nikto scan
        echo -e "${CYAN}  [c] Nikto vulnerability scan...${NC}"
        if command -v nikto &> /dev/null; then
            nikto -h "$url" -output "$port_dir/nikto.txt" -Format txt &
        fi
        
        # Check for robots.txt and sitemap.xml
        echo -e "${CYAN}  [d] Checking common files...${NC}"
        curl -s -L "$url/robots.txt" -o "$port_dir/robots.txt"
        curl -s -L "$url/sitemap.xml" -o "$port_dir/sitemap.xml"
        curl -s -L "$url/.git/HEAD" -o "$port_dir/git_check.txt"
        
        # Check for HTTP methods
        echo -e "${CYAN}  [e] Checking HTTP methods...${NC}"
        nmap -p "$port" --script http-methods "$TARGET" > "$port_dir/http_methods.txt"
        
        # Wait for background jobs
        wait
        
        # Check for specific technologies
        if grep -qi "wordpress" "$port_dir/whatweb.txt"; then
            echo -e "${YELLOW}  [!] WordPress detected - consider running wpscan${NC}"
        fi
        
        if grep -qi "joomla" "$port_dir/whatweb.txt"; then
            echo -e "${YELLOW}  [!] Joomla detected${NC}"
        fi
        
        if grep -qi "drupal" "$port_dir/whatweb.txt"; then
            echo -e "${YELLOW}  [!] Drupal detected${NC}"
        fi
    done
    
    echo -e "${GREEN}[+] Web application scan completed${NC}"
}

# Service-specific Enumeration
service_enum() {
    echo -e "${BLUE}[*] Starting Service-specific Enumeration${NC}"
    
    # Check open ports from quick scan
    if [ ! -f "$OUTPUT_DIR/nmap/quick_tcp.nmap" ]; then
        echo -e "${YELLOW}[!] Running quick scan first...${NC}"
        quick_scan
    fi
    
    # SMB/CIFS (Ports 139, 445)
    if grep -q "139/open\|445/open" "$OUTPUT_DIR/nmap/quick_tcp.nmap"; then
        echo -e "${PURPLE}[*] SMB/CIFS service detected${NC}"
        
        # Enum4linux
        if command -v enum4linux &> /dev/null; then
            echo -e "${CYAN}  [a] Running enum4linux...${NC}"
            enum4linux -a "$TARGET" > "$OUTPUT_DIR/enumeration/enum4linux.txt"
        fi
        
        # SMB client
        echo -e "${CYAN}  [b] Listing SMB shares...${NC}"
        smbclient -L "//$TARGET/" -N > "$OUTPUT_DIR/enumeration/smb_shares.txt"
        
        # Nmap SMB scripts
        echo -e "${CYAN}  [c] Running SMB NSE scripts...${NC}"
        nmap --script smb-enum-shares,smb-enum-users,smb-enum-groups,smb-os-discovery -p 139,445 -oA "$OUTPUT_DIR/enumeration/smb_nmap" "$TARGET"
    fi
    
    # RPC (Port 135)
    if grep -q "135/open" "$OUTPUT_DIR/nmap/quick_tcp.nmap"; then
        echo -e "${PURPLE}[*] RPC service detected${NC}"
        rpcinfo -p "$TARGET" > "$OUTPUT_DIR/enumeration/rpcinfo.txt" 2>&1
    fi
    
    # FTP (Port 21)
    if grep -q "21/open" "$OUTPUT_DIR/nmap/quick_tcp.nmap"; then
        echo -e "${PURPLE}[*] FTP service detected${NC}"
        nmap --script ftp-anon,ftp-bounce,ftp-syst -p 21 -oA "$OUTPUT_DIR/enumeration/ftp_nmap" "$TARGET"
        
        # Try anonymous login
        echo -e "${CYAN}  [a] Testing anonymous FTP login...${NC}"
        ftp -n "$TARGET" << EOF > "$OUTPUT_DIR/enumeration/ftp_anonymous.txt"
quote USER anonymous
quote PASS anonymous
quit
EOF
    fi
    
    # SSH (Port 22)
    if grep -q "22/open" "$OUTPUT_DIR/nmap/quick_tcp.nmap"; then
        echo -e "${PURPLE}[*] SSH service detected${NC}"
        nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 -oA "$OUTPUT_DIR/enumeration/ssh_nmap" "$TARGET"
    fi
    
    # DNS (Port 53)
    if grep -q "53/open" "$OUTPUT_DIR/nmap/quick_tcp.nmap"; then
        echo -e "${PURPLE}[*] DNS service detected${NC}"
        dig ANY "@$TARGET" "$TARGET" > "$OUTPUT_DIR/enumeration/dig_any.txt"
        nmap --script dns-nsid,dns-recursion -p 53 -oA "$OUTPUT_DIR/enumeration/dns_nmap" "$TARGET"
    fi
    
    # SNMP (Port 161)
    if grep -q "161/open" "$OUTPUT_DIR/nmap/quick_tcp.nmap"; then
        echo -e "${PURPLE}[*] SNMP service detected${NC}"
        
        # SNMP walk with public community string
        echo -e "${CYAN}  [a] SNMP walk with public community...${NC}"
        snmpwalk -c public -v1 "$TARGET" > "$OUTPUT_DIR/enumeration/snmpwalk_public.txt" 2>&1
        
        # SNMP walk with private community string
        echo -e "${CYAN}  [b] SNMP walk with private community...${NC}"
        snmpwalk -c private -v1 "$TARGET" > "$OUTPUT_DIR/enumeration/snmpwalk_private.txt" 2>&1
        
        # SNMP NSE scripts
        nmap --script snmp-info,snmp-sysdescr -p 161 -oA "$OUTPUT_DIR/enumeration/snmp_nmap" "$TARGET"
    fi
    
    echo -e "${GREEN}[+] Service enumeration completed${NC}"
}

# Vulnerability Assessment
vulnerability_assessment() {
    echo -e "${BLUE}[*] Starting Vulnerability Assessment${NC}"
    
    # Nmap vulnerability scripts
    echo -e "${CYAN}[1] Running Nmap vulnerability scripts...${NC}"
    nmap --script vuln --script-args=unsafe=1 -oA "$OUTPUT_DIR/exploits/nmap_vuln" "$TARGET"
    
    # Searchsploit for service versions
    echo -e "${CYAN}[2] Searching for exploits based on service versions...${NC}"
    
    # Extract service versions from Nmap output
    if [ -f "$OUTPUT_DIR/nmap/quick_tcp.nmap" ]; then
        grep -E "[0-9]+/tcp.*open.*" "$OUTPUT_DIR/nmap/quick_tcp.nmap" | \
        grep -oP "(?<= ).*?(?= )" | \
        while read -r service; do
            if [ ! -z "$service" ]; then
                echo -e "${YELLOW}[*] Searching exploits for: $service${NC}"
                searchsploit "$service" >> "$OUTPUT_DIR/exploits/searchsploit.txt" 2>/dev/null
            fi
        done
    fi
    
    # Check for Heartbleed
    echo -e "${CYAN}[3] Checking for Heartbleed vulnerability...${NC}"
    nmap --script ssl-heartbleed -p 443 "$TARGET" > "$OUTPUT_DIR/exploits/heartbleed_check.txt"
    
    # Check for Shellshock
    echo -e "${CYAN}[4] Checking for Shellshock vulnerability...${NC}"
    nmap --script http-shellshock -p 80,443,8080,8443 "$TARGET" > "$OUTPUT_DIR/exploits/shellshock_check.txt"
    
    # Check for common misconfigurations
    echo -e "${CYAN}[5] Checking for common misconfigurations...${NC}"
    
    # HTTP security headers check
    for port in 80 443 8080 8443; do
        if timeout 2 nc -z "$TARGET" "$port" 2>/dev/null; then
            local protocol="http"
            [ "$port" -eq 443 ] || [ "$port" -eq 8443 ] && protocol="https"
            
            curl -s -I "$protocol://$TARGET:$port" > "$OUTPUT_DIR/exploits/http_headers_$port.txt"
        fi
    done
    
    echo -e "${GREEN}[+] Vulnerability assessment completed${NC}"
}

# Custom Port Scan
custom_port_scan() {
    echo -e "${BLUE}[*] Custom Port Scan${NC}"
    
    read -p "Enter ports (comma-separated or range like 1-1000): " ports
    read -p "Scan type (tcp/udp/both) [tcp]: " scantype
    scantype=${scantype:-tcp}
    
    if [ "$scantype" = "tcp" ] || [ "$scantype" = "both" ]; then
        echo -e "${CYAN}[*] Scanning TCP ports: $ports${NC}"
        nmap -sC -sV -p "$ports" -oA "$OUTPUT_DIR/nmap/custom_tcp_$ports" "$TARGET"
    fi
    
    if [ "$scantype" = "udp" ] || [ "$scantype" = "both" ]; then
        echo -e "${CYAN}[*] Scanning UDP ports: $ports${NC}"
        nmap -sU -p "$ports" -oA "$OUTPUT_DIR/nmap/custom_udp_$ports" "$TARGET"
    fi
    
    echo -e "${GREEN}[+] Custom port scan completed${NC}"
}

# Brute Force Module
brute_force_module() {
    echo -e "${BLUE}[*] Brute Force Module${NC}"
    
    echo -e "${YELLOW}Warning: Use this only on authorized targets!${NC}"
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi
    
    echo -e "\n${CYAN}Select service to brute force:${NC}"
    echo "1) SSH (port 22)"
    echo "2) FTP (port 21)"
    echo "3) HTTP Basic Auth"
    echo "4) WordPress"
    echo "5) Return to main menu"
    
    read -p "Choice: " brute_choice
    
    case $brute_choice in
        1)
            read -p "Username (or path to userlist): " user
            read -p "Password list path [/usr/share/wordlists/rockyou.txt]: " passlist
            passlist=${passlist:-/usr/share/wordlists/rockyou.txt}
            
            if command -v hydra &> /dev/null; then
                hydra -l "$user" -P "$passlist" ssh://"$TARGET" -o "$OUTPUT_DIR/bruteforce/ssh_hydra.txt"
            fi
            ;;
        2)
            read -p "Username (or path to userlist): " user
            read -p "Password list path [/usr/share/wordlists/rockyou.txt]: " passlist
            passlist=${passlist:-/usr/share/wordlists/rockyou.txt}
            
            if command -v hydra &> /dev/null; then
                hydra -l "$user" -P "$passlist" ftp://"$TARGET" -o "$OUTPUT_DIR/bruteforce/ftp_hydra.txt"
            fi
            ;;
        3)
            read -p "URL (e.g., http://target/admin): " url
            read -p "User list path: " userlist
            read -p "Password list path: " passlist
            
            if command -v hydra &> /dev/null; then
                hydra -L "$userlist" -P "$passlist" "$url" http-get -o "$OUTPUT_DIR/bruteforce/http_basic_hydra.txt"
            fi
            ;;
        4)
            read -p "WordPress login URL: " wp_url
            read -p "Username: " wp_user
            read -p "Password list path: " wp_passlist
            
            if command -v wpscan &> /dev/null; then
                wpscan --url "$wp_url" --usernames "$wp_user" --passwords "$wp_passlist" -o "$OUTPUT_DIR/bruteforce/wpscan.txt"
            fi
            ;;
    esac
    
    echo -e "${GREEN}[+] Brute force module completed${NC}"
}

# Generate Report
generate_report() {
    echo -e "${BLUE}[*] Generating Summary Report${NC}"
    
    REPORT_FILE="$OUTPUT_DIR/scan_report_$SCAN_TIMESTAMP.txt"
    
    {
        echo "HTB Master Scanner - Scan Report"
        echo "================================="
        echo "Target: $TARGET"
        echo "Scan Date: $(date)"
        echo "Scan Duration: Started at $SCAN_TIMESTAMP"
        echo ""
        echo "SUMMARY"
        echo "-------"
        
        # Quick overview of findings
        if [ -f "$OUTPUT_DIR/nmap/quick_tcp.nmap" ]; then
            echo "Open TCP Ports:"
            grep -E "^[0-9]+/tcp.*open" "$OUTPUT_DIR/nmap/quick_tcp.nmap" || echo "None found"
            echo ""
        fi
        
        if [ -f "$OUTPUT_DIR/nmap/quick_udp.nmap" ]; then
            echo "Open UDP Ports:"
            grep -E "^[0-9]+/udp.*open" "$OUTPUT_DIR/nmap/quick_udp.nmap" || echo "None found"
            echo ""
        fi
        
        # Check for interesting findings
        echo "INTERESTING FINDINGS"
        echo "--------------------"
        
        # Check for low-hanging fruit
        if [ -f "$OUTPUT_DIR/enumeration/ftp_anonymous.txt" ] && grep -q "230" "$OUTPUT_DIR/enumeration/ftp_anonymous.txt"; then
            echo "[!] FTP Anonymous login allowed!"
        fi
        
        if [ -f "$OUTPUT_DIR/enumeration/smb_shares.txt" ] && grep -q "Anonymous" "$OUTPUT_DIR/enumeration/smb_shares.txt"; then
            echo "[!] SMB shares accessible anonymously!"
        fi
        
        # Check for vulnerable services
        if [ -f "$OUTPUT_DIR/exploits/searchsploit.txt" ] && [ -s "$OUTPUT_DIR/exploits/searchsploit.txt" ]; then
            echo "[!] Possible exploits found in searchsploit database"
        fi
        
        # Directory listing
        echo ""
        echo "SCAN DIRECTORY STRUCTURE"
        echo "------------------------"
        find "$OUTPUT_DIR" -type f | sed "s|$OUTPUT_DIR/||" | sort
        
        echo ""
        echo "NEXT STEPS RECOMMENDED"
        echo "----------------------"
        echo "1. Review all Nmap scan results"
        echo "2. Check web directories found with Gobuster"
        echo "3. Examine service-specific enumeration results"
        echo "4. Look for default credentials on identified services"
        echo "5. Test identified vulnerabilities"
        
    } > "$REPORT_FILE"
    
    echo -e "${GREEN}[+] Report generated: $REPORT_FILE${NC}"
    echo -e "${CYAN}[*] To view full results, check the following directories:${NC}"
    echo "  - Nmap scans: $OUTPUT_DIR/nmap/"
    echo "  - Web enumeration: $OUTPUT_DIR/web/"
    echo "  - Service enumeration: $OUTPUT_DIR/enumeration/"
    echo "  - Exploits: $OUTPUT_DIR/exploits/"
}

# Automated Full Assessment
automated_full_assessment() {
    echo -e "${BLUE}[*] Starting Automated Full Assessment${NC}"
    echo -e "${YELLOW}This will run multiple scans sequentially.${NC}"
    echo -e "${YELLOW}Estimated time: 15-30 minutes${NC}"
    
    quick_scan
    full_scan
    web_scan
    service_enum
    vulnerability_assessment
    generate_report
    
    echo -e "${GREEN}[+] Automated full assessment completed!${NC}"
}

# Main menu
main_menu() {
    while true; do
        print_banner
        echo -e "${CYAN}Target: ${GREEN}$TARGET${NC}"
        echo -e "${CYAN}Output Directory: ${GREEN}$OUTPUT_DIR${NC}\n"
        
        echo -e "${PURPLE}${BOLD}MAIN MENU${NC}"
        echo -e "${YELLOW}1.  Set Target${NC}"
        echo -e "${YELLOW}2.  Quick Scan (Fast recon)${NC}"
        echo -e "${YELLOW}3.  Full Comprehensive Scan${NC}"
        echo -e "${YELLOW}4.  Web Application Scan${NC}"
        echo -e "${YELLOW}5.  Service-specific Enumeration${NC}"
        echo -e "${YELLOW}6.  Vulnerability Assessment${NC}"
        echo -e "${YELLOW}7.  Custom Port Scan${NC}"
        echo -e "${YELLOW}8.  Brute Force Module${NC}"
        echo -e "${YELLOW}9.  Automated Full Assessment${NC}"
        echo -e "${YELLOW}10. Generate Report${NC}"
        echo -e "${YELLOW}11. View Results${NC}"
        echo -e "${YELLOW}0.  Exit${NC}"
        
        echo -e "\n${CYAN}Select an option (0-11): ${NC}"
        read -r choice
        
        case $choice in
            0)
                echo -e "${GREEN}[+] Exiting HTB Master Scanner${NC}"
                exit 0
                ;;
            1)
                read -p "Enter new target IP/hostname: " TARGET
                setup_directories
                ;;
            2)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    read -p "Enter target IP/hostname: " TARGET
                fi
                setup_directories
                quick_scan
                ;;
            3)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    read -p "Enter target IP/hostname: " TARGET
                fi
                setup_directories
                full_scan
                ;;
            4)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    read -p "Enter target IP/hostname: " TARGET
                fi
                setup_directories
                web_scan
                ;;
            5)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    read -p "Enter target IP/hostname: " TARGET
                fi
                setup_directories
                service_enum
                ;;
            6)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    read -p "Enter target IP/hostname: " TARGET
                fi
                setup_directories
                vulnerability_assessment
                ;;
            7)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    read -p "Enter target IP/hostname: " TARGET
                fi
                setup_directories
                custom_port_scan
                ;;
            8)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    read -p "Enter target IP/hostname: " TARGET
                fi
                setup_directories
                brute_force_module
                ;;
            9)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                    read -p "Enter target IP/hostname: " TARGET
                fi
                setup_directories
                automated_full_assessment
                ;;
            10)
                if [ -z "$TARGET" ]; then
                    echo -e "${RED}[!] Please set target first${NC}"
                else
                    generate_report
                fi
                ;;
            11)
                if [ -z "$OUTPUT_DIR" ]; then
                    echo -e "${RED}[!] No scan directory found${NC}"
                else
                    echo -e "${CYAN}[*] Scan results in: $OUTPUT_DIR${NC}"
                    ls -la "$OUTPUT_DIR"
                fi
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                ;;
        esac
        
        echo -e "\n${CYAN}Press Enter to continue...${NC}"
        read -r
    done
}

# Installation helper
install_dependencies() {
    echo -e "${BLUE}[*] Installing recommended tools${NC}"
    
    if command -v apt &> /dev/null; then
        sudo apt update
        sudo apt install -y nmap gobuster nikto whatweb enum4linux smbclient \
            searchsploit hydra john medusa sqlmap wpscan dirbuster \
            dnsutils snmp python3 python3-pip
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap nikto whatweb samba-client \
            exploit hydra john medusa sqlmap dnsutils net-snmp-utils \
            python3 python3-pip
    elif command -v pacman &> /dev/null; then
        sudo pacman -Syu --noconfirm nmap gobuster nikto whatweb \
            samba hydra john medusa sqlmap wpscan dnsutils net-snmp \
            python python-pip
    else
        echo -e "${RED}[!] Could not detect package manager${NC}"
        return
    fi
    
    # Install Python tools
    pip3 install --upgrade pip
    pip3 install requests beautifulsoup4 lxml
    
    echo -e "${GREEN}[+] Tools installation completed${NC}"
}

# Main execution
if [ "$1" == "--install" ]; then
    install_dependencies
    exit 0
fi

print_banner
check_tools

# Check if target provided as argument
if [ ! -z "$1" ] && [ "$1" != "--install" ]; then
    TARGET="$1"
fi

setup_directories
main_menu




# # Install recommended tools (for Kali/Parrot/Ubuntu)
# ./htb_scanner.sh --install


# Run without target (will ask for it)
# ./htb_scanner.sh

# Run with target IP
# ./htb_scanner.sh 10.10.10.10

# 1. Set target (or provide as argument)
# ./htb_scanner.sh 10.10.10.10

# 2. In the menu:
#    - Choose 2 for Quick Scan (first)
#    - Choose 4 for Web Scan (if web ports found)
#    - Choose 5 for Service Enumeration
#    - Choose 6 for Vulnerability Scan
#    - Choose 10 for Report

# OR use automated full assessment:
#    - Choose 9 for everything at once

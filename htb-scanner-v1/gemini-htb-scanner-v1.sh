#!/bin/bash

# --- COLORS FOR PRETTY OUTPUT ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- SETUP & VALIDATION ---
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: ./htb_scan.sh <TARGET_IP>${NC}"
    exit 1
fi

TARGET=$1
mkdir -p "$TARGET/nmap"
mkdir -p "$TARGET/web"
mkdir -p "$TARGET/vuln"

echo -e "${BLUE}[*] Target set to: $TARGET${NC}"
echo -e "${BLUE}[*] Output directories created in ./$TARGET${NC}"

# --- FUNCTIONS ---

# 1. FAST SCAN: Quick check of top 1000 ports to get started immediately
function scan_fast() {
    echo -e "${YELLOW}[+] Starting FAST TCP Scan (Top 1000 ports)...${NC}"
    nmap -T4 -F -oN "$TARGET/nmap/fast_scan.txt" $TARGET
    echo -e "${GREEN}[*] Fast scan saved to $TARGET/nmap/fast_scan.txt${NC}"
}

# 2. FULL PORT SCAN: Scans all 65535 ports, then scripts/versions on open ones
function scan_full() {
    echo -e "${YELLOW}[+] Phase 1: Identifying ALL open ports (1-65535)...${NC}"
    # This grabs only the port numbers to make the second step faster
    ports=$(nmap -p- --min-rate 1000 -T4 $TARGET | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
    
    if [ -z "$ports" ]; then
        echo -e "${RED}[!] No ports found. Is the host up?${NC}"
        return
    fi

    echo -e "${YELLOW}[+] Phase 2: Deep scanning on ports: $ports${NC}"
    nmap -sC -sV -p"$ports" -oA "$TARGET/nmap/full_scan" $TARGET
    echo -e "${GREEN}[*] Full scan saved to $TARGET/nmap/full_scan.*${NC}"
}

# 3. VULN SCAN: Uses Nmap NSE scripts to check for known CVEs
function scan_vuln() {
    echo -e "${YELLOW}[+] Starting Vulnerability Scan (NSE)...${NC}"
    # We assume you want to check common ports, or you can pass specific ports if known
    nmap --script vuln -T4 -oN "$TARGET/vuln/nmap_vuln.txt" $TARGET
    echo -e "${GREEN}[*] Vuln scan saved to $TARGET/vuln/nmap_vuln.txt${NC}"
}

# 4. WEB ENUMERATION: Runs Gobuster and Nikto
function scan_web() {
    echo -e "${YELLOW}[+] Starting Web Enumeration (Port 80/443)...${NC}"
    
    # Check if user wants http or https
    read -p "Is the target HTTP or HTTPS? (default: http): " PROTO
    PROTO=${PROTO:-http}

    echo -e "${BLUE}[*] Running Gobuster directory brute-force...${NC}"
    # Adjust wordlist path if you are not on Kali/Parrot
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
    
    if [ -f "$WORDLIST" ]; then
        gobuster dir -u $PROTO://$TARGET -w $WORDLIST -o "$TARGET/web/gobuster.txt" -t 50
    else
        echo -e "${RED}[!] Wordlist $WORDLIST not found. Skipping Gobuster.${NC}"
    fi

    echo -e "${BLUE}[*] Running Nikto scanner...${NC}"
    nikto -h $PROTO://$TARGET -output "$TARGET/web/nikto.txt"
    
    echo -e "${GREEN}[*] Web scans saved to $TARGET/web/${NC}"
}

# --- MAIN MENU ---
while true; do
    echo -e "\n${BLUE}--- HTB SCANNER MENU ---${NC}"
    echo "1. Fast Scan (Top 1000 Ports)"
    echo "2. Full Scan (All Ports + Versions + Scripts)"
    echo "3. Vulnerability Scan (Nmap Vuln NSE)"
    echo "4. Web Enumeration (Gobuster + Nikto)"
    echo "5. Run ALL Scans (Sequential)"
    echo "6. Exit"
    
    read -p "Select an option [1-6]: " choice

    case $choice in
        1) scan_fast ;;
        2) scan_full ;;
        3) scan_vuln ;;
        4) scan_web ;;
        5) 
           scan_full
           scan_vuln
           scan_web
           ;;
        6) echo "Exiting..."; exit 0 ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
done

# chmod +x htb_scan.sh
# ./htb_scan.sh 10.10.11.23

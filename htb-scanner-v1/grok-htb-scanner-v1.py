import subprocess
import argparse
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

# Function to check if a tool is installed
def check_tool_installed(tool_name):
    try:
        subprocess.run([tool_name, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

# Function for reconnaissance scan
def reconnaissance_scan(target, output_dir):
    print(f"[+] Starting reconnaissance scan on {target}")
    
    # Ping check
    ping_cmd = ['ping', '-c', '1', target]
    subprocess.run(ping_cmd, stdout=subprocess.DEVNULL)
    
    # Basic Nmap scan
    nmap_cmd = ['nmap', '-sV', '-O', '-oX', f'{output_dir}/recon.xml', target]
    subprocess.run(nmap_cmd)
    
    print("[+] Reconnaissance scan completed. Results in recon.xml")

# Function for vulnerability scan
def vulnerability_scan(target, output_dir):
    print(f"[+] Starting vulnerability scan on {target}")
    
    # Nmap with vuln scripts
    nmap_vuln_cmd = ['nmap', '--script', 'vuln', '-oX', f'{output_dir}/vuln.xml', target]
    subprocess.run(nmap_vuln_cmd)
    
    # If HTTP ports are open, run Nikto
    if check_http_open(output_dir):
        nikto_cmd = ['nikto', '-h', target, '-output', f'{output_dir}/nikto.txt']
        subprocess.run(nikto_cmd)
    
    print("[+] Vulnerability scan completed.")

# Function to check if HTTP/HTTPS is open from Nmap XML
def check_http_open(output_dir):
    try:
        tree = ET.parse(f'{output_dir}/recon.xml')  # Assuming recon has been run or similar
        root = tree.getroot()
        for port in root.iter('port'):
            if port.attrib['portid'] in ['80', '443'] and port.find('state').attrib['state'] == 'open':
                return True
        return False
    except Exception:
        return False

# Function for enumeration scan
def enumeration_scan(target, output_dir):
    print(f"[+] Starting enumeration scan on {target}")
    
    # Directory brute-forcing if HTTP open
    if check_http_open(output_dir):
        gobuster_cmd = ['gobuster', 'dir', '-u', f'http://{target}', '-w', '/usr/share/wordlists/dirb/common.txt', '-o', f'{output_dir}/gobuster.txt']
        subprocess.run(gobuster_cmd)
    
    # SMB enumeration
    enum4linux_cmd = ['enum4linux', '-a', target, '>', f'{output_dir}/enum4linux.txt']
    subprocess.run(enum4linux_cmd, shell=True)
    
    print("[+] Enumeration scan completed.")

# Function for generating report
def generate_report(output_dir):
    print("[+] Generating report")
    report_file = f'{output_dir}/report.md'
    with open(report_file, 'w') as f:
        f.write('# HTB Scan Report\n')
        f.write(f'Generated on: {datetime.now()}\n\n')
        
        # Append recon results
        if os.path.exists(f'{output_dir}/recon.xml'):
            f.write('## Reconnaissance Results\n')
            with open(f'{output_dir}/recon.xml', 'r') as recon:
                f.write('```xml\n' + recon.read() + '\n```\n')
        
        # Append vuln results
        if os.path.exists(f'{output_dir}/vuln.xml'):
            f.write('## Vulnerability Results\n')
            with open(f'{output_dir}/vuln.xml', 'r') as vuln:
                f.write('```xml\n' + vuln.read() + '\n```\n')
        
        # Append other files
        for file in ['nikto.txt', 'gobuster.txt', 'enum4linux.txt']:
            if os.path.exists(f'{output_dir}/{file}'):
                f.write(f'## {file.split(".")[0].capitalize()} Results\n')
                with open(f'{output_dir}/{file}', 'r') as res:
                    f.write('```\n' + res.read() + '\n```\n')
    
    print(f"[+] Report generated: {report_file}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="HTB Machine Scanner Script")
    parser.add_argument('target', type=str, help="Target IP address")
    parser.add_argument('--type', choices=['recon', 'vuln', 'enum', 'report', 'all'], required=True,
                        help="Type of scan: recon, vuln, enum, report, or all")
    parser.add_argument('--output', default='output', help="Output directory (default: output)")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Check required tools
    required_tools = ['nmap', 'nikto', 'gobuster', 'enum4linux']
    for tool in required_tools:
        if not check_tool_installed(tool):
            print(f"[-] Error: {tool} is not installed. Please install it.")
            sys.exit(1)
    
    if args.type == 'recon' or args.type == 'all':
        reconnaissance_scan(args.target, args.output)
    
    if args.type == 'vuln' or args.type == 'all':
        vulnerability_scan(args.target, args.output)
    
    if args.type == 'enum' or args.type == 'all':
        enumeration_scan(args.target, args.output)
    
    if args.type == 'report' or args.type == 'all':
        generate_report(args.output)

if __name__ == "__main__":
    main()


# How to Use This Script
# 
# Prerequisites: Install the tools mentioned (Nmap, Nikto, Gobuster, Enum4linux) on your system (e.g., via apt on Kali). Also, ensure you have a wordlist for Gobuster (like /usr/share/wordlists/dirb/common.txt—adjust if needed).
# Running the Script:
# Save it as htb_scanner.py.
# Example: python htb_scanner.py 10.10.10.123 --type all --output results/ (replace IP with your HTB target).
# Choices:
# recon: Basic host discovery and service scan.
# vuln: Checks for known vulnerabilities.
# enum: Enumerates services like web directories or SMB.
# report: Compiles results into a Markdown file.
# all: Runs everything in sequence.
# 
# 
# Notes: This assumes you've run recon first for some checks (like HTTP ports). For real use, connect via HTB VPN. Customize paths/tools as needed. This is educational—test on your own VMs first!

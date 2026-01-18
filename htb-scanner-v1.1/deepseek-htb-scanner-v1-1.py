#!/usr/bin/env python3
"""
HTB Advanced Scanner - Professional Enumeration Tool
Features:
- Real-time progress with percentages
- No interruptions during scans
- Parallel processing
- Clean, organized output
- Script-like usage from command line
- All results displayed at the end
"""

import sys
import os
import time
import signal
import threading
import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import shutil
import re

# Color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Progress bar class
class ProgressBar:
    def __init__(self, total=100, length=50, prefix='Progress:', suffix='Complete', show_percent=True):
        self.total = total
        self.length = length
        self.prefix = prefix
        self.suffix = suffix
        self.show_percent = show_percent
        self.current = 0
        self.start_time = time.time()
        
    def update(self, current):
        self.current = current
        self.display()
        
    def increment(self, amount=1):
        self.current += amount
        self.display()
        
    def display(self):
        percent = 100 * (self.current / float(self.total))
        filled_length = int(self.length * self.current // self.total)
        bar = '█' * filled_length + '░' * (self.length - filled_length)
        
        elapsed = time.time() - self.start_time
        if self.current > 0:
            estimated_total = elapsed * (self.total / self.current)
            remaining = estimated_total - elapsed
            time_str = f" | Elapsed: {elapsed:.1f}s | Remaining: {remaining:.1f}s"
        else:
            time_str = ""
            
        if self.show_percent:
            print(f'\r{self.prefix} |{bar}| {percent:.1f}% {self.suffix}{time_str}', end='', flush=True)
        else:
            print(f'\r{self.prefix} |{bar}| {self.current}/{self.total} {self.suffix}{time_str}', end='', flush=True)
            
    def complete(self):
        self.update(self.total)
        print()

# Spinner for indeterminate progress
class Spinner:
    def __init__(self, message="", delay=0.1):
        self.message = message
        self.delay = delay
        self.spinner_generator = self.spinning_cursor()
        self.running = False
        self.spinner_thread = None
        
    def spinning_cursor(self):
        while True:
            for cursor in '|/-\\':
                yield cursor
                
    def spin(self):
        while self.running:
            sys.stdout.write(f'\r{self.message} {next(self.spinner_generator)}')
            sys.stdout.flush()
            time.sleep(self.delay)
            
    def __enter__(self):
        self.running = True
        self.spinner_thread = threading.Thread(target=self.spin)
        self.spinner_thread.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self.spinner_thread:
            self.spinner_thread.join()
        sys.stdout.write(f'\r{self.message} ✓\n')
        sys.stdout.flush()

# Nmap scanner with real-time progress
class NmapScanner:
    def __init__(self, target, output_dir, quiet=False):
        self.target = target
        self.output_dir = Path(output_dir)
        self.quiet = quiet
        self.results = {}
        
    def _run_with_progress(self, command, description, total_ports=None):
        """Run command with progress indicator"""
        print(f"{Colors.BLUE}[*]{Colors.END} {description}")
        
        if self.quiet:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout, result.stderr
            
        # For nmap, we can parse output for progress
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        output_lines = []
        last_progress = 0
        
        for line in iter(process.stdout.readline, ''):
            output_lines.append(line)
            
            # Parse nmap progress
            if "About" in line and "% done" in line:
                match = re.search(r'About (\d+\.?\d*)% done', line)
                if match:
                    progress = float(match.group(1))
                    if progress > last_progress:
                        print(f"\r  Progress: {progress:.1f}%", end='', flush=True)
                        last_progress = progress
            elif not self.quiet:
                # Show interesting findings immediately
                if "open" in line.lower() or "discovered" in line.lower():
                    print(f"\r  {line.strip()}")
                    
        process.wait()
        print()  # New line after progress
        
        return ''.join(output_lines), ""
    
    def quick_scan(self):
        """Quick scan top 1000 ports with service detection"""
        cmd = f"nmap -sC -sV -T4 --open -oN {self.output_dir}/nmap_quick.txt -oX {self.output_dir}/nmap_quick.xml {self.target}"
        output, _ = self._run_with_progress(cmd, "Quick scan (top 1000 ports)")
        return self._parse_nmap_xml(f"{self.output_dir}/nmap_quick.xml")
    
    def full_port_scan(self):
        """Scan all 65535 ports"""
        print(f"{Colors.BLUE}[*]{Colors.END} Full port scan (all 65535 ports)")
        print(f"{Colors.YELLOW}[!]{Colors.END} This may take a while...")
        
        # Stage 1: Fast scan to find open ports
        print(f"  Stage 1/2: Fast discovery")
        cmd = f"nmap -T4 --max-retries 1 --min-rate=1000 -p- -oN {self.output_dir}/nmap_all_ports.txt {self.target}"
        output, _ = self._run_with_progress(cmd, "")
        
        # Parse open ports
        open_ports = []
        with open(f"{self.output_dir}/nmap_all_ports.txt", 'r') as f:
            for line in f:
                if "/tcp" in line and "open" in line:
                    port = line.split('/')[0]
                    open_ports.append(port)
        
        if not open_ports:
            print(f"{Colors.YELLOW}[!]{Colors.END} No open TCP ports found")
            return {}
        
        # Stage 2: Service detection on open ports
        print(f"  Stage 2/2: Service detection on {len(open_ports)} open ports")
        ports_str = ','.join(open_ports)
        cmd = f"nmap -sC -sV -T4 -p {ports_str} -oN {self.output_dir}/nmap_services.txt -oX {self.output_dir}/nmap_services.xml {self.target}"
        output, _ = self._run_with_progress(cmd, "")
        
        return self._parse_nmap_xml(f"{self.output_dir}/nmap_services.xml")
    
    def udp_scan(self, top_ports=200):
        """Scan top UDP ports"""
        cmd = f"nmap -sU --top-ports {top_ports} -T4 -oN {self.output_dir}/nmap_udp.txt {self.target}"
        return self._run_with_progress(cmd, f"UDP scan (top {top_ports} ports)")
    
    def vulnerability_scan(self, open_ports=None):
        """Run vulnerability scans on open ports"""
        if open_ports:
            ports_str = ','.join(open_ports)
            cmd = f"nmap --script vuln -p {ports_str} -oN {self.output_dir}/nmap_vuln.txt {self.target}"
        else:
            cmd = f"nmap --script vuln -oN {self.output_dir}/nmap_vuln.txt {self.target}"
        
        return self._run_with_progress(cmd, "Vulnerability scan")
    
    def _parse_nmap_xml(self, xml_file):
        """Parse nmap XML output to structured data"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                'host': self.target,
                'ports': [],
                'services': {}
            }
            
            for host in root.findall('host'):
                for ports in host.findall('ports'):
                    for port in ports.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        state = port.find('state').get('state') if port.find('state') is not None else 'unknown'
                        
                        service_info = {}
                        service = port.find('service')
                        if service is not None:
                            service_info = {
                                'name': service.get('name', ''),
                                'product': service.get('product', ''),
                                'version': service.get('version', ''),
                                'extrainfo': service.get('extrainfo', '')
                            }
                        
                        port_data = {
                            'port': port_id,
                            'protocol': protocol,
                            'state': state,
                            'service': service_info
                        }
                        
                        results['ports'].append(port_data)
                        
                        if state == 'open':
                            service_name = service_info.get('name', 'unknown')
                            if service_name not in results['services']:
                                results['services'][service_name] = []
                            results['services'][service_name].append(port_id)
            
            return results
            
        except Exception as e:
            print(f"{Colors.RED}[-]{Colors.END} Failed to parse XML: {e}")
            return {}

# Web application scanner
class WebScanner:
    def __init__(self, target, output_dir, ports=None):
        self.target = target
        self.output_dir = Path(output_dir) / "web"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ports = ports or [80, 443, 8080, 8443, 8000, 3000]
        self.tools = self._check_tools()
        
    def _check_tools(self):
        """Check which tools are available"""
        tools = {}
        for tool in ['feroxbuster', 'gobuster', 'whatweb', 'dirb', 'ffuf']:
            if shutil.which(tool):
                tools[tool] = True
        return tools
    
    def discover_web_ports(self):
        """Check which ports have web services"""
        web_ports = []
        
        with Spinner("Checking web ports"):
            for port in self.ports:
                try:
                    # Try HTTP
                    result = subprocess.run(
                        f"timeout 2 curl -s -I http://{self.target}:{port}",
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    
                    # Try HTTPS
                    if "HTTP" not in result.stdout:
                        result = subprocess.run(
                            f"timeout 2 curl -s -I -k https://{self.target}:{port}",
                            shell=True,
                            capture_output=True,
                            text=True
                        )
                    
                    if "HTTP" in result.stdout:
                        web_ports.append(port)
                        
                except Exception:
                    continue
        
        return web_ports
    
    def scan_port(self, port):
        """Scan a single web port"""
        print(f"{Colors.CYAN}[*]{Colors.END} Scanning web service on port {port}")
        
        protocol = "https" if port in [443, 8443] else "http"
        url = f"{protocol}://{self.target}:{port}"
        port_dir = self.output_dir / f"port_{port}"
        port_dir.mkdir(exist_ok=True)
        
        results = {
            'port': port,
            'url': url,
            'tools': {}
        }
        
        # 1. Technology detection
        if 'whatweb' in self.tools:
            with Spinner(f"  Technology detection (whatweb)"):
                cmd = f"whatweb -a 3 {url} --log-verbose={port_dir}/whatweb.txt"
                subprocess.run(cmd, shell=True, capture_output=True)
        
        # 2. Directory brute-forcing (parallel)
        dir_tools = []
        if 'feroxbuster' in self.tools:
            dir_tools.append(('feroxbuster', f"feroxbuster -u {url} -w /usr/share/wordlists/dirb/common.txt -o {port_dir}/feroxbuster.txt -t 50 -q"))
        if 'gobuster' in self.tools:
            dir_tools.append(('gobuster', f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -o {port_dir}/gobuster.txt -t 50 -q"))
        
        # Run directory tools in parallel
        if dir_tools:
            print(f"  Directory brute-forcing with {len(dir_tools)} tools...")
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {executor.submit(subprocess.run, cmd, shell=True, capture_output=True): name 
                          for name, cmd in dir_tools}
                
                for future in as_completed(futures):
                    tool_name = futures[future]
                    try:
                        future.result(timeout=300)  # 5 minute timeout
                        results['tools'][tool_name] = "completed"
                    except Exception as e:
                        results['tools'][tool_name] = f"failed: {e}"
        
        # 3. Check common files
        common_files = ['robots.txt', 'sitemap.xml', 'crossdomain.xml', '.git/HEAD', 
                       '.env', 'wp-config.php', 'config.php', 'README.md']
        
        for file in common_files:
            try:
                subprocess.run(
                    f"curl -s -L {url}/{file} -o {port_dir}/{file.replace('/', '_')}.txt",
                    shell=True,
                    capture_output=True,
                    timeout=2
                )
            except:
                pass
        
        return results

# Service-specific enumerator
class ServiceEnumerator:
    def __init__(self, target, output_dir, open_ports):
        self.target = target
        self.output_dir = Path(output_dir) / "services"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.open_ports = open_ports
        
    def enumerate(self):
        """Enumerate services based on open ports"""
        print(f"{Colors.MAGENTA}[*]{Colors.END} Service enumeration")
        
        tasks = []
        
        # Group ports by likely service
        for port_info in self.open_ports:
            port = port_info['port']
            service = port_info['service'].get('name', '')
            
            if '21' in port or service == 'ftp':
                tasks.append(('ftp', self.enumerate_ftp))
            elif '22' in port or service == 'ssh':
                tasks.append(('ssh', self.enumerate_ssh))
            elif '139' in port or '445' in port or service in ['netbios', 'microsoft-ds']:
                tasks.append(('smb', self.enumerate_smb))
            elif '80' in port or '443' in port or service == 'http':
                tasks.append(('http', self.enumerate_http_headers))
            elif '161' in port or service == 'snmp':
                tasks.append(('snmp', self.enumerate_snmp))
        
        # Run enumeration in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(func): name for name, func in tasks}
            
            for future in as_completed(futures):
                service_name = futures[future]
                try:
                    future.result(timeout=60)
                except Exception as e:
                    print(f"{Colors.RED}[-]{Colors.END} {service_name} enumeration failed: {e}")
    
    def enumerate_ftp(self):
        """FTP enumeration"""
        print(f"  FTP enumeration")
        cmds = [
            f"nmap --script ftp-anon,ftp-bounce,ftp-syst -p 21 {self.target} -oN {self.output_dir}/ftp_nmap.txt",
            f"echo 'quit' | timeout 5 ftp -n {self.target} 21 | head -20 > {self.output_dir}/ftp_banner.txt"
        ]
        
        for cmd in cmds:
            subprocess.run(cmd, shell=True, capture_output=True)
    
    def enumerate_smb(self):
        """SMB enumeration"""
        print(f"  SMB enumeration")
        cmds = []
        
        if shutil.which('smbclient'):
            cmds.append(f"smbclient -L //{self.target}/ -N > {self.output_dir}/smb_shares.txt 2>&1")
        
        if shutil.which('enum4linux'):
            cmds.append(f"enum4linux -a {self.target} > {self.output_dir}/enum4linux.txt 2>&1")
        
        cmds.append(f"nmap --script smb-enum-shares,smb-enum-users -p 139,445 {self.target} -oN {self.output_dir}/smb_nmap.txt")
        
        for cmd in cmds:
            subprocess.run(cmd, shell=True, capture_output=True)
    
    def enumerate_ssh(self):
        """SSH enumeration"""
        print(f"  SSH enumeration")
        cmd = f"nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 {self.target} -oN {self.output_dir}/ssh_nmap.txt"
        subprocess.run(cmd, shell=True, capture_output=True)
    
    def enumerate_snmp(self):
        """SNMP enumeration"""
        print(f"  SNMP enumeration")
        community_strings = ['public', 'private', 'manager']
        
        for community in community_strings:
            cmd = f"snmpwalk -c {community} -v1 {self.target} > {self.output_dir}/snmp_{community}.txt 2>&1"
            subprocess.run(cmd, shell=True, capture_output=True)
    
    def enumerate_http_headers(self):
        """HTTP headers enumeration"""
        print(f"  HTTP headers check")
        for port in [80, 443, 8080, 8443]:
            for proto in ['http', 'https']:
                if (proto == 'https' and port in [443, 8443]) or (proto == 'http' and port in [80, 8080]):
                    url = f"{proto}://{self.target}:{port}"
                    cmd = f"curl -s -I {url} > {self.output_dir}/headers_{port}.txt 2>&1"
                    subprocess.run(cmd, shell=True, capture_output=True)

# Main scanner class
class HTBScanner:
    def __init__(self, target, output_dir=None, quiet=False, fast=False):
        self.target = target
        self.quiet = quiet
        self.fast = fast
        
        # Create output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = Path(f"scans/{target}_{timestamp}")
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.nmap = NmapScanner(target, self.output_dir, quiet)
        self.web_scanner = WebScanner(target, self.output_dir)
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'open_ports': [],
            'services': {},
            'web_ports': [],
            'vulnerabilities': [],
            'findings': []
        }
    
    def quick_recon(self):
        """Quick reconnaissance"""
        print(f"{Colors.BOLD}{Colors.CYAN}=== QUICK RECONNAISSANCE ==={Colors.END}")
        
        # Quick Nmap scan
        nmap_results = self.nmap.quick_scan()
        self.results['open_ports'] = nmap_results.get('ports', [])
        self.results['services'] = nmap_results.get('services', {})
        
        # Display results immediately
        self._display_open_ports()
        
        return self.results
    
    def full_scan(self):
        """Full comprehensive scan"""
        print(f"{Colors.BOLD}{Colors.CYAN}=== FULL COMPREHENSIVE SCAN ==={Colors.END}")
        
        # Full port scan
        nmap_results = self.nmap.full_port_scan()
        self.results['open_ports'] = nmap_results.get('ports', [])
        self.results['services'] = nmap_results.get('services', {})
        
        # Display open ports
        self._display_open_ports()
        
        # Run additional scans based on open ports
        self._run_additional_scans()
        
        # Display all results at the end
        self._display_summary()
        
        return self.results
    
    def _run_additional_scans(self):
        """Run additional scans based on discovered services"""
        open_ports = [p['port'] for p in self.results['open_ports'] if p['state'] == 'open']
        
        # 1. Vulnerability scan
        if not self.fast:
            print(f"\n{Colors.BLUE}[*]{Colors.END} Running vulnerability scan")
            self.nmap.vulnerability_scan(open_ports)
        
        # 2. Web scanning
        web_ports = self.web_scanner.discover_web_ports()
        self.results['web_ports'] = web_ports
        
        if web_ports:
            print(f"\n{Colors.GREEN}[+]{Colors.END} Found web services on ports: {', '.join(map(str, web_ports))}")
            
            # Scan each web port
            for port in web_ports:
                self.web_scanner.scan_port(port)
        
        # 3. Service enumeration
        if self.results['open_ports']:
            print(f"\n{Colors.MAGENTA}[*]{Colors.END} Running service enumeration")
            enumerator = ServiceEnumerator(self.target, self.output_dir, self.results['open_ports'])
            enumerator.enumerate()
        
        # 4. UDP scan (optional, can be slow)
        if not self.fast:
            print(f"\n{Colors.BLUE}[*]{Colors.END} Running UDP scan")
            self.nmap.udp_scan()
    
    def _display_open_ports(self):
        """Display open ports in a nice table"""
        open_ports = [p for p in self.results['open_ports'] if p['state'] == 'open']
        
        if not open_ports:
            print(f"{Colors.YELLOW}[!]{Colors.END} No open ports found")
            return
        
        print(f"\n{Colors.GREEN}[+]{Colors.END} Open Ports Found:")
        print(f"{'='*60}")
        print(f"{Colors.BOLD}{'PORT':<8} {'PROTOCOL':<10} {'SERVICE':<15} {'VERSION':<20}{Colors.END}")
        print(f"{'='*60}")
        
        for port in open_ports:
            service = port['service']
            service_name = service.get('name', 'unknown')
            product = service.get('product', '')
            version = service.get('version', '')
            
            version_str = f"{product} {version}".strip()
            if len(version_str) > 20:
                version_str = version_str[:17] + "..."
            
            print(f"{port['port']:<8} {port['protocol']:<10} {service_name:<15} {version_str:<20}")
        
        print(f"{'='*60}")
    
    def _display_summary(self):
        """Display comprehensive summary at the end"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}=== SCAN SUMMARY ==={Colors.END}")
        print(f"Target: {self.target}")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Results directory: {self.output_dir}")
        
        # Open ports
        open_ports = [p for p in self.results['open_ports'] if p['state'] == 'open']
        print(f"\n{Colors.GREEN}[+]{Colors.END} Open Ports: {len(open_ports)}")
        
        # Web services
        if self.results['web_ports']:
            print(f"{Colors.GREEN}[+]{Colors.END} Web Services: {', '.join(map(str, self.results['web_ports']))}")
        
        # Services by type
        print(f"\n{Colors.BOLD}Services by type:{Colors.END}")
        for service, ports in self.results['services'].items():
            if service != 'unknown':
                print(f"  {service}: {', '.join(ports)}")
        
        # Next steps
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Next Steps:{Colors.END}")
        
        if '80' in str(self.results['web_ports']) or '443' in str(self.results['web_ports']):
            print(f"  • Check web directories: {self.output_dir}/web/")
        
        if '21' in str(self.results['services']):
            print(f"  • Check FTP anonymous login")
        
        if '139' in str(self.results['services']) or '445' in str(self.results['services']):
            print(f"  • Check SMB shares: {self.output_dir}/services/")
        
        if '22' in str(self.results['services']):
            print(f"  • Check SSH configuration")
        
        print(f"\n{Colors.CYAN}[*]{Colors.END} Full results available in: {self.output_dir}/")
    
    def generate_report(self):
        """Generate JSON report"""
        report_file = self.output_dir / "scan_report.json"
        
        # Add file listings to report
        self.results['files'] = {}
        for root, dirs, files in os.walk(self.output_dir):
            rel_root = os.path.relpath(root, self.output_dir)
            if rel_root == '.':
                rel_root = ''
            
            for file in files:
                filepath = os.path.join(rel_root, file) if rel_root else file
                self.results['files'][filepath] = os.path.getsize(os.path.join(root, file))
        
        # Write JSON report
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"{Colors.GREEN}[+]{Colors.END} JSON report generated: {report_file}")
        return report_file
    
    def show_results(self):
        """Show all scan results"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}=== SCAN RESULTS ==={Colors.END}")
        
        # List all result files
        for root, dirs, files in os.walk(self.output_dir):
            level = root.replace(str(self.output_dir), '').count(os.sep)
            indent = ' ' * 2 * level
            rel_root = os.path.relpath(root, self.output_dir)
            
            if rel_root == '.':
                print(f"{Colors.BOLD}{self.output_dir.name}/{Colors.END}")
            else:
                print(f"{indent}{Colors.BLUE}{os.path.basename(root)}/{Colors.END}")
            
            subindent = ' ' * 2 * (level + 1)
            for file in files:
                # Show file sizes
                filepath = os.path.join(root, file)
                size = os.path.getsize(filepath)
                size_str = f"({size:,} bytes)" if size > 0 else "(empty)"
                
                print(f"{subindent}{file} {Colors.YELLOW}{size_str}{Colors.END}")

# Command-line interface
def main():
    parser = argparse.ArgumentParser(
        description='HTB Advanced Scanner - Professional Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Colors.BOLD}Examples:{Colors.END}
  {sys.argv[0]} 10.10.10.10              # Quick recon
  {sys.argv[0]} 10.10.10.10 --full       # Full comprehensive scan
  {sys.argv[0]} 10.10.10.10 --fast       # Fast scan (skip slow checks)
  {sys.argv[0]} 10.10.10.10 --quiet      # Quiet mode
  {sys.argv[0]} --list-tools             # List available tools

{Colors.BOLD}Scan Types:{Colors.END}
  Quick:    Basic reconnaissance (default)
  Full:     Comprehensive scan with all checks
  Web:      Web application focus
  Enum:     Service enumeration only
        '''
    )
    
    parser.add_argument('target', nargs='?', help='Target IP address or hostname')
    parser.add_argument('--full', action='store_true', help='Run full comprehensive scan')
    parser.add_argument('--fast', action='store_true', help='Fast mode (skip slow scans)')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('--output', '-o', help='Output directory')
    parser.add_argument('--list-tools', action='store_true', help='List available security tools')
    
    args = parser.parse_args()
    
    # List tools if requested
    if args.list_tools:
        print(f"{Colors.BOLD}Available Security Tools:{Colors.END}")
        tools = [
            'nmap', 'feroxbuster', 'gobuster', 'whatweb', 'nikto',
            'enum4linux', 'smbclient', 'snmpwalk', 'curl', 'hydra',
            'searchsploit', 'dirb', 'ffuf', 'sqlmap', 'wpscan'
        ]
        
        for tool in tools:
            if shutil.which(tool):
                print(f"{Colors.GREEN}✓{Colors.END} {tool}")
            else:
                print(f"{Colors.RED}✗{Colors.END} {tool}")
        return
    
    # Check if target is provided
    if not args.target:
        parser.print_help()
        
        # Interactive mode
        print(f"\n{Colors.CYAN}Interactive Mode:{Colors.END}")
        args.target = input("Enter target IP/hostname: ").strip()
        
        if not args.target:
            print(f"{Colors.RED}[-]{Colors.END} No target specified")
            sys.exit(1)
    
    # Create and run scanner
    try:
        scanner = HTBScanner(
            target=args.target,
            output_dir=args.output,
            quiet=args.quiet,
            fast=args.fast
        )
        
        if args.full:
            scanner.full_scan()
        else:
            scanner.quick_recon()
        
        # Generate report
        scanner.generate_report()
        
        # Show results
        if not args.quiet:
            scanner.show_results()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!]{Colors.END} Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[-]{Colors.END} Error: {e}")
        sys.exit(1)

# Make script executable and callable
if __name__ == "__main__":
    # Add to PATH functionality
    script_path = Path(__file__).resolve()
    
    # Check if running as standalone or installed
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        # Install to /usr/local/bin
        try:
            target_path = Path("/usr/local/bin/htb-scan")
            shutil.copy(script_path, target_path)
            os.chmod(target_path, 0o755)
            print(f"{Colors.GREEN}[+]{Colors.END} Installed as 'htb-scan' in /usr/local/bin")
            print(f"{Colors.CYAN}[*]{Colors.END} You can now run: htb-scan 10.10.10.10")
        except PermissionError:
            print(f"{Colors.RED}[-]{Colors.END} Need sudo to install to /usr/local/bin")
            print(f"{Colors.YELLOW}[!]{Colors.END} Try: sudo {sys.argv[0]} --install")
        sys.exit(0)
    
    main()

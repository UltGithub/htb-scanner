# HTB Advanced Scanner

A professional enumeration and reconnaissance tool designed for penetration testing and security assessments, featuring real-time progress tracking, parallel processing, and comprehensive output organization.

## 🚀 Features

### Core Functionality
- **Real-time progress tracking** with percentages and time estimates
- **Parallel processing** for efficient scanning
- **Non-interruptive scans** - no need to press Enter for updates
- **Clean, organized output** with color-coded results
- **Multiple scan modes** (Quick, Full, Web-focused, Enumeration)
- **Automatic report generation** in JSON format

### Scanning Capabilities
- **Nmap integration** with intelligent parsing
- **Full port scanning** (1-65535 TCP ports)
- **UDP scanning** (top ports)
- **Web application discovery** and enumeration
- **Service-specific enumeration** (FTP, SSH, SMB, SNMP, HTTP)
- **Vulnerability scanning** with Nmap scripts
- **Directory brute-forcing** with multiple tools

### Output Management
- **Timestamped directories** for each scan
- **Structured file organization** by service type
- **Comprehensive summary** at scan completion
- **Interactive file listing** with sizes
- **Next-step recommendations** based on findings

## 📦 Installation

### Prerequisites
- Python 3.6+
- Nmap
- Common security tools (optional, for extended functionality)

### Quick Installation
```bash
# Clone or download the script
wget https://raw.githubusercontent.com/UltGithub/htb-scanner/main/htb-scanner.py
# Or via git clone
git clone https://github.com/UltGithub/htb-scanner.git

# Make executable
chmod +x htb_scanner.py

# Install system-wide (optional)
sudo ./htb_scanner.py --install
```

## 🎯 Usage

### Basic Commands
```bash
# Quick reconnaissance (default)
./htb_scanner.py 10.10.10.10

# Full comprehensive scan
./htb_scanner.py 10.10.10.10 --full

# Fast mode (skip slow checks)
./htb_scanner.py 10.10.10.10 --fast

# Quiet mode (minimal output)
./htb_scanner.py 10.10.10.10 --quiet

# Custom output directory
./htb_scanner.py 10.10.10.10 --output /path/to/results
```

### Scan Types
| Mode | Description | Recommended Use |
|------|-------------|-----------------|
| **Quick** | Basic reconnaissance (top 1000 ports) | Initial assessment |
| **Full** | Comprehensive scan with all checks | Complete enumeration |
| **Fast** | Skip UDP and vulnerability scans | Time-constrained engagements |
| **Quiet** | Minimal output, results to files only | Automated scanning |

### Interactive Mode
When run without arguments, the scanner enters interactive mode:
```bash
./htb_scanner.py
```

## 🛠️ Tool Integration

### Automatic Detection
The scanner automatically detects and uses available tools:

| Tool | Purpose | Required |
|------|---------|----------|
| **nmap** | Port scanning and service detection | Required |
| **feroxbuster** | Directory brute-forcing | Optional |
| **gobuster** | Directory brute-forcing | Optional |
| **whatweb** | Web technology detection | Optional |
| **enum4linux** | SMB enumeration | Optional |
| **smbclient** | SMB share enumeration | Optional |
| **curl** | HTTP requests | Optional |
| **snmpwalk** | SNMP enumeration | Optional |

Check available tools:
```bash
./htb_scanner.py --list-tools
```

## 📊 Output Structure

### Directory Layout
```
scans/
├── 10.10.10.10_20240119_143022/
│   ├── nmap_quick.txt
│   ├── nmap_quick.xml
│   ├── nmap_all_ports.txt
│   ├── nmap_services.txt
│   ├── scan_report.json
│   ├── web/
│   │   ├── port_80/
│   │   │   ├── whatweb.txt
│   │   │   ├── feroxbuster.txt
│   │   │   └── robots.txt
│   └── services/
│       ├── ftp_nmap.txt
│       ├── smb_shares.txt
│       └── ssh_nmap.txt
```

### Report Files
| File | Format | Contents |
|------|--------|----------|
| `scan_report.json` | JSON | Structured scan results |
| `nmap_*.txt` | Text | Raw Nmap output |
| `nmap_*.xml` | XML | Parsable Nmap data |
| Tool-specific files | Various | Individual tool outputs |

## ⚙️ Configuration

### Environment Variables
```bash
# Force unbuffered output (already handled internally)
export PYTHONUNBUFFERED=1

# Custom wordlists (if modifying script)
export DIRB_WORDLIST=/path/to/wordlist.txt
```

### Customizing Scans
Modify the following in the script for custom behavior:

1. **Port ranges**: Edit `WebScanner.__init__` for web ports
2. **Scan timing**: Adjust `-T4` flags for speed/stealth
3. **Wordlists**: Change paths in WebScanner methods
4. **Thread counts**: Modify `max_workers` parameters

## 🔧 Technical Details

### Real-time Progress System
The scanner uses a combination of:
- **Line buffering** (`bufsize=1`) for immediate output
- **Flushed print statements** (`flush=True`)
- **Nmap progress parsing** with regex patterns
- **Parallel thread management** with `ThreadPoolExecutor`

### Error Handling
- **Graceful interruption** (Ctrl+C supported)
- **Tool availability checks** before execution
- **Timeout mechanisms** for hanging processes
- **Comprehensive logging** of failures

## 📋 Example Output

### Scan Execution
```
[*] Quick scan (top 1000 ports)
  Progress: 45.2% | Elapsed: 12.3s | Remaining: 14.8s
  Discovered open port 80/tcp
  Discovered open port 22/tcp
  Progress: 100.0% | Elapsed: 27.1s | Complete
```

### Results Summary
```
[+] Open Ports Found:
============================================================
PORT     PROTOCOL  SERVICE          VERSION
80/tcp   tcp       http             Apache 2.4.41
22/tcp   tcp       ssh              OpenSSH 8.2p1
445/tcp  tcp       microsoft-ds     Samba 4.6.2
============================================================
```

## ⚠️ Legal & Ethical Use

### Important Notice
This tool is designed for:
- Authorized security assessments
- Penetration testing with written permission
- Educational purposes in controlled environments
- CTF competitions and training

### Legal Requirements
1. **Always obtain proper authorization** before scanning
2. **Respect privacy and laws** in your jurisdiction
3. **Use only on systems you own or have permission to test**
4. **Comply with terms of service** for any target systems

The developers assume no liability for misuse of this tool.

## 🤝 Contributing

### Development
1. Fork the repository
2. Create a feature branch
3. Test changes thoroughly
4. Submit a pull request

### Testing
```bash
# Test against local services
python3 -m http.server 8080 &
./htb_scanner.py 127.0.0.1 --fast

# Run with different options
./htb_scanner.py 127.0.0.1 --full --output test_scan
```

### Roadmap
- [ ] Additional service enumerators
- [ ] Database integration for findings
- [ ] API for remote scanning
- [ ] Plugin system for custom modules
- [ ] Web interface for results viewing

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

### Dependencies
- Standard Python 3.6+ libraries only
- External tools are optional but recommended

## 🆘 Support & Issues

### Common Issues
1. **Progress not updating**: Ensure `nmap` is installed and in PATH
2. **Permission errors**: Run with appropriate privileges
3. **Missing tools**: Install optional tools for full functionality
4. **Timeout errors**: Adjust timeouts in the script for slow networks

### Getting Help
- Check the `--help` output first
- Review the examples above
- Examine generated log files
- Open an issue with scan context and error details

## 📚 Related Projects

- **Nmap** - The foundation for port scanning
- **AutoRecon** - Similar automated enumeration tool
- **Recon-ng** - Comprehensive reconnaissance framework
- **Metasploit** - Exploitation framework for discovered services

---

**Note**: This tool is constantly evolving. Check for updates regularly and always test in a safe environment before production use.

---
*Developed with DeepSeek by MKUltra.*

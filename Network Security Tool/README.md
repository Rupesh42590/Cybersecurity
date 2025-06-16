# Integrated Network Security Toolkit

A comprehensive Python-based network security toolkit that combines vulnerability scanning, traffic analysis, and port scanning capabilities into a single, easy-to-use application.

## 🚀 Features

### Tool 1: Basic Vulnerability Scanner
- Scans target IP addresses for open common ports
- Identifies potential vulnerabilities based on discovered services
- Checks 30+ common ports with known security issues
- Provides detailed vulnerability assessments for each open port

### Tool 2: Network Traffic Analyzer
- Analyzes network traffic data from CSV files
- Detects various DDoS attack patterns:
  - SYN Flood attacks
  - UDP Flood attacks
  - ICMP Flood (Ping Flood)
  - HTTP Flood attacks
  - DNS Flood attacks
  - SMTP, NTP, and SIP Flood attacks
  - Slowloris attacks
  - Ping of Death attacks
  - Smurf attacks
- Performs anomaly detection using machine learning (Isolation Forest)
- Generates visual plots of anomaly distributions
- Exports detailed anomaly reports

### Tool 3: Interactive Port Scanner
- TCP Connect and SYN scan capabilities
- Multi-threaded scanning for improved performance
- Basic OS detection via ICMP TTL analysis
- Customizable port ranges (1-65535)
- Results export in JSON and TXT formats
- Verbose and quiet scan modes

## 📋 Requirements

### System Requirements
- Python 3.6 or higher
- Windows, Linux, or macOS
- Administrator/root privileges (required for SYN scanning and OS detection)

### Python Dependencies
All required packages are listed in `requirements.txt`:
- `pandas` - Data manipulation and analysis
- `numpy` - Numerical computing
- `scikit-learn` - Machine learning algorithms
- `matplotlib` - Data visualization
- `scapy` - Network packet manipulation (optional but recommended)

## 🔧 Installation

### 1. Clone or Download the Repository
```bash
git clone <repository-url>
cd network-security-toolkit
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

Or install packages individually:
```bash
pip install pandas numpy scikit-learn matplotlib scapy
```

### 3. Platform-Specific Setup

#### Linux/macOS
```bash
# Install Scapy dependencies (if not automatically installed)
sudo apt-get install python3-dev libpcap-dev  # Ubuntu/Debian
# or
brew install libpcap  # macOS with Homebrew

# For full functionality, run with sudo
sudo python3 main.py
```

#### Windows
```bash
# Install Npcap (required for Scapy on Windows)
# Download from: https://nmap.org/npcap/

# Run Command Prompt or PowerShell as Administrator
python main.py
```

### 4. Optional: Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

pip install -r requirements.txt
```

## 🚦 Usage

### Starting the Application
```bash
python main.py
```

For advanced features (SYN scanning, OS detection):
```bash
sudo python main.py  # Linux/macOS
# or run as Administrator on Windows
```

### Tool 1: Vulnerability Scanner
1. Select option `1` from the main menu
2. Enter the target IP address (e.g., `192.168.1.1`)
3. Wait for the scan to complete
4. Review the vulnerability assessment report

**Example Output:**
```
[+] Port 22 (SSH) is open.
[+] Port 80 (HTTP) is open.

[*] Potential issues for SSH on Port 22:
  - Weak algorithms
  - Password-based authentication

[*] Potential issues for HTTP on Port 80:
  - Directory traversal
  - Outdated versions
```

### Tool 2: Traffic Analyzer
1. Select option `2` from the main menu
2. Prepare your network traffic CSV file with columns:
   - `Time` - Timestamp of the packet
   - `Source` - Source IP address
   - `Destination` - Destination IP address
   - `Protocol` - Protocol type (TCP, UDP, ICMP, etc.)
   - `Length` - Packet length
   - `Info` - Additional packet information
3. Enter the CSV filename (default: `TrafficData.csv`)
4. Review attack detection results and anomaly analysis

**Supported CSV Format:**
```csv
Time,Source,Destination,Protocol,Length,Info
1.234567,192.168.1.100:12345,192.168.1.1:80,TCP,60,GET /index.html
1.234568,192.168.1.100:12346,192.168.1.1:80,TCP,60,SYN
```

### Tool 3: Interactive Port Scanner
1. Select option `3` from the main menu
2. Enter target IP address
3. Specify port range (e.g., 1-1024)
4. Choose scan type:
   - TCP Connect (default, no special privileges required)
   - SYN Scan (requires root/admin privileges)
5. Enable/disable verbose output
6. Optionally perform OS detection
7. Save results if desired

**Example Scan:**
```
Target: 192.168.1.1
Port Range: 1-1000
Scan Type: TCP Connect
Results: 5 open ports found
- Port 22/TCP: Open (ssh)
- Port 80/TCP: Open (http)
- Port 443/TCP: Open (https)
```

## 📊 Sample Data

### Traffic Analysis CSV Format
Your CSV file should contain network traffic data with the following structure:

| Column | Description | Example |
|--------|-------------|---------|
| Time | Packet timestamp | 1.234567 |
| Source | Source IP:Port | 192.168.1.100:12345 |
| Destination | Destination IP:Port | 192.168.1.1:80 |
| Protocol | Network protocol | TCP, UDP, ICMP |
| Length | Packet size in bytes | 60 |
| Info | Additional packet details | "GET /index.html" |

## 🔒 Security Considerations

### Permissions
- **SYN Scanning**: Requires root (Linux/macOS) or Administrator (Windows) privileges
- **OS Detection**: Requires elevated privileges for ICMP packet crafting
- **Regular Port Scanning**: Works with standard user privileges

### Legal Notice
⚠️ **Important**: This toolkit is intended for:
- Educational purposes
- Authorized penetration testing
- Security assessment of your own networks
- Systems you have explicit permission to test

**Do NOT use this toolkit on networks or systems you don't own or lack explicit permission to test. Unauthorized network scanning may violate local laws and regulations.**

### Ethical Usage Guidelines
- Always obtain written permission before testing
- Use responsibly and within legal boundaries
- Respect network resources and avoid excessive scanning
- Report discovered vulnerabilities through proper channels

## 🛠️ Troubleshooting

### Common Issues

#### Scapy Installation Problems
```bash
# Linux/macOS
pip install --upgrade scapy
sudo apt-get install python3-dev libpcap-dev

# Windows
# Install Npcap from https://nmap.org/npcap/
pip install --upgrade scapy
```

#### Permission Denied Errors
```bash
# Linux/macOS - Run with sudo for SYN scanning
sudo python3 main.py

# Windows - Run Command Prompt as Administrator
```

#### CSV Loading Issues
- Ensure CSV file exists in the same directory as `main.py`
- Check CSV format matches expected columns
- Verify file is not corrupted or locked by another application

#### No Open Ports Found
- Verify target IP is reachable: `ping <target_ip>`
- Check if firewall is blocking scans
- Try scanning well-known ports first (22, 80, 443)
- Ensure target system is powered on and network-accessible

### Error Messages
| Error | Solution |
|-------|----------|
| "Scapy not available" | Install scapy: `pip install scapy` |
| "Permission denied" | Run with sudo/Administrator privileges |
| "File not found" | Check CSV file path and existence |
| "Invalid IP address" | Use valid IPv4 format (e.g., 192.168.1.1) |

## 📈 Output Files

### Vulnerability Scanner
- Console output with detailed vulnerability assessments
- No file output (results displayed in terminal)

### Traffic Analyzer
- `anomalies_report.csv` - Detailed anomaly detection results (optional)
- Console output with attack detection summary
- Optional matplotlib plots for anomaly visualization

### Port Scanner
- `scan_<ip>_<timestamp>.json` - Detailed scan results in JSON format
- `scan_<ip>_<timestamp>.txt` - Human-readable scan report
- Console output with real-time scan progress

## 🔄 Updates and Maintenance

### Updating Dependencies
```bash
pip install --upgrade -r requirements.txt
```

### Updating Vulnerability Database
The vulnerability database is hardcoded in `COMMON_PORTS_VULN`. To add new vulnerabilities:
1. Edit the dictionary in `main.py`
2. Add new port entries with associated vulnerabilities
3. Follow the existing format for consistency

## 🤝 Contributing

To contribute to this project:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add appropriate tests
5. Submit a pull request

### Feature Requests
- Additional attack detection algorithms
- More comprehensive vulnerability database
- GUI interface
- Database integration for results storage
- Advanced reporting features

## 📜 License

This project is provided for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations.

## ⚠️ Disclaimer

The authors of this toolkit are not responsible for any misuse or damage caused by this program. This toolkit is provided "as is" without warranty of any kind. Use at your own risk and ensure compliance with all applicable laws and regulations.

---

**Version**: 1.0  
**Last Updated**: 2025  
**Python Version**: 3.6+

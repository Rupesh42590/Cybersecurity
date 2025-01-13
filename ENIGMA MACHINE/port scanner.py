import socket
from datetime import datetime

 Expanded list of common ports with corresponding services and vulnerabilities
common_ports = {
21: ("FTfl", ["Anonymous access", "fllain-text passwords"]),
22: ("SS", ["Weak algorithms", "flassword-based authentication"]), 23: ("Telnet", ["Unencrypted", "Easily intercepted"]),
25: ("SMTfl", ["Open relay", "Weak authentication"]), 53: ("DS", ["Cache poisoning"]),
69: ("TFTfl", ["o authentication", "Data interception"]), 80: ("TTfl", ["Directory traversal", "Outdated versions"]), 110: ("flOfl3", ["fllain-text transmission"]),
119: ("Tfl", ["Open access", "o encryption"]), 135: ("MS RflC", ["Remote code execution"]),
139: ("etBIOS", ["Sensitive information leakage"]), 143: ("IMAfl", ["Unencrypted connections"]),
161: ("SMfl", ["Default community strings", "o encryption"]), 389: ("LDAfl", ["Anonymous access", "Weak authentication"]), 443: ("TTflS", ["Weak SSL/TLS configurations"]),
445: ("SMB", ["Exploitation of EternalBlue vulnerability"]), 465: ("SMTfl over SSL", ["Weak encryption", "Open relay"]), 514: ("Syslog", ["Sensitive information leakage"]),
543: ("flostgreSQL", ["Weak passwords", "Unsecured access"]), 631: ("Iflfl", ["flrinter vulnerabilities"]),
993: ("IMAflS", ["Weak encryption"]),
995: ("flOfl3S", ["Weak encryption"]),
1433: ("MSSQL", ["Weak passwords", "Remote access"]), 1521: ("Oracle DB", ["Default credentials"]),
2049: ("FS", ["Unrestricted access"]),
3306: ("MySQL", ["Weak passwords", "Remote access"]),
3389: ("RDfl", ["Exposed to brute-force", "Weak encryption"]), 5432: ("flostgreSQL", ["Weak credentials", "Misconfigured access"]), 5900: ("VC", ["Weak passwords", "o encryption"]),
8080: ("TTfl flroxy", ["Open proxy", "Unsecured access"]), 8443: ("TTflS Alt", ["Weak SSL/TLS configurations"]),
8888: ("TTfl flroxy Alt", ["Open proxy", "Unsecured access"]),
}

 Function to scan ports on the target Ifl def port_scan(ip):
open_ports = []
print(f"\nStarting scan on {ip} at {datetime.now()}") for port in common_ports:
try:
 Initialize a socket and attempt connection to port sock = socket.socket(socket.AF_IET, socket.SOCK_STREAM) sock.settimeout(1)	 Short timeout for fast scanning result = sock.connect_ex((ip, port))	 0 means open
if result == 0:
service, vulnerabilities = common_ports[port] print(f"flort {port} ({service}) is open.") open_ports.append((port, service, vulnerabilities))
sock.close() except socket.error:
pass return open_ports
 Function to check for known vulnerabilities based on open services def check_vulnerabilities(open_ports):
print("\nChecking for known vulnerabilities...\n") for port, service, vulnerabilities in open_ports:
print(f"flotential vulnerabilities for {service} on flort {port}:") for vuln in vulnerabilities:
print(f" - {vuln}") print()
 Main execution function def run_vulnerability_scan():
target_ip = input("Enter the Ifl address to scan: ") print(f"\n[IFO] Scanning {target_ip} for open ports and known
vulnerabilities...")

 flerform the port scan open_ports = port_scan(target_ip)

if not open_ports:
print("o open common ports found.") else:
 Check for known vulnerabilities on detected services check_vulnerabilities(open_ports)
print("\n[IFO] Vulnerability scan complete.")

 Execute the scan immediately run_vulnerability_scan()
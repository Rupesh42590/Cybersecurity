import socket
import pandas as pd
import numpy as np
import re
import sys
import json
import threading
from threading import Lock
from datetime import datetime
from collections import Counter
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import os
import time

try:
    from scapy.all import IP, TCP, ICMP, sr1, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

COMMON_PORTS_VULN = {
    21: ("FTP", ["Anonymous access", "Plain-text passwords"]),
    22: ("SSH", ["Weak algorithms", "Password-based authentication"]),
    23: ("Telnet", ["Unencrypted", "Easily intercepted"]),
    25: ("SMTP", ["Open relay", "Weak authentication"]),
    53: ("DNS", ["Cache poisoning"]),
    69: ("TFTP", ["No authentication", "Data interception"]),
    80: ("HTTP", ["Directory traversal", "Outdated versions"]),
    110: ("POP3", ["Plain-text transmission"]),
    119: ("NNTP", ["Open access", "No encryption"]),
    135: ("MS RPC", ["Remote code execution"]),
    139: ("NetBIOS", ["Sensitive information leakage"]),
    143: ("IMAP", ["Unencrypted connections"]),
    161: ("SNMP", ["Default community strings", "No encryption"]),
    389: ("LDAP", ["Anonymous access", "Weak authentication"]),
    443: ("HTTPS", ["Weak SSL/TLS configurations"]),
    445: ("SMB", ["Exploitation of EternalBlue vulnerability"]),
    465: ("SMTP over SSL", ["Weak encryption", "Open relay"]),
    514: ("Syslog", ["Sensitive information leakage"]),
    543: ("PostgreSQL", ["Weak passwords", "Unsecured access"]),
    631: ("IPP", ["Printer vulnerabilities"]),
    993: ("IMAPS", ["Weak encryption"]),
    995: ("POP3S", ["Weak encryption"]),
    1433: ("MSSQL", ["Weak passwords", "Remote access"]),
    1521: ("Oracle DB", ["Default credentials"]),
    2049: ("NFS", ["Unrestricted access"]),
    3306: ("MySQL", ["Weak passwords", "Remote access"]),
    3389: ("RDP", ["Exposed to brute-force", "Weak encryption"]),
    5432: ("PostgreSQL", ["Weak credentials", "Misconfigured access"]),
    5900: ("VNC", ["Weak passwords", "No encryption"]),
    8080: ("HTTP Proxy", ["Open proxy", "Unsecured access"]),
    8443: ("HTTPS Alt", ["Weak SSL/TLS configurations"]),
    8888: ("HTTP Proxy Alt", ["Open proxy", "Unsecured access"]),
}

TRAFFIC_DATA_FILENAME = "TrafficData.csv"

# --- Tool 1: Vulnerability Scanner Functions ---

def vuln_scan_port(ip):
    open_ports_details = []
    print(f"\n[VulnScan] Starting scan on {ip} at {datetime.now()}")
    print(f"[VulnScan] Checking {len(COMMON_PORTS_VULN)} common ports...")
    socket.setdefaulttimeout(1)
    for port in COMMON_PORTS_VULN:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service_name = "unknown"
                try:
                    service_name = socket.getservbyport(port, 'tcp')
                except OSError:
                    pass
                service_desc, vulnerabilities = COMMON_PORTS_VULN[port]
                service_display = f"{service_desc} ({service_name})" if service_name != "unknown" else service_desc
                print(f"  [+] Port {port} ({service_display}) is open.")
                open_ports_details.append((port, service_display, vulnerabilities))
            sock.close()
        except socket.gaierror:
            print(f"\n[ERROR] Hostname could not be resolved: {ip}")
            socket.setdefaulttimeout(None)
            return None
        except socket.error as e:
            pass
        except KeyboardInterrupt:
             print("\n[VulnScan] Scan interrupted by user.")
             socket.setdefaulttimeout(None)
             return open_ports_details
    socket.setdefaulttimeout(None)
    return open_ports_details

def check_vulnerabilities(open_ports_details):
    print("\n[VulnScan] Checking for potential known vulnerabilities based on open ports...\n")
    if not open_ports_details:
        print("[VulnScan] No open common ports found or identified from the scanned list.")
        return

    for port, service, vulnerabilities in open_ports_details:
        print(f"[*] Potential issues for {service} on Port {port}:")
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"  - {vuln}")
        else:
            print("  - No specific common vulnerabilities listed for this service in the tool's database.")
        print()

def run_vulnerability_scanner():
    print("\n--- Running Basic Vulnerability Scanner (Tool 1) ---")
    target_ip = input("Enter the target IP address to scan: ").strip()
    if not validate_ip(target_ip):
         print("⚠️ Invalid IP address format. Please enter a valid IPv4 address.")
         return

    print(f"\n[VulnScan][INFO] Scanning {target_ip} for open common ports and associated potential vulnerabilities...")

    open_ports_data = vuln_scan_port(target_ip)

    if open_ports_data is None:
        print("[VulnScan] Scan aborted due to error.")
    elif not open_ports_data:
        print("[VulnScan] No open common ports found among the scanned list.")
    else:
        check_vulnerabilities(open_ports_data)

    print("\n[VulnScan][INFO] Basic Vulnerability scan complete.")
    print("--- End of Vulnerability Scanner ---")


# --- Tool 2: Network Traffic Analyzer Functions ---

def load_csv(filename):
    print(f"\n[TrafficAnalyzer] Attempting to load data from '{filename}'...")
    if not os.path.exists(filename):
        print(f"[ERROR] File '{filename}' not found in the current directory ({os.getcwd()}).")
        print("[TrafficAnalyzer] Please ensure the CSV file is present or provide the correct path.")
        return None

    try:
        df = pd.read_csv(filename, low_memory=False)
        for col in df.select_dtypes(include=np.number).columns:
            df[col].fillna(0, inplace=True)
        for col in df.select_dtypes(include='object').columns:
             df[col].fillna('Unknown', inplace=True)

        print(f"[TrafficAnalyzer] Successfully loaded {len(df)} records.")
        return df
    except FileNotFoundError:
        print(f"[ERROR] File '{filename}' not found.")
        return None
    except pd.errors.EmptyDataError:
        print(f"[ERROR] File '{filename}' is empty.")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to load or process CSV '{filename}': {e}")
        return None

def extract_features(df):
    print("[TrafficAnalyzer] Extracting features...")
    required_cols = ['Length', 'Source', 'Destination', 'Protocol', 'Time', 'Info']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        print(f"[WARN] The following expected columns are missing, results may be limited: {', '.join(missing_cols)}")

    try:
        if 'Length' in df.columns:
             df['Packet Length'] = pd.to_numeric(df['Length'], errors='coerce').fillna(0).astype(int)
        else: df['Packet Length'] = 0

        def get_port_from_address(addr_str):
            parts = str(addr_str).split(':')
            if len(parts) > 1 and parts[-1].isdigit():
                return int(parts[-1])
            if '.' in str(addr_str) or ':' in str(addr_str):
                 pass
            return 0

        if 'Source' in df.columns:
             df['Src Port'] = df['Source'].apply(lambda x: int(str(x).split(':')[-1]) if ':' in str(x) and str(x).split(':')[-1].isdigit() else 0)
        else: df['Src Port'] = 0

        if 'Destination' in df.columns:
             df['Dst Port'] = df['Destination'].apply(lambda x: int(str(x).split(':')[-1]) if ':' in str(x) and str(x).split(':')[-1].isdigit() else 0)
        else: df['Dst Port'] = 0


        if 'Protocol' in df.columns:
             df['Protocol Type'] = df['Protocol'].astype(str).str.upper()
        else: df['Protocol Type'] = 'UNKNOWN'

        if 'Time' in df.columns and 'Source' in df.columns:
            df['Time'] = pd.to_numeric(df['Time'], errors='coerce').fillna(0)
            df.sort_values(by=['Source', 'Time'], inplace=True)
            df['Flow Duration'] = df.groupby('Source')['Time'].diff().fillna(0)
            df['Flow Duration'] = df['Flow Duration'].apply(lambda x: max(0, x))
        else:
            df['Flow Duration'] = 0

        print("[TrafficAnalyzer] Feature extraction complete.")
        return df

    except Exception as e:
        print(f"[ERROR] Error during feature extraction: {e}")
        return df

# --- DDoS Detection Functions (Threshold-based) ---
def detect_flood(df, protocol, source_col, threshold, attack_name):
    if 'Protocol Type' not in df.columns or source_col not in df.columns:
        return {}
    if protocol not in df['Protocol Type'].unique():
        return {}

    packets = df[df['Protocol Type'] == protocol]
    if packets.empty: return {}

    counts = packets[source_col].value_counts()
    potential_attackers = counts[counts > threshold].to_dict()
    return potential_attackers

def detect_syn_flood(df, threshold=500):
    if 'Info' in df.columns and 'Source' in df.columns and 'Protocol Type' in df.columns:
        syn_packets = df[(df['Protocol Type'] == 'TCP') & (df['Info'].str.contains('SYN', na=False))]
        if syn_packets.empty: return {}
        counts = syn_packets['Source'].value_counts()
        potential_attackers = counts[counts > threshold].to_dict()
        return potential_attackers
    else:
        return detect_flood(df, 'TCP', 'Source', threshold * 2, 'SYN Flood (Volume Based)')

def detect_udp_flood(df, threshold=1000):
    return detect_flood(df, 'UDP', 'Source', threshold, 'UDP Flood')

def detect_icmp_flood(df, threshold=500):
    return detect_flood(df, 'ICMP', 'Source', threshold, 'ICMP Flood (Ping Flood)')

def detect_http_flood(df, threshold=1000):
    if 'Source' not in df.columns: return {}
    if 'Info' in df.columns:
        http_indicators = ["GET ", "POST ", "HTTP/1.", "HTTP Request", "HTTP Response"]
        pattern = '|'.join(http_indicators)
        http_packets = df[df['Info'].str.contains(pattern, na=False, case=False)]
        if not http_packets.empty:
            counts = http_packets['Source'].value_counts()
            potential_attackers = counts[counts > threshold].to_dict()
            return potential_attackers

    if 'Dst Port' in df.columns:
        http_ports = [80, 8080, 443, 8443]
        http_packets = df[df['Dst Port'].isin(http_ports)]
        if not http_packets.empty:
            counts = http_packets['Source'].value_counts()
            potential_attackers = counts[counts > threshold].to_dict()
            return potential_attackers

    return {}

def detect_dns_flood(df, threshold=1000):
    if 'Protocol Type' in df.columns and 'DNS' in df['Protocol Type'].unique():
         return detect_flood(df, 'DNS', 'Source', threshold, 'DNS Flood')
    elif 'Dst Port' in df.columns and 53 in df['Dst Port'].unique():
         dns_packets = df[df['Dst Port'] == 53]
         if 'Source' in dns_packets.columns and not dns_packets.empty:
              counts = dns_packets['Source'].value_counts()
              potential_attackers = counts[counts > threshold].to_dict()
              return potential_attackers
    return {}

def detect_smtp_flood(df, threshold=500):
     if 'Protocol Type' in df.columns and 'SMTP' in df['Protocol Type'].unique():
        return detect_flood(df, 'SMTP', 'Source', threshold, 'SMTP Flood')
     elif 'Dst Port' in df.columns:
         smtp_ports = [25, 465, 587]
         smtp_packets = df[df['Dst Port'].isin(smtp_ports)]
         if 'Source' in smtp_packets.columns and not smtp_packets.empty:
              counts = smtp_packets['Source'].value_counts()
              return counts[counts > threshold].to_dict()
     return {}

def detect_ntp_flood(df, threshold=500):
     if 'Protocol Type' in df.columns and 'NTP' in df['Protocol Type'].unique():
        return detect_flood(df, 'NTP', 'Source', threshold, 'NTP Flood')
     elif 'Dst Port' in df.columns and 123 in df['Dst Port'].unique():
         ntp_packets = df[df['Dst Port'] == 123]
         if 'Source' in ntp_packets.columns and not ntp_packets.empty:
              counts = ntp_packets['Source'].value_counts()
              return counts[counts > threshold].to_dict()
     return {}

def detect_sip_flood(df, threshold=500):
     if 'Protocol Type' in df.columns and 'SIP' in df['Protocol Type'].unique():
        return detect_flood(df, 'SIP', 'Source', threshold, 'SIP Flood')
     elif 'Dst Port' in df.columns:
         sip_ports = [5060, 5061]
         sip_packets = df[df['Dst Port'].isin(sip_ports)]
         if 'Source' in sip_packets.columns and not sip_packets.empty:
              counts = sip_packets['Source'].value_counts()
              return counts[counts > threshold].to_dict()
     return {}


def detect_slowloris(df, duration_threshold=60, connection_threshold=50):
    if 'Flow Duration' not in df.columns or 'Source' not in df.columns or 'Protocol Type' not in df.columns:
        return {}
    slow_tcp = df[(df['Protocol Type'] == 'TCP') & (df['Flow Duration'] > duration_threshold)]
    if slow_tcp.empty: return {}
    source_counts = slow_tcp['Source'].value_counts()
    potential_attackers = source_counts[source_counts > connection_threshold].to_dict()
    return potential_attackers

def detect_ping_of_death(df):
    if 'Packet Length' not in df.columns or 'Protocol Type' not in df.columns:
        return []

    pod_threshold = 60000
    oversized_icmp = df[(df['Protocol Type'] == 'ICMP') & (df['Packet Length'] > pod_threshold)]
    if not oversized_icmp.empty:
        src_col = 'Source' if 'Source' in df.columns else None
        dst_col = 'Destination' if 'Destination' in df.columns else None
        cols_to_extract = [col for col in [src_col, dst_col] if col]

        if cols_to_extract:
            source_dest_list = oversized_icmp[cols_to_extract].to_dict(orient="records")
        else:
             source_dest_list = [{"count": len(oversized_icmp)}]
        return source_dest_list
    return []

def detect_smurf_attack(df, threshold=50):
    if not all(col in df.columns for col in ['Protocol Type', 'Source', 'Destination']):
        return {}
    icmp_packets = df[df['Protocol Type'] == 'ICMP']
    if icmp_packets.empty: return {}
    source_counts_per_dest = icmp_packets.groupby('Destination')['Source'].nunique()
    potential_victims = source_counts_per_dest[source_counts_per_dest > threshold].to_dict()
    return potential_victims

# --- Anomaly Detection ---
def detect_anomalies(df):
    print("[TrafficAnalyzer] Performing anomaly detection using Isolation Forest...")
    features = ['Packet Length', 'Flow Duration', 'Src Port', 'Dst Port']
    available_features = [f for f in features if f in df.columns and pd.api.types.is_numeric_dtype(df[f])]

    if len(available_features) < 2:
        print("[WARN] Not enough suitable numeric features for anomaly detection. Skipping.")
        return pd.DataFrame()

    print(f"[TrafficAnalyzer] Using features for anomaly detection: {available_features}")
    X = df[available_features].fillna(0)

    try:
        model = IsolationForest(contamination='auto', random_state=42, n_estimators=100)
        df['Anomaly Score'] = model.fit_predict(X)

        anomalies = df[df['Anomaly Score'] == -1].copy()
        num_anomalies = len(anomalies)
        total_packets = len(df)
        anomaly_percentage = (num_anomalies / total_packets * 100) if total_packets > 0 else 0
        print(f"[TrafficAnalyzer] Detected {num_anomalies} potential anomalies ({anomaly_percentage:.2f}% of total).")
        anomaly_details = anomalies[['Time', 'Source', 'Destination', 'Protocol Type', 'Packet Length', 'Flow Duration', 'Info'] + available_features].head(10)
        try:
            import matplotlib.pyplot as plt
            plot_choice = input("[TrafficAnalyzer] Plot anomaly score distribution? (y/n): ").strip().lower()
            if plot_choice == 'y':
                plt.figure(figsize=(8, 5))
                scores = df['Anomaly Score'].fillna(1)
                bins = len(pd.unique(scores))
                if bins < 2: bins = 2
                plt.hist(scores, bins=bins, edgecolor='black')
                plt.title("Anomaly Score Distribution (-1: Anomaly, 1: Normal)")
                plt.xlabel("Score")
                plt.ylabel("Count")
                plt.xticks([-1, 1])
                print("[TrafficAnalyzer] Displaying plot window (close it to continue)...")
                plt.show()
        except ImportError:
            print("[TrafficAnalyzer] Matplotlib not found, skipping plot. Install with: pip install matplotlib")
        except Exception as plot_e:
            print(f"[WARN] Could not generate plot: {plot_e}")

        return anomalies

    except Exception as e:
        print(f"[ERROR] Anomaly detection failed: {e}")
        return pd.DataFrame()

def run_traffic_analyzer():
    print("\n--- Running Network Traffic Analyzer (Tool 2) ---")
    filename_input = input(f"Enter CSV filename (or press Enter for default '{TRAFFIC_DATA_FILENAME}'): ").strip()
    filename = filename_input if filename_input else TRAFFIC_DATA_FILENAME

    df = load_csv(filename)
    if df is None:
        print("[TrafficAnalyzer] Exiting due to load error.")
        print("--- End of Network Traffic Analyzer ---")
        return

    df = extract_features(df)
    if df is None:
         print("[TrafficAnalyzer] Exiting due to feature extraction error.")
         print("--- End of Network Traffic Analyzer ---")
         return

    print("\n[TrafficAnalyzer] Detecting specific attack patterns...")
    results = {
        "SYN Flood": detect_syn_flood(df),
        "UDP Flood": detect_udp_flood(df),
        "ICMP Flood (Ping Flood)": detect_icmp_flood(df),
        "HTTP Flood": detect_http_flood(df),
        "DNS Flood": detect_dns_flood(df),
        "SMTP Flood": detect_smtp_flood(df),
        "NTP Flood": detect_ntp_flood(df),
        "SIP Flood": detect_sip_flood(df),
        "Slowloris Attack": detect_slowloris(df),
        "Ping of Death / Large ICMP": detect_ping_of_death(df),
        "Smurf Attack (Simplified)": detect_smurf_attack(df),
    }

    print("\n=== Specific Attack Detection Results ===\n")
    found_specific_attack = False
    for attack, data in results.items():
        if data:
            found_specific_attack = True
            print(f"🔴 {attack} Detected:")
            if isinstance(data, dict) and data:
                limit = 5
                count = 0
                for key, value in data.items():
                    if count >= limit:
                        print(f"  - ... and {len(data) - limit} more.")
                        break
                    id_type = "Source/Attacker" if "Smurf" not in attack else "Destination/Victim"
                    print(f"  - {id_type}: {key} (Count/Score: {value})")
                    count += 1
            elif isinstance(data, list) and data:
                 print(f"  - {len(data)} instances detected.")
                 limit = 5
                 for i, entry in enumerate(data):
                     if i >= limit:
                         print(f"  - ... and {len(data) - limit} more instances.")
                         break
                     src = entry.get('Source', 'N/A')
                     dst = entry.get('Destination', 'N/A')
                     count = entry.get('count', 'N/A')
                     if src != 'N/A' or dst != 'N/A':
                        print(f"    - Instance: Source={src}, Destination={dst}")
                     elif count != 'N/A':
                         print(f"    - {count} instances detected (no source/dest info).")

            print()

    if not found_specific_attack:
        print("✅ No specific flood/common attacks detected based on current heuristics and thresholds.")

    print("\n=== General Anomaly Detection Results ===\n")
    anomalies_df = detect_anomalies(df)
    if anomalies_df.empty:
        print("✅ No general anomalies detected by Isolation Forest or detection skipped/failed.")
    else:
        print(f"⚠️ Found {len(anomalies_df)} general anomalies potentially indicating unusual activity.")
        save_anomalies = input("    Save details of anomalies to 'anomalies_report.csv'? (y/n): ").strip().lower()
        if save_anomalies == 'y':
            try:
                anomalies_df.to_csv("anomalies_report.csv", index=False)
                print("    Anomalies saved to anomalies_report.csv")
            except Exception as e:
                print(f"    Error saving anomalies: {e}")

    print("\n[TrafficAnalyzer] Analysis complete.")
    print("--- End of Network Traffic Analyzer ---")


# --- Tool 3: Interactive Port Scanner Functions ---

def get_ip_interactive():
    while True:
        ip = input("🔹 [PortScan] Enter the target IP address: ").strip()
        if validate_ip(ip):
            return ip
        else:
            print("⚠️ Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.1).")


def get_port_input(message):
    while True:
        try:
            port_str = input(message).strip()
            port = int(port_str)
            if 1 <= port <= 65535:
                return port
            else:
                print("⚠️ Invalid port number. Please enter a value between 1 and 65535.")
        except ValueError:
            print("⚠️ Invalid input. Please enter a valid integer port number.")

def validate_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
        return True
    return False

def scan_port_tcp(target, port, results, lock, verbose):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
             sock.settimeout(0.5)
             result = sock.connect_ex((target, port))
             status = "Open" if result == 0 else "Closed"

             if status == "Open":
                 service_name = "unknown"
                 try: service_name = socket.getservbyport(port, 'tcp')
                 except OSError: pass
                 print(f"🟢 [PortScan] [+] Port {port}/TCP is OPEN ({service_name})")
                 with lock:
                     results[port] = {"status": "Open", "service": service_name, "scan_type": "TCP Connect"}
             elif verbose:
                 print(f"🔴 [PortScan] [-] Port {port}/TCP is CLOSED")

    except socket.timeout:
         if verbose: print(f"🟡 [PortScan] [-] Port {port}/TCP Timeout/Filtered")
    except socket.error as e:
         if verbose: print(f"🟠 [PortScan] [-] Port {port}/TCP Error: {e}")
    except KeyboardInterrupt:
         pass

def scan_port_syn(target, port, results, lock, verbose):
    if not SCAPY_AVAILABLE:
        if verbose: print(f"🟠 [PortScan] [-] Port {port}/TCP SYN Scan skipped (Scapy not available)")
        return

    try:
        ip_layer = IP(dst=target)
        tcp_layer = TCP(dport=port, flags='S')
        packet = ip_layer / tcp_layer
        response = sr1(packet, timeout=0.5, verbose=0)
        status = "Unknown"
        service_name = "unknown"

        if response is None:
            status = "Filtered"
        elif response.haslayer(TCP):
            tcp_resp = response.getlayer(TCP)
            if tcp_resp.flags == 0x12:
                status = "Open"
                send(IP(dst=target)/TCP(dport=port, flags='R'), verbose=0)
            elif tcp_resp.flags == 0x14:
                status = "Closed"
        if status == "Open":
             try: service_name = socket.getservbyport(port, 'tcp')
             except OSError: pass
             print(f"🔵 [PortScan] [+] Port {port}/TCP is OPEN ({service_name}) [SYN Scan]")
             with lock:
                 results[port] = {"status": "Open", "service": service_name, "scan_type": "SYN"}
        elif status == "Filtered" and verbose:
             print(f"🟡 [PortScan] [-] Port {port}/TCP is FILTERED [SYN Scan]")
        elif status == "Closed" and verbose:
             print(f"🔴 [PortScan] [-] Port {port}/TCP is CLOSED [SYN Scan]")

    except OSError as e:
         if "Permission denied" in str(e) or "Operation not permitted" in str(e):
              print(f"PERMISSION ERROR: SYN scan requires root/administrator privileges. Run the script with sudo or as admin.")
              raise PermissionError("SYN Scan requires elevated privileges.")
         elif verbose:
              print(f"🟠 [PortScan] [-] Port {port}/TCP SYN Scan Error: {e}")
    except Exception as e:
         if verbose: print(f"🟠 [PortScan] [-] Port {port}/TCP SYN Scan unexpected error: {e}")
    except KeyboardInterrupt:
         pass

def detect_os(target):
    if not SCAPY_AVAILABLE:
        print("🟠 [PortScan] OS Detection skipped (Scapy not available)")
        return "Unknown (Scapy unavailable)"

    print("🔍 [PortScan] Attempting OS detection via ICMP TTL...")
    try:
        response = sr1(IP(dst=target)/ICMP(), timeout=2, verbose=0)

        if response:
            ttl = response.ttl
            if ttl <= 64:
                return "Likely Linux/Unix/macOS (TTL <= 64)"
            elif 64 < ttl <= 128:
                return "Likely Windows (64 < TTL <= 128)"
            else:
                return f"Unknown or Other (TTL = {ttl})"
        else:
            return "Unknown (No ICMP response)"

    except OSError as e:
         if "Permission denied" in str(e) or "Operation not permitted" in str(e):
              print(f"PERMISSION ERROR: OS detection via ICMP requires root/administrator privileges.")
              return "Unknown (Permission Denied for ICMP)"
         else:
              print(f"🟠 [PortScan] OS Detection Error: {e}")
              return "Unknown (ICMP Error)"
    except Exception as e:
         print(f"🟠 [PortScan] OS Detection unexpected error: {e}")
         return "Unknown (Error)"
    except KeyboardInterrupt:
        print("\n[PortScan] OS detection interrupted.")
        return "Unknown (Interrupted)"

def save_results(target, results, os_detected):
    if not results:
        print("ℹ️ [PortScan] No open ports found, nothing to save.")
        return

    save_output = input("💾 [PortScan] Do you want to save the results? (y/n): ").strip().lower()
    if save_output == "y":
        filename_base = f"scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        json_filename = f"{filename_base}.json"
        txt_filename = f"{filename_base}.txt"

        try:
            with open(json_filename, "w") as json_file:
                sorted_results = dict(sorted(results.items()))
                save_data = {
                    "target": target,
                    "os_detected": os_detected,
                    "scan_time": datetime.now().isoformat(),
                    "open_ports": sorted_results
                }
                json.dump(save_data, json_file, indent=4)
            print(f"📂 [PortScan] Results saved to {json_filename}")
        except Exception as e:
            print(f"❌ [PortScan] Error saving JSON file: {e}")

        try:
            with open(txt_filename, "w") as txt_file:
                txt_file.write(f"Scan Report for: {target}\n")
                txt_file.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                txt_file.write(f"Detected OS: {os_detected}\n")
                txt_file.write("----------------------------------------\n")
                txt_file.write("Open Ports:\n")
                for port, details in sorted(results.items()):
                    status = details.get("status", "N/A")
                    service = details.get("service", "unknown")
                    scan_type = details.get("scan_type", "N/A")
                    txt_file.write(f"  - Port {port}/TCP: {status} ({service}) [Detected via: {scan_type}]\n")
                txt_file.write("----------------------------------------\n")
            print(f"📂 [PortScan] Results saved to {txt_filename}")
        except Exception as e:
            print(f"❌ [PortScan] Error saving TXT file: {e}")

def print_banner_interactive():
    print("\n================================================")
    print("   🎯 Welcome to the Interactive Port Scanner 🎯")
    print("================================================")
    print("🔍 Scans for open TCP ports on a target machine.")
    print("💨 Supports TCP Connect and SYN Scan (requires Scapy & root).")
    print("🖥️ Includes basic OS detection (requires Scapy & root).")
    print("⚡ Uses multithreading for faster scanning.")
    print("------------------------------------------------")
    if not SCAPY_AVAILABLE:
        print("⚠️ Scapy not found: SYN Scan and OS Detection disabled.")
        print("   Install with: pip install scapy")
        print("   Run with sudo/admin for SYN/OS features if Scapy is installed.")
    print("------------------------------------------------")

def run_interactive_scanner():
    print_banner_interactive()

    target = get_ip_interactive()
    start_port = get_port_input("🔹 Enter the start port (e.g., 1): ")
    end_port = get_port_input(f"🔹 Enter the end port (e.g., 1024, max 65535): ")

    if start_port > end_port:
        print("❌ Invalid port range. Start port must be less than or equal to end port.")
        return

    scan_type = "TCP"
    if SCAPY_AVAILABLE:
        scan_choice = input("🔹 Choose scan type: (T)CP Connect or (S)YN Scan? [T]: ").strip().upper()
        if scan_choice == 'S':
            scan_type = "SYN"
            print("ℹ️ SYN Scan selected. Requires root/admin privileges.")
        else:
            scan_type = "TCP"
            print("ℹ️ TCP Connect Scan selected.")
    else:
        print("ℹ️ Using TCP Connect Scan (Scapy unavailable for SYN).")

    verbose_choice = input("🔹 Enable verbose output (show closed/filtered ports)? (y/N): ").strip().lower()
    verbose = True if verbose_choice == 'y' else False

    results = {}
    lock = Lock()
    threads = []
    scan_function = scan_port_syn if scan_type == "SYN" else scan_port_tcp

    print(f"\n🚀 Scanning ports {start_port}-{end_port} on {target} using {scan_type} Scan...")
    start_time = datetime.now()

    permission_error_raised = False
    try:
        for port in range(start_port, end_port + 1):
            current_args = (target, port, results, lock, verbose)
            thread = threading.Thread(target=scan_function, args=current_args, daemon=True)
            threads.append(thread)
            thread.start()
            if len(threads) % 50 == 0:
                 time.sleep(0.05)

        for thread in threads:
            thread.join()

    except PermissionError as pe:
         print(f"\n❌ {pe}")
         print("   Aborting scan. Please run with sudo or as administrator for SYN scans.")
         permission_error_raised = True
    except KeyboardInterrupt:
         print("\n\n🛑 Scan interrupted by user. Waiting for active threads to finish...")
         print("   Scan partially completed.")
    except Exception as e:
         print(f"\n❌ An unexpected error occurred during scanning: {e}")


    end_time = datetime.now()
    duration = end_time - start_time
    print(f"\n✅ Scan Completed in {duration}.")

    if permission_error_raised:
        print("   Scan results might be incomplete due to permission errors.")
        os_detected = "Unknown (Scan Error)"
    else:
        os_detected = "Unknown (Skipped)"
        if not permission_error_raised:
             os_choice = input("🔹 Attempt OS detection (requires root/admin & Scapy)? (y/N): ").strip().lower()
             if os_choice == 'y':
                  if SCAPY_AVAILABLE:
                       os_detected = detect_os(target)
                       print(f"🖥️ OS Detection Result: {os_detected}")
                  else:
                       print("   OS Detection requires Scapy library.")
                       os_detected = "Unknown (Scapy unavailable)"
             else:
                 os_detected = "Unknown (Skipped by user)"

        open_ports_count = len(results)
        print(f"\n📊 Found {open_ports_count} open port(s).")
        if open_ports_count > 0 and open_ports_count <= 20:
            for port, details in sorted(results.items()):
                print(f"  -> Port {port}/TCP: {details.get('status')} ({details.get('service')})")
        elif open_ports_count > 20:
             print("   (List of open ports saved to file if chosen)")

        if results:
             save_results(target, results, os_detected)
        else:
             print("   No open ports detected in the specified range.")

    print("\n--- End of Interactive Port Scanner ---")


# --- Main Application Menu ---

def display_menu():
    print("\n======== Integrated Network Security Toolkit ========")
    print("Select a tool to run:")
    print("  1. Basic Vulnerability Scanner (Checks common ports against known issues)")
    print("  2. Network Traffic Analyzer (Analyzes CSV for DDoS/Anomalies)")
    print("  3. Interactive Port Scanner (TCP/SYN Scan, OS Detection)")
    print("  0. Exit")
    print("====================================================")

def main():
    while True:
        display_menu()
        choice = input("Enter your choice (0-3): ").strip()

        if choice == '1':
            run_vulnerability_scanner()
        elif choice == '2':
            run_traffic_analyzer()
        elif choice == '3':
            run_interactive_scanner()
        elif choice == '0':
            print("Exiting Toolkit. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 0 and 3.")

        input("\nPress Enter to return to the main menu...")


if __name__ == "__main__":
    if SCAPY_AVAILABLE and (sys.platform.startswith("linux") or sys.platform.startswith("darwin")):
        try:
            if os.geteuid() != 0:
                print("\n[!] Warning: Script not run as root (sudo).")
                print("    SYN scanning (Tool 3) and OS detection may fail due to permissions.")
        except AttributeError:
            pass
    elif SCAPY_AVAILABLE and sys.platform.startswith("win"):
         import ctypes
         try:
             if not ctypes.windll.shell32.IsUserAnAdmin():
                 print("\n[!] Warning: Script not run as Administrator.")
                 print("    SYN scanning (Tool 3) and OS detection may fail due to permissions.")
         except Exception:
            print("\n[!] Warning: Could not determine administrator status.")
            print("    SYN scanning (Tool 3) and OS detection may require admin rights.")

    main()
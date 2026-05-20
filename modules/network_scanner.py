import socket
from concurrent.futures import ThreadPoolExecutor
import time
from urllib.parse import urlparse
import re

COMMON_PORTS = {
    21: {"service": "FTP", "risk": "High (Cleartext credentials)"},
    22: {"service": "SSH", "risk": "Medium (Secure Access)"},
    23: {"service": "Telnet", "risk": "High (Insecure Cleartext Protocol)"},
    25: {"service": "SMTP", "risk": "Medium (Mail Transfer)"},
    53: {"service": "DNS", "risk": "Low (Domain Name Resolution)"},
    80: {"service": "HTTP", "risk": "Medium (Unencrypted Web)"},
    110: {"service": "POP3", "risk": "High (Cleartext Email Access)"},
    139: {"service": "NetBIOS", "risk": "High (File Sharing)"},
    143: {"service": "IMAP", "risk": "High (Cleartext Email Access)"},
    443: {"service": "HTTPS", "risk": "Low (Secure Web)"},
    445: {"service": "SMB", "risk": "High (Potential vulnerability surface)"},
    1433: {"service": "MS SQL", "risk": "High (Database Access Port)"},
    3306: {"service": "MySQL", "risk": "High (Database Access Port)"},
    3389: {"service": "RDP", "risk": "High (Remote Desktop)"},
    8080: {"service": "HTTP-Proxy/Alt", "risk": "Medium (Alternative HTTP Port)"}
}

def sanitize_host(target):
    """
    Sanitizes raw user input into a clean hostname or IP address suitable for socket operations.
    Handles 'http://', 'https://', trailing paths, ports, and brackets for IPv6.
    """
    target = target.strip()
    
    # 1. Handle prepended scheme protocols
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        host = parsed.netloc
    elif '/' in target or ':' in target:
        # Prepend scheme to help urlparse extract netloc correctly if there is a path
        if '/' in target:
            parsed = urlparse('http://' + target)
            host = parsed.netloc or parsed.path.split('/')[0]
        else:
            host = target
    else:
        host = target

    # 2. Extract port suffix (e.g. localhost:5000 -> localhost)
    if ':' in host:
        # Distinguish IPv6 address containing multiple colons from hostname:port
        if host.count(':') == 1:
            host = host.split(':')[0]
        elif host.startswith('[') and ']' in host:
            # Handle brackets in IPv6 like [::1]:5000
            match = re.match(r'\[(.*?)\]', host)
            if match:
                host = match.group(1)

    # 3. Clean any remaining slash or query parameters
    if '/' in host:
        host = host.split('/')[0]
        
    return host

def scan_port(host, port, family=socket.AF_INET, timeout=1.0):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            service_info = COMMON_PORTS.get(port, {"service": "Unknown", "risk": "Info"})
            banner = ""
            try:
                # Attempt service banner grab with a highly responsive short timeout to prevent socket hangs
                if port in [21, 22, 25]:
                    sock.settimeout(0.3)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            
            sock.close()
            return {
                "port": port,
                "status": "Open",
                "service": service_info["service"],
                "risk": service_info["risk"],
                "banner": banner or "N/A"
            }
        sock.close()
    except Exception:
        pass
    return None

def run_port_scan(target, scan_mode="fast", custom_ports=None):
    # Auto-sanitize user target input (e.g., http://localhost:5000 -> localhost)
    sanitized = sanitize_host(target)
    
    try:
        # Resolve target host using addrinfo to support IPv4 and IPv6 hosts
        addr_info = socket.getaddrinfo(sanitized, None)
        
        # Prioritize IPv4 over IPv6 to ensure maximum compatibility and avoid local resolution deadlocks
        family = None
        host = None
        for res in addr_info:
            fam, _, _, _, sockaddr = res
            ip = sockaddr[0]
            if fam == socket.AF_INET:
                family = fam
                host = ip
                break
        if not host:
            family = addr_info[0][0]
            host = addr_info[0][4][0]
    except socket.gaierror:
        return {"error": "Invalid host or IP address"}

    ports_to_scan = []
    if custom_ports:
        ports_to_scan = custom_ports
    elif scan_mode == "fast":
        ports_to_scan = list(COMMON_PORTS.keys())
    elif scan_mode == "full":
        ports_to_scan = list(range(1, 1025))
        
    open_ports = []
    start_time = time.time()
    
    # Run multi-threaded scan using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(scan_port, host, port, family) for port in ports_to_scan]
        for future in futures:
            res = future.result()
            if res:
                open_ports.append(res)
                
    end_time = time.time()
    scan_duration = round(end_time - start_time, 2)
    
    # Calculate threat metric based on open high-risk ports
    high_risk_count = sum(1 for p in open_ports if "High" in p["risk"])
    medium_risk_count = sum(1 for p in open_ports if "Medium" in p["risk"])
    
    score = (high_risk_count * 30) + (medium_risk_count * 10)
    score = min(score, 100)
    
    if score >= 60 or high_risk_count >= 2:
        level = "High"
    elif score >= 35 or medium_risk_count >= 2:
        level = "Medium"
    else:
        level = "Low"
        
    return {
        "target": sanitized,
        "ip": host,
        "scan_mode": scan_mode,
        "duration": scan_duration,
        "open_ports": open_ports,
        "open_ports_count": len(open_ports),
        "threat_score": score,
        "threat_level": level,
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    }

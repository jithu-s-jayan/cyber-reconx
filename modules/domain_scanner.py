import socket
import whois
import requests
import ssl
import OpenSSL
from datetime import datetime
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Unknown"

def dns_lookup(domain):
    records = {"A": [], "MX": [], "TXT": [], "NS": []}
    
    # Simple A record resolution
    try:
        ip = socket.gethostbyname(domain)
        if ip:
            records["A"].append(ip)
    except Exception:
        pass
        
    # We fallback to standard lookup or basic output to avoid external dnspython dependency complexity
    # We can perform socket-based checks
    for record_type in ["MX", "TXT", "NS"]:
        records[record_type] = ["Lookup bypassed to maintain portable dependencies"]
    return records

def query_whois(domain):
    try:
        w = whois.whois(domain)
        # Parse output into clean dict
        return {
            "registrar": w.registrar or "Unknown",
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date or "Unknown"),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date or "Unknown"),
            "emails": w.emails or "Unknown",
            "country": w.country or "Unknown"
        }
    except Exception as e:
        return {
            "registrar": "Error querying WHOIS",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "emails": "Unknown",
            "country": "Unknown"
        }

def analyze_ssl(domain):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                
                issuer = x509.get_issuer()
                subject = x509.get_subject()
                
                not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
                not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                
                return {
                    "valid": not_after > datetime.utcnow(),
                    "issuer": issuer.CN or "Unknown",
                    "subject": subject.CN or "Unknown",
                    "valid_from": not_before.strftime('%Y-%m-%d'),
                    "valid_until": not_after.strftime('%Y-%m-%d'),
                    "version": x509.get_version() + 1
                }
    except Exception as e:
         return {
            "valid": False,
            "issuer": "N/A or Expired",
            "subject": "N/A",
            "valid_from": "N/A",
            "valid_until": "N/A",
            "version": "N/A"
         }

def get_security_headers(domain):
    headers_to_check = {
        "Strict-Transport-Security": "HSTS (Enforces HTTPS connections)",
        "Content-Security-Policy": "CSP (Prevents XSS attacks)",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME-sniffing Protection",
        "Referrer-Policy": "Controls referrer information disclosure",
        "Permissions-Policy": "Restricts browser feature usage"
    }
    
    results = {}
    try:
        response = requests.get(f"https://{domain}", timeout=4, verify=False, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        headers = response.headers
        for header, description in headers_to_check.items():
            val = headers.get(header)
            results[header] = {
                "present": val is not None,
                "value": val or "Missing",
                "description": description,
                "status": "SECURE" if val else "WARNING"
            }
        
        # Technology Heuristic Detect
        server = headers.get("Server", "Unknown")
        powered_by = headers.get("X-Powered-By", "")
        tech = []
        if "cloudflare" in server.lower():
            tech.append("Cloudflare CDN")
        if "nginx" in server.lower():
            tech.append("Nginx Web Server")
        elif "apache" in server.lower():
            tech.append("Apache Web Server")
        elif "iis" in server.lower():
            tech.append("Microsoft IIS")
            
        if "php" in powered_by.lower():
            tech.append("PHP")
        elif "asp" in powered_by.lower():
            tech.append("ASP.NET")
            
        # Detect CMS
        cms = "Unknown"
        resp_text = response.text.lower()
        if "wp-content" in resp_text or "wordpress" in resp_text:
            cms = "WordPress"
            tech.append("WordPress CMS")
        elif "drupal" in resp_text:
            cms = "Drupal"
            tech.append("Drupal CMS")
        elif "joomla" in resp_text:
            cms = "Joomla"
            tech.append("Joomla CMS")
            
        return results, server, cms, tech
    except Exception as e:
        # Fallback to HTTP
        try:
            response = requests.get(f"http://{domain}", timeout=4, headers={'User-Agent': 'Mozilla/5.0'})
            headers = response.headers
            for header, description in headers_to_check.items():
                val = headers.get(header)
                results[header] = {
                    "present": val is not None,
                    "value": val or "Missing",
                    "description": description,
                    "status": "SECURE" if val else "WARNING"
                }
            return results, headers.get("Server", "Unknown"), "Unknown", []
        except Exception:
            for header, description in headers_to_check.items():
                results[header] = {
                    "present": False,
                    "value": "Could not connect",
                    "description": description,
                    "status": "ERROR"
                }
            return results, "Unknown", "Unknown", []

def run_domain_recon(domain):
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    
    ip = get_ip(domain)
    dns = dns_lookup(domain)
    whois_info = query_whois(domain)
    ssl_info = analyze_ssl(domain)
    headers, server, cms, tech = get_security_headers(domain)
    
    # Dynamic threat score calculation
    score = 0
    warnings = 0
    
    if ssl_info["valid"] is False:
        score += 20
        warnings += 1
    
    for h, details in headers.items():
        if not details["present"]:
            score += 10
            warnings += 1
            
    # Risk evaluation
    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"
        
    return {
        "domain": domain,
        "ip": ip,
        "dns": dns,
        "whois": whois_info,
        "ssl": ssl_info,
        "headers": headers,
        "server": server,
        "cms": cms,
        "technologies": tech if tech else ["None Detected"],
        "threat_score": min(score, 100),
        "threat_level": level,
        "warnings": warnings,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

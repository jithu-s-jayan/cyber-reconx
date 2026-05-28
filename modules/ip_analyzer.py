import requests
import socket

def analyze_ip(ip_address):
    # Validate input or get IP if domain is entered
    try:
        ip = socket.gethostbyname(ip_address)
    except Exception:
        return {"error": "Invalid host or IP address format"}
        
    try:
        # Use a public geolocation API with advanced security fields
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting,mobile", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                # Compute mock intelligence details
                threat_score = 15
                threat_level = "Low"
                
                is_proxy = data.get("proxy", False)
                is_hosting = data.get("hosting", False)
                is_mobile = data.get("mobile", False)
                
                # Check for hosting / datacenter vs residential
                if is_proxy:
                    threat_score += 40
                    threat_level = "High"
                elif is_hosting:
                    threat_score += 15
                    threat_level = "Medium"
                elif is_mobile:
                    threat_score -= 5  # Mobile IPs are usually safe
                    
                if threat_score < 0: threat_score = 0
                
                # Fetch Reverse IP domains (Passive DNS)
                associated_domains = get_reverse_ip_domains(data.get("query"))
                
                # Threat summary logs
                return {
                    "ip": data.get("query"),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "UN"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "zip": data.get("zip", "N/A"),
                    "latitude": data.get("lat", 0.0),
                    "longitude": data.get("lon", 0.0),
                    "timezone": data.get("timezone", "UTC"),
                    "isp": data.get("isp", "Unknown"),
                    "asn": data.get("as", "Unknown"),
                    "is_proxy": is_proxy,
                    "is_hosting": is_hosting,
                    "is_mobile": is_mobile,
                    "threat_score": threat_score,
                    "threat_level": threat_level,
                    "rdns": get_rdns(ip),
                    "associated_domains": associated_domains
                }
            else:
                return {"error": data.get("message", "IP Geolocation lookup failed")}
    except Exception as e:
        pass
        
    return {
        "ip": ip,
        "country": "Unknown",
        "country_code": "UN",
        "region": "Unknown",
        "city": "Unknown",
        "zip": "N/A",
        "latitude": 0.0,
        "longitude": 0.0,
        "timezone": "UTC",
        "isp": "Local / Offline Network",
        "asn": "Private AS",
        "is_proxy": False,
        "is_hosting": False,
        "is_mobile": False,
        "threat_score": 0,
        "threat_level": "Info",
        "rdns": get_rdns(ip),
        "associated_domains": []
    }

def get_rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "No reverse DNS record"

def get_reverse_ip_domains(ip):
    try:
        res = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=5)
        if res.status_code == 200:
            text = res.text.strip()
            if "API count exceeded" in text or "error" in text.lower() or "no dns a records found" in text.lower():
                return []
            domains = text.split('\n')
            return [d.strip() for d in domains if d.strip()][:20]
        return []
    except Exception:
        return []

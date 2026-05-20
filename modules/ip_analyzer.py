import requests
import socket

def analyze_ip(ip_address):
    # Validate input or get IP if domain is entered
    try:
        ip = socket.gethostbyname(ip_address)
    except Exception:
        return {"error": "Invalid host or IP address format"}
        
    try:
        # Use a public geolocation API
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                # Compute mock intelligence details
                threat_score = 15
                threat_level = "Low"
                
                # Check for hosting / datacenter vs residential
                is_hosting = "hosting" in data.get("org", "").lower() or "datacenter" in data.get("isp", "").lower()
                if is_hosting:
                    threat_score += 15
                    
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
                    "threat_score": threat_score,
                    "threat_level": threat_level,
                    "rdns": get_rdns(ip)
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
        "threat_score": 0,
        "threat_level": "Info",
        "rdns": get_rdns(ip)
    }

def get_rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "No reverse DNS record"

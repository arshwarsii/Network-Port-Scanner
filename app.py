from flask import Flask, render_template, request, jsonify
import ipaddress
import shodan
import socket
from concurrent.futures import ThreadPoolExecutor
import os

app = Flask(__name__)

# Safety configuration
MAX_SCAN_IPS = 256  # Maximum number of IPs allowed per scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]

# Initialize Shodan (use environment variable for API key)
SHODAN_API_KEY = os.getenv('Shodan API', '')
shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

def parse_ip_range(ip_range):
    try:
        # Try CIDR notation first
        if '/' in ip_range:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            return list(network.hosts())
        
        # Try IP range format (e.g., 192.168.1.1-192.168.1.5)
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-', 1)
            start = ipaddress.IPv4Address(start_ip.strip())
            end = ipaddress.IPv4Address(end_ip.strip())
            if start > end:
                start, end = end, start
            return [ipaddress.IPv4Address(ip) for ip in range(int(start), int(end)+1)]
        
        # Single IP
        return [ipaddress.IPv4Address(ip_range)]
    
    except (ipaddress.AddressValueError, ValueError):
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_range = request.form.get('ip_range', '').strip()
    if not ip_range:
        return jsonify({"error": "Please enter an IP range to scan"})
    
    # Parse IP range
    ips = parse_ip_range(ip_range)
    if not ips:
        return jsonify({"error": "Invalid IP range format. Use CIDR (192.168.1.0/24) or range (192.168.1.1-192.168.1.5)"})
    
    # Safety check
    if len(ips) > MAX_SCAN_IPS:
        return jsonify({"error": f"Maximum scan range exceeded ({MAX_SCAN_IPS} IPs allowed)"})
    
    # Scan IPs concurrently
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in ips]
        for future in futures:
            results.append(future.result())
    
    return jsonify({"results": results})

def scan_ip(ip):
    result = {"ip": str(ip), "ports": [], "vulnerabilities": [], "source": "local"}
    
    # Try Shodan first if available
    if shodan_api:
        try:
            host = shodan_api.host(str(ip))
            result["ports"] = [{
                "port": item['port'],
                "status": "open",
                "service": item.get('product', 'unknown')
            } for item in host['data']]
            result["vulnerabilities"] = host.get('vulns', [])
            result["source"] = "shodan"
            return result
        except shodan.APIError:
            pass
        except Exception as e:
            print(f"Shodan error: {e}")
    
    # Local port scanning (fixed the socket.connect_ex syntax)
    for port in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                # Fixed the parentheses placement here
                if s.connect_ex((str(ip), port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    result["ports"].append({
                        "port": port,
                        "status": "open",
                        "service": service
                    })
        except:
            continue
    
    return result

if __name__ == '__main__':
    app.run(debug=True)

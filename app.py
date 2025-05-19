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
SHODAN_API_KEY = os.getenv('Sw6nsq5lw00tEfuUk2XGSteUPoTbhJCl', '')
shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

def parse_ip_range(ip_range):
    try:
        if '/' in ip_range:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            return list(network.hosts())
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-', 1)
            start = ipaddress.IPv4Address(start_ip.strip())
            end = ipaddress.IPv4Address(end_ip.strip())
            if start > end:
                start, end = end, start
            return [ipaddress.IPv4Address(ip) for ip in range(int(start), int(end)+1)]
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
    
    ips = parse_ip_range(ip_range)
    if not ips:
        return jsonify({"error": "Invalid IP range format. Use CIDR or IP range"})
    
    if len(ips) > MAX_SCAN_IPS:
        return jsonify({"error": f"Maximum scan range exceeded ({MAX_SCAN_IPS} IPs allowed)"})

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in ips]
        results = [future.result() for future in futures]
    
    return jsonify({"results": results})

def scan_ip(ip):
    result = {"ip": str(ip), "ports": [], "vulnerabilities": [], "source": "shodan"}
    
    if not shodan_api:
        return result
    
    try:
        host = shodan_api.host(str(ip))
        result["ports"] = [{
            "port": item['port'],
            "status": "open",
            "service": item.get('product', 'unknown')
        } for item in host['data']]
        result["vulnerabilities"] = host.get('vulns', [])
        return result
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
        return result
    except Exception as e:
        print(f"General error: {e}")
        return result

@app.route('/get_my_ip', methods=['GET'])
def get_my_ip():
    # X-Forwarded-For header for proxy compatibility
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    return jsonify({"ip": client_ip.split(',')[0].strip()})

if __name__ == '__main__':
    app.run(debug=True)

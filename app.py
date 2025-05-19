from flask import Flask, render_template, request, jsonify
import ipaddress
import shodan
from concurrent.futures import ThreadPoolExecutor
import os
import logging

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)

# Safety configuration
MAX_SCAN_IPS = 256

# Shodan configuration
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

def parse_target(target):
    """Improved target parsing with better error handling"""
    target = target.strip()
    
    try:
        # Try single IP first
        ip = ipaddress.ip_address(target)
        return [ip]
    except ValueError:
        pass

    try:
        # Try CIDR
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            return list(network.hosts())
    except ValueError:
        pass

    try:
        # Try IP range
        if '-' in target:
            start_str, end_str = target.split('-', 1)
            start = ipaddress.ip_address(start_str.strip())
            end = ipaddress.ip_address(end_str.strip())
            if start > end:
                start, end = end, start
            return [ipaddress.ip_address(ip) for ip in range(int(start), int(end)+1)]
    except ValueError:
        pass

    return None

@app.route('/scan', methods=['POST'])
def scan():
    if not request.is_json:
        return jsonify({"error": "Invalid content type, requires JSON"}), 400

    data = request.get_json()
    target = data.get('target', '').strip()
    app.logger.debug(f"Scan request received for target: '{target}'")

    if not target:
        return jsonify({"error": "Please enter an IP address or range"}), 400

    ips = parse_target(target)
    if not ips:
        return jsonify({"error": "Invalid target format. Use: 192.168.1.1, 10.0.0.0/24, or 192.168.1.1-192.168.1.5"}), 400

    if len(ips) > MAX_SCAN_IPS:
        return jsonify({"error": f"Maximum scan range exceeded ({MAX_SCAN_IPS} IPs allowed)"}), 400

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(scan_ip, ips))
        return jsonify({"results": results})
    except Exception as e:
        app.logger.error(f"Scan error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

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
        } for item in host.get('data', [])]
        result["vulnerabilities"] = host.get('vulns', [])
        return result
    except shodan.APIError as e:
        app.logger.warning(f"Shodan API error for {ip}: {str(e)}")
        return result
    except Exception as e:
        app.logger.error(f"Error scanning {ip}: {str(e)}")
        return result

@app.route('/get_my_ip', methods=['GET'])
def get_my_ip():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    return jsonify({"ip": client_ip})

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

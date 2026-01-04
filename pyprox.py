#!/usr/bin/env python3

import dns.message   # pip install dnspython
import dns.rdatatype
import psutil        # pip install psutil
import requests      # pip install requests
import json
from pathlib import Path
import os
import base64
import socket
import threading
import time
import random
import http.server
import socketserver
import urllib.parse
import sqlite3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certs
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Embedded Assets ---

EMBEDDED_OFFLINE_DNS = {
    "cloudflare-dns.com": "203.32.120.226", "dns.google": "8.8.8.8", "doh.opendns.com": "208.67.222.222",
    "secure.avastdns.com": "185.185.133.66", "doh.libredns.gr": "116.202.176.26", "dns.electrotm.org": "78.157.42.100",
    "dns.bitdefender.net": "34.84.232.67", "cluster-1.gac.edu": "138.236.128.101", "api.twitter.com": "104.244.42.66",
    "twitter.com": "104.244.42.1", "pbs.twimg.com": "93.184.220.70", "abs-0.twimg.com": "104.244.43.131",
    "abs.twimg.com": "152.199.24.185", "video.twimg.com": "192.229.220.133", "t.co": "104.244.42.69",
    "ton.local.twitter.com": "104.244.42.1", "instagram.com": "163.70.128.174", "www.instagram.com": "163.70.128.174",
    "static.cdninstagram.com": "163.70.132.63", "scontent.cdninstagram.com": "163.70.132.63",
    "privacycenter.instagram.com": "163.70.128.174", "help.instagram.com": "163.70.128.174",
    "l.instagram.com": "163.70.128.174", "e1.whatsapp.net": "163.70.128.60", "e2.whatsapp.net": "163.70.128.60",
    "wa.me": "185.60.219.60", "web.whatsapp.com": "31.13.83.51", "whatsapp.net": "31.13.83.51",
    "whatsapp.com": "31.13.83.51", "cdn.whatsapp.net": "31.13.83.51", "connect.facebook.net": "31.13.84.51",
    "facebook.com": "31.13.65.49", "developers.facebook.com": "31.13.84.8", "about.meta.com": "163.70.128.13",
    "meta.com": "163.70.128.13", "www.google.com": "142.250.186.36", "youtube.com": "216.239.38.120",
    "youtu.be": "216.239.38.120", "www.youtube.com": "216.239.38.120", "i.ytimg.com": "216.239.38.120",
    "yt3.ggpht.com": "142.250.186.36", "play.google.com": "142.250.184.238", "fonts.gstatic.com": "142.250.185.227",
    "googlevideo.com": "74.125.98.7"
}

EMBEDDED_USER_DNS = {
    "moreweb.ir": "104.21.81.254", "google.com": "172.217.12.142", "bbc.com": "151.101.0.81",
    "boardshop.ir": "185.49.85.44", "www.apple.com": "72.246.165.41", "www.bing.com": "173.222.162.19",
    "www.cloudflare.com": "104.16.123.96", "reddit.com": "151.101.193.140", "wikipedia.org": "198.35.26.96"
}

EMBEDDED_DOH_PROVIDERS = [
    'https://cloudflare-dns.com/dns-query?dns=',
    'https://dns.google/dns-query?dns=',
    'https://doh.opendns.com/dns-query?dns=',
    'https://dns.electrotm.org/dns-query?dns=',
]

V2RAY_CONFIG_TEMPLATE = """
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks",
      "port": 10808,
      "listen": "0.0.0.0",
      "protocol": "socks",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "settings": {
        "auth": "noauth",
        "udp": true
      }
    },
    {
      "tag": "http",
      "port": 10809,
      "listen": "0.0.0.0",
      "protocol": "http",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "settings": {
        "auth": "noauth",
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "http",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": 4500
          }
        ]
      }
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": ["geoip:private"]
      }
    ]
  }
}
"""

# --- Configuration ---
CONFIG = {
    'LISTEN_PORT': 4500,
    'WEB_PORT': 8080,
    'DNS_PORT': 53,
    'OUTBOUND_ADAPTER_IP': '0.0.0.0', # '0.0.0.0' means AUTO
    'FRAGMENT_COUNT_RANGE': [80, 120],  # [Min, Max]
    'FRAGMENT_SLEEP_RANGE': [0.001, 0.005], # [Min, Max] seconds
    'REMOTE_DNS_URL': "",
    'ALLOW_INSECURE_DOH': True
}

# --- Globals ---
START_TIME = time.time()
IP_DL_TRAFFIC = {}
IP_UL_TRAFFIC = {}
GLOBAL_DOH = None
DB_FILE = 'pyprox.db'
DB_LOCK = threading.RLock()

# --- Database Management ---
def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Creates and populates the database if it doesn't exist."""
    with DB_LOCK:
        conn = get_db()
        cursor = conn.cursor()

        # Check if db is new
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
        is_new_db = cursor.fetchone() is None

        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, value TEXT
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_records (
                domain TEXT PRIMARY KEY, ip TEXT, type TEXT
            )''') # type: 'offline' or 'cache'
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS doh_providers (
                url TEXT PRIMARY KEY
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tuner_data (
                domain TEXT PRIMARY KEY, frags INTEGER, sleep REAL, score REAL
            )''')

        if is_new_db:
            print("New database detected. Populating with default data...")
            # Populate settings
            for key, value in CONFIG.items():
                cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, json.dumps(value)))

            # Populate DNS
            for domain, ip in EMBEDDED_OFFLINE_DNS.items():
                cursor.execute("INSERT OR IGNORE INTO dns_records (domain, ip, type) VALUES (?, ?, 'offline')", (domain, ip))
            for domain, ip in EMBEDDED_USER_DNS.items():
                cursor.execute("INSERT OR IGNORE INTO dns_records (domain, ip, type) VALUES (?, ?, 'cache')", (domain, ip))

            # Populate DoH
            for url in EMBEDDED_DOH_PROVIDERS:
                cursor.execute("INSERT OR IGNORE INTO doh_providers (url) VALUES (?)", (url,))

        conn.commit()
        conn.close()
        print("Database initialized.")

def load_config_from_db():
    """Loads configuration from the database into the global CONFIG dict."""
    global CONFIG
    with DB_LOCK:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings")
        rows = cursor.fetchall()
        for row in rows:
            try:
                CONFIG[row['key']] = json.loads(row['value'])
            except (json.JSONDecodeError, TypeError):
                CONFIG[row['key']] = row['value']
        conn.close()
    print("Configuration loaded from database.")

class AutoTuner:
    def __init__(self):
        self.learning_mode = False
        self.learning_thread = None

    def get_settings(self, domain):
        """
        Gets the best settings.
        1. Tries to find settings for the specific domain.
        2. If not found, finds the setting with the highest score globally.
        3. If no settings exist, returns random ones.
        """
        with DB_LOCK:
            conn = get_db()
            cursor = conn.cursor()
            
            # 1. Look for domain-specific setting
            cursor.execute("SELECT frags, sleep FROM tuner_data WHERE domain=?", (domain,))
            row = cursor.fetchone()
            if row:
                print(f"Tuner: Using specific settings for {domain} ({row['frags']} frags, {row['sleep']:.4f}s)")
                conn.close()
                return row['frags'], row['sleep']

            # 2. Look for the best global setting
            cursor.execute("SELECT domain, frags, sleep FROM tuner_data ORDER BY score DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                print(f"Tuner: No specific setting for {domain}. Using best global from '{row['domain']}' ({row['frags']} frags, {row['sleep']:.4f}s)")
                conn.close()
                return row['frags'], row['sleep']
            
            conn.close()

        # 3. Fallback to random
        frag_min, frag_max = CONFIG['FRAGMENT_COUNT_RANGE']
        sleep_min, sleep_max = CONFIG['FRAGMENT_SLEEP_RANGE']
        frags = random.randint(frag_min, frag_max)
        sleep = random.uniform(sleep_min, sleep_max)
        return frags, sleep

    def report(self, domain, frags, sleep, bytes_down):
        """Reports the performance of a setting combination."""
        if not domain:
            return

        with DB_LOCK:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT frags, sleep, score FROM tuner_data WHERE domain=?", (domain,))
            row = cursor.fetchone()
            
            # Check if a used setting has failed
            if row and row['frags'] == frags and abs(row['sleep'] - sleep) < 0.0001:
                # This was a known setting. If it performed poorly, delete it.
                if bytes_down < 1024: # Failed if less than 1KB transferred
                    print(f"Tuner: Learned setting for {domain} failed (score: {bytes_down}). Deleting.")
                    cursor.execute("DELETE FROM tuner_data WHERE domain=?", (domain,))
                    conn.commit()
                    conn.close()
                    return

            # Learn new settings only for reasonably large transfers
            if bytes_down < 10240: # Ignore small connections (<10KB) for learning
                conn.close()
                return

            current_best_score = row['score'] if row else 0
            if bytes_down > current_best_score:
                print(f"Tuner: New best score for {domain}: {bytes_down} bytes (frags: {frags}, sleep: {sleep:.4f}s)")
                cursor.execute("""
                    INSERT OR REPLACE INTO tuner_data (domain, frags, sleep, score)
                    VALUES (?, ?, ?, ?)
                """, (domain, frags, sleep, bytes_down))
                conn.commit()
            conn.close()

    def start_learning_mode(self):
        if not self.learning_mode:
            self.learning_mode = True
            self.learning_thread = threading.Thread(target=self.run_active_learning, daemon=True)
            self.learning_thread.start()
            print("Tuner: Learning mode started.")

    def stop_learning_mode(self):
        if self.learning_mode:
            self.learning_mode = False
            if self.learning_thread and self.learning_thread.is_alive():
                # The thread will stop on its own by checking self.learning_mode
                pass
            print("Tuner: Learning mode stopped.")

    def run_active_learning(self):
        test_domains = ["www.google.com", "www.bing.com", "www.yahoo.com", "www.amazon.com", "www.wikipedia.org"]
        proxy = {'https': 'http://127.0.0.1:' + str(CONFIG['LISTEN_PORT'])}

        while self.learning_mode:
            domain = random.choice(test_domains)
            print(f"Tuner: Actively testing {domain}...")
            try:
                # This request goes through our own proxy, triggering the full fragmentation and reporting logic
                resp = requests.get(f"https://{domain}", proxies=proxy, stream=True, timeout=15, verify=False)
                
                bytes_down = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    bytes_down += len(chunk)
                    if bytes_down > 50 * 1024: # Stop after 50KB
                        break
                resp.close()
            except Exception as e:
                print(f"Tuner: Active learning connection failed for {domain}: {repr(e)}")
            
            time.sleep(random.uniform(2, 5)) # Wait before next test

TUNER = AutoTuner()

class DNS_Over_Fragment:
    def __init__(self):
        self.req = requests.Session()
        self.fragment_proxy = {
            'https': 'http://127.0.0.1:' + str(CONFIG['LISTEN_PORT'])
        }

    def query(self, server_name, force=False):
        with DB_LOCK:
            conn = get_db()
            cursor = conn.cursor()
            # 1. Check DB (Offline and Cache)
            if not force:
                cursor.execute("SELECT ip, type FROM dns_records WHERE domain=?", (server_name,))
                row = cursor.fetchone()
                if row:
                    print(f"DNS ({row['type']}) --> {server_name} : {row['ip']}")
                    conn.close()
                    return row['ip']

            # 2. Online DoH Query
            print(f'Online DNS Query --> {server_name}')
            
            query_message = dns.message.make_query(server_name, 'A')
            query_wire = query_message.to_wire()
            query_base64 = base64.urlsafe_b64encode(query_wire).decode('utf-8').replace('=', '')

            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            ]

            cursor.execute("SELECT url FROM doh_providers")
            providers = [row['url'] for row in cursor.fetchall()]
            random.shuffle(providers)

            for provider_url in providers:
                try:
                    query_url = provider_url + query_base64
                    ans = self.req.get(
                        query_url,
                        headers={'accept': 'application/dns-message', 'User-Agent': random.choice(user_agents)},
                        proxies=self.fragment_proxy,
                        verify=(not CONFIG.get('ALLOW_INSECURE_DOH', True)),
                        timeout=5
                    )

                    if ans.status_code == 200 and ans.headers.get('content-type') == 'application/dns-message':
                        answer_msg = dns.message.from_wire(ans.content)
                        for x in answer_msg.answer:
                            if x.rdtype == dns.rdatatype.A:
                                resolved_ip = x[0].address
                                print(f'Online DNS Resolved --> {server_name} : {resolved_ip}')
                                # Save to cache
                                cursor.execute("INSERT OR REPLACE INTO dns_records (domain, ip, type) VALUES (?, ?, 'cache')", (server_name, resolved_ip))
                                conn.commit()
                                conn.close()
                                return resolved_ip
                    else:
                        print(f'DNS Error ({provider_url}): {ans.status_code} {ans.reason}')
                except Exception as e:
                    print(f'DNS Exception ({provider_url}): {repr(e)}')
            
            conn.close()
            return None

class ThreadedServer(object):
    def __init__(self, host, port):
        self.DoH = GLOBAL_DOH if GLOBAL_DOH else DNS_Over_Fragment()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(128)
        print(f"PyProx listening at: {self.host}:{self.port}")
        while True:
            try:
                client_sock, client_addr = self.sock.accept()
                client_sock.settimeout(21) # Socket timeout
                
                # Slight delay to prevent flooding crashes
                time.sleep(0.01)
                
                thread_up = threading.Thread(target=self.my_upstream, args=(client_sock,))
                thread_up.daemon = True
                thread_up.start()
            except Exception as e:
                print(f"Listener Error: {e}")
                time.sleep(1)

    def handle_client_request(self, client_socket):
        try:
            data = client_socket.recv(16384)
        except Exception:
            client_socket.close()
            return None, None

        if not data:
            client_socket.close()
            return None, None

        # Handle HTTPS (CONNECT)
        if data.startswith(b'CONNECT'):
            server_name, server_port = self.extract_servername_and_port(data)
        # Handle HTTP (Redirect to HTTPS)
        elif any(data.startswith(x) for x in [b'GET', b'POST', b'HEAD', b'OPTIONS', b'PUT', b'DELETE', b'PATCH']):
            try:
                q_line = str(data).split('\r\n')
                q_req = q_line[0].split()
                q_url = q_req[1]
                if 'http://' in q_url:
                    q_url = q_url.replace('http://', 'https://')
                    print(f'Redirecting HTTP to HTTPS: {q_url}')
                    response_data = f'HTTP/1.1 302 Found\r\nLocation: {q_url}\r\nProxy-agent: PyProx/1.0\r\n\r\n'
                    client_socket.sendall(response_data.encode())
                else:
                    # If it's already relative or weird, just close
                    pass
            except:
                pass
            client_socket.close()
            return None, None
        else:
            client_socket.close()
            return None, None

        print(f'{server_name} --> {server_port}')

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(21)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Resolve IP
            try:
                socket.inet_aton(server_name)
                server_ip = server_name
            except socket.error:
                server_ip = self.DoH.query(server_name)

            if not server_ip:
                raise Exception("Could not resolve IP")

            outbound_ip = CONFIG.get('OUTBOUND_ADAPTER_IP', '0.0.0.0')
            if outbound_ip and outbound_ip != '0.0.0.0':
                try:
                    print(f"Binding outbound connection to adapter: {outbound_ip}")
                    server_socket.bind((outbound_ip, 0)) # 0 for ephemeral port
                except Exception as e:
                    print(f"!!! Failed to bind to adapter {outbound_ip}: {e}")
                    # We can either fail here or continue with default routing.
                    # For robustness, we'll let the OS handle it.
                    pass

            try:
                server_socket.connect((server_ip, server_port))
                response_data = b'HTTP/1.1 200 Connection established\r\nProxy-agent: PyProx/1.0\r\n\r\n'
                client_socket.sendall(response_data)
                return server_socket, server_name
            except socket.error:
                print(f"@@@ Connection failed to {server_ip}:{server_port} @@@")
                response_data = b'HTTP/1.1 502 Bad Gateway\r\nProxy-agent: PyProx/1.0\r\n\r\n'
                client_socket.sendall(response_data)
                client_socket.close()
                server_socket.close()
                return None, None

        except Exception as e:
            print(f"Upstream Error: {repr(e)}")
            client_socket.close()
            if 'server_socket' in locals():
                server_socket.close()
            return None, None

    def my_upstream(self, client_sock):
        backend_sock, server_name = self.handle_client_request(client_sock)
        if not backend_sock:
            return False

        # Get learned settings for this domain
        frag_count, frag_sleep = TUNER.get_settings(server_name)
        session_stats = {'dl': 0}

        this_ip = backend_sock.getpeername()[0]
        if this_ip not in IP_UL_TRAFFIC:
            IP_UL_TRAFFIC[this_ip] = 0
            IP_DL_TRAFFIC[this_ip] = 0

        first_flag = True
        while True:
            try:
                if first_flag:
                    first_flag = False
                    time.sleep(0.1) # Wait for full packet
                    data = client_sock.recv(16384)
                    
                    if data:
                        # Start downstream thread
                        thread_down = threading.Thread(target=self.my_downstream, args=(backend_sock, client_sock, session_stats))
                        thread_down.daemon = True
                        thread_down.start()
                        
                        # Send data with fragmentation
                        send_data_in_fragment(data, backend_sock, frag_count, frag_sleep)
                        IP_UL_TRAFFIC[this_ip] += len(data)
                    else:
                        raise Exception('Client SYN closed')
                else:
                    data = client_sock.recv(16384)
                    if data:
                        backend_sock.sendall(data)
                        IP_UL_TRAFFIC[this_ip] += len(data)
                    else:
                        raise Exception('Client pipe closed')
            except Exception:
                TUNER.report(server_name, frag_count, frag_sleep, session_stats['dl'])
                time.sleep(2)
                client_sock.close()
                backend_sock.close()
                return False

    def my_downstream(self, backend_sock, client_sock, stats):
        try:
            this_ip = backend_sock.getpeername()[0]
        except:
            return False

        while True:
            try:
                data = backend_sock.recv(16384)
                if data:
                    client_sock.sendall(data)
                    stats['dl'] += len(data)
                    IP_DL_TRAFFIC[this_ip] += len(data)
                else:
                    raise Exception('Backend pipe closed')
            except Exception:
                time.sleep(2)
                backend_sock.close()
                client_sock.close()
                return False

    def extract_servername_and_port(self, data):
        host_and_port = str(data).split()[1]
        if ':' in host_and_port:
            host, port = host_and_port.split(':')
            return host, int(port)
        else:
            return host_and_port, 443

def send_data_in_fragment(data, sock, num_fragment, fragment_sleep):
    L_data = len(data)
    
    # Ensure we don't sample more than available bytes
    sample_count = min(num_fragment - 1, L_data - 2)
    if sample_count < 1:
        sock.sendall(data)
        return

    indices = random.sample(range(1, L_data - 1), sample_count)
    indices.sort()

    i_pre = 0
    for i in indices:
        fragment_data = data[i_pre:i]
        i_pre = i
        sock.sendall(fragment_data)
        time.sleep(fragment_sleep)
    
    fragment_data = data[i_pre:L_data]
    sock.sendall(fragment_data)

def get_network_adapters():
    """Gets a dictionary of network adapters and their IPv4 addresses."""
    adapters = {'AUTO (Default)': '0.0.0.0'}
    try:
        addrs = psutil.net_if_addrs()
        for name, snic_list in addrs.items():
            for snic in snic_list:
                if snic.family == socket.AF_INET:
                    # In case of multiple IPs, this will just take the first one.
                    if snic.address not in adapters.values():
                         adapters[f"{name} ({snic.address})"] = snic.address
    except Exception as e:
        print(f"Could not list network adapters (is psutil installed?): {e}")
        adapters['Error'] = 'psutil not found?'
    return adapters

# --- DNS Server ---

def handle_dns_request(dns_sock, data, addr):
    """Parses a DNS query, resolves it via DoH, and sends a response."""
    try:
        request = dns.message.from_wire(data)
        
        if not request.question:
            return

        question = request.question[0]
        qname = question.name.to_text().rstrip('.')
        qtype = dns.rdatatype.to_text(question.rdtype)

        print(f"DNS Query from {addr}: {qname} ({qtype})")

        response = dns.message.make_response(request)

        # Only handle A records, as that's what the proxy primarily needs
        if qtype == 'A':
            ip_address = GLOBAL_DOH.query(qname)

            if ip_address:
                answer = dns.rrset.from_text(f'{qname}.', 300, 'IN', 'A', ip_address) # 300s TTL
                response.answer.append(answer)
                print(f"DNS Response sent to {addr}: {qname} -> {ip_address}")
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
                print(f"DNS Response to {addr}: {qname} -> NXDOMAIN")
        else:
            response.set_rcode(dns.rcode.NOTIMP) # Not Implemented for other query types
        
        dns_sock.sendto(response.to_wire(), addr)

    except Exception as e:
        print(f"Error handling DNS request: {repr(e)}")

def dns_server_thread():
    """Listens for incoming DNS queries on a UDP socket."""
    dns_port = CONFIG.get('DNS_PORT')
    if not isinstance(dns_port, int) or dns_port <= 0:
        print("DNS Server disabled (invalid port in config).")
        return
        
    try:
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_sock.bind(('', dns_port))
        print(f"DNS Server listening on port {dns_port} (UDP)")
    except OSError as e:
        print(f"!!! ERROR starting DNS server on port {dns_port}: {e}\n!!! Running on privileged ports (<1024) may require root/admin access.")
        return

    while True:
        try:
            data, addr = dns_sock.recvfrom(1024)
            threading.Thread(target=handle_dns_request, args=(dns_sock, data, addr), daemon=True).start()
        except Exception as e:
            print(f"DNS Server Listener Error: {e}")

def start_dns_server():
    """Starts the DNS server in a separate thread."""
    threading.Thread(target=dns_server_thread, daemon=True).start()

# --- Web Panel ---

WEB_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyProx Control Panel</title>
    <style>
        :root {
            --bg-body: #0f172a;
            --bg-panel: #1e293b;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --border: #334155;
            --success: #10b981;
            --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        body { background: var(--bg-body); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
        
        /* Sidebar */
        .sidebar { width: 260px; background: var(--bg-panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; padding: 1.5rem; flex-shrink: 0; }
        .brand { font-size: 1.5rem; font-weight: 700; color: var(--primary); margin-bottom: 2rem; display: flex; align-items: center; gap: 0.5rem; }
        .nav-item { padding: 0.75rem 1rem; margin-bottom: 0.5rem; border-radius: 0.5rem; cursor: pointer; color: var(--text-muted); transition: all 0.2s; display: flex; align-items: center; gap: 0.75rem; font-weight: 500; }
        .nav-item:hover, .nav-item.active { background: rgba(59, 130, 246, 0.1); color: var(--primary); }
        .nav-icon { width: 20px; height: 20px; opacity: 0.8; }

        /* Main Content */
        .main { flex: 1; overflow-y: auto; padding: 2rem; }
        .header { margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; }
        .page-title { font-size: 1.8rem; font-weight: 600; }
        
        /* Cards */
        .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 1rem; padding: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        .stat-label { color: var(--text-muted); font-size: 0.875rem; margin-bottom: 0.5rem; }
        .stat-value { font-size: 1.8rem; font-weight: 700; color: var(--text-main); }
        
        /* Tables */
        .table-container { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 1rem; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 1rem 1.5rem; background: rgba(0,0,0,0.2); color: var(--text-muted); font-weight: 600; font-size: 0.875rem; }
        td { padding: 1rem 1.5rem; border-top: 1px solid var(--border); font-size: 0.9rem; }
        tr:hover td { background: rgba(255,255,255,0.02); }
        
        /* Forms */
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; margin-bottom: 0.75rem; color: var(--text-muted); font-size: 0.9rem; }
        input[type="text"], input[type="number"], select { width: 100%; padding: 0.75rem; background: var(--bg-body); border: 1px solid var(--border); border-radius: 0.5rem; color: var(--text-main); font-size: 1rem; transition: border 0.2s; }
        input:focus { outline: none; border-color: var(--primary); }
        button { background: var(--primary); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 0.5rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        button:hover { background: var(--primary-hover); }
        
        /* Utilities */
        .hidden { display: none; }
        .badge { padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; background: var(--border); }
        .text-success { color: var(--success); }
        .text-danger { color: var(--danger); }
        
        /* QR Code */
        textarea { width: 100%; height: 300px; background: var(--bg-body); border: 1px solid var(--border); border-radius: 0.5rem; color: var(--text-muted); padding: 1rem; font-family: monospace; resize: vertical; }
        
        @media (max-width: 768px) {
            body { flex-direction: column; height: auto; overflow: auto; }
            .sidebar { width: 100%; border-right: none; border-bottom: 1px solid var(--border); padding: 1rem; }
            .sidebar nav { flex-direction: row; overflow-x: auto; gap: 0.5rem; }
            .nav-item { margin-bottom: 0; white-space: nowrap; }
            .main { padding: 1rem; }
        }
    </style>
</head>
<body>
    <aside class="sidebar">
        <div class="brand">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
            PyProx
        </div>
        <nav>
            <div class="nav-item active" onclick="switchTab('dashboard', this)">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                Dashboard
            </div>
            <div class="nav-item" onclick="switchTab('settings', this)">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                Settings
            </div>
            <div class="nav-item" onclick="switchTab('learning', this)">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path></svg>
                AI Learning
            </div>
            <div class="nav-item" onclick="switchTab('clientcfg', this)">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"></rect><line x1="12" y1="18" x2="12.01" y2="18"></line></svg>
                Client Config
            </div>
            <div class="nav-item" onclick="switchTab('dnsmgr', this)">
                <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
                DNS Manager
            </div>
        </nav>
    </aside>

    <main class="main">
        <div id="dashboard" class="page">
            <div class="header">
                <h1 class="page-title">Dashboard</h1>
                <div class="badge" id="uptime">Uptime: 0s</div>
            </div>
            
            <div class="grid-4">
                <div class="card">
                    <div class="stat-label">Active Domains</div>
                    <div class="stat-value" id="domain_count">0</div>
                </div>
                <div class="card">
                    <div class="stat-label">Total Upload</div>
                    <div class="stat-value" id="total_ul">0 MB</div>
                </div>
                <div class="card">
                    <div class="stat-label">Total Download</div>
                    <div class="stat-value" id="total_dl">0 MB</div>
                </div>
                <div class="card">
                    <div class="stat-label">Status</div>
                    <div class="stat-value text-success">Active</div>
                </div>
            </div>

            <div class="card">
                <h3 style="margin-bottom: 1.5rem;">Live Traffic</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Domain</th><th>IP Address</th><th>Upload</th><th>Download</th></tr></thead>
                        <tbody id="traffic_table"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="settings" class="page hidden">
            <div class="header"><h1 class="page-title">Settings</h1></div>
            <div class="card" style="max-width: 600px;">
                <form onsubmit="saveConfig(event)">
                    <h3 style="margin-bottom: 1.5rem;">Network</h3>
                    <div class="form-group">
                        <label for="adapter_select">Outbound Network Adapter</label>
                        <select id="adapter_select">
                            <!-- Populated by JS -->
                        </select>
                        <small style="color: var(--text-muted); margin-top: 0.5rem; display: block;">Select which network to use for outgoing proxy connections. Useful for routing traffic through a VPN.</small>
                    </div>
                    <h3 style="margin-bottom: 1.5rem; margin-top: 2rem;">Fragmentation Strategy</h3>
                    <div class="form-group">
                        <label>Fragment Count Range (Min - Max)</label>
                        <div style="display: flex; gap: 1rem;">
                            <input type="number" id="frag_min" placeholder="Min">
                            <input type="number" id="frag_max" placeholder="Max">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Sleep Duration Range (Seconds)</label>
                        <div style="display: flex; gap: 1rem;">
                            <input type="number" step="0.001" id="sleep_min" placeholder="Min">
                            <input type="number" step="0.001" id="sleep_max" placeholder="Max">
                        </div>
                    </div>
                    <div class="form-group">
                        <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                            <input type="checkbox" id="insecure_doh" style="width: auto;"> 
                            Allow Insecure DoH (Skip Certificate Check)
                        </label>
                    </div>
                    <button type="submit">Save Changes</button>
                </form>
            </div>
        </div>

        <div id="learning" class="page hidden">
            <div class="header"><h1 class="page-title">AI Learning & Fragmentation</h1></div>
            <div class="grid-4" style="grid-template-columns: 2fr 1fr; gap: 2rem; align-items: flex-start;">
                <div class="card">
                    <h3 style="margin-bottom: 1.5rem;">Learned & Manual Settings</h3>
                    <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Optimized settings for specific domains. The highest-scoring setting is used as a default for new domains.</p>
                    <div class="table-container">
                        <table>
                            <thead><tr><th>Domain</th><th>Fragments</th><th>Sleep</th><th>Score (KB)</th><th>Actions</th></tr></thead>
                            <tbody id="tuner_table"></tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <h3 style="margin-bottom: 1.5rem;" id="tuner_form_title">Add New Setting</h3>
                    <form onsubmit="saveTunerSetting(event)">
                        <div class="form-group">
                            <label for="tuner_domain">Domain</label>
                            <input type="text" id="tuner_domain" placeholder="e.g., google.com" required>
                            <small>The best setting will be used for all other traffic if a specific one isn't found.</small>
                        </div>
                        <div class="form-group">
                            <label for="tuner_frags">Fragment Count</label>
                            <input type="number" id="tuner_frags" required>
                        </div>
                        <div class="form-group">
                            <label for="tuner_sleep">Sleep (seconds)</label>
                            <input type="number" step="0.001" id="tuner_sleep" required>
                        </div>
                        <button type="submit">Save Setting</button>
                        <button type="button" onclick="resetTunerForm()" style="background: var(--border); margin-top: 0.5rem;">Cancel Edit</button>
                    </form>
                    <hr style="margin: 2rem 0; border-color: var(--border);">
                    <h3 style="margin-bottom: 1.5rem;">Auto-Learning</h3>
                    <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Activate to automatically find the best settings. <br><b>Warning:</b> Your connection will be unstable.</p>
                    <button id="learning_mode_btn" onclick="toggleLearningMode()">Start Learning Mode</button>
                    <div id="learning_status_badge" class="badge" style="margin-top: 1rem; display: inline-block;">Status: Inactive</div>
                </div>
            </div>
        </div>

        <div id="clientcfg" class="page hidden">
            <div class="header"><h1 class="page-title">Client Configuration</h1></div>
            <div class="card" style="max-width: 800px;">
                <p style="color: var(--text-muted); margin-bottom: 1rem;">Copy this configuration into a V2Ray-compatible client (e.g., V2RayN, NekoBox).</p>
                <textarea id="config_text" readonly></textarea>
            </div>
        </div>

        <div id="dnsmgr" class="page hidden">
            <div class="header"><h1 class="page-title">DNS Manager</h1></div>
            <div class="grid-4" style="grid-template-columns: 1fr 1fr; gap: 2rem; align-items: flex-start;">
                <div class="card">
                    <h3 style="margin-bottom: 1.5rem;">Add/Edit DNS Record</h3>
                    <form onsubmit="saveDnsRecord(event)">
                        <div class="form-group">
                            <label for="dns_domain">Domain</label>
                            <input type="text" id="dns_domain" placeholder="e.g., google.com" required>
                        </div>
                        <div class="form-group">
                            <label for="dns_ip">IP Address</label>
                            <input type="text" id="dns_ip" placeholder="e.g., 8.8.8.8" required>
                        </div>
                        <div class="form-group">
                            <label for="dns_type">Record Type</label>
                            <select id="dns_type">
                                <option value="cache">Cache (Normal)</option>
                                <option value="offline">Offline (Fallback)</option>
                            </select>
                        </div>
                        <button type="submit">Save Record</button>
                    </form>
                </div>
                <div class="card">
                    <h3 style="margin-bottom: 1.5rem;">DoH Providers</h3>
                     <form onsubmit="saveDohProvider(event)" style="margin-bottom: 1.5rem;">
                        <div class="form-group" style="display: flex; gap: 1rem; align-items: flex-end;">
                            <div style="flex-grow: 1;">
                                <label for="doh_url">Add New Provider URL</label>
                                <input type="text" id="doh_url" placeholder="https://..." required>
                            </div>
                            <button type="submit">Add</button>
                        </div>
                    </form>
                    <div id="doh_provider_list"></div>
                </div>
            </div>
            <div class="card" style="margin-top: 2rem;">
                <h3 style="margin-bottom: 1.5rem;">All DNS Records</h3>
                <div class="table-container">
                    <table>
                        <thead><tr><th>Domain</th><th>Resolved IP</th><th>Type</th></tr></thead>
                        <tbody id="dns_cache_tbody"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>

    <script>
        function switchTab(tabId, navElement) {
            document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
            document.getElementById(tabId).classList.remove('hidden');
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            navElement.classList.add('active');
        }
        
        let lastConfig = '';

        async function fetchData() {
            try {
                const res = await fetch('/api/data');
                const data = await res.json();
                
                // Stats
                document.getElementById('uptime').innerText = 'Uptime: ' + Math.floor(data.uptime / 60) + 'm';
                document.getElementById('domain_count').innerText = Object.keys(data.traffic_dl).length;
                
                let t_ul = 0, t_dl = 0;
                let rows = '';
                for (const [ip, dl] of Object.entries(data.traffic_dl)) {
                    t_dl += dl;
                    const ul = data.traffic_ul[ip] || 0;
                    t_ul += ul;
                    let domain = 'Unknown';
                    const record = data.dns_records.find(r => r.ip === ip);
                    if (record) domain = record.domain;
                    rows += `<tr><td>${domain}</td><td>${ip}</td><td>${(ul/1024).toFixed(1)} KB</td><td>${(dl/1024).toFixed(1)} KB</td></tr>`;
                }
                document.getElementById('traffic_table').innerHTML = rows || '<tr><td colspan="4" style="text-align:center; color:var(--text-muted)">No active traffic</td></tr>';
                document.getElementById('total_ul').innerText = (t_ul/1024/1024).toFixed(2) + ' MB';
                document.getElementById('total_dl').innerText = (t_dl/1024/1024).toFixed(2) + ' MB';

                // Tuner
                let t_rows = '';
                const sortedTuner = Object.entries(data.tuner).sort(([,a],[,b]) => b.score - a.score);
                for (const [dom, info] of sortedTuner) {
                    const isManual = info.score > 1024 * 1024 * 100; // Heuristic for manually added (e.g. > 100MB score)
                    const scoreDisplay = isManual ? 'Manual' : (info.score / 1024).toFixed(0);
                    t_rows += `<tr>
                        <td>${dom}</td>
                        <td>${info.frags}</td>
                        <td>${info.sleep.toFixed(4)}</td>
                        <td>${scoreDisplay}</td>
                        <td style="display: flex; gap: 0.5rem;">
                            <button onclick="editTunerSetting('${dom}', ${info.frags}, ${info.sleep})" style="padding: 0.25rem 0.5rem; font-size: 0.8rem;">Edit</button>
                            <button onclick="deleteTunerSetting('${dom}')" style="background:var(--danger); padding: 0.25rem 0.5rem; font-size: 0.8rem;">Delete</button>
                        </td>
                    </tr>`;
                }
                document.getElementById('tuner_table').innerHTML = t_rows || '<tr><td colspan="5" style="text-align:center; color:var(--text-muted)">No learning data yet</td></tr>';

                // DNS Cache
                let dns_rows = '';
                for (const record of data.dns_records) {
                    const badge_class = record.type === 'offline' ? 'text-danger' : '';
                    dns_rows += `<tr><td>${record.domain}</td><td>${record.ip}</td><td><span class="badge ${badge_class}">${record.type}</span></td></tr>`;
                }
                document.getElementById('dns_cache_tbody').innerHTML = dns_rows || '<tr><td colspan="3" style="text-align:center; color:var(--text-muted)">No DNS records found</td></tr>';

                // DoH Providers
                let doh_rows = '';
                for (const provider of data.doh_providers) {
                    doh_rows += `<div style="display:flex; justify-content: space-between; align-items:center; padding: 0.5rem; border-bottom: 1px solid var(--border);"><span>${provider.url}</span><button onclick="deleteDohProvider('${provider.url}')" style="background:var(--danger); padding: 0.25rem 0.5rem; font-size: 0.8rem;">Delete</button></div>`;
                }
                document.getElementById('doh_provider_list').innerHTML = doh_rows || '<p style="color:var(--text-muted)">No providers configured.</p>';

                // Settings (only if not focused)
                if (document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'SELECT') {
                    document.getElementById('frag_min').value = data.config.FRAGMENT_COUNT_RANGE[0];
                    document.getElementById('frag_max').value = data.config.FRAGMENT_COUNT_RANGE[1];
                    document.getElementById('sleep_min').value = data.config.FRAGMENT_SLEEP_RANGE[0];
                    document.getElementById('sleep_max').value = data.config.FRAGMENT_SLEEP_RANGE[1];
                    document.getElementById('insecure_doh').checked = data.config.ALLOW_INSECURE_DOH;

                    // Populate adapters
                    const adapterSelect = document.getElementById('adapter_select');
                    const currentAdapter = data.config.OUTBOUND_ADAPTER_IP || '0.0.0.0';
                    let adapterOptions = '';
                    for (const [name, ip] of Object.entries(data.adapters)) {
                        const selected = (ip === currentAdapter) ? 'selected' : '';
                        adapterOptions += `<option value="${ip}" ${selected}>${name}</option>`;
                    }
                    adapterSelect.innerHTML = adapterOptions;
                }

                // Learning Mode Status
                const learningStatus = data.tuner_status;
                const statusBadge = document.getElementById('learning_status_badge');
                const learningBtn = document.getElementById('learning_mode_btn');

                if (learningStatus) {
                    statusBadge.innerText = 'Status: Active';
                    statusBadge.style.backgroundColor = 'var(--success)';
                    learningBtn.innerText = 'Stop Learning Mode';
                    learningBtn.style.backgroundColor = 'var(--danger)';
                } else {
                    statusBadge.innerText = 'Status: Inactive';
                    statusBadge.style.backgroundColor = 'var(--border)';
                    learningBtn.innerText = 'Start Learning Mode';
                    learningBtn.style.backgroundColor = 'var(--primary)';
                }

                // Config
                if (data.client_config !== lastConfig) {
                    lastConfig = data.client_config;
                    document.getElementById('config_text').value = data.client_config;
                }
            } catch (e) { console.error("Fetch error", e); }
        }

        async function saveConfig(e) {
            e.preventDefault();
            const payload = {
                FRAGMENT_COUNT_RANGE: [parseInt(document.getElementById('frag_min').value), parseInt(document.getElementById('frag_max').value)],
                FRAGMENT_SLEEP_RANGE: [parseFloat(document.getElementById('sleep_min').value), parseFloat(document.getElementById('sleep_max').value)],
                ALLOW_INSECURE_DOH: document.getElementById('insecure_doh').checked,
                OUTBOUND_ADAPTER_IP: document.getElementById('adapter_select').value
            };
            await fetch('/api/config', { method: 'POST', body: JSON.stringify(payload) });
            alert('Settings Saved!');
            fetchData();
        }

        async function saveDnsRecord(e) {
            e.preventDefault();
            const payload = {
                domain: document.getElementById('dns_domain').value,
                ip: document.getElementById('dns_ip').value,
                type: document.getElementById('dns_type').value,
            };
            await fetch('/api/dns/save', { method: 'POST', body: JSON.stringify(payload) });
            alert('DNS Record Saved!');
            e.target.reset();
            fetchData();
        }

        async function saveDohProvider(e) {
            e.preventDefault();
            const payload = { url: document.getElementById('doh_url').value };
            await fetch('/api/doh/save', { method: 'POST', body: JSON.stringify(payload) });
            alert('DoH Provider Saved!');
            e.target.reset();
            fetchData();
        }

        function editTunerSetting(domain, frags, sleep) {
            document.getElementById('tuner_form_title').innerText = 'Edit Setting';
            document.getElementById('tuner_domain').value = domain;
            document.getElementById('tuner_domain').readOnly = true; // Don't allow editing domain (PK)
            document.getElementById('tuner_frags').value = frags;
            document.getElementById('tuner_sleep').value = sleep;
            document.getElementById('tuner_domain').scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        function resetTunerForm() {
            document.getElementById('tuner_form_title').innerText = 'Add New Setting';
            document.getElementById('tuner_domain').readOnly = false;
            document.querySelector('#learning form').reset();
        }

        async function saveTunerSetting(e) {
            e.preventDefault();
            const payload = {
                domain: document.getElementById('tuner_domain').value,
                frags: parseInt(document.getElementById('tuner_frags').value),
                sleep: parseFloat(document.getElementById('tuner_sleep').value),
            };
            await fetch('/api/tuner/save', { method: 'POST', body: JSON.stringify(payload) });
            alert('Tuner Setting Saved!');
            resetTunerForm();
            fetchData();
        }

        async function deleteDohProvider(url) {
            if (!confirm(`Are you sure you want to delete ${url}?`)) return;
            await fetch('/api/doh/delete', { method: 'POST', body: JSON.stringify({ url }) });
            fetchData();
        }

        async function deleteTunerSetting(domain) {
            if (!confirm(`Are you sure you want to delete the setting for ${domain}?`)) return;
            await fetch('/api/tuner/delete', { method: 'POST', body: JSON.stringify({ domain }) });
            fetchData();
        }

        async function toggleLearningMode() {
            const btn = document.getElementById('learning_mode_btn');
            const isLearning = btn.innerText.includes('Stop');
            if (!isLearning) {
                if (!confirm("Activating learning mode will make the proxy unstable while it tests settings. You should not use the proxy for other tasks. Proceed?")) {
                    return;
                }
            }

            const action = isLearning ? 'stop' : 'start';
            btn.disabled = true;
            btn.innerText = 'Please wait...';
            
            try {
                await fetch('/api/learning_mode', { method: 'POST', body: JSON.stringify({ action }) });
            } catch (e) { alert('Failed to toggle learning mode.'); } finally { btn.disabled = false; fetchData(); }
        }

        setInterval(fetchData, 2000);
        fetchData();
    </script>
</body>
</html>
"""

class WebPanelHandler(http.server.BaseHTTPRequestHandler):
    def _send_response(self, code, content, content_type='application/json'):
        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def _read_body(self):
        length = int(self.headers.get('content-length', 0))
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        if self.path == '/':
            self._send_response(200, WEB_TEMPLATE, 'text/html')
        elif self.path == '/api/data':
            with DB_LOCK:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT domain, ip, type FROM dns_records")
                dns_records = [dict(row) for row in cursor.fetchall()]
                cursor.execute("SELECT url FROM doh_providers")
                doh_providers = [dict(row) for row in cursor.fetchall()]
                cursor.execute("SELECT domain, frags, sleep, score FROM tuner_data")
                tuner_data = {row['domain']: dict(row) for row in cursor.fetchall()}
                conn.close()

                client_config = V2RAY_CONFIG_TEMPLATE
                local_ip = get_local_ip()
                if local_ip != "127.0.0.1":
                    client_config = client_config.replace("127.0.0.1", local_ip)

                data = {
                    'uptime': time.time() - START_TIME,
                    'config': CONFIG,
                    'traffic_ul': IP_UL_TRAFFIC,
                    'traffic_dl': IP_DL_TRAFFIC,
                    'dns_records': dns_records,
                    'doh_providers': doh_providers,
                    'tuner': tuner_data,
                    'adapters': get_network_adapters(),
                    'tuner_status': TUNER.learning_mode,
                    'client_config': client_config
                }
                self._send_response(200, json.dumps(data))
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            body = self._read_body()
            with DB_LOCK:
                conn = get_db()
                cursor = conn.cursor()

                if self.path == '/api/config':
                    for key, value in body.items():
                        if key in CONFIG:
                            CONFIG[key] = value
                            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, json.dumps(value)))
                    conn.commit()
                    self._send_response(200, '{"status": "ok"}')

                elif self.path == '/api/dns/save':
                    cursor.execute("INSERT OR REPLACE INTO dns_records (domain, ip, type) VALUES (?, ?, ?)",
                                   (body['domain'], body['ip'], body['type']))
                    conn.commit()
                    self._send_response(200, '{"status": "ok"}')

                elif self.path == '/api/doh/save':
                    cursor.execute("INSERT OR REPLACE INTO doh_providers (url) VALUES (?)", (body['url'],))
                    conn.commit()
                    self._send_response(200, '{"status": "ok"}')

                elif self.path == '/api/doh/delete':
                    cursor.execute("DELETE FROM doh_providers WHERE url=?", (body['url'],))
                    conn.commit()
                    self._send_response(200, '{"status": "ok"}')

                elif self.path == '/api/learning_mode':
                    action = body.get('action')
                    if action == 'start':
                        TUNER.start_learning_mode()
                        status_message = 'Learning mode started.'
                    elif action == 'stop':
                        TUNER.stop_learning_mode()
                        status_message = 'Learning mode stopped.'
                    else:
                        status_message = 'Invalid action'
                    self._send_response(200, json.dumps({'status': status_message, 'learning_mode': TUNER.learning_mode}))

                elif self.path == '/api/tuner/save':
                    # Use a very high score to prioritize manually added settings. 1GB.
                    manual_score = 1024 * 1024 * 1024
                    cursor.execute("""
                        INSERT OR REPLACE INTO tuner_data (domain, frags, sleep, score)
                        VALUES (?, ?, ?, ?)
                    """, (body['domain'], body['frags'], body['sleep'], manual_score))
                    conn.commit()
                    self._send_response(200, '{"status": "ok"}')

                elif self.path == '/api/tuner/delete':
                    cursor.execute("DELETE FROM tuner_data WHERE domain=?", (body['domain'],))
                    conn.commit()
                    self._send_response(200, '{"status": "ok"}')

                else:
                    self.send_error(404)

                conn.close()

        except Exception as e:
            print(f"POST Error on {self.path}: {e}")
            self.send_error(500)

def start_web_panel():
    server = socketserver.ThreadingTCPServer(('0.0.0.0', CONFIG['WEB_PORT']), WebPanelHandler)
    server.daemon = True
    print(f"Web panel starting at: http://{get_local_ip()}:{CONFIG['WEB_PORT']}")
    threading.Thread(target=server.serve_forever, daemon=True).start()

def get_local_ip():
    """Detects the local LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

if __name__ == "__main__":
    init_database()
    load_config_from_db()
    GLOBAL_DOH = DNS_Over_Fragment()
    start_web_panel()
    start_dns_server()
    ThreadedServer('', CONFIG['LISTEN_PORT']).listen()
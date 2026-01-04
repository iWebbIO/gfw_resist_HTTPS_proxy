#!/usr/bin/env python3

import dns.message   # pip install dnspython
import dns.rdatatype
import requests      # pip install requests
import json
from pathlib import Path
import os
import base64
import socket
import threading
import time
import random

# --- Configuration ---
LISTEN_PORT = 4500    # Listening on 127.0.0.1:4500

# Fragment Settings
# Adjust based on ISP:
# Irancell: num_fragment ~ 10-40, fragment_sleep ~ 0.01
# MCI/Others: num_fragment ~ 80-250, fragment_sleep ~ 0.001 - 0.005
NUM_FRAGMENT = 87
FRAGMENT_SLEEP = 0.005

LOG_EVERY_N_SEC = 30   # Update log file interval
ALLOW_INSECURE_DOH = True   # Allow certificate mismatch for DoH (useful if SNI is faked)

# DNS over HTTPS Provider
DNS_URL = 'https://cloudflare-dns.com/dns-query?dns='
# Alternatives:
# DNS_URL = 'https://dns.google/dns-query?dns='
# DNS_URL = 'https://doh.opendns.com/dns-query?dns='
# DNS_URL = 'https://dns.electrotm.org/dns-query?dns='

# Offline DNS Records (Bypass DNS resolution for these domains)
OFFLINE_DNS = {
    # --- DoH Providers (Essential for bootstrapping) ---
    'cloudflare-dns.com': '203.32.120.226', # Alternate IP for Cloudflare
    # 'cloudflare-dns.com': '1.1.1.1',
    'dns.google': '8.8.8.8',
    'doh.opendns.com': '208.67.222.222',
    'secure.avastdns.com': '185.185.133.66',
    'doh.libredns.gr': '116.202.176.26',
    'dns.electrotm.org': '78.157.42.100',
    'dns.bitdefender.net': '34.84.232.67',
    'cluster-1.gac.edu': '138.236.128.101',

    # --- Social Media (Twitter/X) ---
    'api.twitter.com': '104.244.42.66',
    'twitter.com': '104.244.42.1',
    'pbs.twimg.com': '93.184.220.70',
    'abs-0.twimg.com': '104.244.43.131',
    'abs.twimg.com': '152.199.24.185',
    'video.twimg.com': '192.229.220.133',
    't.co': '104.244.42.69',
    'ton.local.twitter.com': '104.244.42.1',

    # --- Meta (Instagram, WhatsApp, Facebook) ---
    'instagram.com': '163.70.128.174',
    'www.instagram.com': '163.70.128.174',
    'static.cdninstagram.com': '163.70.132.63',
    'scontent.cdninstagram.com': '163.70.132.63',
    'privacycenter.instagram.com': '163.70.128.174',
    'help.instagram.com': '163.70.128.174',
    'l.instagram.com': '163.70.128.174',

    'e1.whatsapp.net': '163.70.128.60',
    'e2.whatsapp.net': '163.70.128.60',
    'wa.me': '185.60.219.60',
    'web.whatsapp.com': '31.13.83.51',
    'whatsapp.net': '31.13.83.51',
    'whatsapp.com': '31.13.83.51',
    'cdn.whatsapp.net': '31.13.83.51',

    'connect.facebook.net': '31.13.84.51',
    'facebook.com': '31.13.65.49',
    'developers.facebook.com': '31.13.84.8',
    'about.meta.com': '163.70.128.13',
    'meta.com': '163.70.128.13',

    # --- Google / YouTube ---
    'www.google.com': '142.250.186.36',
    'youtube.com': '216.239.38.120',
    'youtu.be': '216.239.38.120',
    'www.youtube.com': '216.239.38.120',
    'i.ytimg.com': '216.239.38.120',
    'yt3.ggpht.com': '142.250.186.36',
    'play.google.com': '142.250.184.238',
    'fonts.gstatic.com': '142.250.185.227',
    'googlevideo.com': '74.125.98.7', # Catch-all fallback if needed, though specific subdomains are better
}

# --- Globals ---
DNS_CACHE = {}
IP_DL_TRAFFIC = {}
IP_UL_TRAFFIC = {}

# --- Persistence ---
DNS_FILE = 'dns.json'
DNS_LOCK = threading.RLock()

def load_dns_cache():
    global DNS_CACHE
    if os.path.exists(DNS_FILE):
        try:
            with open(DNS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    DNS_CACHE.update(data)
                    print(f"Loaded {len(data)} DNS records from {DNS_FILE}")
        except Exception as e:
            print(f"Error loading DNS cache: {e}")

def save_dns_cache():
    with DNS_LOCK:
        try:
            with open(DNS_FILE, 'w') as f:
                json.dump(DNS_CACHE, f, indent=4)
        except Exception as e:
            print(f"Error saving DNS cache: {e}")

class DNS_Over_Fragment:
    def __init__(self):
        self.url = DNS_URL
        self.req = requests.session()
        # Route DoH requests through our own fragmenting proxy to bypass SNI filtering on the DoH server
        self.fragment_proxy = {
            'https': 'http://127.0.0.1:' + str(LISTEN_PORT)
        }

    def query(self, server_name):
        # 1. Check Offline DNS
        offline_ip = OFFLINE_DNS.get(server_name)
        if offline_ip:
            print(f'Offline DNS --> {server_name} : {offline_ip}')
            return offline_ip

        # 2. Check Cache
        cache_ip = DNS_CACHE.get(server_name)
        if cache_ip:
            print(f'Cached DNS --> {server_name} : {cache_ip}')
            return cache_ip

        # 3. Online DoH Query
        print(f'Online DNS Query --> {server_name}')
        try:
            query_params = {
                'type': 'A',
                'ct': 'application/dns-message',
            }
            
            query_message = dns.message.make_query(server_name, 'A')
            query_wire = query_message.to_wire()
            query_base64 = base64.urlsafe_b64encode(query_wire).decode('utf-8').replace('=', '')

            query_url = self.url + query_base64
            
            # Send request through the fragment proxy
            ans = self.req.get(
                query_url, 
                params=query_params, 
                headers={'accept': 'application/dns-message'}, 
                proxies=self.fragment_proxy, 
                verify=(not ALLOW_INSECURE_DOH)
            )

            if ans.status_code == 200 and ans.headers.get('content-type') == 'application/dns-message':
                answer_msg = dns.message.from_wire(ans.content)
                resolved_ip = None
                for x in answer_msg.answer:
                    if x.rdtype == dns.rdatatype.A:
                        resolved_ip = x[0].address
                        with DNS_LOCK:
                            DNS_CACHE[server_name] = resolved_ip
                            save_dns_cache()
                        return resolved_ip
                
                print(f'Online DNS Resolved --> {server_name} : {resolved_ip}')
                return resolved_ip
            else:
                print(f'DNS Error: {ans.status_code} {ans.reason}')
        except Exception as e:
            print(f'DNS Exception: {repr(e)}')
        return None

class ThreadedServer(object):
    def __init__(self, host, port):
        self.DoH = DNS_Over_Fragment()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(128)
        print(f"PyProx listening at: {self.host}:{self.port}")
        while True:
            client_sock, client_addr = self.sock.accept()
            client_sock.settimeout(21) # Socket timeout
            
            # Slight delay to prevent flooding crashes
            time.sleep(0.01)
            
            thread_up = threading.Thread(target=self.my_upstream, args=(client_sock,))
            thread_up.daemon = True
            thread_up.start()

    def handle_client_request(self, client_socket):
        try:
            data = client_socket.recv(16384)
        except Exception:
            client_socket.close()
            return None

        if not data:
            client_socket.close()
            return None

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
            return None
        else:
            client_socket.close()
            return None

        print(f'{server_name} --> {server_port}')

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(21)
            server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Resolve IP
            try:
                socket.inet_aton(server_name)
                server_ip = server_name
            except socket.error:
                server_ip = self.DoH.query(server_name)

            if not server_ip:
                raise Exception("Could not resolve IP")

            try:
                server_socket.connect((server_ip, server_port))
                response_data = b'HTTP/1.1 200 Connection established\r\nProxy-agent: PyProx/1.0\r\n\r\n'
                client_socket.sendall(response_data)
                return server_socket
            except socket.error:
                print(f"@@@ Connection failed to {server_ip}:{server_port} @@@")
                response_data = b'HTTP/1.1 502 Bad Gateway\r\nProxy-agent: PyProx/1.0\r\n\r\n'
                client_socket.sendall(response_data)
                client_socket.close()
                server_socket.close()
                return None

        except Exception as e:
            print(f"Upstream Error: {repr(e)}")
            client_socket.close()
            if 'server_socket' in locals():
                server_socket.close()
            return None

    def my_upstream(self, client_sock):
        backend_sock = self.handle_client_request(client_sock)
        if not backend_sock:
            return False

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
                        thread_down = threading.Thread(target=self.my_downstream, args=(backend_sock, client_sock))
                        thread_down.daemon = True
                        thread_down.start()
                        
                        # Send data with fragmentation
                        send_data_in_fragment(data, backend_sock)
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
                time.sleep(2)
                client_sock.close()
                backend_sock.close()
                return False

    def my_downstream(self, backend_sock, client_sock):
        try:
            this_ip = backend_sock.getpeername()[0]
        except:
            return False

        while True:
            try:
                data = backend_sock.recv(16384)
                if data:
                    client_sock.sendall(data)
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

def send_data_in_fragment(data, sock):
    L_data = len(data)
    # Ensure we don't sample more than available bytes
    sample_count = min(NUM_FRAGMENT - 1, L_data - 2)
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
        time.sleep(FRAGMENT_SLEEP)
    
    fragment_data = data[i_pre:L_data]
    sock.sendall(fragment_data)

def log_writer():
    file_name = 'DNS_IP_traffic_info.txt'
    BASE_DIR = Path(__file__).resolve().parent
    log_file_path = os.path.join(BASE_DIR, file_name)
    
    with open(log_file_path, "w") as f:
        while True:
            time.sleep(LOG_EVERY_N_SEC)
            
            # Merge Cache and Offline for display
            full_dns = {**DNS_CACHE, **OFFLINE_DNS}
            inv_dns = {v: k for k, v in full_dns.items()}
            
            f.seek(0)
            f.write('\n########### DNS Cache ##############\n')
            f.write(str(DNS_CACHE).replace(',', ',\n'))
            f.write('\n\n########### Traffic Stats ###########\n')
            
            for ip in IP_UL_TRAFFIC:
                up = round(IP_UL_TRAFFIC[ip] / 1024.0, 3)
                down = round(IP_DL_TRAFFIC.get(ip, 0) / 1024.0, 3)
                host = inv_dns.get(ip, '?')
                status = 'FILTERED?' if (down < 1.0 and up > 0) else '-------'
                f.write(f'{ip:<16} UL={up:<8} KB  DL={down:<8} KB  {status}  Host={host}\n')
                
            f.flush()
            f.truncate()
            print(f"Log updated: {file_name}")

def start_log_writer():
    thread_log = threading.Thread(target=log_writer, args=())
    thread_log.daemon = True
    thread_log.start()

if __name__ == "__main__":
    load_dns_cache()
    start_log_writer()
    ThreadedServer('', LISTEN_PORT).listen()
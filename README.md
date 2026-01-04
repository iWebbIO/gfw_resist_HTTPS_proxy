# PyProx - HTTPS Fragmentation Proxy

A lightweight Python proxy designed to bypass Deep Packet Inspection (DPI) and censorship using TCP fragmentation and DNS over HTTPS (DoH).

## Prerequisites

- Python 3.6+
- Required libraries:
  ```bash
  pip install dnspython requests
  ```

## Quick Start

1. **Run the Script**:
   ```bash
   python pyprox.py
   ```
   *The proxy listens on `127.0.0.1:4500`.*

2. **Connect a Client**:
   - **Option A**: Import `config.json` into a V2Ray-compatible client (V2RayN, NekoBox, etc.). This sets up a local SOCKS5 proxy on port `10808`.
   - **Option B**: Configure your browser or system proxy to use HTTP Proxy `127.0.0.1:4500`.

## Configuration

You can tweak the fragmentation logic in `pyprox.py` to suit your ISP:

```python
# Adjust based on ISP behavior
NUM_FRAGMENT = 87       # Number of fragments per packet
FRAGMENT_SLEEP = 0.005  # Delay in seconds between fragments
```

## Features

- **Fragmentation**: Splits HTTPS Client Hello packets to evade SNI filtering.
- **Secure DNS**: Uses DoH (Cloudflare) routed through the fragmentation tunnel to prevent DNS poisoning.
- **Offline Fallback**: Includes hardcoded IPs for critical services (DoH providers, Social Media) to function even if DNS is blocked entirely.
# DeepInspect Pro

Advanced Deep Packet Inspection engine with a real-time web dashboard.  
Built in Python — extended version of [dpi-engine](https://github.com/Tanishk75/dpi-engine).

---

## Features

- Real-time web dashboard (Flask + SocketIO + Chart.js)
- Live traffic distribution donut chart
- Application breakdown with visual bars
- Blocked flows panel with source/destination IPs
- Detected domains list with app classification
- Single-threaded and multi-threaded DPI engines
- Classifies 20+ apps (YouTube, Netflix, Discord, etc.)
- Blocks traffic by IP, app name, or domain

---

## Usage

### Web Dashboard
```bash
python dashboard.py --pcap input.pcap --block-app YouTube --block-app Facebook
# Open http://localhost:5000
```

### Single-threaded
```bash
python main.py input.pcap output.pcap --block-app YouTube
```

### Multi-threaded
```bash
python main_mt.py input.pcap output.pcap --lbs 2 --fps 4
```

### Generate Test Traffic
```bash
python generate_test_pcap.py
# Creates test_traffic.pcap with 57 packets across 15+ apps
```

---

## Project Structure

```text
dpi_engine_pro/
├── dpi/
│   ├── types.py           # Data structures + app classification
│   ├── pcap_reader.py     # PCAP reader/writer
│   ├── packet_parser.py   # Ethernet/IP/TCP/UDP parser
│   └── sni_extractor.py   # TLS SNI + HTTP Host extractor
├── templates/
│   └── index.html         # Dashboard frontend
├── dashboard.py           # Flask + SocketIO web dashboard
├── main.py                # Single-threaded engine
├── main_mt.py             # Multi-threaded engine
├── generate_test_pcap.py  # Test traffic generator
└── requirements.txt
```

## Requirements

```bash
pip install flask flask-socketio
```

Python 3.10+
---

## Quick Start (Copy & Paste)

### Step 1 — Clone
```bash
git clone https://github.com/Tanishk75/deepinspect-pro.git
cd deepinspect-pro
```

### Step 2 — Install dependencies
```bash
pip install flask flask-socketio
```

### Step 3 — Generate test traffic
```bash
python generate_test_pcap.py
```

### Step 4 — Launch web dashboard
```bash
python dashboard.py --pcap test_traffic.pcap --block-app YouTube --block-app Facebook
```

### Step 5 — Open browser
http://localhost:5000

### Optional — Run without dashboard
```bash
# Single-threaded
python main.py test_traffic.pcap filtered.pcap --block-app YouTube

# Multi-threaded
python main_mt.py test_traffic.pcap filtered_mt.pcap --block-app YouTube --lbs 2 --fps 2
```

---

## Difference from dpi-engine

| Feature | dpi-engine | deepinspect-pro |
|---------|-----------|-----------------|
| Single-threaded engine | ✅ | ✅ |
| Multi-threaded engine | ✅ | ✅ |
| Test traffic generator | ✅ | ✅ |
| Web dashboard | ❌ | ✅ |
| Live donut chart | ❌ | ✅ |
| Blocked flows panel | ❌ | ✅ |
| Detected domains list | ❌ | ✅ |
| External dependencies | None | Flask, SocketIO |
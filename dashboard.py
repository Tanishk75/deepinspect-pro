# dashboard.py
import argparse
import threading
import time
from collections import defaultdict

from flask import Flask, render_template
from flask_socketio import SocketIO

from dpi.pcap_reader   import PcapReader
from dpi.packet_parser import parse
from dpi.sni_extractor import extract_sni, extract_http_host
from dpi.types         import FiveTuple, Flow, AppType, sni_to_app_type


app      = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")


# ── Shared State ──────────────────────────────────────────────────────────────

class DPIState:
    def __init__(self):
        self.lock         = threading.Lock()
        self.flows:       dict[FiveTuple, Flow] = {}
        self.app_stats:   dict[str, int]        = defaultdict(int)
        self.total        = 0
        self.forwarded    = 0
        self.dropped      = 0
        self.blocked_list: list[dict]           = []
        self.domains:      list[dict]           = []
        self.running      = False
        self.done         = False

state = DPIState()


# ── Blocking Rules ────────────────────────────────────────────────────────────

class BlockingRules:
    def __init__(self):
        self.blocked_ips:     set[int]     = set()
        self.blocked_apps:    set[AppType] = set()
        self.blocked_domains: list[str]    = []

    def block_ip(self, ip: str):
        parts = list(map(int, ip.strip().split(".")))
        val   = parts[0] | (parts[1]<<8) | (parts[2]<<16) | (parts[3]<<24)
        self.blocked_ips.add(val)

    def block_app(self, name: str):
        for a in AppType:
            if a.value.lower() == name.lower():
                self.blocked_apps.add(a)
                return

    def block_domain(self, domain: str):
        self.blocked_domains.append(domain.lower())

    def is_blocked(self, src_ip_int: int, app: AppType, sni: str) -> bool:
        if src_ip_int in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        return any(d in sni.lower() for d in self.blocked_domains)


# ── DPI Engine Thread ─────────────────────────────────────────────────────────

def run_dpi(pcap_path: str, rules: BlockingRules):
    state.running = True

    with PcapReader(pcap_path) as reader:
        for raw in reader.packets():
            p = parse(raw.data, raw.ts_sec, raw.ts_usec)
            if not p or not p.has_ip or (not p.has_tcp and not p.has_udp):
                continue

            with state.lock:
                state.total += 1

                key = FiveTuple(p._src_ip_int, p._dst_ip_int,
                                p.src_port, p.dst_port, p.protocol)

                if key not in state.flows:
                    state.flows[key] = Flow(tuple=key)

                flow = state.flows[key]
                flow.packets += 1
                flow.bytes   += len(raw.data)

                # SNI extraction
                if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)
                        and not flow.sni
                        and p.has_tcp and p.dst_port == 443
                        and len(p.payload) > 5):
                    sni = extract_sni(p.payload)
                    if sni:
                        flow.sni      = sni
                        flow.app_type = sni_to_app_type(sni)

                # HTTP Host extraction
                if (flow.app_type in (AppType.UNKNOWN, AppType.HTTP)
                        and not flow.sni
                        and p.has_tcp and p.dst_port == 80
                        and p.payload):
                    host = extract_http_host(p.payload)
                    if host:
                        flow.sni      = host
                        flow.app_type = sni_to_app_type(host)

                # DNS fallback
                if flow.app_type == AppType.UNKNOWN:
                    if p.src_port == 53 or p.dst_port == 53:
                        flow.app_type = AppType.DNS

                # Port fallback
                if flow.app_type == AppType.UNKNOWN:
                    if p.dst_port == 443:
                        flow.app_type = AppType.HTTPS
                    elif p.dst_port == 80:
                        flow.app_type = AppType.HTTP

                # Blocking
                if not flow.blocked:
                    flow.blocked = rules.is_blocked(
                        p._src_ip_int, flow.app_type, flow.sni)
                    if flow.blocked:
                        state.dropped += 1
                        state.blocked_list.append({
                            "src": p.src_ip,
                            "dst": p.dst_ip,
                            "app": flow.app_type.value,
                            "sni": flow.sni,
                        })
                    else:
                        state.forwarded += 1

                state.app_stats[flow.app_type.value] += 1

                if flow.sni:
                    entry = {"sni": flow.sni, "app": flow.app_type.value}
                    if entry not in state.domains:
                        state.domains.append(entry)

            time.sleep(0.05)

    state.running = False
    state.done    = True


# ── Stats Emitter Thread ──────────────────────────────────────────────────────

def emit_stats():
    while True:
        time.sleep(1)
        with state.lock:
            socketio.emit("stats", {
                "total":     state.total,
                "forwarded": state.forwarded,
                "dropped":   state.dropped,
                "flows":     len(state.flows),
                "app_stats": dict(state.app_stats),
                "blocked":   state.blocked_list[-10:],
                "domains":   state.domains[-15:],
                "done":      state.done,
            })


# ── Flask Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("connect")
def on_connect():
    with state.lock:
        socketio.emit("stats", {
            "total":     state.total,
            "forwarded": state.forwarded,
            "dropped":   state.dropped,
            "flows":     len(state.flows),
            "app_stats": dict(state.app_stats),
            "blocked":   state.blocked_list[-10:],
            "domains":   state.domains[-15:],
            "done":      state.done,
        })


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DeepInspect Pro — Web Dashboard")
    ap.add_argument("--pcap",         required=True, help="Input .pcap file")
    ap.add_argument("--block-ip",     metavar="IP",     action="append", default=[])
    ap.add_argument("--block-app",    metavar="APP",    action="append", default=[])
    ap.add_argument("--block-domain", metavar="DOMAIN", action="append", default=[])
    ap.add_argument("--port",         type=int, default=5000)
    args = ap.parse_args()

    rules = BlockingRules()
    for ip  in args.block_ip:     rules.block_ip(ip)
    for a   in args.block_app:    rules.block_app(a)
    for dom in args.block_domain: rules.block_domain(dom)

    dpi_thread = threading.Thread(
        target=run_dpi, args=(args.pcap, rules), daemon=True)
    dpi_thread.start()

    emitter = threading.Thread(target=emit_stats, daemon=True)
    emitter.start()

    print(f"\n[DeepInspect Pro] Dashboard running at http://localhost:{args.port}")
    print(f"[DeepInspect Pro] Processing: {args.pcap}\n")

    socketio.run(app, host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
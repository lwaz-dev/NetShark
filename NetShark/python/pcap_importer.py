"""
NetShark — pcap_importer.py

Flask API with two ways to get packets in:
  1. Upload a .pcap/.pcapng file (parsed with dpkt) — no privileges needed.
  2. Live capture on a real interface (via scapy + Npcap on Windows) —
     needs Npcap installed and this script run as Administrator.

Everything is held in memory in SESSIONS for as long as this process runs.
No database. Restarting the script clears all data.

Run with:
    python pcap_importer.py
(Run PowerShell "as Administrator" if you want to use live capture.)
"""
import datetime
import binascii
import os
import socket
import itertools
import threading

import dpkt
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


@app.errorhandler(Exception)
def handle_any_error(exc):
    """Safety net: never let Flask's default HTML error page leak out —
    the PHP proxy just forwards bodies as-is, and the frontend expects
    JSON everywhere."""
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return jsonify({"error": exc.description}), exc.code
    return jsonify({"error": f"unexpected server error: {exc}"}), 500

UPLOAD_DIR = "/tmp/netshark_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---- in-memory storage ----
# SESSIONS[session_id] = {
#     "session_id": int, "filename": str, "imported_at": iso str,
#     "packet_count": int, "packets": [ {..packet..}, ... ],
#     "source": "pcap_import" | "live", "status": "running" | "stopped"
# }
SESSIONS = {}
_session_id_counter = itertools.count(1)
_sessions_lock = threading.Lock()  # guards SESSIONS dict + packet list mutation

# ---- live capture state (one active capture at a time) ----
live_state = {
    "sniffing": False,
    "thread": None,
    "session_id": None,
    "stop_flag": threading.Event(),
}


# =========================================================================
# Shared helpers
# =========================================================================

def ip_to_str(addr):
    try:
        return socket.inet_ntoa(addr)
    except Exception:
        try:
            return socket.inet_ntop(socket.AF_INET6, addr)
        except Exception:
            return None


def new_session(filename, source):
    session_id = next(_session_id_counter)
    with _sessions_lock:
        SESSIONS[session_id] = {
            "session_id": session_id,
            "filename": filename,
            "imported_at": datetime.datetime.utcnow().isoformat(),
            "packet_count": 0,
            "packets": [],
            "source": source,
            "status": "running",
        }
    return session_id


# =========================================================================
# .pcap file import (dpkt) — unchanged behaviour, no privileges needed
# =========================================================================

def mac_to_str(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)


def extract_sni(payload):
    """Best-effort TLS ClientHello SNI parser, works on raw TCP payload bytes.
    Returns the hostname or None. Fails silently on anything malformed or
    fragmented across multiple packets — this is inherently best-effort."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:  # TLS handshake record
            return None
        pos = 5
        if payload[pos] != 0x01:  # ClientHello
            return None
        pos += 4                      # handshake header: type(1) + length(3)
        pos += 2                      # client version
        pos += 32                     # random
        session_id_len = payload[pos]; pos += 1 + session_id_len
        cipher_len = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2 + cipher_len
        compression_len = payload[pos]; pos += 1 + compression_len
        if pos + 2 > len(payload):
            return None
        ext_total_len = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        end = pos + ext_total_len
        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
            ext_len = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
            if ext_type == 0:  # server_name
                p2 = pos + 2      # skip server_name_list length
                p2 += 1            # skip name_type byte
                name_len = int.from_bytes(payload[p2:p2 + 2], "big"); p2 += 2
                return payload[p2:p2 + name_len].decode("ascii", errors="ignore") or None
            pos += ext_len
    except Exception:
        return None
    return None


def extract_dns_query_dpkt(udp_data):
    try:
        dns = dpkt.dns.DNS(udp_data)
        if dns.qd:
            return dns.qd[0].name
    except Exception:
        pass
    return None


def extract_dns_query_scapy(pkt):
    try:
        from scapy.all import DNS, DNSQR
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            name = pkt[DNSQR].qname
            if isinstance(name, bytes):
                name = name.decode("ascii", errors="ignore")
            return name.rstrip(".")
    except Exception:
        pass
    return None


def classify_and_describe_dpkt(eth):
    """Return a dict of every field the frontend's protocol tree needs."""
    fields = {
        "protocol": "OTHER", "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None, "ttl": None, "flags": None,
        "info": "", "src_mac": mac_to_str(eth.src), "dst_mac": mac_to_str(eth.dst),
        "ethertype": f"0x{eth.type:04x}", "ip_id": None, "seq": None, "ack": None,
        "website": None,
    }

    if isinstance(eth.data, dpkt.arp.ARP):
        arp = eth.data
        fields["protocol"] = "ARP"
        fields["src_ip"] = ip_to_str(arp.spa)
        fields["dst_ip"] = ip_to_str(arp.tpa)
        fields["info"] = f"Who has {fields['dst_ip']}? Tell {fields['src_ip']}"
        return fields

    if not isinstance(eth.data, dpkt.ip.IP):
        return fields

    ip = eth.data
    fields["src_ip"] = ip_to_str(ip.src)
    fields["dst_ip"] = ip_to_str(ip.dst)
    fields["ttl"] = ip.ttl
    fields["ip_id"] = ip.id

    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        fields["protocol"] = "TCP"
        fields["src_port"], fields["dst_port"] = tcp.sport, tcp.dport
        fields["seq"] = tcp.seq
        fields["ack"] = tcp.ack
        flag_names = []
        if tcp.flags & dpkt.tcp.TH_SYN:
            flag_names.append("SYN")
        if tcp.flags & dpkt.tcp.TH_ACK:
            flag_names.append("ACK")
        if tcp.flags & dpkt.tcp.TH_FIN:
            flag_names.append("FIN")
        if tcp.flags & dpkt.tcp.TH_RST:
            flag_names.append("RST")
        if tcp.flags & dpkt.tcp.TH_PUSH:
            flag_names.append("PSH")
        fields["flags"] = ",".join(flag_names)
        fields["info"] = f"{fields['src_port']} -> {fields['dst_port']} [{fields['flags']}]"
        if (tcp.dport == 443 or tcp.sport == 443) and tcp.data:
            fields["website"] = extract_sni(bytes(tcp.data))
    elif isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        fields["protocol"] = "DNS" if 53 in (udp.sport, udp.dport) else "UDP"
        fields["src_port"], fields["dst_port"] = udp.sport, udp.dport
        fields["info"] = f"{fields['src_port']} -> {fields['dst_port']}"
        if fields["protocol"] == "DNS":
            domain = extract_dns_query_dpkt(udp.data)
            fields["website"] = domain
            if domain:
                fields["info"] = f"Query: {domain}"
    elif isinstance(ip.data, dpkt.icmp.ICMP):
        icmp = ip.data
        fields["protocol"] = "ICMP"
        fields["info"] = f"ICMP type={icmp.type}"
    else:
        fields["protocol"] = "IP"

    return fields


def import_pcap(filepath, filename):
    packets = []

    with open(filepath, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        packet_number = 0
        for ts, buf in reader:
            packet_number += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            fields = classify_and_describe_dpkt(eth)

            packets.append({
                "packet_number": packet_number,
                "captured_at": datetime.datetime.utcfromtimestamp(ts).isoformat(),
                "length": len(buf),
                "raw_hex": binascii.hexlify(buf).decode(),
                **fields,
            })

    session_id = new_session(filename, "pcap_import")
    with _sessions_lock:
        SESSIONS[session_id]["packets"] = packets
        SESSIONS[session_id]["packet_count"] = len(packets)
        SESSIONS[session_id]["status"] = "stopped"  # import finishes immediately
    return session_id, len(packets)


@app.route("/import", methods=["POST"])
def upload_and_import():
    if "file" not in request.files:
        return jsonify({"error": "no file field in upload"}), 400

    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "empty filename"}), 400

    safe_name = os.path.basename(uploaded.filename)
    filepath = os.path.join(UPLOAD_DIR, safe_name)
    uploaded.save(filepath)

    try:
        session_id, packet_count = import_pcap(filepath, safe_name)
    except Exception as exc:
        return jsonify({"error": f"failed to parse pcap: {exc}"}), 400
    finally:
        os.remove(filepath)

    return jsonify({"session_id": session_id, "packet_count": packet_count})


# =========================================================================
# Live capture (scapy) — needs Npcap installed + admin privileges
# =========================================================================

def list_interfaces():
    """Return [{name, description}] — works on Windows (Npcap) and Linux."""
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        return [
            {"name": i["name"], "description": i.get("description", "")}
            for i in ifaces
        ]
    except ImportError:
        # Not Windows — fall back to plain interface names.
        try:
            import netifaces
            return [{"name": n, "description": ""} for n in netifaces.interfaces()]
        except ImportError:
            return []


def classify_and_describe_scapy(pkt):
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether

    fields = {
        "protocol": "OTHER", "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None, "ttl": None, "flags": None,
        "info": "", "src_mac": None, "dst_mac": None,
        "ethertype": None, "ip_id": None, "seq": None, "ack": None,
        "website": None,
    }

    if pkt.haslayer(Ether):
        fields["src_mac"] = pkt[Ether].src
        fields["dst_mac"] = pkt[Ether].dst
        fields["ethertype"] = f"0x{pkt[Ether].type:04x}"

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        fields["protocol"] = "ARP"
        fields["src_ip"], fields["dst_ip"] = arp.psrc, arp.pdst
        fields["info"] = f"Who has {fields['dst_ip']}? Tell {fields['src_ip']}"
        return fields

    if not pkt.haslayer(IP):
        return fields

    fields["src_ip"], fields["dst_ip"], fields["ttl"] = pkt[IP].src, pkt[IP].dst, pkt[IP].ttl
    fields["ip_id"] = pkt[IP].id

    if pkt.haslayer(TCP):
        fields["protocol"] = "TCP"
        fields["src_port"], fields["dst_port"] = pkt[TCP].sport, pkt[TCP].dport
        fields["flags"] = pkt[TCP].sprintf("%TCP.flags%")
        fields["seq"] = pkt[TCP].seq
        fields["ack"] = pkt[TCP].ack
        fields["info"] = f"{fields['src_port']} -> {fields['dst_port']} [{fields['flags']}]"
        if (fields["dst_port"] == 443 or fields["src_port"] == 443) and bytes(pkt[TCP].payload):
            fields["website"] = extract_sni(bytes(pkt[TCP].payload))
    elif pkt.haslayer(UDP):
        fields["protocol"] = "DNS" if 53 in (pkt[UDP].sport, pkt[UDP].dport) else "UDP"
        fields["src_port"], fields["dst_port"] = pkt[UDP].sport, pkt[UDP].dport
        fields["info"] = f"{fields['src_port']} -> {fields['dst_port']}"
        if fields["protocol"] == "DNS":
            domain = extract_dns_query_scapy(pkt)
            fields["website"] = domain
            if domain:
                fields["info"] = f"Query: {domain}"
    elif pkt.haslayer(ICMP):
        fields["protocol"] = "ICMP"
        fields["info"] = f"ICMP type={pkt[ICMP].type}"
    else:
        fields["protocol"] = "IP"

    return fields


def capture_loop(interface, session_id):
    from scapy.all import sniff

    def on_packet(pkt):
        if live_state["stop_flag"].is_set():
            return
        fields = classify_and_describe_scapy(pkt)
        with _sessions_lock:
            session = SESSIONS[session_id]
            packet_number = len(session["packets"]) + 1
            session["packets"].append({
                "packet_number": packet_number,
                "captured_at": datetime.datetime.utcnow().isoformat(),
                "length": len(pkt),
                "raw_hex": binascii.hexlify(bytes(pkt)).decode(),
                **fields,
            })
            session["packet_count"] = packet_number

    try:
        sniff(
            iface=interface,
            prn=on_packet,
            stop_filter=lambda p: live_state["stop_flag"].is_set(),
            store=False,
        )
    finally:
        with _sessions_lock:
            SESSIONS[session_id]["status"] = "stopped"


@app.route("/interfaces", methods=["GET"])
def get_interfaces():
    return jsonify(list_interfaces())


@app.route("/live/status", methods=["GET"])
def live_status():
    session = SESSIONS.get(live_state["session_id"]) if live_state["session_id"] else None
    return jsonify({
        "sniffing": live_state["sniffing"],
        "session_id": live_state["session_id"],
        "packet_count": session["packet_count"] if session else 0,
    })


@app.route("/live/start", methods=["POST"])
def live_start():
    if live_state["sniffing"]:
        return jsonify({"error": "a live capture is already running"}), 400

    interface = request.json.get("interface") if request.is_json else None
    if not interface:
        return jsonify({"error": "interface is required"}), 400

    session_id = new_session(f"live: {interface}", "live")

    live_state["stop_flag"].clear()
    live_state["session_id"] = session_id
    live_state["sniffing"] = True
    live_state["thread"] = threading.Thread(
        target=capture_loop, args=(interface, session_id), daemon=True
    )

    try:
        live_state["thread"].start()
    except Exception as exc:
        live_state["sniffing"] = False
        return jsonify({
            "error": f"could not start capture: {exc}. "
                     "Make sure Npcap is installed and this script is running "
                     "as Administrator."
        }), 500

    return jsonify({"session_id": session_id, "interface": interface})


@app.route("/live/stop", methods=["POST"])
def live_stop():
    if not live_state["sniffing"]:
        return jsonify({"error": "no live capture running"}), 400

    live_state["stop_flag"].set()
    live_state["thread"].join(timeout=5)
    live_state["sniffing"] = False
    session_id = live_state["session_id"]
    packet_count = SESSIONS[session_id]["packet_count"] if session_id else 0
    live_state["session_id"] = None

    return jsonify({"session_id": session_id, "packet_count": packet_count})


# =========================================================================
# Shared read endpoints — same shape for pcap-imported and live sessions
# =========================================================================

@app.route("/sessions", methods=["GET"])
def list_sessions():
    """Summary of every session held in memory (not the full packet lists)."""
    return jsonify([
        {
            "session_id": s["session_id"],
            "filename": s["filename"],
            "imported_at": s["imported_at"],
            "packet_count": s["packet_count"],
            "source": s["source"],
            "status": s["status"],
        }
        for s in SESSIONS.values()
    ])


@app.route("/sessions/<int:session_id>/packets", methods=["GET"])
def get_packets(session_id):
    """Paginated + filterable packet list for one session.

    Query params: page (default 1), per_page (default 50),
    protocol, src_ip, dst_ip (all optional exact-match filters).
    """
    session = SESSIONS.get(session_id)
    if session is None:
        return jsonify({"error": "session not found"}), 404

    packets = session["packets"]

    protocol = request.args.get("protocol")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")

    if protocol:
        packets = [p for p in packets if p["protocol"] == protocol]
    if src_ip:
        packets = [p for p in packets if p["src_ip"] == src_ip]
    if dst_ip:
        packets = [p for p in packets if p["dst_ip"] == dst_ip]

    page = max(int(request.args.get("page", 1)), 1)
    per_page = max(int(request.args.get("per_page", 50)), 1)
    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        "session_id": session_id,
        "total_matching": len(packets),
        "page": page,
        "per_page": per_page,
        "status": session["status"],
        "packets": packets[start:end],
    })


@app.route("/sessions/<int:session_id>/packets/<int:packet_number>", methods=["GET"])
def get_packet_detail(session_id, packet_number):
    session = SESSIONS.get(session_id)
    if session is None:
        return jsonify({"error": "session not found"}), 404

    for p in session["packets"]:
        if p["packet_number"] == packet_number:
            return jsonify(p)

    return jsonify({"error": "packet not found"}), 404


# =========================================================================
# Hosts — unique devices seen in a session, plus active nmap scanning
# =========================================================================

@app.route("/sessions/<int:session_id>/hosts", methods=["GET"])
def get_hosts(session_id):
    """Every unique IP seen as src or dst in this session, with counts."""
    session = SESSIONS.get(session_id)
    if session is None:
        return jsonify({"error": "session not found"}), 404

    hosts = {}
    for p in session["packets"]:
        for ip in (p.get("src_ip"), p.get("dst_ip")):
            if not ip:
                continue
            if ip not in hosts:
                hosts[ip] = {"ip": ip, "packets_as_src": 0, "packets_as_dst": 0}
        if p.get("src_ip"):
            hosts[p["src_ip"]]["packets_as_src"] += 1
        if p.get("dst_ip"):
            hosts[p["dst_ip"]]["packets_as_dst"] += 1

    return jsonify(sorted(hosts.values(), key=lambda h: h["ip"]))


@app.route("/sessions/<int:session_id>/statistics", methods=["GET"])
def get_statistics(session_id):
    """Protocol breakdown, top talkers, and a packets-over-time timeline."""
    session = SESSIONS.get(session_id)
    if session is None:
        return jsonify({"error": "session not found"}), 404

    packets = session["packets"]
    total_packets = len(packets)
    total_bytes = sum(p["length"] for p in packets)

    # protocol breakdown
    proto_stats = {}
    for p in packets:
        proto = p["protocol"] or "OTHER"
        if proto not in proto_stats:
            proto_stats[proto] = {"protocol": proto, "count": 0, "bytes": 0}
        proto_stats[proto]["count"] += 1
        proto_stats[proto]["bytes"] += p["length"]
    protocol_breakdown = sorted(proto_stats.values(), key=lambda x: -x["count"])

    # top talkers — by total packets (as src + dst combined) and bytes
    talkers = {}
    for p in packets:
        for ip in (p.get("src_ip"), p.get("dst_ip")):
            if not ip:
                continue
            if ip not in talkers:
                talkers[ip] = {"ip": ip, "packets": 0, "bytes": 0}
            talkers[ip]["packets"] += 1
            talkers[ip]["bytes"] += p["length"]
    top_talkers = sorted(talkers.values(), key=lambda x: -x["packets"])[:10]

    # timeline — bucket packets into up to ~30 buckets across the capture span
    timeline = []
    if packets:
        times = [datetime.datetime.fromisoformat(p["captured_at"]) for p in packets]
        start, end = min(times), max(times)
        span_seconds = max((end - start).total_seconds(), 1)
        bucket_count = min(30, max(1, int(span_seconds)))
        bucket_size = span_seconds / bucket_count

        buckets = [0] * bucket_count
        for t in times:
            offset = (t - start).total_seconds()
            idx = min(int(offset / bucket_size), bucket_count - 1)
            buckets[idx] += 1

        for i, count in enumerate(buckets):
            bucket_time = start + datetime.timedelta(seconds=i * bucket_size)
            timeline.append({"time": bucket_time.strftime("%H:%M:%S"), "count": count})

    unique_hosts = len(talkers)
    duration_seconds = 0
    if len(packets) >= 2:
        times = [datetime.datetime.fromisoformat(p["captured_at"]) for p in packets]
        duration_seconds = (max(times) - min(times)).total_seconds()

    return jsonify({
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "unique_hosts": unique_hosts,
        "duration_seconds": round(duration_seconds, 1),
        "protocol_breakdown": protocol_breakdown,
        "top_talkers": top_talkers,
        "timeline": timeline,
    })


# =========================================================================
# Firewall — real Windows Firewall blocking via netsh (needs Administrator)
# =========================================================================

import ipaddress
import subprocess

# BLOCKED_IPS[ip] = iso timestamp when blocked. This is our own bookkeeping
# so the UI knows what it has blocked — the actual enforcement lives in
# Windows Firewall itself, not in this dict.
BLOCKED_IPS = {}


def firewall_rule_name(ip):
    # netsh doesn't like every character in rule names; keep it simple.
    safe = ip.replace(":", "_").replace(".", "_")
    return f"NetShark_Block_{safe}"


def run_netsh(args):
    """Run a netsh command, return (success, output_or_error)."""
    try:
        result = subprocess.run(
            ["netsh"] + args,
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or result.stdout.strip()
        return True, result.stdout.strip()
    except FileNotFoundError:
        return False, "netsh not found — this feature only works on Windows."
    except Exception as exc:
        return False, str(exc)


@app.route("/firewall/blocked", methods=["GET"])
def list_blocked():
    return jsonify([
        {"ip": ip, "blocked_at": ts} for ip, ts in BLOCKED_IPS.items()
    ])


@app.route("/firewall/block", methods=["POST"])
def block_ip():
    ip = (request.json or {}).get("ip") if request.is_json else None
    if not ip:
        return jsonify({"error": "ip is required"}), 400

    try:
        ipaddress.ip_address(ip)  # validate — also blocks command-injection attempts
    except ValueError:
        return jsonify({"error": f"'{ip}' is not a valid IP address"}), 400

    rule_name = firewall_rule_name(ip)

    ok_in, msg_in = run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}",
    ])
    ok_out, msg_out = run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip}",
    ])

    if not (ok_in and ok_out):
        # roll back whichever half succeeded so we don't leave a half-blocked state
        run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
        error = msg_in if not ok_in else msg_out
        return jsonify({
            "error": f"could not add firewall rule: {error}. "
                     "Make sure this script is running as Administrator."
        }), 500

    BLOCKED_IPS[ip] = datetime.datetime.utcnow().isoformat()
    return jsonify({"ip": ip, "status": "blocked"})


@app.route("/firewall/unblock", methods=["POST"])
def unblock_ip():
    ip = (request.json or {}).get("ip") if request.is_json else None
    if not ip:
        return jsonify({"error": "ip is required"}), 400

    rule_name = firewall_rule_name(ip)
    ok, msg = run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])

    if not ok:
        return jsonify({
            "error": f"could not remove firewall rule: {msg}. "
                     "Make sure this script is running as Administrator."
        }), 500

    BLOCKED_IPS.pop(ip, None)
    return jsonify({"ip": ip, "status": "unblocked"})


# =========================================================================
# Website monitoring + domain blocking — real DNS-level blocking via the
# Windows hosts file (needs Administrator, same as everything else above).
# =========================================================================

HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_MARKER = "# NetShark-block:"

# BLOCKED_DOMAINS[domain] = iso timestamp when blocked.
BLOCKED_DOMAINS = {}


def domain_variants(domain):
    """Block both the bare domain and its www. variant."""
    domain = domain.lower().strip().rstrip(".")
    variants = {domain}
    if domain.startswith("www."):
        variants.add(domain[4:])
    else:
        variants.add(f"www.{domain}")
    return variants


def read_hosts_file():
    with open(HOSTS_FILE_PATH, "r") as f:
        return f.readlines()


def write_hosts_file(lines):
    with open(HOSTS_FILE_PATH, "w") as f:
        f.writelines(lines)


def flush_dns_cache():
    subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=10)


@app.route("/websites/<int:session_id>", methods=["GET"])
def get_websites(session_id):
    """Every domain seen (DNS queries + TLS SNI) in this session, with counts."""
    session = SESSIONS.get(session_id)
    if session is None:
        return jsonify({"error": "session not found"}), 404

    sites = {}
    for p in session["packets"]:
        domain = p.get("website")
        if not domain:
            continue
        if domain not in sites:
            sites[domain] = {"domain": domain, "count": 0, "src_ips": set()}
        sites[domain]["count"] += 1
        if p.get("src_ip"):
            sites[domain]["src_ips"].add(p["src_ip"])

    result = [
        {"domain": s["domain"], "count": s["count"], "src_ips": sorted(s["src_ips"])}
        for s in sites.values()
    ]
    return jsonify(sorted(result, key=lambda s: -s["count"]))


@app.route("/domains/blocked", methods=["GET"])
def list_blocked_domains():
    return jsonify([
        {"domain": d, "blocked_at": ts} for d, ts in BLOCKED_DOMAINS.items()
    ])


@app.route("/domains/block", methods=["POST"])
def block_domain():
    domain = (request.json or {}).get("domain") if request.is_json else None
    if not domain:
        return jsonify({"error": "domain is required"}), 400

    domain = domain.lower().strip()
    variants = domain_variants(domain)

    try:
        lines = read_hosts_file()
        new_lines = list(lines)
        for variant in variants:
            new_lines.append(f"0.0.0.0 {variant} {HOSTS_MARKER}{domain}\n")
        write_hosts_file(new_lines)
        flush_dns_cache()
    except PermissionError:
        return jsonify({
            "error": "permission denied writing the hosts file. "
                     "Make sure this script is running as Administrator."
        }), 500
    except Exception as exc:
        return jsonify({"error": f"could not block domain: {exc}"}), 500

    BLOCKED_DOMAINS[domain] = datetime.datetime.utcnow().isoformat()
    return jsonify({"domain": domain, "status": "blocked"})


@app.route("/domains/unblock", methods=["POST"])
def unblock_domain():
    domain = (request.json or {}).get("domain") if request.is_json else None
    if not domain:
        return jsonify({"error": "domain is required"}), 400

    domain = domain.lower().strip()
    marker = f"{HOSTS_MARKER}{domain}"

    try:
        lines = read_hosts_file()
        new_lines = [line for line in lines if marker not in line]
        write_hosts_file(new_lines)
        flush_dns_cache()
    except PermissionError:
        return jsonify({
            "error": "permission denied writing the hosts file. "
                     "Make sure this script is running as Administrator."
        }), 500
    except Exception as exc:
        return jsonify({"error": f"could not unblock domain: {exc}"}), 500

    BLOCKED_DOMAINS.pop(domain, None)
    return jsonify({"domain": domain, "status": "unblocked"})


@app.route("/sessions/<int:session_id>/terminal-log", methods=["GET"])
def terminal_log(session_id):
    """Feed for the Terminal view: every packet with a resolved website,
    newest-relevant-only via `after` (a packet_number cursor)."""
    session = SESSIONS.get(session_id)
    if session is None:
        return jsonify({"error": "session not found"}), 404

    after = int(request.args.get("after", 0))
    entries = []
    for p in session["packets"]:
        if p["packet_number"] <= after or not p.get("website"):
            continue
        domain = p["website"]
        is_blocked = any(
            domain == d or domain.endswith("." + d) for d in BLOCKED_DOMAINS
        )
        entries.append({
            "packet_number": p["packet_number"],
            "captured_at": p["captured_at"],
            "domain": domain,
            "src_ip": p.get("src_ip"),
            "protocol": p["protocol"],
            "blocked": is_blocked,
        })

    return jsonify(entries)


@app.route("/scan", methods=["POST"])
def scan_host():
    """Active nmap scan of one IP: open ports, service versions, OS guess.

    Requires the nmap binary installed and on PATH. OS detection (-O) and
    SYN scan need Administrator — run this whole script elevated, same as
    for live capture.
    """
    try:
        import nmap
    except ImportError:
        return jsonify({
            "error": "python-nmap is not installed. Run: pip install python-nmap"
        }), 500

    target = (request.json or {}).get("ip") if request.is_json else None
    if not target:
        return jsonify({"error": "ip is required"}), 400

    try:
        scanner = nmap.PortScanner()
        # -F: fast scan (top 100 ports), -sV: service/version detection,
        # -O: OS detection (needs admin), -T4: faster timing.
        scanner.scan(hosts=target, arguments="-F -sV -O -T4")
    except nmap.PortScannerError as exc:
        return jsonify({
            "error": f"nmap error: {exc}. Is the nmap binary installed and "
                     "on your PATH? https://nmap.org/download.html"
        }), 500
    except Exception as exc:
        return jsonify({"error": f"scan failed: {exc}"}), 500

    if target not in scanner.all_hosts():
        return jsonify({
            "ip": target,
            "state": "no response",
            "ports": [],
            "os_guesses": [],
        })

    host_data = scanner[target]

    ports = []
    for proto in host_data.all_protocols():
        for port, info in host_data[proto].items():
            ports.append({
                "port": port,
                "protocol": proto,
                "state": info.get("state"),
                "service": info.get("name"),
                "product": info.get("product"),
                "version": info.get("version"),
            })
    ports.sort(key=lambda p: p["port"])

    os_guesses = [
        {"name": m.get("name"), "accuracy": m.get("accuracy")}
        for m in host_data.get("osmatch", [])
    ]

    return jsonify({
        "ip": target,
        "state": host_data.state(),
        "hostname": host_data.hostname() or None,
        "ports": ports,
        "os_guesses": os_guesses,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

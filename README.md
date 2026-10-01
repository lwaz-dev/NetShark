# NetShark

A Wireshark-style packet analyzer with a dark dashboard UI: sidebar nav,
live capture, pcap import, active nmap scanning, and real Windows Firewall
blocking — all in one page. No database anywhere, everything lives in
memory while the Python engine runs.

**New file:** `web/logo.png` — your NetShark logo, used as the sidebar
brand image, header logo, and browser favicon. Drop it into `web`
alongside the other files.

## One-time setup for live capture: install Npcap

Live capture needs the same driver Wireshark itself uses.

1. Download Npcap: https://npcap.com/#download
2. Run the installer. Leave "Install Npcap in WinPcap API-compatible Mode"
   checked. You can leave "Restrict Npcap driver's access to
   Administrators only" checked too — that's fine, since you'll run the
   Python engine as Administrator anyway (see below).
3. Restart isn't usually required, but if live capture still fails after
   installing, restart and try again.

If you skip this, pcap file import still works fine — only the live
capture button needs Npcap.

## One-time setup for active device scanning (nmap)

The "Hosts" button lets you scan a device for open ports, service
versions, and an OS guess. This needs the real `nmap` program installed,
not just the `python-nmap` package (which is only a thin wrapper around
it).

1. Download Nmap for Windows: https://nmap.org/download.html
2. Run the installer. It may offer to also install Npcap — if you
   already installed Npcap for live capture, you can skip that step in
   the Nmap installer.
3. Make sure `nmap` is on your PATH (the installer usually does this
   automatically). Test it by opening a new terminal and running `nmap -v`.
4. `pip install python-nmap`

Only scan devices and networks you actually own or have permission to
test — an nmap scan looks identical to an attack from the target's point
of view.

## Running it (three things, in order)

**1. Python engine — must run as Administrator for live capture to work:**

Right-click PowerShell → "Run as Administrator", then:
```
cd C:\Users\djlaz\OneDrive\Desktop\NetShark
pip install dpkt flask flask-cors scapy
python python\pcap_importer.py
```
Leave this running. It listens on `http://127.0.0.1:5000`.

(If you only ever plan to import pcap files and never use live capture,
you don't need Administrator — but there's no downside to always running
it elevated.)

**2. PHP server (separate, normal, non-admin terminal is fine):**
```
cd C:\Users\djlaz\OneDrive\Desktop\NetShark
php -S localhost:8000 -t web
```

**3. Open the app:**
```
http://localhost:8000/index.php
```

## Using live capture

1. The interface dropdown in the top bar lists your network adapters
   (e.g. "Wi-Fi", "Ethernet") — pick the one that's actually connected.
2. Click "Start Live Capture". The packet table starts filling in real
   time (it refreshes automatically every 1.5 seconds while capturing).
3. Click "Stop" when you're done. The session stays in the dropdown so
   you can keep browsing what was captured.

## Using pcap import

1. Click "Choose file", pick a `.pcap`/`.pcapng` file, click "Import pcap".
2. Same session dropdown, filters, and detail pane as live capture.

Sample files if you want to test without capturing your own traffic:
https://wiki.wireshark.org/SampleCaptures

## Using device scanning

1. With a session selected, click "Hosts" in the toolbar — it lists every
   unique IP seen in that session's traffic so far.
2. Click "Scan" next to any IP. This runs `nmap -F -sV -O` against it
   (fast scan, top 100 ports, service versions, OS guess) and can take
   10-30 seconds.
3. Results show open ports with service/version, plus OS guesses with a
   confidence percentage.

OS detection specifically needs Administrator privileges — if you're
already running the Python engine elevated for live capture, this works
automatically. Without admin, port/service results still work, OS
guesses just won't.

## Using IP blocking (real Windows Firewall)

This adds actual Windows Firewall rules — it's not cosmetic, blocked IPs
genuinely can't send or receive traffic on this machine until unblocked.

1. Click "Hosts" to see a Block button next to every IP seen in the
   capture, or click "Firewall" to block any IP directly (doesn't need
   to appear in a capture first).
2. Blocking creates two firewall rules (`NetShark_Block_<ip>`, one
   inbound, one outbound) via `netsh advfirewall`.
3. The "Firewall" panel lists everything currently blocked and lets you
   unblock with one click, which removes both rules cleanly.

This needs Administrator — same requirement as live capture. If you get
an "Access is denied" style error, the Python engine isn't running
elevated.

You can also verify a block worked from outside the app: open Windows
Defender Firewall with Advanced Security and look for rules named
`NetShark_Block_...` under Inbound/Outbound Rules.

## Using the Terminal (website monitoring + blocking)

Click "Terminal" in the sidebar — it's a real, working view, not a
placeholder like the other nav items.

**Monitoring:** while a session is selected (live capture or pcap
import), the terminal streams every website it can identify from traffic:
- DNS queries (the domain being looked up)
- TLS SNI from HTTPS connections (the domain in the ClientHello, before
  encryption starts) — this is how it can identify HTTPS sites even
  though the rest of the traffic is encrypted

Each line shows time, ALLOWED or BLOCKED, source IP, and the domain.

**Blocking — real, at the DNS level:** type commands directly at the
prompt:
```
block facebook.com
unblock facebook.com
list
clear
help
```
`block` adds entries to the Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`)
pointing the domain (and its `www.` variant) at `0.0.0.0`, then flushes
the DNS cache. This is real, at the OS level — it affects every browser
and app on this machine, not just what NetShark itself sees. `unblock`
removes those entries cleanly.

This needs Administrator (same requirement as everything else) since
writing to the hosts file needs elevated permissions.

**Note on SNI parsing:** it's best-effort — a ClientHello that gets split
across multiple TCP packets won't be parsed. Most real-world HTTPS
traffic sends it in one packet, so this works most of the time, but
occasional misses are expected and not a bug.

## Using Statistics

Click "Statistics" in the sidebar (now a real page, not a placeholder)
for a breakdown of the currently selected session:

- Summary cards: total packets, total data, unique hosts, capture duration
- Protocol Breakdown: doughnut chart + legend table with percentages and
  bytes per protocol
- Top Talkers: the 10 busiest IPs by packet count (as source or
  destination combined)
- Traffic Over Time: a line chart of packet volume across the capture,
  bucketed into up to 30 time slices

Click "Refresh" to recompute after more packets have come in (useful
during a live capture). Charts are drawn with Chart.js, loaded from
cdnjs — an internet connection is needed for that one library.

**If the Terminal appears empty or shows connection errors:** confirm
`websites.php` is actually in your `web` folder (it was added alongside
the domain-blocking feature — easy to miss if you only copied some
files that round). It now prints a clear error line in the terminal
window itself if it can't reach that file, instead of failing silently.
Also make sure the Python engine was restarted after the website/SNI
detection code was added — packets captured before that point won't
have a website recorded, so nothing will show up in the log for them.

## Troubleshooting live capture

- **"could not start capture" error mentioning Npcap/Administrator** —
  either Npcap isn't installed (see setup above), or PowerShell wasn't
  run as Administrator. Close it, reopen with "Run as Administrator",
  and start the Python engine again.
- **Interface dropdown is empty or says "No interfaces found"** — Npcap
  isn't installed yet, or the Python engine needs restarting after you
  installed it.
- **Nothing shows up after clicking Start** — check you picked the
  adapter you're actually using (e.g. "Wi-Fi" vs a disconnected
  "Ethernet"), and that some traffic is actually happening (browse to a
  site while it's running).

## Known limitation

Everything lives in the Flask process's memory. Restarting
`pcap_importer.py` clears all sessions, live and imported alike.

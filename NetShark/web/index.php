<?php
// index.php — page shell. All data comes in via JS calling api.php, upload.php,
// live.php, scan.php, firewall.php.
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetShark</title>
<link rel="icon" href="logo.png">
<link rel="stylesheet" href="style.css">
</head>
<body>

<div class="app-shell">

    <aside class="sidebar">
        <div class="sidebar-brand">
            <img src="logo.png" alt="NetShark" class="sidebar-logo">
        </div>
        <nav class="sidebar-nav">
            <button class="nav-item active" data-view="capture">
                <svg class="nav-icon icon-cyan" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
                Capture
            </button>
            <button class="nav-item" data-view="terminal">
                <svg class="nav-icon icon-green" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                Terminal
            </button>
            <button class="nav-item" data-view="packets">
                <svg class="nav-icon icon-orange" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
                Packets
            </button>
            <button class="nav-item" data-view="statistics">
                <svg class="nav-icon icon-purple" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                Statistics
            </button>
            <button class="nav-item" data-view="protocols">
                <svg class="nav-icon icon-pink" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                Protocols
            </button>
            <button class="nav-item" data-view="filters-page">
                <svg class="nav-icon icon-yellow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
                Filters
            </button>
            <button class="nav-item" data-view="settings">
                <svg class="nav-icon icon-slate" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                Settings
            </button>
        </nav>
        <div class="sidebar-footer">
            <img src="logo.png" alt="" class="sidebar-footer-logo">
            <div>
                <div class="footer-title">NetShark v1.0</div>
                <div class="footer-subtitle">Network Analysis Tool</div>
            </div>
        </div>
    </aside>

    <main class="main-content">

        <header class="top-header">
            <div class="brand">
                <img src="logo.png" alt="" class="brand-logo">
                <div>
                    <div class="brand-title">NetShark <svg class="sparkle" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l1.5 5.5L19 9l-5.5 1.5L12 16l-1.5-5.5L5 9l5.5-1.5z"/></svg><svg class="sparkle sparkle-sm" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l1.5 5.5L19 9l-5.5 1.5L12 16l-1.5-5.5L5 9l5.5-1.5z"/></svg></div>
                    <div class="brand-tagline">Capture &bull; Analyze &bull; Secure</div>
                </div>
            </div>
            <div class="header-status">
                <span class="live-dot" id="live-dot"></span>
                <span id="live-status-text">Idle</span>
                <button class="icon-btn" data-nav-target="settings" title="Settings">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                </button>
                <button class="icon-btn" id="theme-toggle" title="Toggle light/dark theme">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                </button>
                <span class="avatar-icon" title="NetShark user">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </span>
            </div>
        </header>

        <section id="view-capture" class="view">

            <div class="toolbar">
                <div class="toolbar-group">
                    <label>Interface</label>
                    <select id="interface-select"><option value="">Loading interfaces…</option></select>
                </div>
                <div class="toolbar-group">
                    <label>Protocol</label>
                    <select id="filter-protocol">
                        <option value="">All</option>
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="DNS">DNS</option>
                        <option value="ARP">ARP</option>
                        <option value="ICMP">ICMP</option>
                        <option value="OTHER">Other</option>
                    </select>
                </div>
                <div class="toolbar-group">
                    <label>Source IP</label>
                    <input type="text" id="filter-src" placeholder="e.g. 192.168.1.5">
                </div>
                <div class="toolbar-group">
                    <label>Destination IP</label>
                    <input type="text" id="filter-dst" placeholder="e.g. 8.8.8.8">
                </div>

                <div class="toolbar-actions">
                    <button id="start-live" class="btn btn-primary"><svg class="btn-icon" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Capture</button>
                    <button id="stop-live" class="btn btn-danger" disabled><svg class="btn-icon" viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="5" width="14" height="14" rx="1"/></svg> Stop</button>
                    <button id="apply-filters" class="btn btn-outline">Apply</button>
                    <button id="show-hosts" class="btn btn-outline">Hosts</button>
                    <button id="show-firewall" class="btn btn-outline">Firewall</button>
                </div>
            </div>

            <div class="toolbar-secondary">
                <label class="import-label">
                    <input type="file" id="pcap-file" accept=".pcap,.pcapng">
                    <span class="btn btn-outline">Choose file</span>
                </label>
                <button id="upload-btn" class="btn btn-outline">Import pcap</button>
                <label class="session-label">
                    Session:
                    <select id="session-select"><option value="">— none imported yet —</option></select>
                </label>
                <span id="upload-status"></span>
            </div>

            <div class="hosts-panel" id="hosts-panel" hidden>
                <table id="hosts-table">
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Packets (as src)</th>
                            <th>Packets (as dst)</th>
                            <th>Scan</th>
                            <th>Firewall</th>
                        </tr>
                    </thead>
                    <tbody id="hosts-table-body"></tbody>
                </table>
                <div id="scan-result"></div>
            </div>

            <div class="hosts-panel" id="firewall-panel" hidden>
                <div class="firewall-add">
                    <input type="text" id="manual-block-ip" placeholder="IP to block, e.g. 203.0.113.5">
                    <button id="manual-block-btn" class="btn btn-danger">Block this IP</button>
                </div>
                <table id="firewall-table">
                    <thead>
                        <tr><th>Blocked IP</th><th>Blocked at</th><th>Action</th></tr>
                    </thead>
                    <tbody id="firewall-table-body">
                        <tr><td colspan="3">No IPs currently blocked.</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="packet-list-card">
                <table id="packet-table">
                    <thead>
                        <tr>
                            <th class="col-check"><input type="checkbox" disabled></th>
                            <th>No.</th>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Protocol</th>
                            <th>Length</th>
                            <th>Info</th>
                            <th>Scan</th>
                            <th>Firewall</th>
                        </tr>
                    </thead>
                    <tbody id="packet-table-body">
                        <tr><td colspan="10" class="empty-row">Import a pcap file or start a live capture to get started.</td></tr>
                    </tbody>
                </table>
                <div class="pagination">
                    <button id="prev-page" class="btn btn-outline">&laquo; Prev</button>
                    <span id="page-indicator">Page 1</span>
                    <button id="next-page" class="btn btn-outline">Next &raquo;</button>
                </div>
            </div>

            <div class="detail-card">
                <div class="detail-tabs">
                    <button class="tab-btn active" data-tab="tree">Packet Details</button>
                    <button class="tab-btn" data-tab="hex">Hex View</button>
                    <button class="tab-btn" data-tab="raw">Raw Data</button>
                </div>

                <div class="detail-body">
                    <div class="detail-main">
                        <div class="tab-panel active" id="tab-tree">
                            <p class="placeholder">Click a packet above to see its details.</p>
                        </div>
                        <div class="tab-panel" id="tab-hex">
                            <p class="placeholder">Click a packet above to see its hex dump.</p>
                        </div>
                        <div class="tab-panel" id="tab-raw">
                            <p class="placeholder">Click a packet above to see its raw hex.</p>
                        </div>
                    </div>

                    <div class="detail-side">
                        <div class="side-card" id="packet-summary-card" hidden>
                            <h3>Packet Summary</h3>
                            <dl id="packet-summary-list"></dl>
                        </div>
                        <div class="side-card" id="packet-info-card" hidden>
                            <h3>Packet Info</h3>
                            <div id="packet-info-body"></div>
                        </div>
                    </div>
                </div>
            </div>

        </section>

        <section id="view-terminal" class="view" hidden>
            <div class="terminal-toolbar">
                <div class="terminal-status">
                    <span class="live-dot" id="terminal-live-dot"></span>
                    <span id="terminal-status-text">Watching session: none</span>
                </div>
                <div class="terminal-stats">
                    <span id="terminal-blocked-count">0 domains blocked</span>
                </div>
            </div>
            <div class="terminal-window" id="terminal-window">
                <div class="terminal-output" id="terminal-output"><div class="term-line term-system">NetShark Terminal — type <span class="term-cmd">help</span> for commands.</div></div>
                <div class="terminal-input-row">
                    <span class="terminal-prompt">netshark&gt;</span>
                    <input type="text" id="terminal-input" autocomplete="off" spellcheck="false" placeholder="block facebook.com">
                </div>
            </div>
        </section>

        <section id="view-statistics" class="view" hidden>
            <div class="stats-header">
                <div>
                    <span id="stats-session-label">No session selected</span>
                </div>
                <button id="stats-refresh" class="btn btn-outline">Refresh</button>
            </div>

            <div class="stats-summary-row">
                <div class="stat-card">
                    <div class="stat-value" id="stat-total-packets">—</div>
                    <div class="stat-label">Total Packets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-total-bytes">—</div>
                    <div class="stat-label">Total Data</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-unique-hosts">—</div>
                    <div class="stat-label">Unique Hosts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-duration">—</div>
                    <div class="stat-label">Duration</div>
                </div>
            </div>

            <div class="stats-charts-row">
                <div class="chart-card">
                    <h3>Protocol Breakdown</h3>
                    <div class="chart-with-legend">
                        <canvas id="protocol-chart"></canvas>
                        <table class="legend-table" id="protocol-legend"></table>
                    </div>
                </div>
                <div class="chart-card">
                    <h3>Top Talkers</h3>
                    <canvas id="talkers-chart"></canvas>
                </div>
            </div>

            <div class="chart-card chart-card-wide">
                <h3>Traffic Over Time</h3>
                <canvas id="timeline-chart"></canvas>
            </div>
        </section>

        <section id="view-placeholder" class="view" hidden>
            <div class="placeholder-page">
                <h2 id="placeholder-title">Coming soon</h2>
                <p>This section isn't built yet — Capture is the working part of NetShark for now.</p>
            </div>
        </section>

    </main>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js"></script>
<script src="app.js"></script>
</body>
</html>

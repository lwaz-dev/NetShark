// app.js — talks only to api.php / upload.php / live.php / scan.php /
// firewall.php (same-origin PHP), never directly to the Python Flask service.

const state = {
    sessionId: null,
    page: 1,
    perPage: 50,
    totalMatching: 0,
    selectedPacket: null,
};

function svgIcon(name) {
    const icons = {
        check: '<svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
        x: '<svg class="badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    };
    return icons[name] || '';
}

const els = {
    // sidebar / nav
    navItems: document.querySelectorAll('.nav-item'),
    viewCapture: document.getElementById('view-capture'),
    viewTerminal: document.getElementById('view-terminal'),
    viewStatistics: document.getElementById('view-statistics'),
    viewPlaceholder: document.getElementById('view-placeholder'),
    placeholderTitle: document.getElementById('placeholder-title'),

    // terminal
    terminalLiveDot: document.getElementById('terminal-live-dot'),
    terminalStatusText: document.getElementById('terminal-status-text'),
    terminalBlockedCount: document.getElementById('terminal-blocked-count'),
    terminalOutput: document.getElementById('terminal-output'),
    terminalInput: document.getElementById('terminal-input'),

    // statistics
    statsSessionLabel: document.getElementById('stats-session-label'),
    statsRefresh: document.getElementById('stats-refresh'),
    statTotalPackets: document.getElementById('stat-total-packets'),
    statTotalBytes: document.getElementById('stat-total-bytes'),
    statUniqueHosts: document.getElementById('stat-unique-hosts'),
    statDuration: document.getElementById('stat-duration'),
    protocolLegend: document.getElementById('protocol-legend'),

    // header
    liveDot: document.getElementById('live-dot'),
    liveStatusText: document.getElementById('live-status-text'),

    // toolbar
    interfaceSelect: document.getElementById('interface-select'),
    filterProtocol: document.getElementById('filter-protocol'),
    filterSrc: document.getElementById('filter-src'),
    filterDst: document.getElementById('filter-dst'),
    startLive: document.getElementById('start-live'),
    stopLive: document.getElementById('stop-live'),
    applyFilters: document.getElementById('apply-filters'),
    showHosts: document.getElementById('show-hosts'),
    showFirewall: document.getElementById('show-firewall'),

    // upload row
    fileInput: document.getElementById('pcap-file'),
    uploadBtn: document.getElementById('upload-btn'),
    uploadStatus: document.getElementById('upload-status'),
    sessionSelect: document.getElementById('session-select'),

    // hosts / firewall panels
    hostsPanel: document.getElementById('hosts-panel'),
    hostsTableBody: document.getElementById('hosts-table-body'),
    scanResult: document.getElementById('scan-result'),
    firewallPanel: document.getElementById('firewall-panel'),
    firewallTableBody: document.getElementById('firewall-table-body'),
    manualBlockIp: document.getElementById('manual-block-ip'),
    manualBlockBtn: document.getElementById('manual-block-btn'),

    // packet table
    tableBody: document.getElementById('packet-table-body'),
    prevPage: document.getElementById('prev-page'),
    nextPage: document.getElementById('next-page'),
    pageIndicator: document.getElementById('page-indicator'),

    // detail card
    tabBtns: document.querySelectorAll('.tab-btn'),
    tabTree: document.getElementById('tab-tree'),
    tabHex: document.getElementById('tab-hex'),
    tabRaw: document.getElementById('tab-raw'),
    summaryCard: document.getElementById('packet-summary-card'),
    summaryList: document.getElementById('packet-summary-list'),
    infoCard: document.getElementById('packet-info-card'),
    infoBody: document.getElementById('packet-info-body'),
};

let blockedIps = new Set();
let livePollTimer = null;
let currentPagePackets = [];
let expandedDetailRows = new Set();

// =========================================================================
// Sidebar navigation
// =========================================================================

const PLACEHOLDER_TITLES = {
    packets: 'Packets',
    protocols: 'Protocols',
    'filters-page': 'Filters',
    settings: 'Settings',
};

const REAL_VIEWS = ['capture', 'terminal', 'statistics'];

// ---- theme toggle ----
const THEME_KEY = 'netshark-theme';
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
}
applyTheme(localStorage.getItem(THEME_KEY) || 'dark');

document.getElementById('theme-toggle').addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(current === 'dark' ? 'light' : 'dark');
});

// ---- header gear jumps to the Settings nav item ----
document.querySelectorAll('[data-nav-target]').forEach(btn => {
    btn.addEventListener('click', () => {
        const target = btn.dataset.navTarget;
        document.querySelector(`.nav-item[data-view="${target}"]`)?.click();
    });
});

els.navItems.forEach(btn => {
    btn.addEventListener('click', () => {
        els.navItems.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const view = btn.dataset.view;
        els.viewCapture.setAttribute('hidden', '');
        els.viewTerminal.setAttribute('hidden', '');
        els.viewStatistics.setAttribute('hidden', '');
        els.viewPlaceholder.setAttribute('hidden', '');

        if (view === 'capture') {
            els.viewCapture.removeAttribute('hidden');
        } else if (view === 'terminal') {
            els.viewTerminal.removeAttribute('hidden');
            startTerminalPolling();
        } else if (view === 'statistics') {
            els.viewStatistics.removeAttribute('hidden');
            loadStatistics();
        } else {
            els.viewPlaceholder.removeAttribute('hidden');
            els.placeholderTitle.textContent = PLACEHOLDER_TITLES[view] || 'Coming soon';
        }

        if (view !== 'terminal') stopTerminalPolling();
    });
});

// =========================================================================
// Sessions / interfaces
// =========================================================================

async function loadSessions(selectSessionId = null) {
    const res = await fetch('api.php?action=sessions');
    const sessions = await res.json();

    els.sessionSelect.innerHTML = '';
    if (sessions.length === 0) {
        els.sessionSelect.innerHTML = '<option value="">— none imported yet —</option>';
        return;
    }

    for (const s of sessions) {
        const opt = document.createElement('option');
        opt.value = s.session_id;
        opt.textContent = `#${s.session_id} — ${s.filename} (${s.packet_count} pkts)`;
        els.sessionSelect.appendChild(opt);
    }

    const toSelect = selectSessionId ?? sessions[sessions.length - 1].session_id;
    els.sessionSelect.value = toSelect;
    state.sessionId = Number(toSelect);
    state.page = 1;
    loadPackets();
}

async function loadInterfaces() {
    try {
        const res = await fetch('api.php?action=interfaces');
        const interfaces = await res.json();

        els.interfaceSelect.innerHTML = '';
        if (!Array.isArray(interfaces) || interfaces.length === 0) {
            els.interfaceSelect.innerHTML = '<option value="">No interfaces found</option>';
            return;
        }
        for (const iface of interfaces) {
            const opt = document.createElement('option');
            opt.value = iface.name;
            opt.textContent = iface.description ? `${iface.name} — ${iface.description}` : iface.name;
            els.interfaceSelect.appendChild(opt);
        }
    } catch (err) {
        els.interfaceSelect.innerHTML = '<option value="">Could not load interfaces</option>';
    }
}

// =========================================================================
// Packet table
// =========================================================================

async function loadPackets() {
    if (!state.sessionId) {
        els.tableBody.innerHTML = '<tr><td colspan="10" class="empty-row">Import a pcap file or start a live capture to get started.</td></tr>';
        return;
    }

    const params = new URLSearchParams({
        action: 'packets',
        session_id: state.sessionId,
        page: state.page,
        per_page: state.perPage,
        protocol: els.filterProtocol.value,
        src_ip: els.filterSrc.value.trim(),
        dst_ip: els.filterDst.value.trim(),
    });

    const res = await fetch(`api.php?${params.toString()}`);
    const data = await res.json();

    if (data.error) {
        els.tableBody.innerHTML = `<tr><td colspan="10" class="empty-row">${data.error}</td></tr>`;
        return;
    }

    state.totalMatching = data.total_matching;
    currentPagePackets = data.packets;
    els.tableBody.innerHTML = '';

    if (data.packets.length === 0) {
        els.tableBody.innerHTML = '<tr><td colspan="10" class="empty-row">No packets match these filters.</td></tr>';
    }

    for (const p of data.packets) {
        const relevantIp = p.src_ip || p.dst_ip;
        const isBlocked = relevantIp && blockedIps.has(relevantIp);

        const tr = document.createElement('tr');
        tr.dataset.packetNumber = p.packet_number;
        tr.innerHTML = `
            <td class="col-check"><input type="checkbox" ${state.selectedPacket === p.packet_number ? 'checked' : ''} disabled></td>
            <td>${p.packet_number}</td>
            <td>${p.captured_at.replace('T', ' ').split('.')[0]}</td>
            <td>${p.src_ip ?? ''}${p.src_port ? ':' + p.src_port : ''}</td>
            <td>${p.dst_ip ?? ''}${p.dst_port ? ':' + p.dst_port : ''}</td>
            <td><span class="proto-badge proto-${p.protocol || 'OTHER'}">${p.protocol}</span></td>
            <td>${p.length}</td>
            <td>${p.info ?? ''}</td>
            <td>${relevantIp ? `<button class="scan-btn" data-ip="${relevantIp}">Scan</button>` : ''}</td>
            <td>${relevantIp
                ? `<button class="firewall-badge ${isBlocked ? 'blocked' : 'allowed'} row-fw-toggle" data-ip="${relevantIp}">
                       ${isBlocked ? svgIcon('x') + ' Blocked' : svgIcon('check') + ' Allowed'}
                   </button>`
                : ''}</td>
        `;

        tr.addEventListener('click', (e) => {
            if (e.target.closest('button')) return; // don't select when clicking a button
            selectPacket(tr, p);
        });

        els.tableBody.appendChild(tr);
    }

    els.tableBody.querySelectorAll('.scan-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            els.hostsPanel.removeAttribute('hidden');
            els.hostsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            runScan(btn.dataset.ip, btn);
        });
    });

    els.tableBody.querySelectorAll('.row-fw-toggle').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleBlockBadge(btn.dataset.ip, btn);
        });
    });

    // auto-select the first packet if nothing (still) selected on this page
    if (currentPagePackets.length > 0) {
        const stillValid = currentPagePackets.some(p => p.packet_number === state.selectedPacket);
        if (!stillValid) {
            state.selectedPacket = currentPagePackets[0].packet_number;
            expandedDetailRows.add(state.selectedPacket);
        }
        const selRow = els.tableBody.querySelector(`tr[data-packet-number="${state.selectedPacket}"]`);
        if (selRow) {
            selRow.classList.add('selected');
            selRow.querySelector('input[type=checkbox]').checked = true;
        }
        const fullPacket = currentPagePackets.find(p => p.packet_number === state.selectedPacket);
        if (fullPacket) showPacketDetail(fullPacket);
    }
    renderDetailPacketList();

    const totalPages = Math.max(1, Math.ceil(state.totalMatching / state.perPage));
    els.pageIndicator.textContent = `Page ${state.page} of ${totalPages} (${state.totalMatching} packets)`;
}

// =========================================================================
// Packet selection + detail tabs
// =========================================================================

function selectPacket(row, packetSummary) {
    document.querySelectorAll('#packet-table tbody tr.selected')
        .forEach(r => { r.classList.remove('selected'); r.querySelector('input[type=checkbox]').checked = false; });
    row.classList.add('selected');
    row.querySelector('input[type=checkbox]').checked = true;
    state.selectedPacket = packetSummary.packet_number;
    expandedDetailRows.add(packetSummary.packet_number);

    const fullPacket = currentPagePackets.find(p => p.packet_number === packetSummary.packet_number);
    if (fullPacket) showPacketDetail(fullPacket);
    renderDetailPacketList();
}

els.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        els.tabBtns.forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
    });
});

function formatHexDump(hex) {
    const bytes = hex.match(/.{1,2}/g) || [];
    let out = '';
    for (let i = 0; i < bytes.length; i += 16) {
        const chunk = bytes.slice(i, i + 16);
        const offset = i.toString(16).padStart(4, '0');
        const hexPart = chunk.join(' ').padEnd(47, ' ');
        const asciiPart = chunk.map(b => {
            const code = parseInt(b, 16);
            return (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.';
        }).join('');
        out += `${offset}  ${hexPart}  ${asciiPart}\n`;
    }
    return out;
}

function buildProtocolTree(p) {
    const layers = [];

    if (p.src_mac || p.dst_mac) {
        layers.push({
            title: 'Ethernet II',
            rows: [
                ['Source MAC', p.src_mac ?? '—'],
                ['Destination MAC', p.dst_mac ?? '—'],
                ['Type', p.ethertype ?? '—'],
            ],
        });
    }

    if (p.src_ip || p.dst_ip) {
        layers.push({
            title: p.protocol === 'ARP' ? 'Address Resolution Protocol' : 'Internet Protocol',
            rows: [
                ['Source', p.src_ip ?? '—'],
                ['Destination', p.dst_ip ?? '—'],
                ...(p.ttl !== null && p.ttl !== undefined ? [['TTL', p.ttl]] : []),
                ...(p.ip_id !== null && p.ip_id !== undefined ? [['Identification', p.ip_id]] : []),
            ],
        });
    }

    if (p.protocol === 'TCP') {
        layers.push({
            title: 'Transmission Control Protocol',
            rows: [
                ['Source Port', p.src_port ?? '—'],
                ['Destination Port', p.dst_port ?? '—'],
                ['Sequence Number', p.seq ?? '—'],
                ['Acknowledgment Number', p.ack ?? '—'],
                ['Flags', p.flags ?? '—'],
                ['Length', `${p.length} bytes`],
            ],
        });
    } else if (p.protocol === 'UDP' || p.protocol === 'DNS') {
        layers.push({
            title: p.protocol === 'DNS' ? 'User Datagram Protocol (DNS)' : 'User Datagram Protocol',
            rows: [
                ['Source Port', p.src_port ?? '—'],
                ['Destination Port', p.dst_port ?? '—'],
                ['Length', `${p.length} bytes`],
            ],
        });
    } else if (p.protocol === 'ICMP') {
        layers.push({
            title: 'Internet Control Message Protocol',
            rows: [['Info', p.info ?? '—']],
        });
    }

    if (layers.length === 0) {
        layers.push({ title: 'Raw Frame', rows: [['Length', `${p.length} bytes`]] });
    }

    return layers.map((layer, i) => `
        <div class="tree-layer" data-index="${i}">
            <div class="tree-layer-header">
                <span class="chevron">&#9656;</span> ${layer.title}
            </div>
            <div class="tree-layer-body">
                ${layer.rows.map(([label, value]) => `
                    <div>${label}: <span class="val">${value}</span></div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

function describePacket(p) {
    if (p.protocol === 'TCP') {
        const flags = (p.flags || '').split(',').filter(Boolean);
        if (flags.includes('SYN') && flags.includes('ACK')) return 'TCP handshake — SYN-ACK response.';
        if (flags.includes('SYN')) return 'TCP handshake — connection request (SYN).';
        if (flags.includes('FIN')) return 'TCP connection close (FIN).';
        if (flags.includes('RST')) return 'TCP connection reset (RST).';
        if (flags.length === 1 && flags[0] === 'ACK' && p.length < 100) return 'TCP acknowledgment / keep-alive.';
        return `TCP segment, flags: ${p.flags || '—'}.`;
    }
    if (p.protocol === 'DNS') return 'DNS query or response.';
    if (p.protocol === 'UDP') return 'UDP datagram.';
    if (p.protocol === 'ARP') return p.info || 'ARP request/reply.';
    if (p.protocol === 'ICMP') return p.info || 'ICMP message (e.g. ping).';
    return 'Unclassified traffic (likely IPv6 or another protocol not yet parsed).';
}

function showPacketDetail(p) {
    // Hex View tab
    els.tabHex.innerHTML = `<div class="hex-dump">${formatHexDump(p.raw_hex)}</div>`;

    // Raw Data tab
    els.tabRaw.innerHTML = `<div class="raw-dump">${p.raw_hex}</div>`;

    // Packet Summary side card
    els.summaryCard.removeAttribute('hidden');
    els.summaryList.innerHTML = `
        <div><dt>Number</dt><dd>${p.packet_number}</dd></div>
        <div><dt>Time</dt><dd>${p.captured_at}</dd></div>
        <div><dt>Source IP</dt><dd>${p.src_ip ?? '—'}</dd></div>
        <div><dt>Destination IP</dt><dd>${p.dst_ip ?? '—'}</dd></div>
        <div><dt>Protocol</dt><dd>${p.protocol}</dd></div>
        <div><dt>Length</dt><dd>${p.length} bytes</dd></div>
    `;

    // Packet Info side card
    const relevantIp = p.src_ip || p.dst_ip;
    const isBlocked = relevantIp && blockedIps.has(relevantIp);
    els.infoCard.removeAttribute('hidden');
    els.infoBody.innerHTML = `
        <p>${describePacket(p)}</p>
        ${relevantIp ? `<span class="firewall-badge ${isBlocked ? 'blocked' : 'allowed'}">
            ${isBlocked ? svgIcon('x') + ' Blocked by firewall' : svgIcon('check') + ' Allowed by firewall'}
        </span>` : ''}
    `;
}

function renderDetailPacketList() {
    if (currentPagePackets.length === 0) {
        els.tabTree.innerHTML = '<p class="placeholder">Click a packet above to see its details.</p>';
        return;
    }

    els.tabTree.innerHTML = `
        <div class="detail-packet-list">
            ${currentPagePackets.map(p => {
                const isExpanded = expandedDetailRows.has(p.packet_number);
                return `
                    <div class="detail-row ${isExpanded ? 'expanded' : ''}" data-packet-number="${p.packet_number}">
                        <div class="detail-row-summary">
                            <span class="chevron">&#9656;</span>
                            <span class="drs-num">${p.packet_number}</span>
                            <span class="drs-time">${p.captured_at.replace('T', ' ').split('.')[0]}</span>
                            <span class="drs-src">${p.src_ip ?? ''}</span>
                            <span class="drs-dst">${p.dst_ip ?? ''}</span>
                            <span class="proto-badge proto-${p.protocol || 'OTHER'}">${p.protocol}</span>
                            <span class="drs-len">${p.length}</span>
                            <span class="drs-info">${p.info ?? ''}</span>
                        </div>
                        <div class="detail-row-tree">
                            <div class="proto-tree">${buildProtocolTree(p)}</div>
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;

    els.tabTree.querySelectorAll('.detail-row-summary').forEach(summary => {
        summary.addEventListener('click', () => {
            const row = summary.closest('.detail-row');
            const num = Number(row.dataset.packetNumber);
            row.classList.toggle('expanded');
            if (row.classList.contains('expanded')) {
                expandedDetailRows.add(num);
            } else {
                expandedDetailRows.delete(num);
            }
        });
    });

    els.tabTree.querySelectorAll('.tree-layer-header').forEach(header => {
        header.addEventListener('click', (e) => {
            e.stopPropagation();
            header.parentElement.classList.toggle('expanded');
        });
    });

    // scroll the selected packet's row into view
    const selectedRow = els.tabTree.querySelector(`.detail-row[data-packet-number="${state.selectedPacket}"]`);
    if (selectedRow) selectedRow.scrollIntoView({ block: 'nearest' });
}

// =========================================================================
// Live capture
// =========================================================================

function startLivePolling() {
    stopLivePolling();
    livePollTimer = setInterval(loadPackets, 1500);
}

function stopLivePolling() {
    if (livePollTimer) {
        clearInterval(livePollTimer);
        livePollTimer = null;
    }
}

els.startLive.addEventListener('click', async () => {
    const interface_ = els.interfaceSelect.value;
    if (!interface_) {
        els.uploadStatus.textContent = 'Pick an interface first.';
        return;
    }

    els.uploadStatus.textContent = 'Starting live capture…';
    try {
        const res = await fetch('live.php?action=start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: interface_ }),
        });
        const data = await res.json();

        if (data.error) {
            els.uploadStatus.textContent = `Error: ${data.error}`;
            return;
        }

        els.uploadStatus.textContent = 'Live capture running…';
        els.startLive.disabled = true;
        els.stopLive.disabled = false;
        els.liveDot.classList.add('is-live');
        els.liveStatusText.textContent = 'Live';
        await loadSessions(data.session_id);
        startLivePolling();
    } catch (err) {
        els.uploadStatus.textContent = `Error: ${err.message}`;
    }
});

els.stopLive.addEventListener('click', async () => {
    try {
        const res = await fetch('live.php?action=stop', { method: 'POST' });
        const data = await res.json();

        if (data.error) {
            els.uploadStatus.textContent = `Error: ${data.error}`;
            return;
        }

        els.uploadStatus.textContent = `Live capture stopped. ${data.packet_count} packets captured.`;
        els.startLive.disabled = false;
        els.stopLive.disabled = true;
        els.liveDot.classList.remove('is-live');
        els.liveStatusText.textContent = 'Idle';
        stopLivePolling();
        loadPackets();
    } catch (err) {
        els.uploadStatus.textContent = `Error: ${err.message}`;
    }
});

// =========================================================================
// pcap upload
// =========================================================================

els.fileInput.addEventListener('change', () => {
    if (els.fileInput.files[0]) {
        els.uploadStatus.textContent = `Selected: ${els.fileInput.files[0].name}`;
    }
});

els.uploadBtn.addEventListener('click', async () => {
    const file = els.fileInput.files[0];
    if (!file) {
        els.uploadStatus.textContent = 'Choose a file first.';
        return;
    }

    els.uploadStatus.textContent = 'Uploading and parsing…';
    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch('upload.php', { method: 'POST', body: formData });
        const data = await res.json();

        if (data.error) {
            els.uploadStatus.textContent = `Error: ${data.error}`;
            return;
        }

        els.uploadStatus.textContent = `Imported ${data.packet_count} packets.`;
        await loadSessions(data.session_id);
    } catch (err) {
        els.uploadStatus.textContent = `Error: ${err.message}`;
    }
});

// =========================================================================
// Hosts + active nmap scan
// =========================================================================

els.showHosts.addEventListener('click', async () => {
    const isHidden = els.hostsPanel.hasAttribute('hidden');
    if (!isHidden) {
        els.hostsPanel.setAttribute('hidden', '');
        return;
    }
    els.firewallPanel.setAttribute('hidden', '');

    if (!state.sessionId) {
        els.uploadStatus.textContent = 'Import or capture something first.';
        return;
    }

    els.hostsPanel.removeAttribute('hidden');
    els.hostsTableBody.innerHTML = '<tr><td colspan="5">Loading hosts…</td></tr>';
    els.scanResult.innerHTML = '';

    await refreshBlockedIps();

    const res = await fetch(`api.php?action=hosts&session_id=${state.sessionId}`);
    const hosts = await res.json();

    if (hosts.error) {
        els.hostsTableBody.innerHTML = `<tr><td colspan="5">${hosts.error}</td></tr>`;
        return;
    }

    els.hostsTableBody.innerHTML = '';
    for (const h of hosts) {
        const isBlocked = blockedIps.has(h.ip);
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${h.ip}</td>
            <td>${h.packets_as_src}</td>
            <td>${h.packets_as_dst}</td>
            <td><button class="scan-btn" data-ip="${h.ip}">Scan</button></td>
            <td><button class="block-btn ${isBlocked ? 'is-blocked' : ''}" data-ip="${h.ip}">
                ${isBlocked ? 'Unblock' : 'Block'}
            </button></td>
        `;
        els.hostsTableBody.appendChild(tr);
    }

    document.querySelectorAll('#hosts-table .block-btn').forEach(btn => {
        btn.addEventListener('click', () => toggleBlock(btn.dataset.ip, btn));
    });

    document.querySelectorAll('#hosts-table .scan-btn').forEach(btn => {
        btn.addEventListener('click', () => runScan(btn.dataset.ip, btn));
    });
});

async function runScan(ip, btn) {
    btn.disabled = true;
    btn.textContent = 'Scanning…';
    els.scanResult.innerHTML = `<p>Scanning ${ip} — this can take 10-30 seconds…</p>`;

    try {
        const res = await fetch('scan.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        const data = await res.json();

        if (data.error) {
            els.scanResult.innerHTML = `<p class="scan-error">${data.error}</p>`;
            return;
        }

        const portsRows = data.ports.length
            ? data.ports.map(p => `
                <tr>
                    <td>${p.port}/${p.protocol}</td>
                    <td>${p.state}</td>
                    <td>${p.service ?? ''}</td>
                    <td>${(p.product ?? '') + (p.version ? ' ' + p.version : '')}</td>
                </tr>
            `).join('')
            : '<tr><td colspan="4">No open ports found (fast scan, top 100 ports).</td></tr>';

        const osRows = data.os_guesses.length
            ? data.os_guesses.map(o => `<li>${o.name} (${o.accuracy}% confidence)</li>`).join('')
            : '<li>No OS match (needs Administrator privileges for OS detection).</li>';

        els.scanResult.innerHTML = `
            <h3>${data.ip} — ${data.state}${data.hostname ? ' (' + data.hostname + ')' : ''}</h3>
            <table id="hosts-table"><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
                <tbody>${portsRows}</tbody>
            </table>
            <h4>OS guesses</h4>
            <ul>${osRows}</ul>
        `;
    } catch (err) {
        els.scanResult.innerHTML = `<p class="scan-error">Error: ${err.message}</p>`;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Scan';
    }
}

// =========================================================================
// Firewall (real Windows Firewall block/unblock)
// =========================================================================

async function refreshBlockedIps() {
    const res = await fetch('firewall.php?action=list');
    const data = await res.json();
    blockedIps = new Set(Array.isArray(data) ? data.map(d => d.ip) : []);
    return data;
}

async function renderFirewallPanel() {
    els.firewallTableBody.innerHTML = '<tr><td colspan="3">Loading…</td></tr>';
    const data = await refreshBlockedIps();

    if (data.error) {
        els.firewallTableBody.innerHTML = `<tr><td colspan="3">${data.error}</td></tr>`;
        return;
    }

    if (data.length === 0) {
        els.firewallTableBody.innerHTML = '<tr><td colspan="3">No IPs currently blocked.</td></tr>';
        return;
    }

    els.firewallTableBody.innerHTML = '';
    for (const entry of data) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${entry.ip}</td>
            <td>${entry.blocked_at.replace('T', ' ').split('.')[0]}</td>
            <td><button class="block-btn is-blocked" data-ip="${entry.ip}">Unblock</button></td>
        `;
        els.firewallTableBody.appendChild(tr);
    }

    els.firewallTableBody.querySelectorAll('.block-btn').forEach(btn => {
        btn.addEventListener('click', () => toggleBlock(btn.dataset.ip, btn, renderFirewallPanel));
    });
}

async function toggleBlock(ip, btn, afterRefresh = null) {
    const isCurrentlyBlocked = blockedIps.has(ip);
    const action = isCurrentlyBlocked ? 'unblock' : 'block';

    btn.disabled = true;
    btn.textContent = isCurrentlyBlocked ? 'Unblocking…' : 'Blocking…';

    try {
        const res = await fetch(`firewall.php?action=${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        const data = await res.json();

        if (data.error) {
            els.uploadStatus.textContent = `Error: ${data.error}`;
            btn.disabled = false;
            btn.textContent = isCurrentlyBlocked ? 'Unblock' : 'Block';
            return;
        }

        if (isCurrentlyBlocked) blockedIps.delete(ip); else blockedIps.add(ip);

        btn.classList.toggle('is-blocked', !isCurrentlyBlocked);
        btn.textContent = isCurrentlyBlocked ? 'Block' : 'Unblock';
        btn.disabled = false;

        if (afterRefresh) afterRefresh();
        loadPackets(); // refresh inline firewall badges in the packet table
    } catch (err) {
        els.uploadStatus.textContent = `Error: ${err.message}`;
        btn.disabled = false;
        btn.textContent = isCurrentlyBlocked ? 'Unblock' : 'Block';
    }
}

// same as toggleBlock but for the inline badge button in the packet table
async function toggleBlockBadge(ip, btn) {
    await refreshBlockedIps();
    await toggleBlock(ip, btn);
}

els.showFirewall.addEventListener('click', () => {
    const isHidden = els.firewallPanel.hasAttribute('hidden');
    if (!isHidden) {
        els.firewallPanel.setAttribute('hidden', '');
        return;
    }
    els.hostsPanel.setAttribute('hidden', '');
    els.firewallPanel.removeAttribute('hidden');
    renderFirewallPanel();
});

els.manualBlockBtn.addEventListener('click', async () => {
    const ip = els.manualBlockIp.value.trim();
    if (!ip) return;

    els.manualBlockBtn.disabled = true;
    els.manualBlockBtn.textContent = 'Blocking…';

    try {
        const res = await fetch('firewall.php?action=block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        const data = await res.json();

        if (data.error) {
            els.uploadStatus.textContent = `Error: ${data.error}`;
        } else {
            els.manualBlockIp.value = '';
            blockedIps.add(ip);
            renderFirewallPanel();
            loadPackets();
        }
    } catch (err) {
        els.uploadStatus.textContent = `Error: ${err.message}`;
    } finally {
        els.manualBlockBtn.disabled = false;
        els.manualBlockBtn.textContent = 'Block this IP';
    }
});

// =========================================================================
// Filters / pagination
// =========================================================================

els.sessionSelect.addEventListener('change', () => {
    state.sessionId = Number(els.sessionSelect.value) || null;
    state.page = 1;
    loadPackets();
});

els.applyFilters.addEventListener('click', () => {
    state.page = 1;
    loadPackets();
});

els.prevPage.addEventListener('click', () => {
    if (state.page > 1) {
        state.page -= 1;
        loadPackets();
    }
});

els.nextPage.addEventListener('click', () => {
    const totalPages = Math.max(1, Math.ceil(state.totalMatching / state.perPage));
    if (state.page < totalPages) {
        state.page += 1;
        loadPackets();
    }
});

// =========================================================================
// Terminal — live website monitor + block/unblock commands
// =========================================================================

let terminalPollTimer = null;
let terminalAfter = 0;
let blockedDomains = new Set();

function termPrint(html, cls = '') {
    const line = document.createElement('div');
    line.className = `term-line ${cls}`;
    line.innerHTML = html;
    els.terminalOutput.appendChild(line);
    els.terminalOutput.scrollTop = els.terminalOutput.scrollHeight;
}

async function refreshBlockedDomains() {
    try {
        const res = await fetch('websites.php?action=blocked');
        const data = await res.json();
        blockedDomains = new Set(Array.isArray(data) ? data.map(d => d.domain) : []);
        els.terminalBlockedCount.textContent = `${blockedDomains.size} domain${blockedDomains.size === 1 ? '' : 's'} blocked`;
        return data;
    } catch (err) {
        termPrint(`Could not reach websites.php — is it in your web folder? (${err.message})`, 'term-error');
        return [];
    }
}

async function pollTerminalLog() {
    if (!state.sessionId) {
        els.terminalStatusText.textContent = 'Watching session: none';
        els.terminalLiveDot.classList.remove('is-live');
        return;
    }

    els.terminalStatusText.textContent = `Watching session #${state.sessionId}`;
    els.terminalLiveDot.classList.toggle('is-live', livePollTimer !== null);

    let entries;
    try {
        const res = await fetch(`websites.php?action=log&session_id=${state.sessionId}&after=${terminalAfter}`);
        entries = await res.json();
    } catch (err) {
        stopTerminalPolling();
        termPrint(`Lost connection to websites.php — polling stopped. (${err.message})`, 'term-error');
        return;
    }
    if (entries && entries.error) {
        stopTerminalPolling();
        termPrint(entries.error, 'term-error');
        return;
    }
    if (!Array.isArray(entries) || entries.length === 0) return;

    for (const e of entries) {
        terminalAfter = Math.max(terminalAfter, e.packet_number);
        const time = e.captured_at.replace('T', ' ').split('.')[0];
        const statusHtml = e.blocked
            ? '<span class="term-blocked">BLOCKED</span>'
            : '<span class="term-allowed">ALLOWED</span>';
        termPrint(
            `<span class="term-time">[${time}]</span> ${statusHtml} ${e.src_ip ?? '?'} &rarr; <span class="term-domain">${e.domain}</span> <span class="term-proto">(${e.protocol})</span>`,
            e.blocked ? 'term-blocked-line' : ''
        );
    }
}

function startTerminalPolling() {
    refreshBlockedDomains();
    pollTerminalLog();
    stopTerminalPolling();
    terminalPollTimer = setInterval(pollTerminalLog, 2000);
}

function stopTerminalPolling() {
    if (terminalPollTimer) {
        clearInterval(terminalPollTimer);
        terminalPollTimer = null;
    }
}

async function runTerminalCommand(raw) {
    const trimmed = raw.trim();
    if (!trimmed) return;

    termPrint(`<span class="term-prompt-echo">netshark&gt;</span> ${trimmed}`);

    const [cmd, ...rest] = trimmed.split(/\s+/);
    const arg = rest.join(' ');

    switch (cmd.toLowerCase()) {
        case 'help':
            termPrint(
                'Commands: <span class="term-cmd">block &lt;domain&gt;</span>, ' +
                '<span class="term-cmd">unblock &lt;domain&gt;</span>, ' +
                '<span class="term-cmd">list</span> (show blocked domains), ' +
                '<span class="term-cmd">clear</span>'
            );
            break;

        case 'clear':
            els.terminalOutput.innerHTML = '';
            break;

        case 'list': {
            const data = await refreshBlockedDomains();
            if (!data.length) {
                termPrint('No domains currently blocked.');
            } else {
                data.forEach(d => termPrint(`<span class="term-domain">${d.domain}</span> — blocked at ${d.blocked_at.replace('T', ' ').split('.')[0]}`));
            }
            break;
        }

        case 'block': {
            if (!arg) { termPrint('Usage: block &lt;domain&gt;', 'term-error'); break; }
            termPrint(`Blocking ${arg}…`);
            try {
                const res = await fetch('websites.php?action=block', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: arg }),
                });
                const data = await res.json();
                if (data.error) {
                    termPrint(data.error, 'term-error');
                } else {
                    termPrint(`<span class="term-blocked">BLOCKED</span> ${arg} (and www.${arg.replace(/^www\./, '')}) — hosts file + DNS cache flushed`);
                    refreshBlockedDomains();
                }
            } catch (err) {
                termPrint(`Error: ${err.message}`, 'term-error');
            }
            break;
        }

        case 'unblock': {
            if (!arg) { termPrint('Usage: unblock &lt;domain&gt;', 'term-error'); break; }
            termPrint(`Unblocking ${arg}…`);
            try {
                const res = await fetch('websites.php?action=unblock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: arg }),
                });
                const data = await res.json();
                if (data.error) {
                    termPrint(data.error, 'term-error');
                } else {
                    termPrint(`<span class="term-allowed">UNBLOCKED</span> ${arg}`);
                    refreshBlockedDomains();
                }
            } catch (err) {
                termPrint(`Error: ${err.message}`, 'term-error');
            }
            break;
        }

        default:
            termPrint(`Unknown command: ${cmd}. Type <span class="term-cmd">help</span>.`, 'term-error');
    }
}

els.terminalInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        const value = els.terminalInput.value;
        els.terminalInput.value = '';
        runTerminalCommand(value);
    }
});

// =========================================================================
// Statistics — protocol breakdown, top talkers, traffic timeline
// =========================================================================

let protocolChartInstance = null;
let talkersChartInstance = null;
let timelineChartInstance = null;

const PROTO_COLORS = {
    TCP: '#3b82f6', UDP: '#22c55e', DNS: '#8b5cf6',
    ARP: '#eab308', ICMP: '#f97316', OTHER: '#64748b', IP: '#64748b',
};

function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDuration(seconds) {
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    const mins = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return `${mins}m ${secs}s`;
}

async function loadStatistics() {
    if (!state.sessionId) {
        els.statsSessionLabel.textContent = 'No session selected — import or capture something first.';
        return;
    }

    els.statsSessionLabel.textContent = `Session #${state.sessionId}`;

    const res = await fetch(`api.php?action=statistics&session_id=${state.sessionId}`);
    const data = await res.json();

    if (data.error) {
        els.statsSessionLabel.textContent = data.error;
        return;
    }

    els.statTotalPackets.textContent = data.total_packets.toLocaleString();
    els.statTotalBytes.textContent = formatBytes(data.total_bytes);
    els.statUniqueHosts.textContent = data.unique_hosts;
    els.statDuration.textContent = formatDuration(data.duration_seconds);

    renderProtocolChart(data.protocol_breakdown, data.total_packets);
    renderTalkersChart(data.top_talkers);
    renderTimelineChart(data.timeline);
}

function renderProtocolChart(breakdown, totalPackets) {
    const ctx = document.getElementById('protocol-chart');
    if (protocolChartInstance) protocolChartInstance.destroy();

    protocolChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: breakdown.map(b => b.protocol),
            datasets: [{
                data: breakdown.map(b => b.count),
                backgroundColor: breakdown.map(b => PROTO_COLORS[b.protocol] || '#64748b'),
                borderColor: '#131c2e',
                borderWidth: 2,
            }],
        },
        options: {
            plugins: { legend: { display: false } },
            cutout: '65%',
        },
    });

    els.protocolLegend.innerHTML = breakdown.map(b => {
        const pct = totalPackets ? ((b.count / totalPackets) * 100).toFixed(1) : '0.0';
        const color = PROTO_COLORS[b.protocol] || '#64748b';
        return `
            <tr>
                <td><span class="legend-dot" style="background:${color}"></span>${b.protocol}</td>
                <td>${b.count.toLocaleString()}</td>
                <td>${pct}%</td>
                <td>${formatBytes(b.bytes)}</td>
            </tr>
        `;
    }).join('');
}

function renderTalkersChart(talkers) {
    const ctx = document.getElementById('talkers-chart');
    if (talkersChartInstance) talkersChartInstance.destroy();

    talkersChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: talkers.map(t => t.ip),
            datasets: [{
                label: 'Packets',
                data: talkers.map(t => t.packets),
                backgroundColor: '#3b82f6',
                borderRadius: 4,
            }],
        },
        options: {
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8b9bb4' }, grid: { color: '#223049' } },
                y: { ticks: { color: '#8b9bb4' }, grid: { display: false } },
            },
        },
    });
}

function renderTimelineChart(timeline) {
    const ctx = document.getElementById('timeline-chart');
    if (timelineChartInstance) timelineChartInstance.destroy();

    timelineChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timeline.map(t => t.time),
            datasets: [{
                label: 'Packets',
                data: timeline.map(t => t.count),
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59,130,246,0.15)',
                fill: true,
                tension: 0.3,
                pointRadius: 0,
            }],
        },
        options: {
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8b9bb4', maxTicksLimit: 10 }, grid: { display: false } },
                y: { ticks: { color: '#8b9bb4' }, grid: { color: '#223049' } },
            },
        },
    });
}

els.statsRefresh.addEventListener('click', loadStatistics);

// ---- initial load ----
refreshBlockedIps().then(() => {
    loadSessions();
});
loadInterfaces();

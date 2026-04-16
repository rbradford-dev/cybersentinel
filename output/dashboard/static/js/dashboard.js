/* ================================================================
   CyberSentinel Dashboard — Client-side JavaScript
   Minimal — HTMX does most interactive work.
   ================================================================ */

// ---- Severity donut chart ----
function initSeverityChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const chartData = {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
            data: [
                data.critical || 0,
                data.high || 0,
                data.medium || 0,
                data.low || 0,
                data.info || 0,
            ],
            backgroundColor: [
                '#ff4444',
                '#ff8844',
                '#ffaa00',
                '#4488ff',
                '#64748b',
            ],
            borderColor: '#1a1d2e',
            borderWidth: 2,
            hoverOffset: 6,
        }]
    };

    return new Chart(ctx, {
        type: 'doughnut',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e2e8f0',
                        font: { family: "'JetBrains Mono', monospace", size: 11 },
                        padding: 12,
                        usePointStyle: true,
                        pointStyle: 'circle',
                    }
                },
                tooltip: {
                    backgroundColor: '#1a1d2e',
                    borderColor: '#2d3748',
                    borderWidth: 1,
                    titleColor: '#e2e8f0',
                    bodyColor: '#e2e8f0',
                    titleFont: { family: "'Inter', sans-serif", weight: '600' },
                    bodyFont: { family: "'JetBrains Mono', monospace" },
                    padding: 10,
                    cornerRadius: 6,
                }
            }
        }
    });
}

// ---- Refresh severity chart ----
let severityChart = null;

function refreshSeverityChart() {
    fetch('/api/v1/findings/stats')
        .then(r => r.json())
        .then(data => {
            if (severityChart) {
                severityChart.data.datasets[0].data = [
                    data.critical || 0,
                    data.high || 0,
                    data.medium || 0,
                    data.low || 0,
                    data.info || 0,
                ];
                severityChart.update();
            } else {
                severityChart = initSeverityChart('severity-chart', data);
            }
        })
        .catch(err => console.warn('Chart refresh error:', err));
}

// ---- SSE handler for agent output stream ----
function connectAgentStream(sessionId) {
    const outputPanel = document.getElementById('output-panel');
    const statusEl = document.getElementById('stream-status');
    if (!outputPanel) return;

    const url = sessionId
        ? `/stream/agent-output?session_id=${sessionId}`
        : '/stream/agent-output';

    const evtSource = new EventSource(url);

    const prefixMap = {
        'routing':        { cls: 'log-route', prefix: '[ROUTE]' },
        'agent_start':    { cls: 'log-start', prefix: '[START]' },
        'finding':        { cls: 'log-find',  prefix: '[FIND]' },
        'agent_complete': { cls: 'log-done',  prefix: '[DONE]' },
        'synthesis':      { cls: 'log-synth', prefix: '[SYNTH]' },
        'done':           { cls: 'log-done',  prefix: '[DONE]' },
        'error':          { cls: 'log-err',   prefix: '[ERR]' },
    };

    function appendLine(cls, text) {
        const p = document.createElement('p');
        p.className = cls;
        p.textContent = text;
        outputPanel.appendChild(p);
        scrollTerminal(outputPanel);
    }

    // Listen for each event type
    ['routing', 'agent_start', 'finding', 'agent_complete', 'synthesis', 'done', 'error'].forEach(evtType => {
        evtSource.addEventListener(evtType, function(e) {
            const data = JSON.parse(e.data);
            const info = prefixMap[evtType] || { cls: 'log-system', prefix: '[INFO]' };

            let msg = '';
            switch (evtType) {
                case 'routing':
                    msg = `${info.prefix} Intent: ${data.intent} → Agents: ${(data.agents || []).join(', ')} (${(data.confidence * 100).toFixed(0)}%)`;
                    break;
                case 'agent_start':
                    msg = `${info.prefix} ${data.agent} — ${data.task || 'processing...'}`;
                    break;
                case 'finding':
                    msg = `${info.prefix} [${(data.severity || '').toUpperCase()}] ${data.title || 'Finding'} ${data.cve_id ? '(' + data.cve_id + ')' : ''}`;
                    break;
                case 'agent_complete':
                    msg = `${info.prefix} ${data.agent} — ${data.status} | ${data.findings_count} finding(s) | ${data.execution_ms}ms`;
                    break;
                case 'synthesis':
                    msg = `${info.prefix} ${data.summary || 'Synthesizing results...'}`;
                    break;
                case 'done':
                    msg = `${info.prefix} Analysis complete. ${data.total_findings} finding(s). ${data.summary || ''}`;
                    evtSource.close();
                    if (statusEl) statusEl.textContent = 'Complete';
                    // Show results section
                    const resultsDiv = document.getElementById('query-results');
                    if (resultsDiv) resultsDiv.classList.remove('hidden');
                    break;
                case 'error':
                    msg = `${info.prefix} ${data.message || data.error || 'Unknown error'}`;
                    break;
            }
            appendLine(info.cls, msg);
        });
    });

    evtSource.onerror = function() {
        appendLine('log-err', '[ERR] SSE connection lost');
        evtSource.close();
        if (statusEl) statusEl.textContent = 'Disconnected';
    };

    if (statusEl) statusEl.textContent = 'Connected';
    return evtSource;
}

// ---- Auto-scroll terminal panel to bottom ----
function scrollTerminal(el) {
    if (!el) el = document.getElementById('output-panel');
    if (el) el.scrollTop = el.scrollHeight;
}

// ---- Format relative time ("2 minutes ago") ----
function timeAgo(isoString) {
    if (!isoString) return '—';
    const date = new Date(isoString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);

    if (seconds < 10) return 'just now';
    if (seconds < 60) return seconds + 's ago';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + 'm ago';
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + 'h ago';
    const days = Math.floor(hours / 24);
    return days + 'd ago';
}

// ---- Apply timeAgo to all elements with data-time ----
function refreshTimeAgo() {
    document.querySelectorAll('[data-time]').forEach(el => {
        el.textContent = timeAgo(el.getAttribute('data-time'));
    });
}

// ---- Copy finding to clipboard ----
function copyFinding(findingId) {
    const text = `Finding ID: ${findingId}`;
    navigator.clipboard.writeText(text).then(() => {
        // Brief visual feedback
        const btn = document.querySelector(`[data-copy="${findingId}"]`);
        if (btn) {
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = orig; }, 1500);
        }
    });
}

// ---- Export findings as JSON download ----
function exportFindings() {
    fetch('/api/v1/findings?limit=1000')
        .then(r => r.json())
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cybersentinel_findings_${new Date().toISOString().slice(0, 10)}.json`;
            a.click();
            URL.revokeObjectURL(url);
        });
}

// ---- Run Query form submission ----
function submitQuery(formEl) {
    const query = formEl.querySelector('[name="query"]').value.trim();
    const type = formEl.querySelector('[name="type"]').value;
    if (!query) return;

    // Clear previous output
    const outputPanel = document.getElementById('output-panel');
    if (outputPanel) outputPanel.innerHTML = '';

    // Hide results section
    const resultsDiv = document.getElementById('query-results');
    if (resultsDiv) resultsDiv.classList.add('hidden');

    // POST query to API
    fetch('/api/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: query, type: type })
    })
    .then(r => r.json())
    .then(data => {
        // Connect SSE with the returned session_id
        connectAgentStream(data.session_id);
    })
    .catch(err => {
        if (outputPanel) {
            const p = document.createElement('p');
            p.className = 'log-err';
            p.textContent = `[ERR] Failed to submit query: ${err.message}`;
            outputPanel.appendChild(p);
        }
    });
}

// ---- Sidebar severity update via HTMX afterSwap ----
document.addEventListener('htmx:afterSwap', function(evt) {
    // After HTMX swaps severity stats, format them
    if (evt.detail.target && evt.detail.target.id === 'sidebar-severity-inner') {
        try {
            const data = JSON.parse(evt.detail.xhr.responseText);
            evt.detail.target.innerHTML = `
                <div class="flex justify-between"><span class="text-cs-red">CRITICAL</span><span>${data.critical || 0}</span></div>
                <div class="flex justify-between"><span class="text-cs-orange">HIGH</span><span>${data.high || 0}</span></div>
                <div class="flex justify-between"><span class="text-cs-yellow">MEDIUM</span><span>${data.medium || 0}</span></div>
                <div class="flex justify-between"><span class="text-cs-blue">LOW</span><span>${data.low || 0}</span></div>
            `;
        } catch (e) { /* ignore parse errors */ }
    }
});

// ---- Init on page load ----
document.addEventListener('DOMContentLoaded', function() {
    // Refresh relative timestamps
    refreshTimeAgo();
    setInterval(refreshTimeAgo, 30000);

    // Init severity chart if canvas exists
    if (document.getElementById('severity-chart')) {
        refreshSeverityChart();
        setInterval(refreshSeverityChart, 30000);
    }
});

// Global variables and elements
let threatDistributionChart = null;

// Intercept global fetch to redirect to /login on 401 Unauthorized responses
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    try {
        const response = await originalFetch(...args);
        if (response.status === 401 && !window.location.pathname.includes('/login')) {
            window.location.href = '/login';
        }
        return response;
    } catch (e) {
        return Promise.reject(e);
    }
};

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    loadUserProfile();
    loadDashboardStats();
    loadActivityFeed();
    loadScanHistory();
    setupNavigation();
    setupFormHandlers();
});

// 1. Clock initialization
function initClock() {
    const clockEl = document.getElementById("realtime-clock");
    if (clockEl) {
        setInterval(() => {
            const date = new Date();
            clockEl.textContent = date.toTimeString().split(' ')[0];
        }, 1000);
    }
}

// 1.5. Dynamic User Profile Loader
function loadUserProfile() {
    fetch('/api/me')
        .then(res => {
            if (res.status === 401) {
                window.location.href = '/login';
                return;
            }
            return res.json();
        })
        .then(user => {
            if (!user) return;
            
            // Update username in sidebar
            const nameEl = document.getElementById("sidebar-username");
            if (nameEl) {
                nameEl.textContent = user.name.toUpperCase();
            }
            
            // Update avatar in sidebar
            const avatarEl = document.getElementById("sidebar-avatar");
            if (avatarEl) {
                if (user.avatar) {
                    avatarEl.innerHTML = `<img src="${user.avatar}" alt="${user.name}" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`;
                } else {
                    // Extract initials
                    const initials = user.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
                    avatarEl.innerHTML = `<span style="font-family: 'Orbitron', sans-serif; font-size: 0.95rem; font-weight: 800; color: var(--cyan); text-shadow: 0 0 8px var(--cyan-glow);">${initials}</span>`;
                }
            }
            
            // Update status text with dynamic provider indicator
            const statusEl = document.getElementById("sidebar-status");
            if (statusEl) {
                const providerTag = user.provider === 'google' ? 'GOOGLE SSO' : 'LOCAL SHELL';
                statusEl.innerHTML = `<span class="pulse-dot" style="background-color: ${user.provider === 'google' ? 'var(--cyan)' : 'var(--purple)'}; box-shadow: 0 0 8px ${user.provider === 'google' ? 'var(--cyan)' : 'var(--purple)'};"></span> ${providerTag}`;
            }
        })
        .catch(err => console.error("Error loading operator profile:", err));
}

// 2. Load stats from DB
function loadDashboardStats() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            document.getElementById("stat-total").textContent = data.total_scans;
            document.getElementById("stat-high").textContent = data.high_threats;
            document.getElementById("stat-medium").textContent = data.medium_threats;
            document.getElementById("stat-score").textContent = data.avg_score + "%";
            
            // Build / Update Chart
            initChart(data.low_threats, data.medium_threats, data.high_threats);
        })
        .catch(err => console.error("Error loading dashboard stats:", err));
}

// 3. Init Chart.js threat indicator
function initChart(low, medium, high) {
    const ctx = document.getElementById('threatDistributionChart');
    if (!ctx) return;
    
    if (threatDistributionChart) {
        threatDistributionChart.destroy();
    }
    
    threatDistributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low Risk', 'Medium Risk', 'High Risk'],
            datasets: [{
                data: [low || 1, medium || 0, high || 0],
                backgroundColor: [
                    '#34c759', // Green
                    '#ffcc00', // Yellow
                    '#ff3b30'  // Red
                ],
                borderWidth: 1,
                borderColor: '#1b1e2e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#8a93a6',
                        font: { family: 'Orbitron', size: 10 }
                    }
                }
            },
            cutout: '70%'
        }
    });
}

// 4. Load live activity feed logs
function loadActivityFeed() {
    const feed = document.getElementById("activity-log-feed");
    if (!feed) return;
    
    fetch('/api/activity')
        .then(res => res.json())
        .then(data => {
            feed.innerHTML = "";
            data.forEach(log => {
                const dateStr = new Date(log.timestamp * 1000).toISOString().replace('T', ' ').split('.')[0];
                let colorClass = "text-white";
                if (log.event_type === "SCAN_COMPLETED") {
                    colorClass = log.message.includes("High") ? "text-red" : log.message.includes("Medium") ? "text-yellow" : "text-green";
                } else if (log.event_type === "SYSTEM_BOOT") {
                    colorClass = "text-cyan";
                }
                
                feed.innerHTML += `<p class="${colorClass}">[${log.event_type}] [${dateStr}] ${log.message}</p>`;
            });
        })
        .catch(err => console.error("Error loading activity feed logs:", err));
}

// 5. Load scan history records
function loadScanHistory() {
    const tbody = document.getElementById("history-table-body");
    if (!tbody) return;
    
    fetch('/api/history')
        .then(res => res.json())
        .then(data => {
            tbody.innerHTML = "";
            if (data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center">No compiled intelligence logs in database.</td></tr>`;
                return;
            }
            data.forEach(scan => {
                const dateStr = new Date(scan.timestamp * 1000).toLocaleString();
                const scoreColor = scan.threat_level === "High" ? "text-red" : scan.threat_level === "Medium" ? "text-yellow" : "text-green";
                
                tbody.innerHTML += `
                    <tr>
                        <td class="text-white font-weight-bold">${scan.target}</td>
                        <td><span class="tag">${scan.scan_type}</span></td>
                        <td>${dateStr}</td>
                        <td><span class="${scoreColor} font-weight-bold">${scan.threat_score}% (${scan.threat_level})</span></td>
                        <td class="truncate-text">${scan.summary}</td>
                        <td>
                            <a href="/api/report/${scan.id}" class="btn btn-secondary border-cyan btn-sm"><i class="fa-solid fa-download"></i> PDF REPORT</a>
                        </td>
                    </tr>
                `;
            });
        })
        .catch(err => console.error("Error loading history:", err));
}

// 6. Navigation SPA logic
function setupNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    const contents = document.querySelectorAll(".tab-content");
    const titleEl = document.getElementById("current-section-title");
    
    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const section = item.getAttribute("data-section");
            
            navItems.forEach(i => i.classList.remove("active"));
            item.classList.add("active");
            
            contents.forEach(c => c.classList.remove("active"));
            document.getElementById(`section-${section}`).classList.add("active");
            
            // Set topbar title
            let title = "Operations Control Center";
            if (section === "domain") title = "Website & Domain Intelligence Module";
            else if (section === "username") title = "Identity Footprint Discovery Module";
            else if (section === "network") title = "TCP Port Sweeper & Scanner Module";
            else if (section === "ip-intel") title = "IP Geolocation & Threat Diagnostics";
            else if (section === "history") title = "Security Records Database";
            
            titleEl.textContent = title;
        });
    });
}

function switchTab(section) {
    const navItem = document.querySelector(`.nav-item[data-section="${section}"]`);
    if (navItem) {
        navItem.click();
    }
}

// 7. Core Intelligence Modules API Handlers
function setupFormHandlers() {
    
    // Website Intel Form
    const domainForm = document.getElementById("domain-recon-form");
    if (domainForm) {
        domainForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const target = document.getElementById("domain-target-input").value.trim();
            const loader = document.getElementById("domain-loader");
            const area = document.getElementById("domain-results-area");
            
            loader.classList.remove("hidden");
            area.classList.add("hidden");
            
            fetch('/api/domain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            })
            .then(res => res.json())
            .then(data => {
                loader.classList.add("hidden");
                if (data.error) {
                    alert("Error running intelligence check: " + data.error);
                    return;
                }
                
                // Display Results
                area.classList.remove("hidden");
                document.getElementById("res-domain-name").textContent = data.domain.toUpperCase();
                document.getElementById("res-domain-ip").textContent = data.ip;
                document.getElementById("res-domain-score").textContent = data.threat_score + "%";
                
                const badge = document.getElementById("res-domain-badge");
                badge.textContent = data.threat_level;
                badge.className = "threat-score-badge " + (data.threat_level === "High" ? "bg-red" : data.threat_level === "Medium" ? "bg-yellow" : "");
                
                document.getElementById("res-domain-server").textContent = data.server;
                document.getElementById("res-domain-cms").textContent = data.cms;
                document.getElementById("res-domain-tech").textContent = data.technologies.join(", ");
                
                document.getElementById("res-ssl-valid").textContent = data.ssl.valid ? "Valid / Encrypted" : "Expired / Invalid";
                document.getElementById("res-ssl-valid").className = data.ssl.valid ? "text-green" : "text-red";
                document.getElementById("res-ssl-issuer").textContent = data.ssl.issuer;
                document.getElementById("res-ssl-dates").textContent = `${data.ssl.valid_from} to ${data.ssl.valid_until}`;
                
                document.getElementById("res-whois-registrar").textContent = data.whois.registrar;
                document.getElementById("res-whois-created").textContent = data.whois.creation_date;
                document.getElementById("res-whois-expires").textContent = data.whois.expiration_date;
                document.getElementById("res-whois-emails").textContent = data.whois.emails;
                
                // Security Headers listing
                const headerList = document.getElementById("res-headers-list");
                headerList.innerHTML = "";
                for (const [hName, hDetails] of Object.entries(data.headers)) {
                    headerList.innerHTML += `
                        <div class="header-pill">
                            <div class="header-pill-left">
                                <span class="header-pill-name">${hName}</span>
                                <span class="header-pill-desc text-white">${hDetails.value}</span>
                            </div>
                            <span class="status-badge ${hDetails.status === "SECURE" ? "secure" : "warning"}">${hDetails.status}</span>
                        </div>
                    `;
                }
                
                // Reload summary statistics
                loadDashboardStats();
                loadActivityFeed();
                loadScanHistory();
            })
            .catch(err => {
                loader.classList.add("hidden");
                console.error(err);
            });
        });
    }

    // Username Intel Form
    const usernameForm = document.getElementById("username-recon-form");
    if (usernameForm) {
        usernameForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const target = document.getElementById("username-target-input").value.trim();
            const loader = document.getElementById("username-loader");
            const area = document.getElementById("username-results-area");
            const loaderSubtext = loader.querySelector("p");

            loader.classList.remove("hidden");
            area.classList.add("hidden");

            // Show different loader text for real name vs username
            const isRealName = target.includes(" ");
            if (loaderSubtext) {
                loaderSubtext.innerHTML = isRealName
                    ? `<span class="text-purple share-tech-mono">Resolving social handles for "<b>${target}</b>" via public index...</span>`
                    : `<span class="text-purple share-tech-mono">Querying public HTTP endpoints for username <b>@${target}</b>...</span>`;
            }

            fetch('/api/username', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            })
            .then(res => res.json())
            .then(data => {
                loader.classList.add("hidden");
                area.classList.remove("hidden");

                const displayLabel = data.is_real_name
                    ? data.username
                    : "@" + data.username;

                document.getElementById("res-username-target").textContent = displayLabel;
                document.getElementById("res-username-found").textContent = data.found_count;
                document.getElementById("res-username-score").textContent = data.threat_score + "%";

                const badge = document.getElementById("res-username-badge");
                badge.textContent = data.threat_level;
                badge.className = "threat-score-badge " + (data.threat_level === "High" ? "bg-red" : data.threat_level === "Medium" ? "bg-yellow" : "bg-purple");

                const list = document.getElementById("res-username-list");
                list.innerHTML = "";

                data.results.forEach(item => {
                    const found = item.status === "Found";
                    const statusClass = found ? "status-found" : "status-missing";
                    const iconClass  = found ? "fa-solid fa-square-check text-green" : "fa-solid fa-circle-xmark text-red";

                    // Show the resolved handle (e.g. leomessi) as a sub-label when searching by real name
                    const handleLabel = (data.is_real_name && item.resolved_handle)
                        ? `<span class="resolved-handle share-tech-mono">@${item.resolved_handle}</span>`
                        : "";

                    const btnHtml = found
                        ? `<a href="${item.link}" target="_blank" rel="noopener noreferrer"
                                class="btn btn-secondary border-cyan btn-sm">
                                <i class="fa-solid fa-arrow-up-right-from-square"></i> VIEW
                           </a>`
                        : `<span class="text-muted share-tech-mono" style="font-size:0.75rem;">—</span>`;

                    list.innerHTML += `
                        <div class="glass-card profile-stat-card ${found ? 'card-found' : ''}">
                            <div class="profile-card-left">
                                <span class="profile-platform">${item.platform}</span>
                                ${handleLabel}
                                <p class="${statusClass} share-tech-mono" style="margin-top:8px;">
                                    <i class="${iconClass}"></i> ${item.status.toUpperCase()}
                                </p>
                            </div>
                            <div class="profile-card-right">${btnHtml}</div>
                        </div>
                    `;
                });

                loadDashboardStats();
                loadActivityFeed();
                loadScanHistory();
            })
            .catch(err => {
                loader.classList.add("hidden");
                console.error(err);
            });
        });
    }

    // Network Port Sweeper Form
    const networkForm = document.getElementById("network-recon-form");
    if (networkForm) {
        networkForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const target = document.getElementById("network-target-input").value.trim();
            const mode = document.getElementById("network-mode-select").value;
            const loader = document.getElementById("network-loader");
            const area = document.getElementById("network-results-area");
            const logsBox = document.getElementById("network-live-logs");
            
            loader.classList.remove("hidden");
            area.classList.add("hidden");
            logsBox.innerHTML = "<p>[*] Initiating fast TCP multi-thread socket sweep...</p>";
            
            // Simulating real-time socket sweep prints
            let count = 0;
            const liveLogsArr = [
                "[*] Scanning port 21 (FTP)...",
                "[*] Scanning port 22 (SSH)...",
                "[*] Scanning port 80 (HTTP)...",
                "[*] Scanning port 443 (HTTPS)...",
                "[*] Checking port service version banner maps...",
                "[*] Structuring intelligence exposure coefficients..."
            ];
            
            const logInterval = setInterval(() => {
                if (count < liveLogsArr.length) {
                    logsBox.innerHTML += `<p class="text-cyan">${liveLogsArr[count]}</p>`;
                    logsBox.scrollTop = logsBox.scrollHeight;
                    count++;
                } else {
                    clearInterval(logInterval);
                }
            }, 400);
            
            fetch('/api/network', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target, mode: mode })
            })
            .then(res => res.json())
            .then(data => {
                clearInterval(logInterval);
                loader.classList.add("hidden");
                
                if (data.error) {
                    alert("Error scanning host: " + data.error);
                    return;
                }
                
                area.classList.remove("hidden");
                document.getElementById("res-network-target").textContent = data.target;
                document.getElementById("res-network-mode").textContent = data.scan_mode === "fast" ? "Fast Sweep" : "Deep Scan";
                document.getElementById("res-network-duration").textContent = data.duration;
                document.getElementById("res-network-score").textContent = data.threat_score + "%";
                
                const badge = document.getElementById("res-network-badge");
                badge.textContent = data.threat_level;
                badge.className = "threat-score-badge " + (data.threat_level === "High" ? "bg-red" : data.threat_level === "Medium" ? "bg-yellow" : "");
                
                const tableTbody = document.getElementById("res-network-ports-table");
                tableTbody.innerHTML = "";
                if (data.open_ports.length === 0) {
                    tableTbody.innerHTML = `<tr><td colspan="5" class="text-center text-green">All scanned ports are closed / filtered. Excellent security posture!</td></tr>`;
                } else {
                    data.open_ports.forEach(p => {
                        const riskColor = p.risk.includes("High") ? "text-red" : p.risk.includes("Medium") ? "text-yellow" : "text-cyan";
                        tableTbody.innerHTML += `
                            <tr>
                                <td class="text-white share-tech-mono font-weight-bold">Port ${p.port}</td>
                                <td><span class="tag">${p.service}</span></td>
                                <td class="truncate-text share-tech-mono">${p.banner}</td>
                                <td class="text-green font-weight-bold">Open</td>
                                <td><span class="${riskColor} font-weight-bold">${p.risk}</span></td>
                            </tr>
                        `;
                    });
                }
                
                loadDashboardStats();
                loadActivityFeed();
                loadScanHistory();
            })
            .catch(err => {
                clearInterval(logInterval);
                loader.classList.add("hidden");
                console.error(err);
            });
        });
    }

    // IP Geolocation Form
    const ipForm = document.getElementById("ip-recon-form");
    if (ipForm) {
        ipForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const target = document.getElementById("ip-target-input").value.trim();
            const loader = document.getElementById("ip-loader");
            const area = document.getElementById("ip-results-area");
            
            loader.classList.remove("hidden");
            area.classList.add("hidden");
            
            fetch('/api/ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            })
            .then(res => res.json())
            .then(data => {
                loader.classList.add("hidden");
                if (data.error) {
                    alert("IP error: " + data.error);
                    return;
                }
                
                area.classList.remove("hidden");
                document.getElementById("res-ip-address").textContent = data.ip;
                document.getElementById("res-ip-isp").textContent = data.isp;
                document.getElementById("res-ip-score").textContent = data.threat_score + "%";
                
                const badge = document.getElementById("res-ip-badge");
                badge.textContent = data.threat_level;
                badge.className = "threat-score-badge " + (data.threat_level === "High" ? "bg-red" : data.threat_level === "Medium" ? "bg-yellow" : "");
                
                document.getElementById("res-ip-country").textContent = `${data.country} (${data.country_code})`;
                document.getElementById("res-ip-city").textContent = `${data.region} / ${data.city}`;
                document.getElementById("res-ip-zip").textContent = data.zip;
                
                document.getElementById("res-ip-rdns").textContent = data.rdns;
                document.getElementById("res-ip-asn").textContent = data.asn;
                document.getElementById("res-ip-coords").textContent = `Lat: ${data.latitude} / Lon: ${data.longitude}`;
                
                loadDashboardStats();
                loadActivityFeed();
                loadScanHistory();
            })
            .catch(err => {
                loader.classList.add("hidden");
                console.error(err);
            });
        });
    }
}

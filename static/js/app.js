// ─────────────────────────────────────────────
//  Cyber ReconX — app.js
//  Fixes: hash-based SPA routing, persistent UI
// ─────────────────────────────────────────────

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

    // Restore tab from URL hash on page load (e.g. /dashboard#username)
    const hash = window.location.hash.replace('#', '');
    const validTabs = ['home', 'domain', 'username', 'network', 'ip-intel', 'image-intel', 'history'];
    if (hash && validTabs.includes(hash)) {
        _activateTab(hash, false); // false = don't push state again
    }
});

// ─── 1. CLOCK ───────────────────────────────
function initClock() {
    const clockEl = document.getElementById("realtime-clock");
    if (clockEl) {
        const tick = () => { clockEl.textContent = new Date().toTimeString().split(' ')[0]; };
        tick();
        setInterval(tick, 1000);
    }
}

// ─── 1.5. USER PROFILE ──────────────────────
function loadUserProfile() {
    fetch('/api/me')
        .then(res => {
            if (res.status === 401) { window.location.href = '/login'; return; }
            return res.json();
        })
        .then(user => {
            if (!user) return;

            const nameEl = document.getElementById("sidebar-username");
            if (nameEl) nameEl.textContent = user.name.toUpperCase();

            const avatarEl = document.getElementById("sidebar-avatar");
            if (avatarEl) {
                if (user.avatar) {
                    avatarEl.innerHTML = `<img src="${user.avatar}" alt="${user.name}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
                } else {
                    const initials = user.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
                    avatarEl.innerHTML = `<span style="font-family:'Orbitron',sans-serif;font-size:0.95rem;font-weight:800;color:var(--cyan);text-shadow:0 0 8px var(--cyan-glow);">${initials}</span>`;
                }
            }

            const statusEl = document.getElementById("sidebar-status");
            if (statusEl) {
                const providerTag = user.provider === 'google' ? 'GOOGLE SSO' : 'LOCAL SHELL';
                const color = user.provider === 'google' ? 'var(--cyan)' : 'var(--purple)';
                statusEl.innerHTML = `<span class="pulse-dot" style="background-color:${color};box-shadow:0 0 8px ${color};"></span> ${providerTag}`;
            }
        })
        .catch(err => console.error("Error loading operator profile:", err));
}

// ─── 2. STATS ───────────────────────────────
function loadDashboardStats() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            document.getElementById("stat-total").textContent = data.total_scans;
            document.getElementById("stat-high").textContent = data.high_threats;
            document.getElementById("stat-medium").textContent = data.medium_threats;
            document.getElementById("stat-score").textContent = data.avg_score + "%";
            initChart(data.low_threats, data.medium_threats, data.high_threats);
        })
        .catch(err => console.error("Error loading dashboard stats:", err));
}

// ─── 3. CHART ───────────────────────────────
function initChart(low, medium, high) {
    const ctx = document.getElementById('threatDistributionChart');
    if (!ctx) return;
    if (threatDistributionChart) threatDistributionChart.destroy();

    threatDistributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low Risk', 'Medium Risk', 'High Risk'],
            datasets: [{
                data: [low || 1, medium || 0, high || 0],
                backgroundColor: ['#34c759', '#ffcc00', '#ff3b30'],
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
                    labels: { color: '#8a93a6', font: { family: 'Orbitron', size: 10 } }
                }
            },
            cutout: '70%'
        }
    });
}

// ─── 4. ACTIVITY FEED ───────────────────────
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

// ─── 5. SCAN HISTORY ────────────────────────
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
                        <td>${dateStr}</td>
                        <td><span class="tag">${scan.scan_type}</span></td>
                        <td class="text-white font-weight-bold">${scan.target}</td>
                        <td><span class="${scoreColor} font-weight-bold">${scan.threat_score}%</span></td>
                        <td><span class="${scoreColor} font-weight-bold">${scan.threat_level}</span></td>
                        <td><a href="/api/report/${scan.id}" class="btn btn-secondary border-cyan btn-sm"><i class="fa-solid fa-download"></i> PDF REPORT</a></td>
                    </tr>`;
            });
        })
        .catch(err => console.error("Error loading history:", err));
}

// ─── 6. NAVIGATION (Hash-based SPA routing) ─
const SECTION_TITLES = {
    home:      "Operations Control Center",
    domain:    "Website & Domain Intelligence Module",
    username:  "Identity Footprint Discovery Module",
    network:   "TCP Port Sweeper & Scanner Module",
    "ip-intel": "IP Geolocation & Threat Diagnostics",
    "image-intel": "AI-Powered Reverse Image Investigation Module",
    history:   "Security Records Database"
};

/**
 * Core tab-activation function.
 * @param {string} section  - Tab key e.g. "domain"
 * @param {boolean} pushState - Whether to push a new history entry (default true)
 */
function _activateTab(section, pushState = true) {
    const navItems = document.querySelectorAll(".nav-item");
    const contents = document.querySelectorAll(".tab-content");
    const titleEl  = document.getElementById("current-section-title");

    navItems.forEach(i => i.classList.remove("active"));
    const activeNav = document.querySelector(`.nav-item[data-section="${section}"]`);
    if (activeNav) activeNav.classList.add("active");

    contents.forEach(c => c.classList.remove("active"));
    const activeSection = document.getElementById(`section-${section}`);
    if (activeSection) activeSection.classList.add("active");

    if (titleEl) titleEl.textContent = SECTION_TITLES[section] || "Operations Control Center";

    // Update URL hash WITHOUT causing a page reload
    if (pushState) {
        history.pushState({ tab: section }, '', `#${section}`);
    }
}

function setupNavigation() {
    const navItems = document.querySelectorAll(".nav-item");

    navItems.forEach(item => {
        item.addEventListener("click", e => {
            e.preventDefault();
            const section = item.getAttribute("data-section");
            _activateTab(section);
        });
    });

    // Handle browser back / forward buttons
    window.addEventListener("popstate", event => {
        const tab = (event.state && event.state.tab) || 'home';
        _activateTab(tab, false); // Already in history, don't push again
    });
}

// Public helper used by Quick Tool cards (onclick="switchTab('domain')")
function switchTab(section) {
    _activateTab(section);
}

// ─── 7. FORM HANDLERS ───────────────────────
function setupFormHandlers() {

    // Website Intel
    const domainForm = document.getElementById("domain-recon-form");
    if (domainForm) {
        domainForm.addEventListener("submit", e => {
            e.preventDefault();
            const target  = document.getElementById("domain-target-input").value.trim();
            const loader  = document.getElementById("domain-loader");
            const area    = document.getElementById("domain-results-area");

            loader.classList.remove("hidden");
            area.classList.add("hidden");

            fetch('/api/domain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            })
            .then(res => res.json())
            .then(data => {
                loader.classList.add("hidden");
                if (data.error) { alert("Error: " + data.error); return; }
                renderDomainResults(data);
                area.classList.remove("hidden");
                loadDashboardStats();
            })
            .catch(() => { loader.classList.add("hidden"); alert("Connection error."); });
        });
    }

    // Username / Identity
    const usernameForm = document.getElementById("username-recon-form");
    if (usernameForm) {
        usernameForm.addEventListener("submit", e => {
            e.preventDefault();
            const target  = document.getElementById("username-target-input").value.trim();
            const loader  = document.getElementById("username-loader");
            const area    = document.getElementById("username-results-area");
            const loaderP = loader.querySelector("p.text-purple");

            loader.classList.remove("hidden");
            area.classList.add("hidden");

            if (loaderP) {
                const hasSpace = target.includes(' ');
                loaderP.textContent = hasSpace
                    ? "Resolving real name to handles via Wikidata..."
                    : "Scanning platforms for username footprint...";
            }

            fetch('/api/username', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            })
            .then(res => res.json())
            .then(data => {
                loader.classList.add("hidden");
                if (data.error) { alert("Error: " + data.error); return; }
                renderUsernameResults(data);
                area.classList.remove("hidden");
                loadDashboardStats();
            })
            .catch(() => { loader.classList.add("hidden"); alert("Connection error."); });
        });
    }

    // Port Scanner
    const networkForm = document.getElementById("network-recon-form");
    if (networkForm) {
        networkForm.addEventListener("submit", e => {
            e.preventDefault();
            const target = document.getElementById("network-target-input").value.trim();
            const mode   = document.getElementById("network-mode-select").value;
            const loader = document.getElementById("network-loader");
            const area   = document.getElementById("network-results-area");
            const logs   = document.getElementById("network-live-logs");

            loader.classList.remove("hidden");
            area.classList.add("hidden");
            logs.innerHTML = "<p>[*] Initialising thread pool...</p>";

            const liveInterval = setInterval(() => {
                const msgs = ["[*] Probing socket endpoints...", "[*] Checking TCP handshake...", "[*] Awaiting banner response...", "[*] Mapping service fingerprints..."];
                logs.innerHTML += `<p>${msgs[Math.floor(Math.random() * msgs.length)]}</p>`;
                logs.scrollTop = logs.scrollHeight;
            }, 800);

            fetch('/api/network', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, mode })
            })
            .then(res => res.json())
            .then(data => {
                clearInterval(liveInterval);
                loader.classList.add("hidden");
                if (data.error) { alert("Error: " + data.error); return; }
                renderNetworkResults(data);
                area.classList.remove("hidden");
                loadDashboardStats();
            })
            .catch(() => { clearInterval(liveInterval); loader.classList.add("hidden"); alert("Connection error."); });
        });
    }

    // IP Geolocation
    const ipForm = document.getElementById("ip-recon-form");
    if (ipForm) {
        ipForm.addEventListener("submit", e => {
            e.preventDefault();
            const target = document.getElementById("ip-target-input").value.trim();
            const loader = document.getElementById("ip-loader");
            const area   = document.getElementById("ip-results-area");

            loader.classList.remove("hidden");
            area.classList.add("hidden");

            fetch('/api/ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            })
            .then(res => res.json())
            .then(data => {
                loader.classList.add("hidden");
                if (data.error) { alert("Error: " + data.error); return; }
                renderIpResults(data);
                area.classList.remove("hidden");
                loadDashboardStats();
            })
            .catch(() => { loader.classList.add("hidden"); alert("Connection error."); });
        });
    }

    // History search filter
    const historySearch = document.getElementById("history-search-input");
    if (historySearch) {
        historySearch.addEventListener("input", () => {
            const q = historySearch.value.toLowerCase();
            document.querySelectorAll("#history-table-body tr").forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
            });
        });
    }

    // AI-Powered Reverse Image Intel Drag & Drop / Upload Handler
    const dropZone = document.getElementById("image-drop-zone");
    const fileInput = document.getElementById("image-file-input");
    const resetBtn = document.getElementById("reset-upload-btn");
    const imageForm = document.getElementById("image-recon-form");
    const uploadArea = document.getElementById("upload-preview-area");
    const previewImg = document.getElementById("preview-image");
    const filenameTxt = document.getElementById("preview-filename-txt");
    const filesizeTxt = document.getElementById("preview-filesize-txt");
    
    if (dropZone && fileInput) {
        // Trigger click event on dropZone to open file dialog
        dropZone.addEventListener("click", () => {
            fileInput.click();
        });
        
        // Highlight drag area on dragover
        dropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropZone.classList.add("dragover");
        });
        
        // Remove highlight on dragleave
        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("dragover");
        });
        
        // Handle file drop
        dropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropZone.classList.remove("dragover");
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                handleFileSelect(files[0]);
            }
        });
        
        // Handle native file selection
        fileInput.addEventListener("change", () => {
            if (fileInput.files.length > 0) {
                handleFileSelect(fileInput.files[0]);
            }
        });
    }
    
    function handleFileSelect(file) {
        if (!file) return;
        
        const ext = file.name.split('.').pop().toLowerCase();
        const allowed = ['jpg', 'jpeg', 'png', 'webp'];
        if (!allowed.includes(ext)) {
            alert("File type not supported. Allowed formats: PNG, JPG, JPEG, WEBP");
            return;
        }
        
        filenameTxt.textContent = file.name;
        filesizeTxt.textContent = `${(file.size / 1024).toFixed(2)} KB`;
        
        const reader = new FileReader();
        reader.onload = (e) => {
            previewImg.src = e.target.result;
            dropZone.classList.add("hidden");
            uploadArea.classList.remove("hidden");
        };
        reader.readAsDataURL(file);
    }
    
    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            imageForm.reset();
            dropZone.classList.remove("hidden");
            uploadArea.classList.add("hidden");
            previewImg.src = "";
            filenameTxt.textContent = "filename.jpg";
            filesizeTxt.textContent = "0.0 KB";
        });
    }
    
    if (imageForm) {
        imageForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const file = fileInput.files[0];
            if (!file) return;
            
            const loader = document.getElementById("image-loader");
            const area = document.getElementById("image-results-area");
            const progress = document.getElementById("image-progress-bar");
            const logs = document.getElementById("image-live-logs");
            
            loader.classList.remove("hidden");
            area.classList.add("hidden");
            
            progress.style.width = "0%";
            logs.innerHTML = "<p class='text-cyan'>[*] Initializing target visual grid telemetry...</p>";
            
            let step = 0;
            const logSteps = [
                { percent: 15, msg: "[*] Opening image container and auditing file integrity...", color: "text-white" },
                { percent: 30, msg: "[*] Processing 64-bit Difference Hash (dHash) visual fingerprint...", color: "text-green" },
                { percent: 50, msg: "[*] Hashing visual pixels completed. Visual Key generated...", color: "text-cyan" },
                { percent: 70, msg: "[*] Scanning EXIF hardware parameters and location metadata...", color: "text-yellow" },
                { percent: 85, msg: "[*] Querying public OSINT domain indexes and reverse lookup databases...", color: "text-purple" },
                { percent: 95, msg: "[*] Generating threat reports and calculating remediation scores...", color: "text-white" }
            ];
            
            const logInterval = setInterval(() => {
                if (step < logSteps.length) {
                    const s = logSteps[step];
                    progress.style.width = `${s.percent}%`;
                    logs.innerHTML += `<p class="${s.color}">${s.msg}</p>`;
                    logs.scrollTop = logs.scrollHeight;
                    step++;
                }
            }, 500);
            
            const formData = new FormData();
            formData.append("image", file);
            
            fetch("/api/reverse-image", {
                method: "POST",
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                clearInterval(logInterval);
                if (data.error) {
                    loader.classList.add("hidden");
                    alert("Error: " + data.error);
                    return;
                }
                
                progress.style.width = "100%";
                logs.innerHTML += "<p class='text-green'>[✓] Reverse Image Investigation complete. Loading results...</p>";
                logs.scrollTop = logs.scrollHeight;
                
                setTimeout(() => {
                    loader.classList.add("hidden");
                    renderImageResults(data);
                    area.classList.remove("hidden");
                    loadDashboardStats();
                    loadScanHistory();
                }, 400);
            })
            .catch((err) => {
                clearInterval(logInterval);
                loader.classList.add("hidden");
                alert("Connection error occurred during reverse image scan.");
                console.error(err);
            });
        });
    }
}

// ─── 8. RESULT RENDERERS ────────────────────

function renderDomainResults(data) {
    setText("res-domain-name",   data.domain || "-");
    setText("res-domain-ip",     data.ip || "Unresolved");
    setText("res-domain-server", data.server || "Unknown");
    setText("res-domain-cms",    data.cms || "Not Detected");
    setText("res-domain-tech",   Array.isArray(data.technologies) ? data.technologies.join(", ") : (data.technologies || "-"));
    setText("res-ssl-valid",     data.ssl_valid ? "✓ Valid" : "✗ Invalid / None");
    setText("res-ssl-issuer",    data.ssl_issuer || "-");
    setText("res-ssl-dates",     data.ssl_dates || "-");
    setText("res-whois-registrar", data.registrar || "-");
    setText("res-whois-created",   data.creation_date || "-");
    setText("res-whois-expires",   data.expiration_date || "-");
    setText("res-whois-emails",    Array.isArray(data.emails) ? data.emails.join(", ") : (data.emails || "None disclosed"));

    const badge = document.getElementById("res-domain-badge");
    const score = document.getElementById("res-domain-score");
    if (badge) { badge.textContent = data.threat_level || "LOW"; setBadgeColor(badge, data.threat_level); }
    if (score) score.textContent = (data.threat_score || 0) + "%";

    const headersList = document.getElementById("res-headers-list");
    if (headersList && data.security_headers) {
        headersList.innerHTML = "";
        data.security_headers.forEach(h => {
            headersList.innerHTML += `
                <div class="header-pill ${h.present ? 'secure' : 'warning'}">
                    <div class="header-pill-left">
                        <span class="header-pill-name">${h.header}</span>
                        <span class="header-pill-desc">${h.description || ""}</span>
                    </div>
                    <span class="status-badge ${h.present ? 'secure' : 'warning'}">${h.present ? "ACTIVE" : "MISSING"}</span>
                </div>`;
        });
    }
}

function renderUsernameResults(data) {
    setText("res-username-target", data.username || "-");
    setText("res-username-found",  data.found_count || 0);

    const badge = document.getElementById("res-username-badge");
    const score = document.getElementById("res-username-score");
    if (badge) { badge.textContent = data.threat_level || "LOW"; setBadgeColor(badge, data.threat_level); }
    if (score) score.textContent = (data.threat_score || 0) + "%";

    const list = document.getElementById("res-username-list");
    if (list && data.results) {
        list.innerHTML = "";
        data.results.forEach(r => {
            const isFound  = r.status === "Found";
            const handle   = r.resolved_handle ? `<span class="resolved-handle">@${r.resolved_handle}</span>` : "";
            const linkHtml = isFound
                ? `<a href="${r.link}" target="_blank" rel="noopener noreferrer" class="status-found"><i class="fa-solid fa-arrow-up-right-from-square"></i> View Profile</a>`
                : `<span class="status-missing"><i class="fa-solid fa-xmark"></i> ${r.status}</span>`;

            list.innerHTML += `
                <div class="glass-card profile-stat-card ${isFound ? 'card-found' : ''}">
                    <div class="profile-card-left">
                        <span class="profile-platform">${r.platform}</span>
                        ${handle}
                    </div>
                    <div class="profile-card-right">${linkHtml}</div>
                </div>`;
        });
    }
}

function renderNetworkResults(data) {
    setText("res-network-target",   data.target || "-");
    setText("res-network-mode",     data.scan_mode || "-");
    setText("res-network-duration", data.duration || "0");

    const badge = document.getElementById("res-network-badge");
    const score = document.getElementById("res-network-score");
    if (badge) { badge.textContent = data.threat_level || "LOW"; setBadgeColor(badge, data.threat_level); }
    if (score) score.textContent = (data.threat_score || 0) + "%";

    const tbody = document.getElementById("res-network-ports-table");
    if (tbody && data.open_ports) {
        tbody.innerHTML = "";
        if (data.open_ports.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center">No open ports detected.</td></tr>`;
        } else {
            data.open_ports.forEach(p => {
                const riskClass = p.risk === "High" ? "text-red" : p.risk === "Medium" ? "text-yellow" : "text-green";
                tbody.innerHTML += `
                    <tr>
                        <td class="text-cyan font-weight-bold">${p.port}</td>
                        <td>${p.service || "Unknown"}</td>
                        <td>${p.banner || "-"}</td>
                        <td><span class="text-green"><i class="fa-solid fa-circle-check"></i> Open</span></td>
                        <td><span class="${riskClass}">${p.risk || "Low"}</span></td>
                    </tr>`;
            });
        }
    }
}

function renderIpResults(data) {
    setText("res-ip-address",  data.ip || "-");
    setText("res-ip-isp",      data.isp || "-");
    setText("res-ip-isp2",     data.isp || "-");
    setText("res-ip-country",  `${data.country || "-"} (${data.country_code || "?"})`);
    setText("res-ip-city",     `${data.region || "-"} / ${data.city || "-"}`);
    setText("res-ip-zip",      data.postal || "-");
    setText("res-ip-rdns",     data.rdns || "-");
    setText("res-ip-timezone", data.timezone || "-");
    setText("res-ip-coords",   data.lat && data.lon ? `${data.lat}, ${data.lon}` : "-");
    setText("res-ip-asn",      data.asn || "-");
    setText("res-ip-org",      data.org || "-");
    setText("res-ip-vpn",      data.is_proxy ? "⚠ Proxy / VPN Detected" : "Clean — No proxy detected");

    const badge = document.getElementById("res-ip-badge");
    const score = document.getElementById("res-ip-score");
    if (badge) { badge.textContent = data.threat_level || "LOW"; setBadgeColor(badge, data.threat_level); }
    if (score) score.textContent = (data.threat_score || 0) + "%";
}

function renderImageResults(data) {
    const thumbImg = document.getElementById("res-image-thumb");
    if (thumbImg) thumbImg.src = data.image_url || "";
    
    setText("res-image-filename", data.filename || "payload.jpg");
    setText("res-image-hash", data.fingerprint || "0000000000000000");
    setText("res-image-duration", data.duration !== undefined ? data.duration.toFixed(3) : "0.000");
    
    const threatBadge = document.getElementById("res-image-threat-badge");
    const threatScore = document.getElementById("res-image-threat-score");
    if (threatBadge) {
        threatBadge.textContent = data.threat_level || "LOW";
        setBadgeColor(threatBadge, data.threat_level);
    }
    if (threatScore) threatScore.textContent = (data.threat_score || 0) + "%";
    
    const intelBadge = document.getElementById("res-image-intel-badge");
    const intelScore = document.getElementById("res-image-intel-score");
    if (intelBadge) {
        const iScore = data.intelligence_score || 0;
        let intelLevel = "EXCELLENT";
        if (iScore < 45) intelLevel = "CRITICAL";
        else if (iScore < 70) intelLevel = "FAIR";
        
        intelBadge.textContent = intelLevel;
        intelBadge.className = "threat-score-badge";
        if (intelLevel === "CRITICAL") intelBadge.classList.add("bg-red");
        else if (intelLevel === "FAIR") intelBadge.classList.add("bg-yellow");
        else intelBadge.classList.add("bg-cyan");
    }
    if (intelScore) intelScore.textContent = (data.intelligence_score || 0) + "%";
    
    const gpsAlert = document.getElementById("gps-exposure-alert");
    const gpsAlertText = document.getElementById("gps-alert-text");
    if (gpsAlert) {
        if (data.metadata && data.metadata.gps_latitude !== null) {
            gpsAlert.classList.remove("hidden");
            if (gpsAlertText) {
                gpsAlertText.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <strong>CRITICAL OPSEC TELEMETRY EXPOSURE:</strong> Active GPS coordinates detected inside image headers (${data.metadata.gps_coords}). Physical location exposure hazard mapped.`;
            }
        } else {
            gpsAlert.classList.add("hidden");
        }
    }
    
    if (data.metadata) {
        setText("res-exif-make", data.metadata.camera_make || "N/A");
        setText("res-exif-model", data.metadata.camera_model || "N/A");
        setText("res-exif-date", data.metadata.timestamp || "N/A");
        setText("res-exif-software", data.metadata.software || "N/A");
        setText("res-exif-fnumber", data.metadata.f_number || "N/A");
        setText("res-exif-shutter", data.metadata.exposure_time || "N/A");
        setText("res-exif-iso", data.metadata.iso || "N/A");
        
        setText("res-file-size", data.metadata.file_size || "N/A");
        setText("res-file-dimensions", data.metadata.resolution || "N/A");
        setText("res-file-format", data.metadata.format || "N/A");
        setText("res-file-mode", data.metadata.mode || "N/A");
        setText("res-gps-coords", data.metadata.gps_coords || "N/A");
        
        const gpsLink = document.getElementById("res-gps-link");
        const gpsNoLink = document.getElementById("res-gps-nolink");
        if (data.metadata.gps_latitude !== null && data.metadata.gps_longitude !== null) {
            if (gpsLink) {
                gpsLink.href = `https://www.google.com/maps/search/?api=1&query=${data.metadata.gps_latitude},${data.metadata.gps_longitude}`;
                gpsLink.classList.remove("hidden");
            }
            if (gpsNoLink) gpsNoLink.classList.add("hidden");
        } else {
            if (gpsLink) gpsLink.classList.add("hidden");
            if (gpsNoLink) gpsNoLink.classList.remove("hidden");
        }
    }
    
    const matchList = document.getElementById("res-match-list");
    if (matchList) {
        matchList.innerHTML = "";
        if (!data.matches || data.matches.length === 0) {
            matchList.innerHTML = `<div class="text-center share-tech-mono" style="padding:15px; color:rgba(255,255,255,0.3);">No visual similarities resolved in public datasets.</div>`;
        } else {
            data.matches.forEach(m => {
                const badgeClass = m.match_type === "Exact Match" 
                    ? "match-type-exact" 
                    : m.match_type === "High Similarity" 
                        ? "match-type-high" 
                        : "match-type-partial";
                        
                const fillClass = m.match_type === "Exact Match"
                    ? "bg-green-fill"
                    : m.match_type === "High Similarity"
                        ? "bg-yellow-fill"
                        : "bg-cyan-fill";
                
                const cardHtml = `
                    <div class="match-card">
                        <div class="match-card-header">
                            <span class="match-category-tag">${m.category.toUpperCase()}</span>
                            <span class="match-type-badge ${badgeClass}">${m.match_type.toUpperCase()}</span>
                        </div>
                        <div class="match-details-body">
                            <div class="match-thumb-preview">
                                <img src="${m.thumbnail}" alt="${m.domain} Visual Match" class="match-thumb-img">
                            </div>
                            <div class="match-details-left">
                                <div class="match-source-title">${m.source_name}</div>
                                <div class="match-summary-text">${m.summary}</div>
                                <div class="match-recon-suggestion">
                                    <span class="suggestion-label"><i class="fa-solid fa-fingerprint text-purple"></i> OSINT RECON SUGGESTION:</span>
                                    <p class="suggestion-text">${m.recon_suggestion}</p>
                                </div>
                                <div class="match-meta-info">
                                    <span><i class="fa-solid fa-globe text-cyan"></i> ${m.domain}</span>
                                    <span><i class="fa-solid fa-clock text-purple"></i> First Detected: ${m.timestamp}</span>
                                    <span><i class="fa-solid fa-triangle-exclamation text-yellow"></i> Host Risk: ${m.risk}</span>
                                </div>
                            </div>
                            <div class="match-details-right">
                                <div class="match-confidence-container">
                                    <div class="match-confidence-txt">Confidence: ${m.confidence}%</div>
                                    <div class="match-bar-container">
                                        <div class="match-bar-fill ${fillClass}" style="width: ${m.confidence}%"></div>
                                    </div>
                                </div>
                                <a href="${m.url}" target="_blank" rel="noopener noreferrer" class="btn btn-primary btn-sm border-cyan btn-glow" style="font-size:0.75rem; padding: 6px 12px; margin-top:8px; width:100%; justify-content:center;"><i class="fa-solid fa-arrow-up-right-from-square"></i> Explore Source</a>
                            </div>
                        </div>
                    </div>`;
                matchList.innerHTML += cardHtml;
            });
        }
    }
}

// ─── UTILITIES ──────────────────────────────

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function setBadgeColor(el, level) {
    el.className = el.className.replace(/\bbg-\w+\b/g, '').trim();
    if (level === "High")   el.classList.add("bg-red");
    else if (level === "Medium") el.classList.add("bg-yellow");
    else el.classList.add("bg-cyan");
}

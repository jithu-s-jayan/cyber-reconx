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
    const validTabs = ['home', 'domain', 'username', 'network', 'ip-intel', 'image', 'history'];
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
                let badgeClass = "badge-info";
                if (scan.threat_level === "High") badgeClass = "badge-danger";
                else if (scan.threat_level === "Medium") badgeClass = "badge-warning";
                
                tbody.innerHTML += `
                    <tr>
                        <td class="text-white font-weight-bold">${scan.target}</td>
                        <td><span class="badge ${badgeClass}">${scan.scan_type}</span></td>
                        <td class="mono-text" style="font-size:0.82rem;">${dateStr}</td>
                        <td><span class="badge ${badgeClass}">${scan.threat_level} (${scan.threat_score}%)</span></td>
                        <td class="text-white" style="font-size:0.82rem; max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${scan.summary || ''}">${scan.summary || '-'}</td>
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
    "image":   "AI-Powered Reverse Image Investigation Module",
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

    // Phone Intel
    const phoneForm = document.getElementById("phone-recon-form");
    if (phoneForm) {
        phoneForm.addEventListener("submit", e => {
            e.preventDefault();
            const target = document.getElementById("phone-target-input").value.trim();
            const loader = document.getElementById("phone-loader");
            const area   = document.getElementById("phone-results-area");

            loader.classList.remove("hidden");
            area.classList.add("hidden");

            fetch('/api/phone', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            })
            .then(res => res.json())
            .then(data => {
                loader.classList.add("hidden");
                if (data.error) { alert("Error: " + data.error); return; }
                renderPhoneResults(data);
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
    
    let currentSelectedFile = null;
    
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
                currentSelectedFile = files[0];
                handleFileSelect(files[0]);
            }
        });
        
        // Handle native file selection
        fileInput.addEventListener("change", () => {
            if (fileInput.files.length > 0) {
                currentSelectedFile = fileInput.files[0];
                handleFileSelect(fileInput.files[0]);
            }
        });
    }
    
    function handleFileSelect(file) {
        if (!file) return;
        
        // Reset and clear any previous validation failures
        const errorMsg = document.getElementById("dropzone-error-msg");
        if (errorMsg) {
            errorMsg.remove();
        }
        dropZone.classList.remove("pulse-red-border", "wiggle");
        
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
            currentSelectedFile = null;
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
            const file = currentSelectedFile || fileInput.files[0];
            if (!file) {
                // Pulse drop zone neon-red, play wiggle animation, and show error log in drop zone
                dropZone.classList.add("pulse-red-border", "wiggle");
                let validationError = document.getElementById("dropzone-error-msg");
                if (!validationError) {
                    validationError = document.createElement("p");
                    validationError.id = "dropzone-error-msg";
                    validationError.style.color = "var(--neon-red)";
                    validationError.style.marginTop = "15px";
                    validationError.style.fontFamily = "'JetBrains Mono', monospace";
                    validationError.style.fontSize = "0.85rem";
                    validationError.style.fontWeight = "bold";
                    dropZone.appendChild(validationError);
                }
                validationError.textContent = "* ERROR: Target visual node payload not loaded. Please select or drop an image file first. *";
                
                // Clear wiggle animation class after it completes so it can be re-triggered
                setTimeout(() => {
                    dropZone.classList.remove("wiggle");
                }, 800);
                return;
            }
            
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
    
    if (data.ssl) {
        setText("res-ssl-valid",     data.ssl.valid ? "\u2714 Valid" : "\u274C Invalid / None");
        setText("res-ssl-issuer",    data.ssl.issuer || "-");
        setText("res-ssl-dates",     (data.ssl.valid_from && data.ssl.valid_until) ? `${data.ssl.valid_from} to ${data.ssl.valid_until}` : "-");
    } else {
        setText("res-ssl-valid",     "-");
        setText("res-ssl-issuer",    "-");
        setText("res-ssl-dates",     "-");
    }

    if (data.whois) {
        setText("res-whois-registrar", data.whois.registrar || "-");
        setText("res-whois-created",   data.whois.creation_date || "-");
        setText("res-whois-expires",   data.whois.expiration_date || "-");
        setText("res-whois-emails",    Array.isArray(data.whois.emails) ? data.whois.emails.join(", ") : (data.whois.emails || "None disclosed"));
    } else {
        setText("res-whois-registrar", "-");
        setText("res-whois-created",   "-");
        setText("res-whois-expires",   "-");
        setText("res-whois-emails",    "-");
    }

    const badge = document.getElementById("res-domain-badge");
    const score = document.getElementById("res-domain-score");
    if (badge) { badge.textContent = data.threat_level || "LOW"; setBadgeColor(badge, data.threat_level); }
    if (score) score.textContent = (data.threat_score || 0) + "%";

    const headersList = document.getElementById("res-headers-list");
    if (headersList && data.headers) {
        headersList.innerHTML = "";
        Object.entries(data.headers).forEach(([headerName, h]) => {
            headersList.innerHTML += `
                <div class="header-pill ${h.present ? 'secure' : 'warning'}">
                    <div class="header-pill-left">
                        <span class="header-pill-name">${headerName}</span>
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
            
            let lastActive = "";
            if (r.last_active) {
                if (r.last_active === "Private") {
                    lastActive = `<span class="badge" style="font-size: 0.7rem; margin-top:4px; display:inline-block; background:rgba(255,255,255,0.1); color:#aaa;"><i class="fa-solid fa-lock" style="margin-right:3px;"></i>Last Active: Private</span>`;
                } else {
                    lastActive = `<span class="badge badge-info" style="font-size: 0.7rem; margin-top:4px; display:inline-block;"><i class="fa-regular fa-clock" style="margin-right:3px;"></i>Last Active: ${r.last_active}</span>`;
                }
            }
            
            list.innerHTML += `
                <div class="glass-card profile-stat-card ${isFound ? 'card-found' : ''}">
                    <div class="profile-card-left" style="display:flex; flex-direction:column; align-items:flex-start;">
                        <div>
                            <span class="profile-platform">${r.platform}</span>
                            ${handle}
                        </div>
                        ${lastActive}
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

function renderPhoneResults(data) {
    setText("res-phone-number",  data.formatted || "-");
    setText("res-phone-carrier", data.carrier || "Unknown Network");
    setText("res-phone-line",    data.line_type || "Unknown Type");
    setText("res-phone-location",data.location || "Unknown Location");
    setText("res-phone-country-code", data.country_code || "-");
    setText("res-phone-network", data.carrier || "Unknown Network");
    setText("res-phone-timezone",data.timezones || "-");

    const badge = document.getElementById("res-phone-badge");
    const score = document.getElementById("res-phone-score");
    if (badge) { badge.textContent = data.threat_level || "LOW"; setBadgeColor(badge, data.threat_level); }
    if (score) score.textContent = (data.threat_score || 0) + "%";

    const warningsArea = document.getElementById("phone-warnings-area");
    const warningsList = document.getElementById("res-phone-warnings");
    warningsList.innerHTML = "";
    if (data.warnings && data.warnings.length > 0) {
        warningsArea.classList.remove("hidden");
        data.warnings.forEach(w => {
            const li = document.createElement("li");
            li.textContent = w;
            li.style.marginBottom = "5px";
            warningsList.appendChild(li);
        });
    } else {
        warningsArea.classList.add("hidden");
    }

    // OSINT Links
    const linksArea = document.getElementById("phone-osint-links-area");
    if (data.links) {
        linksArea.classList.remove("hidden");
        document.getElementById("btn-phone-google").href = data.links.google_dork || "#";
        document.getElementById("btn-phone-whatsapp").href = data.links.whatsapp || "#";
        document.getElementById("btn-phone-truecaller").href = data.links.truecaller || "#";
    } else {
        linksArea.classList.add("hidden");
    }
}

function renderImageResults(data) {
    try {
        // ── Basic file parameters ──
        setText("res-image-filename", data.filename || "TARGET_ASSET.JPG");

        const meta = data.metadata || {};
        setText("res-image-dimensions", meta.resolution || "Unknown");
        setText("res-image-duration", data.duration || "0.000");

        // ── Threat badge & score ──
        const badge = document.getElementById("res-image-badge");
        const score = document.getElementById("res-image-score");
        if (badge) { badge.textContent = (data.threat_level || "LOW").toUpperCase(); setBadgeColor(badge, data.threat_level); }
        if (score) score.textContent = (data.threat_score || 0) + "%";

        // ── OPSEC quality index ──
        const intelBadge = document.getElementById("res-image-intel-badge");
        const intelScore = document.getElementById("res-image-intel-score");
        const opsecScore = data.intelligence_score || 100;
        let opsecLevel = "EXCELLENT";
        if (opsecScore < 50) opsecLevel = "CRITICAL";
        else if (opsecScore < 80) opsecLevel = "MODERATE";
        if (intelBadge) {
            intelBadge.textContent = opsecLevel;
            intelBadge.className = "badge";
            if (opsecLevel === "EXCELLENT") intelBadge.classList.add("badge-info");
            else if (opsecLevel === "MODERATE") intelBadge.classList.add("badge-warning");
            else intelBadge.classList.add("badge-danger");
        }
        if (intelScore) intelScore.textContent = opsecScore + "%";

        // ── Image preview ──
        const previewImg = document.getElementById("res-image-preview");
        if (previewImg) {
            previewImg.src = data.image_url || "";
            previewImg.onerror = () => {
                previewImg.src = "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=600&q=80";
            };
        }

        // ── File details ──
        setText("res-image-hash", data.fingerprint || "-");
        setText("res-image-format", meta.format || "-");
        setText("res-image-size", meta.file_size || "-");
        setText("res-image-mode", meta.mode || "-");

        // ── EXIF Hardware ──
        setText("res-exif-make", meta.camera_make || "-");
        setText("res-exif-model", meta.camera_model || "-");
        setText("res-exif-date", meta.timestamp || "-");
        setText("res-exif-software", meta.software || "-");
        setText("res-exif-fnumber", meta.f_number || "-");
        setText("res-exif-shutter", meta.exposure_time || "-");
        setText("res-exif-iso", meta.iso || "-");

        // ── GPS coordinates ──
        const coordsText = document.getElementById("res-gps-coords");
        const gpsLinkBtn = document.getElementById("res-gps-link");
        const gpsNoLinkSpan = document.getElementById("res-gps-nolink");
        const gpsAlertPane = document.getElementById("gps-exposure-alert");
        const gpsAlertText = document.getElementById("gps-alert-text");

        const parsedLat = parseFloat(meta.gps_latitude);
        const parsedLon = parseFloat(meta.gps_longitude);

        if (meta.gps_latitude !== null && meta.gps_longitude !== null &&
            meta.gps_latitude !== undefined && meta.gps_longitude !== undefined &&
            !isNaN(parsedLat) && !isNaN(parsedLon)) {
            const coordsStr = `${parsedLat.toFixed(5)}, ${parsedLon.toFixed(5)}`;
            if (coordsText) coordsText.textContent = coordsStr;
            if (gpsLinkBtn) {
                gpsLinkBtn.href = `https://www.google.com/maps/search/?api=1&query=${parsedLat},${parsedLon}`;
                gpsLinkBtn.classList.remove("hidden");
            }
            if (gpsNoLinkSpan) gpsNoLinkSpan.classList.add("hidden");
            if (gpsAlertPane) gpsAlertPane.classList.remove("hidden");
            if (gpsAlertText) {
                gpsAlertText.textContent = `Visual asset contains embedded GPS coordinates [${coordsStr}]. This exposes the exact physical location where the image was captured — critical OPSEC vulnerability.`;
            }
        } else {
            if (coordsText) coordsText.textContent = "N/A";
            if (gpsLinkBtn) { gpsLinkBtn.href = "#"; gpsLinkBtn.classList.add("hidden"); }
            if (gpsNoLinkSpan) gpsNoLinkSpan.classList.remove("hidden");
            if (gpsAlertPane) gpsAlertPane.classList.add("hidden");
        }

        // ─────────────────────────────────────────────────────────────────
        // ── MATCHES / SOURCES PANEL ──
        // ─────────────────────────────────────────────────────────────────
        const matchList = document.getElementById("res-image-mentions");
        if (!matchList) return;

        matchList.innerHTML = "";
        let html = "";

        const lensUrl = data.lens_url || null;
        const subjectGuess = data.subject_guess || null;
        const personInfo = data.person_info || null;
        const hasRealResults = data.has_real_results || false;
        const matches = data.matches || [];

        // ── Google Lens CTA Banner (always shown at top) ──
        if (lensUrl) {
            html += `
            <div class="lens-cta-banner">
                <div class="lens-cta-left">
                    <i class="fa-brands fa-google" style="font-size:1.8rem; background: linear-gradient(135deg,#4285F4,#EA4335,#FBBC05,#34A853); -webkit-background-clip:text; -webkit-text-fill-color:transparent;"></i>
                    <div>
                        <div class="lens-cta-title">Live Visual Index Search</div>
                        <div class="lens-cta-sub">View all matching sources, similar images, and web presence for this exact image</div>
                    </div>
                </div>
                <a href="${lensUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-primary btn-glow" style="white-space:nowrap; font-size:0.8rem; padding:10px 20px;">
                    <i class="fa-solid fa-arrow-up-right-from-square"></i> View Similar Images
                </a>
            </div>`;
        }

        // ── Subject / Person Identification Banner ──
        if (subjectGuess || personInfo) {
            const displayName = personInfo ? personInfo.name : subjectGuess;
            const displayDesc = personInfo ? personInfo.description : `Google identified this image as: "${subjectGuess}"`;

            html += `
            <div class="subject-id-banner">
                <div class="subject-id-icon">
                    <i class="fa-solid ${personInfo ? 'fa-user-check' : 'fa-magnifying-glass-chart'}" style="font-size:1.5rem;"></i>
                </div>
                <div class="subject-id-info">
                    <div class="subject-id-label">${personInfo ? '👤 PERSON IDENTIFIED' : '🔍 SUBJECT IDENTIFIED'}</div>
                    <div class="subject-id-name">${displayName}</div>
                    ${displayDesc ? `<div class="subject-id-desc">${displayDesc}</div>` : ''}
                </div>
                ${lensUrl ? `<a href="https://www.google.com/search?q=${encodeURIComponent(displayName)}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" style="white-space:nowrap; font-size:0.75rem;"><i class="fa-solid fa-magnifying-glass"></i> Search "${displayName}"</a>` : ''}
            </div>`;
        }

        // ── Divider: Source Intelligence ──
        html += `
        <div class="similar-matches-divider" style="margin: 20px 0 16px 0;">
            <span class="divider-line"></span>
            <span class="divider-text"><i class="fa-solid fa-fingerprint"></i> IMAGE SOURCE INTELLIGENCE</span>
            <span class="divider-line"></span>
        </div>`;

        if (!hasRealResults && matches.length === 1 && matches[0].domain === "lens.google.com") {
            // ── No parsed results: show clean fallback ──
            html += `
            <div class="no-results-panel">
                <i class="fa-solid fa-circle-info text-cyan" style="font-size:2rem; margin-bottom:12px;"></i>
                <h4 style="color:#fff; margin-bottom:8px; font-family:'Orbitron',sans-serif; font-size:1rem;">Real-Time Visual Search Results</h4>
                <p style="color:var(--text-muted); font-size:0.85rem; line-height:1.6; max-width:600px; margin:0 auto 16px;">
                    Google's anti-bot protections blocked direct scraping of visual matches for this image session. 
                    Click the <strong style="color:var(--neon-cyan);">View Similar Images</strong> button above to view all real similar images, 
                    source pages, and exact matches directly on Google.
                </p>
                ${lensUrl ? `<a href="${lensUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-primary btn-glow" style="font-size:0.85rem;"><i class="fa-brands fa-google"></i> View Complete Index Results</a>` : ''}
            </div>`;
        } else {
            // ── Show real parsed matches ──
            const originalSource = matches.find(m => m.category === "Possible Original Source");
            const otherMatches = matches.filter(m => m.category !== "Possible Original Source");

            // Original Source Spotlight Card
            if (originalSource) {
                const conf = originalSource.confidence || 95;
                const hasThumb = originalSource.thumbnail && (originalSource.thumbnail.startsWith("http") || originalSource.thumbnail.startsWith("data:"));

                html += `
                <div class="spotlight-card">
                    <div class="spotlight-glow-border"></div>
                    <div class="spotlight-badge-container">
                        <span class="spotlight-badge"><i class="fa-solid fa-circle-check text-green"></i> ORIGINAL SOURCE — REAL MATCH</span>
                        <span class="match-type-badge match-type-exact">${(originalSource.match_type || "EXACT").toUpperCase()}</span>
                    </div>
                    <div class="spotlight-body">
                        <div class="spotlight-left">
                            ${hasThumb ? `
                            <div class="spotlight-thumb-wrapper">
                                <img class="spotlight-thumb-img" src="${originalSource.thumbnail}" alt="${originalSource.source_name}" 
                                     onerror="this.parentElement.style.display='none'">
                                <div class="spotlight-thumb-scan"></div>
                            </div>` : ''}
                            <div class="spotlight-info">
                                <h3 class="spotlight-title" style="font-size:1rem; word-break:break-word;">${originalSource.source_name || originalSource.domain}</h3>
                                <p class="spotlight-summary">${originalSource.summary || ""}</p>
                                <div class="spotlight-meta">
                                    <span><i class="fa-solid fa-globe text-cyan"></i> <strong style="color:#fff;">${originalSource.domain}</strong></span>
                                    <span><i class="fa-solid fa-calendar-days text-purple"></i> ${originalSource.timestamp || "-"}</span>
                                </div>
                            </div>
                        </div>
                        <div class="spotlight-right">
                            <div class="match-confidence-container">
                                <div class="match-confidence-txt">Source Confidence: <span class="text-green" style="font-weight:800;">${conf}%</span></div>
                                <div class="match-bar-container"><div class="match-bar-fill bg-green-fill" style="width:${conf}%"></div></div>
                            </div>
                            <div style="margin-top:12px; display:flex; flex-direction:column; gap:8px;">
                                <a href="${originalSource.url}" target="_blank" rel="noopener noreferrer" 
                                   class="btn btn-primary btn-glow spotlight-action-btn" 
                                   style="font-size:0.78rem; padding:10px 14px; display:flex; align-items:center; justify-content:center; gap:6px; width:100%;">
                                    <i class="fa-solid fa-arrow-up-right-from-square"></i> Visit Source Page
                                </a>
                            </div>
                        </div>
                    </div>
                    ${originalSource.recon_suggestion ? `
                    <div class="spotlight-recon-suggestion">
                        <div class="spotlight-suggestion-label"><i class="fa-solid fa-lightbulb"></i> ORIGINAL SOURCE RECON ANALYSIS</div>
                        <div class="spotlight-suggestion-text">${originalSource.recon_suggestion}</div>
                    </div>` : ""}
                </div>`;
            }

            // Similar / Related Matches Grid
            if (otherMatches.length > 0) {
                html += `
                <div class="similar-matches-divider">
                    <span class="divider-line"></span>
                    <span class="divider-text"><i class="fa-solid fa-clone"></i> SIMILAR IMAGES & WEB DISTRIBUTION</span>
                    <span class="divider-line"></span>
                </div>
                <div class="similar-matches-grid">`;

                otherMatches.forEach(m => {
                    const conf = m.confidence || 50;
                    const badgeClass = (m.match_type || "").toLowerCase().includes("high") ? "match-type-high"
                        : (m.match_type || "").toLowerCase().includes("exact") ? "match-type-exact"
                        : "match-type-partial";
                    const fillClass = conf >= 85 ? "bg-green-fill" : conf >= 70 ? "bg-yellow-fill" : "bg-cyan-fill";
                    const hasThumb = m.thumbnail && (m.thumbnail.startsWith("http") || m.thumbnail.startsWith("data:"));

                    html += `
                    <div class="match-card">
                        <div class="match-card-header">
                            <span class="match-category-tag"><i class="fa-solid fa-shield-halved"></i> ${m.category || "Similar Match"}</span>
                            <span class="match-type-badge ${badgeClass}">${(m.match_type || "SIMILAR").toUpperCase()}</span>
                        </div>
                        <div class="match-details-body">
                            ${hasThumb ? `
                            <div class="match-thumb-preview">
                                <img class="match-thumb-img" src="${m.thumbnail}" alt="${m.source_name || ""}"
                                     onerror="this.parentElement.style.display='none'">
                            </div>` : ''}
                            <div class="match-details-left">
                                <div class="match-source-title" style="word-break:break-word;">${m.source_name || m.domain}</div>
                                <div class="match-summary-text">${m.summary || ""}</div>
                                ${m.recon_suggestion ? `
                                <div class="match-recon-suggestion">
                                    <div class="suggestion-label"><i class="fa-solid fa-lightbulb"></i> RECON NOTE</div>
                                    <div class="suggestion-text">${m.recon_suggestion}</div>
                                </div>` : ""}
                                <div class="match-meta-info">
                                    <span><i class="fa-solid fa-globe"></i> ${m.domain}</span>
                                    ${m.timestamp ? `<span><i class="fa-solid fa-calendar-days"></i> ${m.timestamp}</span>` : ""}
                                </div>
                            </div>
                            <div class="match-details-right">
                                <div class="match-confidence-container">
                                    <div class="match-confidence-txt">Similarity: ${conf}%</div>
                                    <div class="match-bar-container"><div class="match-bar-fill ${fillClass}" style="width:${conf}%"></div></div>
                                </div>
                                <div style="margin-top:10px;">
                                    <a href="${m.url}" target="_blank" rel="noopener noreferrer"
                                       class="btn btn-primary btn-sm btn-glow"
                                       style="font-size:0.72rem; padding:6px 12px; display:inline-flex; align-items:center; gap:5px; width:100%; justify-content:center;">
                                        <i class="fa-solid fa-arrow-up-right-from-square"></i> Visit Source
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>`;
                });

                html += `</div>`;
            }
        }

        matchList.innerHTML = html;

    } catch (e) {
        console.error("Critical rendering error in renderImageResults:", e);
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



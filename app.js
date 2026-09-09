/**
 * CODEGUARD AI — Frontend Controller & UI Interactivity
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide icons
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    // Scanner instance
    const scanner = new CodeSecurityScanner();

    // DOM Elements
    const codeEditor = document.getElementById('codeEditor');
    const lineNumbers = document.getElementById('lineNumbers');
    const languageSelect = document.getElementById('languageSelect');
    const fileInfo = document.getElementById('fileInfo');
    const scanCodeBtn = document.getElementById('scanCodeBtn');
    const clearCodeBtn = document.getElementById('clearCodeBtn');
    const reScanBtn = document.getElementById('reScanBtn');
    const generateReportBtn = document.getElementById('generateReportBtn');
    const scanProgressModal = document.getElementById('scanProgressModal');
    const scanProgressBar = document.getElementById('scanProgressBar');
    const scanStatusTitle = document.getElementById('scanStatusTitle');
    const scanStatusDesc = document.getElementById('scanStatusDesc');
    const dashboardSection = document.getElementById('dashboard');
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const navLinks = document.getElementById('navLinks');

    // Modals
    const vulnDetailModal = document.getElementById('vulnDetailModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const modalCloseActionBtn = document.getElementById('modalCloseActionBtn');
    
    const securityReportModal = document.getElementById('securityReportModal');
    const closeReportModalBtn = document.getElementById('closeReportModalBtn');
    const printReportBtn = document.getElementById('printReportBtn');
    const copyReportBtn = document.getElementById('copyReportBtn');

    // AI Fix elements
    const explainFixBtn = document.getElementById('explainFixBtn');
    const copySecureCodeBtn = document.getElementById('copySecureCodeBtn');
    const aiExplanationBox = document.getElementById('aiExplanationBox');

    // Sample Snippets Database
    const sampleSnippets = {
        sqli: {
            language: 'python',
            filename: 'auth_service.py',
            code: `import sqlite3

username = input("Enter username: ")
connection = sqlite3.connect("users.db")
query = "SELECT * FROM users WHERE username='" + username + "'"
result = connection.execute(query)
print(result.fetchall())`
        },
        xss: {
            language: 'javascript',
            filename: 'comment_renderer.js',
            code: `// Unsafe DOM XSS injection pattern
const comment = new URLSearchParams(window.location.search).get('comment');
document.getElementById('comments').innerHTML = "<div class='user-comment'>" + comment + "</div>";`
        },
        secret: {
            language: 'javascript',
            filename: 'config.js',
            code: `// Hardcoded API credentials in source repository
const stripeSecretKey = "sk_live_51Nc928374910283749102837";
const githubToken = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
console.log("Stripe and GitHub clients initialized.");`
        },
        cmdi: {
            language: 'python',
            filename: 'diagnostics.py',
            code: `import os

target = input("Enter IP address to ping: ")
# Dangerous shell command injection vulnerability
os.system("ping -c 4 " + target)`
        }
    };

    // Load initial default sample (SQLi)
    loadSample('sqli');

    // Update Line Numbers on input
    codeEditor.addEventListener('input', updateLineNumbers);
    codeEditor.addEventListener('scroll', () => {
        lineNumbers.scrollTop = codeEditor.scrollTop;
    });

    function updateLineNumbers() {
        const lines = codeEditor.value.split('\n').length;
        let numbersStr = '';
        for (let i = 1; i <= Math.max(lines, 1); i++) {
            numbersStr += i + '\n';
        }
        lineNumbers.textContent = numbersStr;
    }

    // Language selector change
    languageSelect.addEventListener('change', (e) => {
        const lang = e.target.value;
        fileInfo.textContent = `main.${lang === 'python' ? 'py' : lang === 'javascript' ? 'js' : lang === 'java' ? 'java' : lang === 'php' ? 'php' : lang === 'sql' ? 'sql' : 'c'}`;
    });

    // Sample button clicks
    document.querySelectorAll('.btn-sample').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const sampleKey = e.target.getAttribute('data-sample');
            loadSample(sampleKey);
        });
    });

    function loadSample(key) {
        const sample = sampleSnippets[key];
        if (sample) {
            languageSelect.value = sample.language;
            fileInfo.textContent = sample.filename;
            codeEditor.value = sample.code;
            updateLineNumbers();
        }
    }

    // Clear Code Button
    clearCodeBtn.addEventListener('click', () => {
        codeEditor.value = '';
        updateLineNumbers();
    });

    // Mobile Menu Toggle
    mobileMenuBtn.addEventListener('click', () => {
        navLinks.classList.toggle('active');
    });

    // Scan Code Execution Flow
    scanCodeBtn.addEventListener('click', () => {
        const codeText = codeEditor.value.trim();
        if (!codeText) {
            alert('Please enter or paste source code before running a security scan.');
            return;
        }

        // Show scan animation modal
        scanProgressModal.classList.remove('hidden');
        scanProgressBar.style.width = '0%';
        
        const steps = [
            { title: 'Parsing Source Code...', desc: 'Analyzing AST structures and syntax trees...', progress: '25%' },
            { title: 'Detecting Security Patterns...', desc: 'Matching AST nodes against CWE vulnerability rules...', progress: '55%' },
            { title: 'Calculating Risk Posture...', desc: 'Evaluating severity weights and confidence scores...', progress: '85%' },
            { title: 'Analysis Complete.', desc: 'Generating AI remediation recommendations...', progress: '100%' }
        ];

        let currentStep = 0;
        const interval = setInterval(() => {
            if (currentStep < steps.length) {
                scanStatusTitle.textContent = steps[currentStep].title;
                scanStatusDesc.textContent = steps[currentStep].desc;
                scanProgressBar.style.width = steps[currentStep].progress;
                currentStep++;
            } else {
                clearInterval(interval);
                setTimeout(() => {
                    scanProgressModal.classList.add('hidden');
                    runAnalysisAndRender(codeText);
                }, 400);
            }
        }, 350);
    });

    // Run Analysis and Render Dashboard
    let currentAnalysisResult = null;

    function runAnalysisAndRender(codeText) {
        const lang = languageSelect.value;
        const result = scanner.scan(codeText, lang);
        currentAnalysisResult = result;

        // Render Dashboard Metrics
        document.getElementById('securityScoreVal').textContent = result.score;
        document.getElementById('beforeScoreNum').textContent = `${result.score} / 100`;
        document.getElementById('afterScoreNum').textContent = `${result.afterScore} / 100`;
        
        // Update Radial Ring
        const ringProgress = document.getElementById('ringProgress');
        const circumference = 314; // 2 * pi * r (r=50)
        const offset = circumference - (result.score / 100) * circumference;
        ringProgress.style.strokeDashoffset = offset;
        
        // Color score ring & badge based on severity
        const scoreBadge = document.getElementById('scoreBadge');
        if (result.score < 50) {
            ringProgress.style.stroke = 'var(--accent-red)';
            scoreBadge.className = 'severity-badge critical';
            scoreBadge.textContent = 'CRITICAL RISK';
        } else if (result.score < 75) {
            ringProgress.style.stroke = 'var(--accent-amber)';
            scoreBadge.className = 'severity-badge high';
            scoreBadge.textContent = 'ELEVATED RISK';
        } else {
            ringProgress.style.stroke = 'var(--accent-green)';
            scoreBadge.className = 'severity-badge low';
            scoreBadge.textContent = 'SECURE POSTURE';
        }

        // Summary Counts
        document.getElementById('countCritical').textContent = result.counts.critical;
        document.getElementById('countHigh').textContent = result.counts.high;
        document.getElementById('countMedium').textContent = result.counts.medium;
        document.getElementById('countLow').textContent = result.counts.low;
        document.getElementById('totalVulnCount').textContent = result.counts.total;

        document.getElementById('metaLang').textContent = lang.toUpperCase();
        document.getElementById('metaTime').textContent = result.scanTime;

        // Render Vulnerability Cards
        const container = document.getElementById('vulnerabilitiesContainer');
        container.innerHTML = '';

        if (result.findings.length === 0) {
            container.innerHTML = `
                <div class="vuln-card" style="grid-column: 1 / -1; text-align: center; padding: 3rem;">
                    <i data-lucide="shield-check" style="width: 48px; height: 48px; color: var(--accent-green); margin: 0 auto 1rem;"></i>
                    <h4>No Vulnerabilities Detected</h4>
                    <p>Static pattern analysis found no known security flaws in the submitted code snippet.</p>
                </div>
            `;
        } else {
            result.findings.forEach(vuln => {
                const card = document.createElement('div');
                card.className = 'vuln-card';
                card.innerHTML = `
                    <div class="vuln-card-top">
                        <span class="severity-badge ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
                        <span class="cwe-tag">${vuln.cwe}</span>
                    </div>
                    <div class="vuln-title-group">
                        <h4>${vuln.title}</h4>
                    </div>
                    <p class="vuln-risk-desc">${vuln.risk}</p>
                    <div class="vuln-card-footer">
                        <span class="affected-line">Affected: ${vuln.affectedLine}</span>
                        <button class="btn btn-subtle btn-sm view-vuln-btn" data-id="${vuln.id}">
                            View Details <i data-lucide="arrow-right"></i>
                        </button>
                    </div>
                `;
                container.appendChild(card);
            });

            // Bind view detail buttons
            document.querySelectorAll('.view-vuln-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const vulnId = e.currentTarget.getAttribute('data-id');
                    openVulnDetailModal(vulnId);
                });
            });
        }

        // Update AI Fix diff if findings exist
        if (result.findings.length > 0) {
            const primaryVuln = result.findings[0];
            document.getElementById('vulnerableCodeBlock').querySelector('code').textContent = primaryVuln.vulnerableSnippet;
            document.getElementById('secureCodeBlock').querySelector('code').textContent = primaryVuln.secureSnippet;
        }

        // Reveal Dashboard Section smoothly
        dashboardSection.classList.remove('hidden');
        dashboardSection.scrollIntoView({ behavior: 'smooth' });

        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }

    reScanBtn.addEventListener('click', () => {
        dashboardSection.classList.add('hidden');
        document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
    });

    // Vulnerability Detail Modal Handler
    function openVulnDetailModal(vulnId) {
        const vuln = VULNERABILITY_DATABASE[vulnId];
        if (!vuln) return;

        document.getElementById('modalSeverityBadge').className = `severity-badge ${vuln.severity}`;
        document.getElementById('modalSeverityBadge').textContent = vuln.severity.toUpperCase();
        document.getElementById('modalVulnTitle').textContent = vuln.title;
        document.getElementById('modalCweBadge').textContent = vuln.cwe;

        const modalBody = document.getElementById('modalBodyContent');
        modalBody.innerHTML = `
            <div>
                <div class="modal-section-title">What Happened?</div>
                <p class="modal-text">${vuln.whatHappened}</p>
            </div>
            <div>
                <div class="modal-section-title">Why Is It Dangerous?</div>
                <p class="modal-text">${vuln.whyDangerous}</p>
            </div>
            <div>
                <div class="modal-section-title">Attack Vector Chain</div>
                <div class="attack-chain-flow">
                    <div class="chain-step">${vuln.attackChain[0]}</div>
                    <span class="chain-arrow">→</span>
                    <div class="chain-step">${vuln.attackChain[1]}</div>
                    <span class="chain-arrow">→</span>
                    <div class="chain-step">${vuln.attackChain[2]}</div>
                    <span class="chain-arrow">→</span>
                    <div class="chain-step">${vuln.attackChain[3]}</div>
                </div>
            </div>
            <div>
                <div class="modal-section-title">Recommended Remediation</div>
                <p class="modal-text">${vuln.recommendation}</p>
            </div>
        `;

        vulnDetailModal.classList.remove('hidden');
    }

    closeModalBtn.addEventListener('click', () => vulnDetailModal.classList.add('hidden'));
    modalCloseActionBtn.addEventListener('click', () => vulnDetailModal.classList.add('hidden'));
    vulnDetailModal.addEventListener('click', (e) => {
        if (e.target === vulnDetailModal) vulnDetailModal.classList.add('hidden');
    });

    // AI Fix Explainer
    explainFixBtn.addEventListener('click', () => {
        aiExplanationBox.classList.toggle('hidden');
    });

    // Copy Secure Code
    copySecureCodeBtn.addEventListener('click', () => {
        const secureCode = document.getElementById('secureCodeBlock').querySelector('code').textContent;
        navigator.clipboard.writeText(secureCode).then(() => {
            const originalText = copySecureCodeBtn.innerHTML;
            copySecureCodeBtn.innerHTML = `<i data-lucide="check"></i> Copied!`;
            if (typeof lucide !== 'undefined') lucide.createIcons();
            setTimeout(() => {
                copySecureCodeBtn.innerHTML = originalText;
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }, 2000);
        });
    });

    // Security Report Modal Handler
    generateReportBtn.addEventListener('click', () => {
        if (!currentAnalysisResult) return;

        document.getElementById('reportTimestamp').textContent = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
        document.getElementById('reportScoreVal').textContent = `${currentAnalysisResult.score} / 100`;
        
        const tableBody = document.getElementById('reportTableBody');
        tableBody.innerHTML = '';
        currentAnalysisResult.findings.forEach(f => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="severity-badge ${f.severity}">${f.severity}</span></td>
                <td><strong>${f.title}</strong></td>
                <td><span class="cwe-tag">${f.cwe}</span></td>
                <td class="font-mono">${f.affectedLine}</td>
            `;
            tableBody.appendChild(row);
        });

        securityReportModal.classList.remove('hidden');
    });

    closeReportModalBtn.addEventListener('click', () => securityReportModal.classList.add('hidden'));
    securityReportModal.addEventListener('click', (e) => {
        if (e.target === securityReportModal) securityReportModal.classList.add('hidden');
    });

    printReportBtn.addEventListener('click', () => {
        window.print();
    });

    copyReportBtn.addEventListener('click', () => {
        const reportText = `CODEGUARD AI SECURITY REPORT\nScore: ${currentAnalysisResult.score}/100\nTotal Vulnerabilities: ${currentAnalysisResult.counts.total}\nCritical: ${currentAnalysisResult.counts.critical}, High: ${currentAnalysisResult.counts.high}\nGenerated by techinA`;
        navigator.clipboard.writeText(reportText).then(() => {
            const orig = copyReportBtn.innerHTML;
            copyReportBtn.innerHTML = `<i data-lucide="check"></i> Summary Copied`;
            if (typeof lucide !== 'undefined') lucide.createIcons();
            setTimeout(() => {
                copyReportBtn.innerHTML = orig;
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }, 2000);
        });
    });
});

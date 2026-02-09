# BİGR Shield - Security Validation Engine Design

**Date:** 2026-02-09
**Status:** DRAFT - Awaiting Review
**Context:** BİGR Discovery subproject - adds BAS (Breach & Attack Simulation) capability
**Target:** Lightweight, kademeli security posture validation for SMBs to enterprises

---

## 1. Product Vision

**BİGR Discovery** tells you *what* you have on your network.
**BİGR Shield** tells you *how protected* it is.

Users enter an IP, domain, or CIDR range. Shield scans from the outside (cloud) to validate:
- Are ports properly filtered?
- Are TLS certificates strong and current?
- Are known CVEs patched?
- Are default credentials removed?
- Are web apps resistant to basic attacks?

The result: a **Shield Score** (0-100) with actionable remediation steps.

### Target Users (Layered UI)

| Layer | User | UI Mode | Depth |
|-------|------|---------|-------|
| Simple | KOBİ IT admin, bireysel | "Quick Scan" - IP gir, rapor al | Perimeter + TLS + CVE |
| Standard | Security-aware IT | Full dashboard, filtreleme, trend | + OWASP + credentials |
| Expert | SOC / Security analyst | MITRE ATT&CK heatmap, raw findings, API | + custom templates, scheduling |

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    BİGR Shield                           │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Orchestrator │  │  Results     │  │  Reporting   │  │
│  │  (Python)     │  │  Aggregator  │  │  Engine      │  │
│  │              │  │              │  │              │  │
│  │  - Job queue  │  │  - Normalize │  │  - Score     │  │
│  │  - Rate limit │  │  - Dedupe    │  │  - ATT&CK    │  │
│  │  - Scheduling │  │  - Enrich    │  │  - Remediate │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                  │                  │          │
│  ┌──────┴──────────────────┴──────────────────┘          │
│  │                                                       │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────┐          │
│  │  │  Nmap   │  │ Nuclei  │  │   Custom    │          │
│  │  │ Scanner │  │ Scanner │  │  Modules    │          │
│  │  │         │  │         │  │             │          │
│  │  │ - Ports │  │ - CVE   │  │ - DNS/SPF  │          │
│  │  │ - Svc   │  │ - Miscon│  │ - Headers  │          │
│  │  │ - OS    │  │ - Creds │  │ - DB Expose│          │
│  │  │ - Banner│  │ - OWASP │  │ - TLS Deep │          │
│  │  └─────────┘  └─────────┘  └─────────────┘          │
│  │                                                       │
│  └───────────────────┬───────────────────────────────────┘
│                      │                                    │
└──────────────────────┼────────────────────────────────────┘
                       │ Internet
                       ▼
              ┌────────────────┐
              │  Target System │
              │  (User's IP)   │
              └────────────────┘
```

### Tech Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Orchestrator | Python 3.12 + asyncio | Mevcut BİGR backend ile uyumlu |
| Port Scanner | Nmap (subprocess) | Endüstri standardı, güvenilir |
| Vuln Scanner | Nuclei (Go binary) | 6500+ template, MIT, hızlı |
| Custom Modules | Python | DNS, headers, TLS deep check |
| API | FastAPI (mevcut backend'e ek route'lar) | Tek backend, tek deploy |
| Frontend | Vue 3 (mevcut SPA'ya ek sayfalar) | Tutarlı UX |
| Job Queue | SQLite + asyncio.Queue (Phase 1) | Basit, external dep yok |
| CVE Data | NVD JSON feeds + EPSS API + CISA KEV | Ücretsiz, güncel |

### Safety Controls

| Control | Implementation |
|---------|---------------|
| Rate limiting | Max 1 concurrent scan per IP, 10 req/min |
| Authorization | User must verify IP ownership (DNS TXT record OR email to abuse contact) |
| Non-destructive | Read-only probes, no exploit execution |
| Scope lock | Only scan user-specified targets, never expand |
| Timeout | 5 min max per scan, 30s per individual check |
| Logging | All scans logged with timestamp, source, target, results |

---

## 3. Data Model

### New Tables/Collections

```python
# Shield Scan Job
class ShieldScan:
    id: str                    # UUID
    target: str                # IP, domain, or CIDR
    target_type: str           # "ip" | "domain" | "cidr"
    status: str                # "queued" | "running" | "completed" | "failed"
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    shield_score: float | None # 0-100
    grade: str | None          # A+ to F

    # Scan config
    scan_depth: str            # "quick" | "standard" | "deep"
    modules_enabled: list[str] # ["tls", "ports", "cve", "headers", ...]

    # Results summary
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int

# Individual Finding
class ShieldFinding:
    id: str                    # UUID
    scan_id: str               # FK -> ShieldScan
    module: str                # "tls" | "ports" | "cve" | "headers" | "dns" | "creds" | "owasp"
    severity: str              # "critical" | "high" | "medium" | "low" | "info"
    title: str                 # "TLS 1.0 Enabled"
    description: str           # Human-readable explanation
    remediation: str           # "Disable TLS 1.0 in your web server config..."

    # Technical details
    target_ip: str
    target_port: int | None
    evidence: dict             # Raw scan output

    # MITRE ATT&CK mapping (optional)
    attack_technique: str | None  # "T1190"
    attack_tactic: str | None     # "Initial Access"

    # CVE specific (optional)
    cve_id: str | None
    cvss_score: float | None
    epss_score: float | None
    cisa_kev: bool

# Shield Score History (for trends)
class ShieldScoreHistory:
    id: str
    target: str
    scan_id: str
    score: float
    grade: str
    scanned_at: datetime
    breakdown: dict            # Per-module scores
```

### Shield Score Calculation

```
Shield Score = Σ(module_weight × module_score) / Σ(module_weight)

Module Weights:
  tls:      20  (encryption is fundamental)
  ports:    20  (attack surface)
  cve:      25  (known vulnerabilities - highest weight)
  headers:  10  (defense-in-depth)
  dns:      10  (email/phishing protection)
  creds:    10  (access control)
  owasp:     5  (application layer)

Module Score = (passed_checks / total_checks) × 100

Grade Mapping:
  A+: 95-100  |  A: 90-94  |  B+: 85-89  |  B: 75-84
  C+: 70-74   |  C: 60-69  |  D: 40-59   |  F: 0-39
```

---

## 4. API Design

### New Endpoints

```
POST   /api/shield/scan              # Start a new scan
GET    /api/shield/scan/{id}         # Get scan status + results
GET    /api/shield/scan/{id}/findings  # Get all findings for a scan
GET    /api/shield/history/{target}  # Score history for a target
DELETE /api/shield/scan/{id}         # Cancel a running scan

# Quick scan (simplified)
POST   /api/shield/quick             # Quick scan, returns results inline

# Module-specific
GET    /api/shield/modules           # List available scan modules
GET    /api/shield/templates         # List Nuclei templates in use
```

### Request/Response Examples

```json
// POST /api/shield/scan
{
  "target": "example.com",
  "depth": "standard",
  "modules": ["tls", "ports", "cve", "headers", "dns"]
}

// Response
{
  "scan_id": "sh_abc123",
  "status": "queued",
  "estimated_duration_seconds": 120,
  "target": "example.com",
  "resolved_ips": ["93.184.216.34"]
}

// GET /api/shield/scan/sh_abc123
{
  "id": "sh_abc123",
  "target": "example.com",
  "status": "completed",
  "shield_score": 72.5,
  "grade": "B",
  "duration_seconds": 87,
  "summary": {
    "total_checks": 48,
    "passed": 35,
    "failed": 8,
    "warnings": 5
  },
  "module_scores": {
    "tls": { "score": 85, "checks": 6, "passed": 5, "findings": 1 },
    "ports": { "score": 70, "checks": 12, "passed": 8, "findings": 4 },
    "cve": { "score": 60, "checks": 15, "passed": 9, "findings": 6 },
    "headers": { "score": 50, "checks": 8, "passed": 4, "findings": 4 },
    "dns": { "score": 90, "checks": 5, "passed": 4, "findings": 1 }
  },
  "top_findings": [
    {
      "severity": "critical",
      "module": "cve",
      "title": "CVE-2024-6387 (RegreSSHion) - OpenSSH RCE",
      "target": "93.184.216.34:22",
      "remediation": "Upgrade OpenSSH to 9.8p1 or later"
    }
  ]
}
```

---

## 5. Wave Implementation Plan

### Wave 1: Foundation + TLS (Hafta 1-2)

**Goal:** Scan altyapısı + ilk görsel sonuç (TLS validation)

**Backend:**
```
bigr_discovery/
├── shield/
│   ├── __init__.py
│   ├── models.py           # ShieldScan, ShieldFinding, ShieldScoreHistory
│   ├── orchestrator.py     # Scan job manager, async queue
│   ├── scorer.py           # Shield score calculation
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── base.py         # Abstract ScanModule class
│   │   └── tls_check.py    # TLS/SSL validation module
│   └── api/
│       ├── __init__.py
│       └── routes.py       # /api/shield/* endpoints
```

**TLS Module checks:**
- Certificate validity (expired? expiring soon?)
- Certificate chain completeness
- Protocol versions (TLS 1.0/1.1 = fail, TLS 1.2 = warn, TLS 1.3 = pass)
- Cipher suite strength (weak ciphers = fail)
- HSTS header presence
- Certificate key size (< 2048 = fail)
- Self-signed detection
- Certificate transparency logs

**Frontend:**
```
src/views/ShieldView.vue         # Main Shield page
src/components/shield/
├── ScanForm.vue                 # Target input + depth selector
├── ShieldScore.vue              # Big score gauge (reuse ComplianceGauge pattern)
├── ModuleScoreCards.vue          # Per-module score cards
└── FindingsList.vue             # Findings table with severity badges
```

**Tests:** 12-15 unit tests
- Orchestrator: queue, start, complete, fail, timeout
- TLS module: valid cert, expired cert, weak cipher, self-signed
- Scorer: calculation accuracy
- API: endpoints, validation, error handling

**Deliverable:** Kullanıcı bir domain girer -> TLS score + findings görür

---

### Wave 2: Perimeter Scanning (Hafta 3-4)

**Goal:** Port/service scan + HTTP headers + DNS security

**New modules:**
```
shield/modules/
├── port_scan.py          # Nmap wrapper
├── http_headers.py       # Security headers check
└── dns_security.py       # SPF/DKIM/DMARC validation
```

**Port Scan Module (Nmap):**
- Top 1000 ports scan
- Service version detection (-sV)
- Dangerous ports flagging (21/FTP, 23/Telnet, 445/SMB, 3389/RDP, 27017/MongoDB, 6379/Redis)
- Unnecessary open port warnings
- Firewall detection
- Result: port_list, service_map, dangerous_ports

**HTTP Headers Module:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection (deprecated but still checked)
- Referrer-Policy
- Permissions-Policy
- Server header info leak
- X-Powered-By info leak

**DNS Security Module:**
- SPF record presence + validity
- DKIM record check
- DMARC record + policy level (none/quarantine/reject)
- DNSSEC validation
- MX record security
- CAA record (Certificate Authority Authorization)

**Frontend additions:**
```
src/components/shield/
├── PortScanResults.vue      # Port list with risk indicators
├── HeadersChecklist.vue     # Green/red checklist of headers
├── DnsSecurityCard.vue      # SPF/DKIM/DMARC status
└── ShieldTimeline.vue       # Scan progress timeline
```

**Tests:** 15-18 unit tests per module

**Deliverable:** Tam perimeter raporu - portlar, headers, DNS hepsi tek score'da

---

### Wave 3: CVE Intelligence (Hafta 5-6)

**Goal:** Keşfedilen servisleri CVE veritabanıyla eşleştir + Nuclei ile doğrula

**New modules:**
```
shield/modules/
├── cve_matcher.py        # NVD + EPSS + CISA KEV enrichment
└── nuclei_scanner.py     # Nuclei Go binary wrapper
```

**CVE Matcher Flow:**
```
1. Port scan results → service + version list
2. Service versions → CPE (Common Platform Enumeration) mapping
3. CPE → NVD CVE lookup
4. CVE list → EPSS score enrichment (exploitation probability)
5. CVE list → CISA KEV check (actively exploited?)
6. Priority = f(CVSS, EPSS, KEV, asset_criticality)
```

**Nuclei Integration:**
```python
# Template selection based on discovered services
class NucleiScanner:
    def select_templates(self, services: list[Service]) -> list[str]:
        """Pick relevant Nuclei templates based on discovered services."""
        templates = []
        for svc in services:
            if svc.name == "http":
                templates += ["cves/", "misconfiguration/", "default-logins/"]
            if svc.name == "ssh":
                templates += ["network/ssh-*.yaml"]
            if svc.name == "ftp":
                templates += ["network/ftp-*.yaml"]
        return templates

    async def run(self, target: str, templates: list[str]) -> list[Finding]:
        """Run Nuclei with selected templates, parse JSON output."""
        cmd = [
            "nuclei",
            "-target", target,
            "-t", ",".join(templates),
            "-json",
            "-rate-limit", "50",
            "-timeout", "10",
            "-severity", "critical,high,medium",
        ]
        # Parse and return findings
```

**CVE Data Management:**
- NVD JSON feeds: daily download + incremental updates
- EPSS scores: daily CSV update from first.org
- CISA KEV: JSON feed, updated as published
- Local SQLite cache with last_updated tracking

**Frontend additions:**
```
src/components/shield/
├── CveFindings.vue          # CVE list with CVSS/EPSS/KEV badges
├── AttackSurfaceMap.vue     # Visual: port -> service -> CVE chain
└── PriorityMatrix.vue       # CVSS vs EPSS scatter plot
```

**MITRE ATT&CK Mapping:**
- Each finding maps to ATT&CK technique ID
- Aggregate into tactic-level coverage view
- Generate ATT&CK Navigator JSON export

**Tests:** 20+ unit tests
- CPE mapping accuracy
- CVE matching logic
- EPSS/KEV enrichment
- Nuclei output parsing
- Priority scoring

**Deliverable:** "Bu serviste CVE-2024-6387 var, EPSS %95, CISA KEV'de, CVSS 9.8 → CRITICAL"

---

### Wave 4: Active Testing (Hafta 7-8)

**Goal:** Default credential check + OWASP basic probes + remediation engine

**New modules:**
```
shield/modules/
├── credential_check.py    # Default/common credential testing
├── owasp_probes.py        # Basic web application testing
└── remediation.py         # Remediation recommendation engine
```

**Credential Check Module:**
- Common service defaults: SSH, FTP, MySQL, PostgreSQL, MongoDB, Redis, RabbitMQ
- Web admin panels: /admin, /wp-admin, /phpmyadmin
- IoT device defaults (camera, printer, router)
- Rate-limited: max 3 attempts per service
- Safe: only test known default credentials, not brute force
- Credential database: YAML file with vendor/product/default_creds

**OWASP Basic Probes:**
- SQL Injection (error-based detection, not exploitation)
- Reflected XSS (harmless payload: `<script>alert(1)</script>`)
- Directory traversal (`../../etc/passwd` pattern)
- Server-Side Request Forgery (SSRF canary)
- Open redirect detection
- Information disclosure (stack traces, debug pages)
- All non-destructive: detect vulnerability existence, don't exploit

**Remediation Engine:**
```python
class RemediationEngine:
    """Generate actionable remediation steps per finding."""

    def get_remediation(self, finding: ShieldFinding) -> Remediation:
        return Remediation(
            summary="Disable TLS 1.0 on your web server",
            steps=[
                "For Nginx: set `ssl_protocols TLSv1.2 TLSv1.3;`",
                "For Apache: set `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`",
                "For IIS: Disable TLS 1.0 in Registry Editor",
            ],
            references=[
                "https://ssl-config.mozilla.org/",
                "CIS Benchmark: TLS Configuration",
            ],
            effort="low",        # low | medium | high
            impact="high",       # low | medium | high
            priority_label="Quick Win",  # Quick Win | Important | Major Effort
        )
```

**Remediation Priority Matrix:**

| | Low Effort | High Effort |
|---|---|---|
| **High Impact** | 🟢 Quick Win (do first) | 🟡 Major Project |
| **Low Impact** | 🔵 Nice to Have | 🔴 Deprioritize |

**Frontend additions:**
```
src/components/shield/
├── CredentialFindings.vue    # Credential test results
├── OwaspResults.vue          # OWASP probe results
├── RemediationPlan.vue       # Prioritized fix list with effort/impact
├── ShieldReport.vue          # Full printable/exportable report
└── AttackHeatmap.vue         # MITRE ATT&CK Navigator-style heatmap
```

**Full Shield Dashboard (final):**
```
┌─────────────────────────────────────────────────┐
│  BİGR Shield - Security Validation              │
│                                                  │
│  ┌──────────┐  ┌──────────────────────────────┐ │
│  │  Shield   │  │  Module Scores               │ │
│  │  Score    │  │  TLS: 85  Ports: 70  CVE: 60│ │
│  │   72/100  │  │  Headers: 50  DNS: 90       │ │
│  │   Grade B │  │  Creds: 100  OWASP: 75      │ │
│  └──────────┘  └──────────────────────────────┘ │
│                                                  │
│  ┌──────────────────────────────────────────────┐│
│  │  Findings (13 total)                         ││
│  │  🔴 2 Critical  🟠 4 High  🟡 5 Medium     ││
│  │  🔵 2 Low                                    ││
│  │                                               ││
│  │  ┌─────────────────────────────────────────┐ ││
│  │  │ CRITICAL: CVE-2024-6387 on :22          │ ││
│  │  │ HIGH: TLS 1.0 enabled on :443           │ ││
│  │  │ HIGH: Missing CSP header                │ ││
│  │  │ HIGH: Default admin/admin on :8080      │ ││
│  │  │ ...                                      │ ││
│  │  └─────────────────────────────────────────┘ ││
│  └──────────────────────────────────────────────┘│
│                                                  │
│  ┌────────────────┐  ┌────────────────────────┐ │
│  │ ATT&CK Heatmap │  │ Remediation Plan       │ │
│  │ [visual grid]   │  │ 1. Patch OpenSSH ⚡    │ │
│  │                 │  │ 2. Disable TLS 1.0 ⚡  │ │
│  │                 │  │ 3. Add CSP header ⚡   │ │
│  │                 │  │ 4. Change defaults 🔧  │ │
│  └────────────────┘  └────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

**Tests:** 15-20 unit tests
- Credential module: safe testing, rate limiting, timeout
- OWASP probes: detection accuracy, non-destructive verification
- Remediation engine: correct steps per finding type
- Full integration test: scan -> score -> report

**Deliverable:** Tam BAS raporu - score, findings, ATT&CK map, remediation plan

---

## 6. Frontend Route & Navigation

```
/shield                    # Shield dashboard (scan form + recent scans)
/shield/scan/:id           # Scan results detail
/shield/scan/:id/findings  # All findings for a scan
/shield/history            # Score trend over time
/shield/report/:id         # Printable report view
```

Sidebar'a yeni item:
```
Dashboard
Assets
Topology
Compliance
Analytics
Vulnerabilities
Risk
Certificates
──────────────
🛡️ Shield        ← NEW
──────────────
Settings
```

---

## 7. Mevcut BİGR Discovery ile Entegrasyon

Shield, mevcut Discovery verilerini kullanır:

```
Discovery assets  ──→  Shield otomatik hedef önerisi
Discovery CVE     ──→  Shield CVE doğrulaması (pasif → aktif)
Discovery certs   ──→  Shield TLS deep check
Discovery ports   ──→  Shield port risk analizi

Shield findings   ──→  Discovery risk score güncelleme
Shield score      ──→  Dashboard'da Shield widget
```

**Dashboard widget (DashboardView.vue'ye eklenir):**
```
┌──────────────────────────────┐
│  🛡️ Shield Score             │
│  Last scan: 2 hours ago      │
│                               │
│  72/100 (B)   ▲ +5 from last │
│  3 critical findings          │
│  [Run New Scan]               │
└──────────────────────────────┘
```

---

## 8. Nmap & Nuclei Binary Management

```python
# shield/tools.py
import shutil
import subprocess

class ToolManager:
    """Manage external tool binaries."""

    REQUIRED_TOOLS = {
        "nmap": {"min_version": "7.90", "install": "brew install nmap / apt install nmap"},
        "nuclei": {"min_version": "3.0", "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    }

    def check_tools(self) -> dict[str, bool]:
        """Check if required tools are available."""
        status = {}
        for tool, info in self.REQUIRED_TOOLS.items():
            path = shutil.which(tool)
            status[tool] = path is not None
        return status

    def get_tool_path(self, name: str) -> str:
        """Get path to tool binary, raise if not found."""
        path = shutil.which(name)
        if not path:
            raise ToolNotFoundError(
                f"{name} not found. Install: {self.REQUIRED_TOOLS[name]['install']}"
            )
        return path
```

**Settings sayfasında tool status gösterimi:**
```
Scanner Tools:
  nmap:   ✅ v7.94 (/usr/bin/nmap)
  nuclei: ✅ v3.1.0 (/usr/local/bin/nuclei)
```

---

## 9. Security & Legal

### IP Ownership Verification (Phase 1: basit)

```
Option A: DNS TXT Record
  "Add TXT record: bigr-verify=sh_abc123 to your domain"
  → System checks DNS, confirms ownership

Option B: File Upload
  "Upload /.well-known/bigr-verify.txt with content: sh_abc123"
  → System fetches file, confirms ownership

Option C: Self-attestation (MVP)
  "I confirm I am authorized to scan this target" checkbox
  → Log consent with timestamp + IP
```

MVP'de Option C yeterli. Phase 2'de A veya B eklenebilir.

### Rate Limiting

```python
RATE_LIMITS = {
    "free": {
        "scans_per_day": 3,
        "targets_per_scan": 1,
        "max_concurrent": 1,
    },
    "standard": {
        "scans_per_day": 20,
        "targets_per_scan": 10,
        "max_concurrent": 3,
    },
    "expert": {
        "scans_per_day": 100,
        "targets_per_scan": 50,
        "max_concurrent": 10,
    },
}
```

---

## 10. Testing Strategy

### Per-Wave Test Counts

| Wave | Unit | Integration | E2E | Total |
|------|------|-------------|-----|-------|
| Wave 1 | 15 | 3 | 1 | 19 |
| Wave 2 | 45 | 6 | 2 | 53 |
| Wave 3 | 25 | 5 | 2 | 32 |
| Wave 4 | 20 | 5 | 2 | 27 |
| **Total** | **105** | **19** | **7** | **131** |

### Test Approach

- **Unit tests:** Her modülün her check'i izole test edilir (mock Nmap/Nuclei output)
- **Integration tests:** Orchestrator → module → results pipeline
- **E2E tests:** Full scan against test target (localhost veya scanme.nmap.org)
- **Safety tests:** Rate limiting, timeout, scope enforcement

### Mock Scan Targets

```python
# tests/fixtures/mock_targets.py
MOCK_NMAP_OUTPUT = """
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1
80/tcp   open  http     nginx 1.24.0
443/tcp  open  https    nginx 1.24.0
3306/tcp open  mysql    MySQL 8.0.35
"""

MOCK_NUCLEI_OUTPUT = [
    {"template-id": "CVE-2024-6387", "severity": "critical", ...},
    {"template-id": "http-missing-security-headers", "severity": "medium", ...},
]
```

---

## 11. Deployment

### Local Development
```bash
# Nmap + Nuclei gerekli
brew install nmap
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Normal BİGR Discovery başlatma
bigr serve --port 8090
# Shield otomatik olarak /api/shield/* altında aktif
```

### Cloud / SaaS (Gelecek)
- Render web service (mevcut altyapı)
- Nmap + Nuclei Docker container'da
- Job queue: Redis + Celery (Phase 2)
- Scan worker: ayrı container

---

## 12. Success Metrics

| Metric | Wave 1 | Wave 4 (Final) |
|--------|--------|----------------|
| Scan modules | 1 (TLS) | 7 (all) |
| Checks per scan | ~8 | ~50+ |
| Shield score accuracy | Basic | Weighted, calibrated |
| MITRE ATT&CK coverage | None | 15+ techniques |
| Avg scan time | 10s | 90-120s |
| Frontend pages | 2 | 6 |
| Total tests | 19 | 131 |

---

## 13. Risk & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Nmap/Nuclei not installed | Scan fails | Graceful error + install instructions in UI |
| False positives | User trust erodes | Conservative severity, verify before reporting |
| Legal issues (scanning) | Liability | Clear ToS, authorization flow, logging |
| Scan timeout (slow target) | Bad UX | Progressive results, per-module timeout |
| CVE data staleness | Miss new vulns | Daily NVD/EPSS/KEV update cron |
| Nuclei template breakage | Scan errors | Pin template version, test before update |

---

*Design by: MAX + Okan | Research: BAS_MARKET_RESEARCH_2026.md | Date: 2026-02-09*

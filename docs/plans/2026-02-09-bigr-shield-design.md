# BİGR Shield - Security Validation Engine Design

**Date:** 2026-02-09 (Updated: 2026-02-10)
**Status:** REVIEWED - 9.8/10 (NotebookLM Workgroup)
**Context:** BİGR Discovery subproject - adds BAS (Breach & Attack Simulation) capability
**Target:** Lightweight, kademeli security posture validation for SMBs to enterprises
**Review:** [NotebookLM Reassessment](../../../docs/comms/notebooklm/2026-02-10-response-bigr-shield-reassessment.md)

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

### Unique Selling Proposition: "Collective Security Wisdom"

Rakipler (Picus $30K+/yıl, Cymulate, AttackIQ) statik test senaryoları çalıştırır ve tehdit istihbaratını dışarıdan alır. BİGR Shield farklıdır:

- **Self-Learning:** Experience DB sayesinde her taramadan öğrenir. Bir hedefte tespit edilen saldırı paternini anında diğer tüm hedefler için "Pre-Scan Warning"a dönüştürür.
- **AI-Native:** Genesis'in 34 model + 5 provider altyapısı ile scan pipeline'ın her adımında en uygun AI modeli çalışır.
- **Demokratize:** Multi-Provider maliyet arbitrajı sayesinde AI Pentesting'i premium değil standart özellik olarak sunar. KOBİ'ye aylık 99$ "Sanal Güvenlik Mühendisi."
- **Full CTEM:** Gartner'ın 5 fazlı CTEM döngüsünün tamamını (Scoping → Discovery → Prioritization → Validation → Mobilization) tek ekosistemde karşılar.

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

### Genesis AI Integration (6-Layer Stack)

Shield, Genesis'in 6 katmanlı AI altyapısını kullanır:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 6: Task Journal + Wisdom                             │
│  Context recovery, pattern guidance, session continuity     │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Multi-Provider Model Orchestration                │
│  34 models, 5 providers, dynamic routing, cost arbitrage    │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: AEGIS Orchestrator                                │
│  Phase-based agents, quality gates, pointer context         │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Experience DB v2 (Collective Memory)              │
│  Sessions → Contexts → Outcomes → Wisdom                    │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Neural Council + Whisper System                   │
│  Strategic decisions, tactical guidance, multi-agent forum   │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: AEGIS Supervision                                 │
│  Guardian (pre-hoc blocking), Coach, Observer, Evaluator    │
└─────────────────────────────────────────────────────────────┘
```

**Per-Wave AI Model Strategy:**

| Wave | AI Role | Model Tier | Model | Cost |
|------|---------|------------|-------|------|
| Wave 1 | TLS remediation config generation | Tier 1 (fast/cheap) | Haiku 4.5 | $0.25/M |
| Wave 2 | Port risk analysis, header explanation | Tier 1 | Haiku 4.5 | $0.25/M |
| Wave 3 | CVE false positive elimination | Tier 2 (balanced) | Sonnet 4.5 / GPT-4o | $3/M |
| Wave 3 | EPSS + context risk prioritization | Tier 2 | Sonnet 4.5 | $3/M |
| Wave 4 | Remediation plan + script generation | Tier 3 (complex) | Opus 4.6 / DeepSeek-R1 | $15/M |
| Wave 4 | Multi-CVE chain analysis | Tier 3 | Opus 4.6 | $15/M |
| All | Predictive Shadow Defense | Tier 1→3 (escalating) | Trust Ladder | Variable |

**AEGIS Integration in Scan Pipeline:**

```
User → Scan Request
         │
    ┌────▼─────┐
    │  AEGIS   │  Guardian: Scope lock, rate limit enforcement
    │ Guardian │  Coach: "Bu target profili X'e benziyor, dikkat"
    └────┬─────┘
         │
    ┌────▼─────┐
    │  Scan    │  Haiku: Banner → service fingerprint
    │ Modules  │  Nuclei + Nmap: Raw scan
    └────┬─────┘
         │
    ┌────▼─────┐
    │  AI      │  Sonnet: False positive filtreleme
    │ Analysis │  "CVE-XXXX bu versiyon + OS ile gerçekten örtüşüyor mu?"
    └────┬─────┘
         │
    ┌────▼─────┐
    │  AI      │  Opus: Multi-finding bağlam analizi
    │Remediate │  Sisteme özel Ansible/Bash script üretimi
    └────┬─────┘
         │
    ┌────▼──────┐
    │Experience │  Pattern kayıt: service+version → CVE correlation
    │   DB      │  Wisdom: Hangi remediation gerçekten çalıştı?
    └────┬──────┘
         │
    ┌────▼─────┐
    │  Neural  │  Karmaşık risk kararları: Council tartışması
    │ Council  │  "Bu 3 CVE birlikte bir attack chain oluşturuyor mu?"
    └──────────┘
```

---

## 3. Predictive Shadow Defense

**Konsept:** Tarama başlatmadan tahmin üretme.

Shield bir IP'ye tam tarama **başlatmadan önce**, sadece banner grabbing ile Experience DB'deki benzer binlerce varlığın paterninden yola çıkarak ön tahmin üretir:

> "Bu hedefe dair ilk izlenim: nginx 1.24.0 + Ubuntu 22.04 profiline sahip.
> Experience DB'deki benzer 847 hedefin %85'inde CVE-2024-6387 ve TLS 1.0 tespit edildi.
> Tahmini Shield Score: ~65 (C). Tam tarama ile doğrulamak ister misiniz?"

### Nasıl Çalışır?

```
Phase 1: Instant Fingerprint (< 2 saniye)
  ├── TCP banner grab (port 22, 80, 443)
  ├── HTTP response headers (Server, X-Powered-By)
  ├── TLS certificate CN/SAN + protocol version
  └── DNS reverse lookup

Phase 2: Pattern Match (< 1 saniye)
  ├── Experience DB query: "service_fingerprint SIMILAR TO ..."
  ├── Historical scan results for similar profiles
  ├── Known CVE correlation for detected versions
  └── Confidence score based on sample size

Phase 3: Prediction Report
  ├── Predicted Shield Score (range: min-max)
  ├── Top 5 likely findings (with probability %)
  ├── Recommended scan depth (quick vs deep)
  └── "Verify with full scan" CTA
```

### Data Model Addition

```python
class ShieldPrediction:
    id: str                      # UUID
    target: str                  # IP or domain
    fingerprint: dict            # {services, os_hint, tls_version, server_header}
    predicted_score: float       # 0-100 (estimated)
    confidence: float            # 0-1 (sample size dependent)
    likely_findings: list[dict]  # [{cve_id, probability, severity}]
    similar_targets_count: int   # How many similar targets in Experience DB
    created_at: datetime
    verified_by_scan: str | None # FK -> ShieldScan (after full scan)
    prediction_accuracy: float | None  # Post-verification delta
```

### API Endpoints

```
POST  /api/shield/predict           # Instant prediction (no full scan)
GET   /api/shield/predict/{id}      # Get prediction result
POST  /api/shield/predict/{id}/verify  # Trigger full scan to verify prediction
```

### Experience DB Feedback Loop

```
Scan completes → Compare prediction vs actual:
  ├── prediction_accuracy = 1 - |predicted_score - actual_score| / 100
  ├── Per-finding accuracy: was each predicted CVE actually found?
  ├── Log to Experience DB as outcome
  └── Wisdom update: adjust confidence weights

Over time:
  ├── "nginx 1.24.0 → CVE-2024-6387" confidence: 0.85 → 0.92
  ├── "OpenSSH 8.9 → RegreSSHion" confidence: 0.90 → 0.95
  └── New patterns auto-detected, awaiting human validation
```

### Trust Ladder for Predictions

| Prediction Confidence | UI Behavior |
|----------------------|-------------|
| < 0.3 (low) | Don't show prediction, go straight to scan |
| 0.3 - 0.6 (medium) | Show as "preliminary estimate", emphasize verify |
| 0.6 - 0.8 (high) | Show prediction prominently, verify button |
| > 0.8 (very high) | Show as "high-confidence prediction", scan validates |

### Frontend

```
src/components/shield/
├── PredictionCard.vue         # Instant prediction display
├── PredictionAccuracy.vue     # Post-scan accuracy comparison
└── SimilarTargetsPanel.vue    # "847 similar targets scanned before"
```

**Wave Placement:** Foundation in Wave 1 (fingerprint + DB query), enriched per wave as Experience DB grows.

---

## 4. Data Model

### Core Tables

> Note: `ShieldPrediction` model defined in Section 3 (Predictive Shadow Defense) above.

### Scan Tables

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

## 5. API Design

> Predictive Shadow Defense endpoints (`/api/shield/predict/*`) defined in Section 3.

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

## 6. Wave Implementation Plan

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

**AI Integration (Wave 1) - "The Quick Fixer":**
- **Model:** Haiku 4.5 ($0.25/M) - hızlı, ucuz
- **Görev:** Statik remediation metni yerine, tespit edilen sunucu tipine göre (nginx/Apache/IIS) copy-paste hazır config bloğu üretir
- **Örnek:** TLS 1.0 bulundu + nginx 1.24 tespit edildi → Haiku üretir:
  ```nginx
  # /etc/nginx/conf.d/ssl.conf - TLS 1.0/1.1 devre dışı bırakma
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;
  ssl_prefer_server_ciphers off;
  ```
- **AEGIS Guardian:** Config uygulama riskini analiz eder, uyarı ekler
- **Predictive Shadow Defense foundation:** Banner grab + Experience DB query altyapısı kurulur

**Deliverable:** Kullanıcı bir domain girer -> TLS score + AI-generated fix config görür

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

**AI Integration (Wave 2) - "The Explainer":**
- **Model:** Haiku 4.5 ($0.25/M)
- **Görev:** Port risk açıklaması ve header eksikliği etkisi:
  - "Port 3389 (RDP) açık. Bu, uzaktan masaüstü erişimi sağlar ve brute-force saldırılarına açıktır."
  - "CSP header eksik. Bu, XSS saldırılarının tarayıcı tarafında engellenmemesi anlamına gelir."
- **Experience DB:** Port profilleri pattern olarak kaydedilir. "MongoDB 27017 açık + auth yok" → otomatik critical flag

**Deliverable:** Tam perimeter raporu - portlar, headers, DNS hepsi tek score'da + AI açıklamalar

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

**AI Integration (Wave 3) - "The Contextual Filter":**
- **Model:** Sonnet 4.5 / GPT-4o ($3/M) - Tier 2 dengeli
- **Görev 1 - False Positive Elimination:**
  ```
  Prompt: "Nuclei CVE-2024-6387 tespit etti. Hedef: OpenSSH 8.9p1 on Ubuntu 22.04.
  Experience DB'de bu version+OS kombinasyonu 234 kez tarandı.
  Bu CVE bu konfigürasyonda gerçekten exploit edilebilir mi?"

  Sonnet: "Evet. OpenSSH 8.9p1 etkilenen versiyon aralığında (8.5p1-9.7p1).
  Ubuntu 22.04'ün default sshd_config'i race condition'a açık.
  Confidence: 0.94. Gerçek pozitif."
  ```
- **Görev 2 - Attack Chain Detection:**
  - Birden fazla finding'i birleştirip saldırı zinciri tespit eder
  - "Port 22 açık + CVE-2024-6387 + default SSH key = Remote Code Execution chain"
- **Neural Council:** Karmaşık multi-CVE kararları çoklu ajan tartışmasına açılır
- **Predictive Shadow Defense enrichment:** CVE correlation verileri Experience DB'ye beslenir

**Deliverable:** "Bu serviste CVE-2024-6387 var, EPSS %95, CISA KEV'de, CVSS 9.8 → CRITICAL (AI-verified, false positive eliminated)"

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

**AI Integration (Wave 4) - "The Architect":**
- **Model:** Opus 4.6 / DeepSeek-R1 ($15/M) - Tier 3 derin analiz
- **Görev 1 - Intelligent Remediation Plan:**
  ```
  Input: 13 findings (2 critical, 4 high, 5 medium, 2 low)
         Target: nginx 1.24 + Ubuntu 22.04 + MySQL 8.0

  Opus output:
  {
    "remediation_plan": {
      "phase_1_immediate": [
        {
          "finding": "CVE-2024-6387",
          "action": "Upgrade OpenSSH",
          "script": "#!/bin/bash\nsudo apt update && sudo apt install openssh-server=1:9.8p1-1",
          "effort": "low",
          "impact": "critical",
          "estimated_downtime": "30 seconds (service restart)"
        }
      ],
      "phase_2_this_week": [...],
      "phase_3_next_sprint": [...]
    },
    "ansible_playbook": "---\n- hosts: target\n  tasks:\n    - name: Upgrade OpenSSH..."
  }
  ```
- **Görev 2 - AEGIS Orchestrator Integration:**
  - Her critical finding → Task Journal'da otomatik task
  - Remediation ajanı (Opus) spawn → sisteme özel script üretir
  - Kullanıcı uygular → Shield re-scan → Task kapatılır
- **Görev 3 - Experience DB Wisdom Loop:**
  - "Bu remediation bu konfigürasyonda işe yaradı" → wisdom olarak kaydedilir
  - Sonraki benzer hedeflerde aynı remediation önce önerilir
- **Conversational Shield (optional):**
  - Chat interface: "Benim sunucumda ne sorun var?" → doğal dilde cevap
  - Scan başlatma ve sonuç sorgulama konuşarak

**Deliverable:** Tam BAS raporu - score, findings, ATT&CK map, AI-generated remediation scripts + Ansible playbooks

---

## 7. Frontend Route & Navigation

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

## 8. Mevcut BİGR Discovery ile Entegrasyon

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

## 9. Nmap & Nuclei Binary Management

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

## 10. Security & Legal

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

## 11. Testing Strategy

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

## 12. Deployment

### Local Development
```bash
# Nmap + Nuclei gerekli
brew install nmap
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Normal BİGR Discovery başlatma
bigr serve --port 9978
# Shield otomatik olarak /api/shield/* altında aktif
```

### Cloud / SaaS (Gelecek)
- Render web service (mevcut altyapı)
- Nmap + Nuclei Docker container'da
- Job queue: Redis + Celery (Phase 2)
- Scan worker: ayrı container

---

## 13. CTEM Framework Mapping

Gartner'ın Continuous Threat Exposure Management (CTEM) framework'ünün 5 fazı:

```
┌─────────┐    ┌───────────┐    ┌────────────────┐    ┌────────────┐    ┌──────────────┐
│ Scoping  │───▶│ Discovery │───▶│Prioritization  │───▶│ Validation │───▶│Mobilization  │
│          │    │           │    │                │    │            │    │              │
│  AEGIS   │    │   BİGR    │    │Neural Council  │    │   BİGR     │    │   AEGIS      │
│ Guardian │    │ Discovery │    │+ Experience DB │    │  Shield    │    │ Orchestrator │
│          │    │           │    │                │    │            │    │+ Task Journal│
└─────────┘    └───────────┘    └────────────────┘    └────────────┘    └──────────────┘
```

| CTEM Phase | Genesis Component | Capability |
|-----------|-------------------|------------|
| **Scoping** | AEGIS Guardian | Kapsam kilidi, IP ownership doğrulama, iş kritikliği bağlamı |
| **Discovery** | BİGR Discovery | Ağ varlık envanteri, mDNS, ARP sweep, subnet tarama |
| **Prioritization** | Neural Council + Experience DB | Çoklu ajan tartışması ile gerçek risk sıralaması (CVSS + EPSS + business context) |
| **Validation** | BİGR Shield | Nuclei/Nmap saldırı simülasyonu, TLS/port/CVE/credential doğrulama |
| **Mobilization** | AEGIS Orchestrator + Task Journal | Zafiyet → Task açma, AI remediation script üretimi, kapatılana kadar takip |

**Mobilization detayı (rakiplerin en zayıf noktası, Genesis'in en güçlü yeri):**
- Her critical/high finding otomatik olarak Task Journal'da task'a dönüşür
- AEGIS Orchestrator remediation ajanı spawn eder (Opus/DeepSeek-R1)
- Ajan, sisteme özel Ansible playbook veya Bash script üretir
- Kullanıcı uygular → Re-scan ile doğrulama → Task kapatılır
- Experience DB'ye wisdom olarak kaydedilir: "Bu remediation bu konfigürasyonda işe yaradı"

---

## 14. Success Metrics

| Metric | Wave 1 | Wave 4 (Final) |
|--------|--------|----------------|
| Scan modules | 1 (TLS) | 7 (all) |
| Checks per scan | ~8 | ~50+ |
| Shield score accuracy | Basic | Weighted, calibrated |
| MITRE ATT&CK coverage | None | 15+ techniques |
| Avg scan time | 10s | 90-120s |
| Frontend pages | 2 | 8 |
| Total tests | 19 | 145+ |
| **AI Metrics** | | |
| AI-generated remediations | Config snippets | Full Ansible playbooks |
| False positive rate | Baseline (no AI filter) | <5% (Sonnet filtering) |
| Prediction accuracy | Foundation (data collection) | >80% (Experience DB mature) |
| AI model cost per scan | ~$0.01 (Haiku only) | ~$0.15 (full pipeline) |
| Experience DB patterns | Seeding | 1000+ scan patterns |

---

## 15. Risk & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Nmap/Nuclei not installed | Scan fails | Graceful error + install instructions in UI |
| False positives | User trust erodes | Conservative severity, verify before reporting |
| Legal issues (scanning) | Liability | Clear ToS, authorization flow, logging |
| Scan timeout (slow target) | Bad UX | Progressive results, per-module timeout |
| CVE data staleness | Miss new vulns | Daily NVD/EPSS/KEV update cron |
| Nuclei template breakage | Scan errors | Pin template version, test before update |
| AI hallucination in remediation | Wrong fix advice | AEGIS Guardian review + "AI-generated" disclaimer |
| AI cost escalation | Budget overrun | Trust Ladder: start Haiku, escalate only when needed |
| Prediction overconfidence | User skips scan | Always show confidence %, "verify" CTA prominent |
| Experience DB cold start | No predictions initially | Seed with public scan data, predictions after 100+ scans |
| UX complexity (AI layers) | User confusion | Layered UI: Simple hides AI, Expert exposes all |

---

*Design by: MAX + Okan | Reviewed by: NotebookLM Workgroup (9.8/10)*
*Research: BAS_MARKET_RESEARCH_2026.md | Date: 2026-02-09 (Updated: 2026-02-10)*

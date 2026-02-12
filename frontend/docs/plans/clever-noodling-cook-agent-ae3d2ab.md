# BIGR Discovery -- Full Roadmap

**Date:** 2026-02-12
**Version:** 2.0
**Author:** MAX + Okan
**Vision:** Karmasik ag yoneticisinin en iyi arkadasi -- BIGR-uyumlu varlik kesfi, siniflandirma ve guvenlik platformu. Enterprise altyapi, ev kullanicisi yuzey.

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| DONE | Completed and tested |
| IN-PROGRESS | Active development |
| DESIGN-READY | Design doc approved, ready to implement |
| PLANNED | Roadmapped, design pending or in draft |
| FUTURE | Vision-level, no active design |

---

## Phase 1: Core Scanner + CLI [DONE]

**Goal:** MVP -- hybrid network scanner with BIGR 4-group classification.
**Completed:** 2026-02 | **Tests:** 79 | **Commits:** 3

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 1A - Scanner Engine | Passive scanner (ARP table, mDNS, NetBIOS), Active scanner (Scapy ARP + TCP port scan), Hybrid orchestrator (passive-first, active if root) | DONE |
| 1B - Classification | BIGR 4-group mapper (ag_ve_sistemler, uygulamalar, iot, tasinabilir), Score-based confidence (port + MAC vendor + hostname + OS fingerprint), YAML rule engine with hardcoded fallback, MAC normalization + randomized MAC detection, OUI vendor database (38,870 entries) | DONE |
| 1C - Output + CLI | Typer CLI (scan, report, serve, version), JSON/CSV export, Web Dashboard (FastAPI) with dark theme, filters, export | DONE |

**Dependencies:** None (foundation layer).

---

## Phase 2: Persistent Inventory [DONE]

**Goal:** Scan results persist between runs. Change tracking. Service discovery. Manual overrides.
**Completed:** 2026-02 | **Tests:** 159 (cumulative) | **Lines:** +2,831 | **Agents:** 4 parallel

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 2A - SQLite Persistence | Scans, assets, scan_assets, asset_changes tables. CRUD operations, upsert with dedup by (ip, mac). Scan history tracking. | DONE |
| 2B - Scan Diff & Change Detection | Diff engine comparing consecutive scans: new/removed/changed assets. `asset_changes` table with typed changes (port_change, category_change, vendor_change). CLI `--diff` flag + `bigr changes` command. Dashboard "Changes" tab. | DONE |
| 2C - mDNS/Bonjour Service Discovery | 15 mDNS service types monitored (_googlecast, _airplay, _ipp, _hap, _ssh, _rtsp, _homekit, etc.). Service-based scoring function (`score_by_services`). Integration into hybrid scan flow. | DONE |
| 2D - Manual Category Override | `bigr tag` / `bigr untag` / `bigr tags` CLI commands. `manual_category` + `manual_note` fields in assets table. Override precedence over auto-classification. Dashboard badge for manual overrides. | DONE |

**Dependencies:** Phase 1 (scanner + classifier).

---

## Phase 3: Continuous Monitoring & Alerting [DONE]

**Goal:** Surekli ag izleme ve yeni/degisen cihazlar icin anlik bildirim.
**Priority:** HIGH
**Effort:** 3-4 agent sprints

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 3A - Daemon Mode (Watch) | `bigr watch` command with configurable interval (`--interval 5m` or `--cron`). `bigr/watcher.py` background scheduler. PID file for single-instance control (`~/.bigr/watcher.pid`). Config via `~/.bigr/config.yaml` (multi-target, intervals, labels). Graceful shutdown (SIGTERM/SIGINT). Rotating log (`~/.bigr/watcher.log`). | DONE |
| 3B - Alert & Notification Engine | 6 alert types: new_device (WARNING), rogue_device (CRITICAL), port_change (INFO), category_change (WARNING), device_missing (INFO), mass_change (CRITICAL). 5 notification channels: Webhook (Slack/Discord/Teams), Desktop (macOS/Linux native), Email (SMTP), Telegram Bot, Log (always-on fallback). YAML alert rules with conditions (subnet, vendor filters). `bigr/alerts/` package (engine, channels, models). | DONE |
| 3C - Multi-Subnet / VLAN | Multiple subnet scanning (`bigr scan` with multiple CIDRs). Config-driven target list. Subnet label + VLAN tag per asset. `subnets` table + asset enrichment. Dashboard subnet filter dropdown. | DONE |

**Dependencies:** Phase 2 (persistence + diff).

---

## Phase 4: Network Intelligence [DONE]

**Goal:** Pasif kesfin otesinde, aktif ag istihbaratiyla daha derin cihaz anlayisi. Classification accuracy %75 -> %95+.
**Priority:** HIGH
**Effort:** 4-5 agent sprints

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 4A - SNMP Switch Integration | `pysnmp` SNMPv2c/v3 queries. MAC-to-switch-port mapping (dot1dTpFdbPort, dot1dBasePortIfIndex, ifName). VLAN info (Cisco vtpVlanState). `bigr/scanner/snmp.py` + `bigr/scanner/switch_map.py`. Dashboard "Switch Port" column. | DONE |
| 4B - Advanced Device Fingerprinting v2 | 5-signal fingerprinting: TCP/IP stack (TTL, window size, TCP options, p0f DB), HTTP User-Agent harvesting, TLS certificate analysis (CN, SAN, Issuer, key size), DHCP fingerprinting (Option 55 + fingerbank DB), DNS query analysis (passive). Multi-signal scoring integration. `bigr/classifier/fingerprint_v2.py`, `tcp_fingerprint.py`, `http_fingerprint.py`, `tls_fingerprint.py`, `dhcp_fingerprint.py`, `combine_fingerprints.py`. | DONE |
| 4C - Network Topology Map | D3.js force-directed graph. Nodes colored by BIGR category, sized by port count / risk. Subnet clustering. Zoom/pan/click-for-details. `/dashboard/topology` route. `bigr/topology.py` graph builder. Frontend: `TopologyCanvas.vue`, `TopologyLegend.vue`, `TopologyStats.vue`. | DONE |

**Dependencies:** Phase 3 (daemon provides continuous data feed).

---

## Phase 5: Compliance & Reporting [DONE]

**Goal:** Yonetim icin BIGR uyumluluk raporu ve trend analizi.
**Priority:** MEDIUM
**Effort:** 3 agent sprints

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 5A - BIGR Compliance Dashboard | Compliance score = (Classified / Total) x 100. Breakdown: Fully classified (>=0.7), Partially (0.3-0.7), Unclassified (<0.3), Manual override. Gauge chart, pie/donut chart, 30-day trend line, action items list, subnet comparison. `bigr/compliance.py`. Frontend: `ComplianceGauge.vue`, `ComplianceBreakdown.vue`, `SubnetComplianceTable.vue`, `ActionItemsList.vue`, `ComplianceDistribution.vue`. | DONE |
| 5B - PDF/HTML Report Generator | `bigr report --format pdf/html/bigr-matrix`. Jinja2 templates. Executive summary, category distribution, asset tables per category, change report (30 days), action recommendations. Inline SVG charts. UTF-8 Turkish support. `bigr/report/generator.py`, `bigr/report/charts.py`. | DONE |
| 5C - Historical Trending & Analytics | Asset count time series (7/30/90 days). Category trend (stacked area). New vs lost devices (bar chart). "Most changed devices" table. Subnet trend comparison. `bigr/analytics.py`. Frontend: `TrendLineChart.vue`, `MostChangedTable.vue`, `ScanFrequencyChart.vue`. | DONE |

**Dependencies:** Phase 2 (persistence) + Phase 3 (continuous scan data).

---

## Phase 6: Vulnerability & Risk [DONE]

**Goal:** Varlik envanterini guvenlik aciklariyla eslestir.
**Priority:** MEDIUM-HIGH
**Effort:** 3-4 agent sprints

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 6A - CVE Correlation Engine | Vendor + version -> CPE -> CVE matching. NVD JSON feed (offline cache), CISA KEV (active exploitation), EPSS API (exploitation probability). 4-tier matching: exact CPE, vendor-only, port-based, banner-based. `bigr/vuln/cve_db.py`, `matcher.py`, `nvd_sync.py`, `models.py`. Frontend: `VulnSummaryCards.vue`, `VulnAssetTable.vue`, `CveDetailPanel.vue`. | DONE |
| 6B - Risk Scoring Engine | Device Risk Score = CVE (0.35) + Exposure (0.25) + Classification (0.20) + Age (0.10) + Change Frequency (0.10). Risk heatmap (IP vs score). Top 10 risky devices table. Category-level average risk. `bigr/risk/scorer.py`, `models.py`. Frontend: `RiskOverviewCards.vue`, `RiskHeatmap.vue`, `TopRisksTable.vue`, `RiskFactorsChart.vue`. | DONE |
| 6C - Certificate Discovery & Monitoring | TLS cert scanner for all HTTPS ports. Data: Subject CN, SAN, Issuer, validity dates, key size, algorithm, self-signed detection. Alerts: 30-day expiry (WARNING), expired (CRITICAL), self-signed (INFO), weak key (WARNING). `bigr/scanner/tls.py`. Frontend: `CertTable.vue`, `CertSummaryCards.vue`. | DONE |

**Dependencies:** Phase 4 (fingerprinting provides version data for CVE matching).

---

## Phase 7: Shield -- Security Validation Engine [DONE]

**Goal:** Breach & Attack Simulation (BAS). "BIGR Discovery tells you WHAT you have. BIGR Shield tells you HOW PROTECTED it is."
**Design:** Reviewed 9.8/10 by NotebookLM Workgroup
**Effort:** 4 waves (8 weeks)

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 7A - Wave 1: Foundation + TLS | Scan orchestrator (async queue, job management). Shield Score engine (weighted module scoring, A+ to F grading). TLS module: cert validity, chain completeness, protocol versions, cipher strength, HSTS, key size, self-signed detection. API: `/api/shield/scan`, `/api/shield/scan/{id}`. Predictive Shadow Defense foundation (banner grab + DB query). AI: Haiku 4.5 generates server-specific TLS fix configs. Frontend: `ScanForm.vue`, `ShieldScore.vue`, `ModuleScoreCards.vue`, `FindingsList.vue`, `PredictionCard.vue`. | DONE |
| 7B - Wave 2: Perimeter Scanning | Port scan module (Nmap wrapper): top 1000 ports, service version detection, dangerous port flagging, firewall detection. HTTP headers module: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, info leak detection. DNS security module: SPF/DKIM/DMARC, DNSSEC, MX security, CAA record. AI: Haiku 4.5 explains port risks and header impacts. Frontend: `PortScanResults.vue`, `HeadersChecklist.vue`, `DnsSecurityCard.vue`, `ShieldTimeline.vue`. | DONE |
| 7C - Wave 3: CVE Intelligence | CVE matcher module: service versions -> CPE -> NVD CVE lookup -> EPSS enrichment -> CISA KEV check. Nuclei integration: template selection by discovered services, JSON output parsing. MITRE ATT&CK mapping per finding. AI: Sonnet 4.5 eliminates false positives + detects attack chains. Frontend: `CveFindings.vue`, `AttackSurfaceMap.vue`, `PriorityMatrix.vue`. | DONE |
| 7D - Wave 4: Active Testing | Credential check module: default/common credentials for SSH, FTP, MySQL, MongoDB, Redis, web admin panels, IoT devices. OWASP probes: SQLi detection, XSS, directory traversal, SSRF, open redirect, info disclosure (all non-destructive). Remediation engine: effort/impact matrix, priority labels (Quick Win / Important / Major Effort). AI: Opus generates system-specific Ansible playbooks + Bash scripts. Frontend: `CredentialFindings.vue`, `OwaspResults.vue`, `RemediationPlan.vue`. | DONE |

**Dependencies:** Phase 6 (CVE data + risk scoring). Nmap + Nuclei binaries required.

---

## Phase 8: Agent Platform & Consumer Experience [DONE]

**Goal:** Transform from CLI tool into always-on agent platform with consumer-grade UX.
**Design docs:** Home Dashboard Design (2026-02-11), Missing Links Design (2026-02-11)

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 8A - Agent Architecture | Always-on daemon agent with auto-update. Auth (JWT). Job queue (async). Rate limiting. Agent heartbeat + registration. `bigr/agent/` package (auth, queue, ratelimit, alerts, updater). `bigr/core/database.py` + `services.py`. | DONE |
| 8B - Threat Intelligence Platform | Multi-source threat feeds: FireHOL, abuse.ch, AlienVault OTX, CINS Score, AbuseIPDB. Threat correlation with discovered assets. `bigr/threat/` package (models, api, feeds/). | DONE |
| 8C - AI Router & Local Intelligence | Multi-provider AI routing (34 models, 5 providers). Cost-optimized model selection per task tier. Local Ollama provider for offline. Budget tracking. `bigr/ai/` package (router, config, models, local_provider, cloud_provider, budget, threat_analyzer, api). | DONE |
| 8D - Onboarding Experience | AI-guided device identification (chat-style, not forms). 3-step flow: Auto-scan -> AI chat device matching -> "Protection Started". Frontend: `OnboardingView.vue`, `WelcomeStep.vue`, `NetworkScanStep.vue`, `NameNetworkStep.vue`, `ReadyStep.vue`. Backend: `bigr/onboarding/` (service, api). | DONE |
| 8E - Subscription & Pricing | Tiered plans (Free / Pro / Family / Enterprise). Feature gating. Usage tracking. `bigr/subscription/` (plans, models, service, api). Frontend: `PricingView.vue`. | DONE |
| 8F - Remediation Engine | Automated remediation suggestions. Dead man's switch for rollback safety. `bigr/remediation/` (engine, models, deadman, api). Frontend: `RemediationView.vue`. | DONE |
| 8G - Language & Humanizer | Natural language event translation. Technical events -> human-readable messages. "Port 445 blocked" -> "Akilli TV'niz tehlikeli bir sunucuya baglanmaya calisti ve engellendi." `bigr/language/` package. | DONE |
| 8H - Consumer Dashboard | "Ev Kalkani" (Home Shield) dashboard: Animated shield status (green/yellow/red), natural language status sentence, 4 life cards (Verilerim, Ailem, Evim, Bolgem), social-media-style security timeline. Simple sidebar (5 items) with progressive disclosure toggle to advanced mode. Mobile-first design. Frontend: `HomeDashboardView.vue`, `DashboardView.vue`. | DONE |

**Dependencies:** Phase 7 (Shield provides the security validation layer).

---

## Phase 9: Firewall & Network Protection [DONE]

**Goal:** Active threat blocking beyond passive monitoring.

| Sub-phase | Deliverables | Status |
|-----------|-------------|--------|
| 9A - Local Firewall Engine | iptables (Linux) / pf (macOS) rule management on agent machine. Rule categories: threat blocking, ad blocking, port protection. Rule explanation system (human-readable reasons). `bigr/firewall/` package (service). Frontend: `FirewallView.vue`. | DONE |
| 9B - Family Shield | Family member device management. Per-person device grouping. Per-device Shield scanning and status. `bigr/family/` package. Frontend: `FamilyView.vue`, `SafetyRing.vue`, `DeviceCard.vue`. | DONE |
| 9C - Collective Intelligence (Waze Effect) | Anonymous community threat signals. Regional threat aggregation. "Your neighborhood blocked 1.2K phishing attacks this week." `bigr/collective/` package. Frontend: `CollectiveView.vue`. | DONE |
| 9D - Notification System | In-app notification center. Push notification integration. Alert routing by severity. Frontend: `NotificationsView.vue`, `NotificationCard.vue`. | DONE |

**Dependencies:** Phase 8 (agent platform + AI layer).

---

## Phase 10: Guardian DNS Protection [IN-PROGRESS]

**Goal:** Always-on DNS filtering for whole-network protection (Shield DNS layer from Network Security Management Roadmap).
**Design:** Network Security Management Roadmap (2026-02-12), Guardian Frontend Plan (clever-noodling-cook.md)
**Priority:** HIGHEST -- Lowest barrier to biggest impact, router-independent

### 10A - Guardian Backend [DONE]

DNS filtering server (port 53). Blocklist management (StevenBlack, AdGuard, EasyPrivacy, OISD, URLhaus). Custom block/allow rules (domain + wildcard). Statistics tracking (queries, blocked, cache hits). Health monitoring (dns_resolution, upstream_reachable, blocklist_fresh, cache). 8 API endpoints (`/api/guardian/*`). 143 tests, 20 source files. `bigr/guardian/` package.

| Deliverable | Status |
|-------------|--------|
| DNS server (UDP+TCP, port 53) | DONE |
| Blocklist sync + management | DONE |
| Custom rule CRUD | DONE |
| Query statistics + top blocked | DONE |
| Health monitoring (4 checks) | DONE |
| API endpoints (8 total) | DONE |

### 10B - Guardian Frontend [ACTIVE PRIORITY]

Guardian DNS filtering page in the Vue SPA. Sidebar item, route, composable, view, mock data, tests.

| Deliverable | Status |
|-------------|--------|
| `useGuardian.ts` composable (state, fetch, CRUD) | PLANNED |
| `GuardianView.vue` (status banner, stats cards, 4 tabs) | PLANNED |
| Router + Sidebar integration | PLANNED |
| Mock data (demo mode) | PLANNED |
| Unit tests (composable + view) | PLANNED |

### 10C - Discovery <-> Guardian Integration [PLANNED]

Discovery dashboard Shield status widget includes Guardian blocked count. Rule sync from Discovery threat intelligence to Guardian blocklists. Real-time event streaming (WebSocket). Guardian offline detection + fallback indicator.

**Dependencies:** Phase 9 (firewall + family). Guardian backend (10A) must be complete before frontend (10B).

---

## Phase 11: Missing Links -- Product Differentiation [DESIGN-READY]

**Goal:** Transform BIGR from a technical "tool" into an addictive, growing "product."
**Design:** Missing Links Design Doc (2026-02-11) -- Council-driven sektoral benchmark analysis
**Reference leaders:** Fing, Little Snitch, Picus/Cymulate, Waze, Duolingo

### 11A - IoT Safe Mode (Picus Safety) [DESIGN-READY]

**Problem:** Active exploit testing can brick fragile IoT devices (cameras, smart appliances, sensors).

| Deliverable | Status |
|-------------|--------|
| Device sensitivity profiler (safe / cautious / fragile) | DESIGN-READY |
| Shield orchestrator module selection by sensitivity | DESIGN-READY |
| Fragile = passive-only scan, Cautious = info-level Nuclei only | DESIGN-READY |
| Per-device scan mode toggle in UI (Safe / Normal / Full) | DESIGN-READY |
| Classifier enhancement with fragile device categories | DESIGN-READY |

### 11B - Safety Streak (Duolingo Engagement) [DESIGN-READY]

**Problem:** Static security score has no retention mechanism. No "loss aversion."

| Deliverable | Status |
|-------------|--------|
| Streak engine (`bigr/engagement/streak.py`) | DESIGN-READY |
| Streak rules: scan interval, critical response time, alert acknowledgment | DESIGN-READY |
| Streak display in Shield (kalkan) area | DESIGN-READY |
| Push notifications: motivation, warning (6hr before break), broken, milestones | DESIGN-READY |
| Milestone badges: 7d / 30d / 90d / 180d / 365d | DESIGN-READY |
| `SafetyStreak` data model + API endpoints (4) | DESIGN-READY |

### 11C - Enhanced mDNS Discovery (Fing Quality) [DESIGN-READY]

**Problem:** ARP+Nmap finds IP/MAC/OS but not real device identity ("Salon Apple TV'si", "Philips Hue Bridge v2").

| Deliverable | Status |
|-------------|--------|
| Passive mDNS listener (`bigr/scanner/mdns_listener.py`) -- enriched version | DESIGN-READY |
| UPnP/SSDP service discovery | DESIGN-READY |
| Asset enrichment: friendly_name, device_model, device_manufacturer, mdns_services | DESIGN-READY |
| Daemon integration (30s timeout, post-ARP, pre-Nmap) | DESIGN-READY |
| Dashboard: real device names + models in onboarding and device cards | DESIGN-READY |

### 11D - Privacy Tracker Blocker (Little Snitch Effect) [DESIGN-READY]

**Problem:** Users want privacy protection, not just security. "Your smart TV tried to connect to an ad server in China. Blocked."

| Deliverable | Status |
|-------------|--------|
| Tracker intelligence module (`bigr/privacy/tracker_intelligence.py`) | DESIGN-READY |
| Tracker DB: EasyList, Disconnect.me, Peter Lowe's List, CNAME cloaking list | DESIGN-READY |
| TrackerEvent model (asset_ip, domain, category, action) | DESIGN-READY |
| Firewall integration: `sync_tracker_rules()` | DESIGN-READY |
| "Verilerim" card enrichment: weekly blocked tracker stats by category | DESIGN-READY |
| Timeline humanized events: "Your fridge tried to send data to analytics server. Blocked." | DESIGN-READY |
| API: `/api/privacy/stats`, `/api/privacy/events`, `/api/privacy/device/{ip}` | DESIGN-READY |

**Dependencies:** Phase 10 (Guardian DNS filtering is the enforcement mechanism for tracker blocking).

---

## Phase 12: Family Mesh & Growth [DESIGN-READY]

**Goal:** Cross-network family protection + organic growth mechanism.
**Design:** Missing Links Design Doc (2026-02-11)

### 12A - Family Mesh Protocol [DESIGN-READY]

**Problem:** Family Shield promise: "Dad at office, kid at school, mom at home = One dashboard." But different physical networks are not unified.

| Deliverable | Status |
|-------------|--------|
| `family_uuid` generation + QR code pairing | DESIGN-READY |
| Agent heartbeat with family context | DESIGN-READY |
| Backend mesh aggregation (`bigr/family/mesh.py`) | DESIGN-READY |
| Multi-location "Ailem" card: home/office/school with per-location status | DESIGN-READY |
| Family streak = minimum streak across all locations | DESIGN-READY |
| API: `/api/family/mesh/heartbeat`, `dashboard`, `join`, `locations` | DESIGN-READY |

### 12B - Guest Network Loop (Waze Viral Growth) [DESIGN-READY]

**Problem:** No organic growth mechanism. Each home owner should become a "security ambassador."

| Deliverable | Status |
|-------------|--------|
| New device -> "Guest" option in notification | DESIGN-READY |
| 24-hour safe guest profile creation | DESIGN-READY |
| Share link generation (`bigr.app/guest/{code}`) | DESIGN-READY |
| Landing page: "Your host provides secure internet" + CTA | DESIGN-READY |
| GuestInvite model with tracking (pending/claimed/converted/expired) | DESIGN-READY |
| Gamification: referral rewards (Bronze -> Diamond tiers) | DESIGN-READY |
| API: `/api/growth/guest-invite`, `claim`, `referral-stats` | DESIGN-READY |

**Dependencies:** Phase 11 (IoT Safe Mode + mDNS for rich device identification). Phase 9B (Family Shield).

---

## Phase 13: Shield DNS Deployment & Router Adapter [PLANNED]

**Goal:** Multiple deployment options for Guardian/Shield DNS + router integration.
**Design:** Network Security Management Roadmap (2026-02-12)

### 13A - Shield Multi-Deployment [PLANNED]

| Deliverable | Status |
|-------------|--------|
| Raspberry Pi deployment script (dedicated always-on) | PLANNED |
| Docker image (`docker run bigr/shield`) | PLANNED |
| Same-machine mode (for development/testing) | PLANNED |
| Safe fallback DNS chain: Shield -> Quad9 -> Cloudflare Family | PLANNED |
| Short DHCP lease (5-10min) for fast failover | PLANNED |
| Discovery <-> Shield communication protocol (health, rules, stats, events WS) | PLANNED |
| Dashboard: Shield online/offline indicator + fallback status | PLANNED |

### 13B - Router Adapter Framework [PLANNED]

| Deliverable | Status |
|-------------|--------|
| RouterAdapter interface (detect, firewall, DNS, info capabilities) | PLANNED |
| Auto-discovery (gateway HTTP probing -> platform detection) | PLANNED |
| OpenWrt adapter (ubus JSON-RPC) -- first priority | PLANNED |
| UniFi adapter (REST API) | PLANNED |
| Mikrotik adapter (REST API) | PLANNED |
| pfSense/OPNsense adapter (REST API) | PLANNED |
| Capability-based UI actions (direct block vs recommended action) | PLANNED |
| Router credential secure storage (OS keychain) | PLANNED |

### 13C - DNS Security Protocols [PLANNED]

| Deliverable | Status |
|-------------|--------|
| DNS-over-HTTPS (DoH) for upstream queries | PLANNED |
| DNS-over-TLS (DoT) alternative | PLANNED |
| DNSSEC validation | PLANNED |
| DNS cache with TTL management | PLANNED |

**Dependencies:** Phase 10 (Guardian backend as DNS server). Estimated: 4-6 weeks.

---

## Phase 14: Integration & Enterprise [PLANNED]

**Goal:** External tool integration and enterprise features.
**Design:** Product Roadmap (Phase 7 original)

### 14A - REST API v1 (External Integration) [PLANNED]

| Deliverable | Status |
|-------------|--------|
| API key + JWT authentication | PLANNED |
| Assets CRUD + search (paginated, filterable) | PLANNED |
| Scans: trigger, history, diff | PLANNED |
| Changes: polling endpoint | PLANNED |
| Compliance: score + trend | PLANNED |
| Vulnerabilities per asset | PLANNED |
| Export: CSV, JSON, Syslog | PLANNED |

### 14B - SIEM Integration [PLANNED]

| Deliverable | Status |
|-------------|--------|
| Syslog export (RFC 5424) | PLANNED |
| Splunk HEC (HTTP Event Collector) | PLANNED |
| Elasticsearch index push | PLANNED |
| Generic webhook (JSON payload) | PLANNED |
| Real-time push in watcher mode | PLANNED |

### 14C - LDAP/Active Directory Integration [PLANNED]

| Deliverable | Status |
|-------------|--------|
| LDAP connector | PLANNED |
| Computer object -> asset enrichment (owner, department, location) | PLANNED |
| DHCP lease -> user mapping | PLANNED |
| `bigr ldap configure/sync/enrich` CLI commands | PLANNED |

### 14D - NAC Integration [PLANNED]

| Deliverable | Status |
|-------------|--------|
| Policy engine: trigger + conditions -> action | PLANNED |
| Cisco ISE (pxGrid API) | PLANNED |
| Aruba ClearPass (REST API) | PLANNED |
| 802.1X RADIUS attribute push | PLANNED |
| VLAN assignment via SNMP | PLANNED |

**Dependencies:** Phase 13 (Shield + Router adapters).

---

## Phase 15: ISP Partnership & Advanced Protocols [FUTURE]

**Goal:** ISP-level integration for maximum protection coverage.

| Deliverable | Status |
|-------------|--------|
| TR-069/TR-369 (USP) Local Agent mode | FUTURE |
| ISP partnership program (Turk Telekom, Superonline, TurkNet) | FUTURE |
| Matter/Thread IoT policy (MUD RFC 8520) integration | FUTURE |
| ACS (Auto Configuration Server) or USP Controller development | FUTURE |
| Certification process | FUTURE |

**Dependencies:** Phase 14 + business development. Estimated: 3-6 months.

---

## Phase 16: Scale & Production [FUTURE]

**Goal:** Production-ready, multi-site, high-availability deployment.

### 16A - Multi-Site Management [FUTURE]

Central dashboard with distributed scanners. Agent-based architecture (per-site scanner agent). gRPC or REST agent-to-server communication. Site-level compliance comparison. Global network map.

### 16B - PostgreSQL Migration [FUTURE]

SQLite -> PostgreSQL (Alembic migrations). Connection pooling (asyncpg). Read replica for reporting.

### 16C - Web UI Modernization [FUTURE]

Vue.js SPA (already started). Real-time WebSocket updates. Role-based access control (admin, viewer, auditor). i18n (Turkish/English). Dark/light theme toggle.

### 16D - Containerization & Distribution [FUTURE]

Docker image (multi-arch: amd64/arm64). Docker Compose (scanner + dashboard + DB). Helm chart (Kubernetes). Systemd service unit. PyPI publish (`pip install bigr-discovery`). Standalone GitHub repo.

### 16E - Performance & Scale [FUTURE]

Async scanning (asyncio + Scapy). Multi-subnet concurrent scanning. Target: 10,000+ devices. Scan time: /24 < 10s, /16 < 5m. DB query optimization (indexes, partitioning).

**Dependencies:** All previous phases.

---

## Dependency Graph

```
Phase 1 (Scanner)
  |
  v
Phase 2 (Persistence)
  |
  v
Phase 3 (Monitoring) ---------> Phase 5 (Compliance)
  |                                |
  v                                v
Phase 4 (Intelligence) -------> Phase 6 (Vuln & Risk)
                                   |
                                   v
                                Phase 7 (Shield BAS)
                                   |
                                   v
                                Phase 8 (Agent Platform)
                                   |
                                   v
                                Phase 9 (Firewall/Family)
                                   |
                                   v
                          Phase 10 (Guardian DNS) <---- CURRENT
                                   |
                              +----+----+
                              |         |
                              v         v
                    Phase 11        Phase 13
                  (Missing Links)  (Deployment/Router)
                        |               |
                        v               v
                    Phase 12        Phase 14
                  (Mesh/Growth)    (Enterprise)
                                       |
                                       v
                                  Phase 15 (ISP)
                                       |
                                       v
                                  Phase 16 (Scale)
```

---

## Timeline (Suggested)

```
2026-Q1 (Feb-Mar):
  Phase 1-9:   DONE (all completed)
  Phase 10A:   Guardian Backend -- DONE
  Phase 10B:   Guardian Frontend -- ACTIVE PRIORITY
  Phase 10C:   Discovery <-> Guardian Integration

2026-Q2 (Apr-Jun):
  Phase 11:    Missing Links (IoT Safe Mode, Streak, mDNS v2, Tracker Blocker)
  Phase 12:    Family Mesh + Guest Growth Loop
  Phase 13A:   Shield Multi-Deployment (Docker, RPi)

2026-Q3 (Jul-Sep):
  Phase 13B:   Router Adapter Framework (OpenWrt, UniFi, Mikrotik)
  Phase 13C:   DNS Security (DoH/DoT/DNSSEC)
  Phase 14A-B: REST API + SIEM Integration

2026-Q4 (Oct-Dec):
  Phase 14C-D: LDAP/AD + NAC Integration
  Phase 16D:   Containerization + PyPI Publish

2027-Q1:
  Phase 15:    ISP Partnership
  Phase 16:    Scale & Production
  Standalone GitHub repo
  First external beta users
```

---

## Success Metrics

| Metric | Phase 2 | Phase 6 | Phase 10 (Now) | Phase 14 Target | Phase 16 Target |
|--------|---------|---------|----------------|-----------------|-----------------|
| Asset detection | 10 devices | 50+ | 100+ | 500+ | 10,000+ |
| Classification accuracy | ~75% | ~90% | ~95% | ~97% | ~99% |
| Scan time (/24) | 25s | 18s | 15s | 12s | <10s |
| Supported signals | 6 | 12 | 15 | 18 | 20+ |
| Backend test files | 18 | 50+ | 75 | 100+ | 150+ |
| Frontend test files | 0 | 10 | 25 | 40+ | 60+ |
| Backend modules | 4 | 12 | 21 | 25+ | 30+ |
| Frontend views | 2 | 10 | 23 | 28+ | 35+ |
| BIGR compliance | Manual | Automated | Continuous | Continuous + SIEM | Continuous + multi-site |
| Network protection | Passive only | Passive + alerts | DNS filtering | DNS + Firewall + Router | Full stack |
| AI models used | 0 | 0 | Multi-provider | Multi-provider | Multi-provider + local |

---

## Competitive Position

| Feature | BIGR Discovery | Nmap | Qualys | Tenable | Fing | Pi-hole |
|---------|---------------|------|--------|---------|------|---------|
| BIGR classification | Native | None | None | None | None | None |
| Turkish interface | Yes | No | No | No | No | No |
| Price | Free/Open | Free | $$$$$ | $$$$$ | Freemium | Free |
| Install | `pip install` | apt/brew | SaaS+Agent | SaaS+Agent | App Store | Docker/RPi |
| Offline support | Full | Full | No | No | Partial | Full |
| YAML rules | Yes | NSE scripts | No | No | No | No |
| DNS protection | Guardian | No | No | No | No | Yes |
| BAS (Shield) | Native | No | Partial | Partial | No | No |
| Family features | Yes | No | No | No | Yes | No |
| AI intelligence | Multi-model | No | Limited | Limited | No | No |
| Target market | TR SMB + Public sector | General | Enterprise | Enterprise | Consumer | Prosumer |
| CTEM coverage | Full 5-phase | Discovery only | Partial | Partial | Discovery | Protection |

---

## CTEM Framework Mapping (Gartner)

```
Scoping       -> AEGIS Guardian (scope lock, IP ownership, business criticality)
Discovery     -> BIGR Discovery (ARP, mDNS, SSDP, SNMP, fingerprinting)
Prioritization -> Neural Council + Experience DB (multi-agent risk ranking)
Validation    -> BIGR Shield (Nuclei/Nmap BAS, TLS/port/CVE/credential testing)
Mobilization  -> AEGIS Orchestrator + Task Journal + Remediation Engine
```

---

*This roadmap is a living document. Updated after each phase completion.*
*Last update: 2026-02-12 by MAX + Okan*
*Source docs: design (2026-02-09), phase2-roadmap (2026-02-09), product-roadmap (2026-02-09), shield-design (2026-02-09/10), home-dashboard-design (2026-02-11), missing-links-design (2026-02-11), network-security-management-roadmap (2026-02-12), guardian-frontend-plan (2026-02-12)*

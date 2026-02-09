# Breach and Attack Simulation (BAS) - Deep Research Report

**Date:** 2026-02-09
**Context:** BIGR Discovery - Adding BAS capability for security control validation
**Scope:** Market leaders, open-source landscape, MITRE ATT&CK integration, architecture patterns, SMB approach

---

## Table of Contents

1. [Market Leaders & How They Work](#1-market-leaders--how-they-work)
2. [Open Source BAS Tools](#2-open-source-bas-tools)
3. [MITRE ATT&CK Framework Integration](#3-mitre-attck-framework-integration)
4. [Technical Architecture Patterns](#4-technical-architecture-patterns)
5. [Lightweight BAS for SMBs](#5-lightweight-bas-for-smbs)
6. [Integration with Asset Discovery](#6-integration-with-asset-discovery)
7. [Recent Trends (2025-2026)](#7-recent-trends-2025-2026)
8. [Actionable Recommendations for BIGR Discovery](#8-actionable-recommendations-for-bigr-discovery)

---

## 1. Market Leaders & How They Work

### Market Overview

The BAS market was valued at **USD 1.05 billion in 2025** and is forecast to reach **USD 3.00 billion by 2030**, growing at a **23.40% CAGR** ([Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/breach-and-attack-simulation-market)). Some estimates project even higher growth to USD 6.50 billion by 2030 at 34.17% CAGR.

Key drivers:
- Average breach cost climbed to **USD 4.88 million in 2024**
- Shift from point-in-time pentests to **continuous validation**
- Regulatory pressure for demonstrable security posture
- SaaS-based models represent **67%** of deployments; enterprise usage at **72%**, SMB adoption at **28%**

### 1.1 Picus Security

**Founded:** 2013 (Turkey - Ankara), **Pioneer of BAS category**

**Architecture:**

```
                    +-------------------+
                    |   Picus Manager   |
                    |   (Cloud/SaaS)    |
                    |                   |
                    | - Threat Library  |
                    | - AI Orchestrator |
                    | - Reporting       |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v-----+  +-----v-------+
     | Simulation |  | Simulation |  | Integration |
     |   Agent    |  |   Agent    |  |    Agent    |
     | (Windows)  |  |  (Linux)   |  | (SIEM/EDR) |
     +------------+  +------------+  +-------------+

     Agents deployed in customer environment
     Manager orchestrates from cloud
```

**How Simulations Work:**
- Each threat simulation is composed of **30+ atomic-level actions** per emulation plan
- Actions test specific techniques (process injection, PowerShell abuse, registry modification)
- Actions execute **independently** -- no single test depends on another
- Manager initiates attacks from cloud, terminating on agents in customer environment
- AI-generated adversary emulation: multi-agent orchestration automates research, payload, and TTP mapping from live threat intelligence feeds

**Attack Vectors Tested:**
| Vector | What's Tested |
|--------|--------------|
| Network Infiltration | NGFW, IPS/IDS bypass |
| Email Infiltration | 2,546+ real-world email threats, 10,167+ unique actions |
| Web Application | WAF, IPS, Web Security Gateways |
| Endpoint | Ransomware, DLL side-loading, rootkits, APT campaigns (Win/Linux/macOS) |
| Data Exfiltration | DLP controls, PII/PCI/source code leaks |
| URL Filtering | Phishing and malicious site blocking |

**Integrations:** Microsoft, Palo Alto, CrowdStrike, Splunk, AWS, Cisco, Check Point, IBM Security, SentinelOne, Fortinet, F5, Trend Micro, Trellix, Imperva, VMware Carbon Black, Securonix, Exabeam

**Pricing:** Starts ~**$30,000+/year** (enterprise)

Sources:
- [Picus BAS Platform](https://www.picussecurity.com/breach-and-attack-simulation)
- [Picus AI Validation Platform](https://www.helpnetsecurity.com/2025/10/14/picus-security-validation-platform-bas/)
- [Picus Threat Emulation](https://www.picussecurity.com/product/threat-emulation)

---

### 1.2 AttackIQ

**Key Innovation:** Founding research partner of MITRE Center for Threat-Informed Defense

**Architecture:**
- **Anatomic Engine**: Enables operators to create complex adversary attack graphs (attack flows) purpose-built for emulating attacker patterns
- **Command Center**: Unified control plane for orchestrating, managing, and measuring testing efforts
- Every test, emulation, and validation scenario grounded in real TTPs mapped directly to MITRE ATT&CK
- Point-and-click full kill-chain automation

**Key Differentiators:**
- Deepest MITRE ATT&CK alignment in the industry
- Full-scale automated offering across entire kill chain
- **Adversarial Exposure Validation (AEV)** platform launched in Feb 2025 -- uses AI to synthesize vulnerability data, attack paths, and threat intelligence
- Supports SIEM, EDR, XDR validation

Sources:
- [AttackIQ Platform](https://www.attackiq.com/platform/)
- [AttackIQ MITRE ATT&CK](https://www.attackiq.com/mitre-attack/)

---

### 1.3 SafeBreach

**Key Innovation:** "Black box" approach -- does not know network layout, simulates like a real attacker

**Architecture:**
- Deploys **lightweight simulators** (virtual agents) across the network
- Creates a **"digital twin"** of the organization's security environment
- Runs continuous, non-disruptive simulations
- Core: **"Hacker's Playbook"** -- industry's largest attack content repository
  - Updated within **24 hours** of US-CERT and FBI-Flash alerts
  - Widest MITRE coverage

**Simulation Flow:**
```
1. Deploy simulators -----> 2. Initiate scenarios
         |                          |
         v                          v
3. Attempt infiltration     4. Lateral movement
         |                          |
         v                          v
5. Privilege escalation     6. Data exfiltration
         |                          |
         v                          v
7. Report: What worked, what was blocked, remediation steps
```

**Key Module - SafeBreach Propagate:** Emulates lateral movement, privilege escalation, and credential harvesting to quantify post-breach blast radius

Sources:
- [SafeBreach Platform](https://www.safebreach.com/)
- [SafeBreach BAS](https://www.safebreach.com/breach-and-attack-simulation/)
- [SafeBreach Whitepaper](https://www.elasticito.com/wp-content/uploads/2020/02/SafeBreach-whitepaper-Simulating-a-Hacker.pdf)

---

### 1.4 Cymulate

**Key Innovation:** Modular 10-vector architecture with clear security scoring

**Attack Vectors (10 modules):**

| # | Vector | Purpose |
|---|--------|---------|
| 1 | Recon | Reconnaissance & resource development |
| 2 | Email Gateway | Malicious payload delivery via email |
| 3 | Phishing Awareness | Employee security awareness campaigns |
| 4 | Web Application Firewall | WAF bypass attempts |
| 5 | Web Gateway | URL filtering and web security |
| 6 | Endpoint Security | Behavioral/signature attacks, MITRE ATT&CK |
| 7 | Lateral Movement (Hopper) | Internal network segmentation testing |
| 8 | Data Exfiltration | DLP testing (HTTP/S, DNS, ICMP tunneling, etc.) |
| 9 | Immediate Threats | Latest CVE and zero-day testing |
| 10 | Full Kill Chain | End-to-end APT campaigns |

**Data Exfiltration Methods Tested:** HTTP, HTTPS, DNS, DNS tunneling, ICMP tunneling, Telnet, email, removable hardware, cloud services

**Market Position:**
- **20.7% market share** in BAS category (2025)
- 44 badges in G2 Fall 2025, including 14 first-place awards
- Gartner Customers' Choice 2025
- Pricing starts ~**$7,000/month** (up to 1,000 endpoints)
- Launched **SMB-focused packages** in February 2025

Sources:
- [Cymulate Platform](https://cymulate.com/platform/)
- [Cymulate Exposure Management](https://www.helpnetsecurity.com/2025/08/05/cymulate-exposure-management-platform/)
- [Cymulate Data Exfiltration](https://cymulate.com/data-exfiltration)

---

### 1.5 Other Notable Commercial Players

| Vendor | Approach | Key Differentiator |
|--------|----------|-------------------|
| **Pentera** | Automated pentesting | Category leader in Automated Security Validation; lower setup costs |
| **Horizon3.ai (NodeZero)** | Autonomous pentesting | Dynamically traverses networks, chains exposures like real adversary |
| **XM Cyber** | Attack path management | Hybrid cloud attack path analysis |
| **SCYTHE** | Purple team platform | Flexible toolkit for custom attack campaigns |

Sources:
- [Pentera vs NodeZero](https://www.peerspot.com/products/comparisons/pentera_vs_the-nodezero-platform)
- [Horizon3.ai](https://horizon3.ai/)
- [Top 10 BAS Tools 2026](https://gbhackers.com/best-breach-and-attack-simulation-bas-tools/)

---

### Pricing Summary

| Vendor | Annual Cost (approx) | Target Market |
|--------|---------------------|--------------|
| Picus Security | $30,000+ | Enterprise |
| Cymulate | $84,000+ ($7K/mo) | Enterprise, SMB (2025+) |
| AttackIQ | Custom (enterprise) | Large Enterprise |
| SafeBreach | Custom (enterprise) | Large Enterprise |
| Pentera | Custom (lower than average) | Mid-market, Enterprise |
| Open Source (CALDERA, etc.) | Free (+ engineering time) | All |

---

## 2. Open Source BAS Tools

### 2.1 Atomic Red Team (Red Canary)

**What:** Library of small, portable detection tests mapped to MITRE ATT&CK
**License:** MIT License
**Language:** PowerShell (Invoke-AtomicRedTeam), YAML definitions
**GitHub:** [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)

**Coverage:** 261 ATT&CK techniques, 1,225+ Atomic Tests

**Architecture:**
```
+--------------------+      +--------------------+
|   YAML Test Defs   |      | Invoke-Atomic      |
|   (atomics/)       +----->| RedTeam (PowerShell)|
|                    |      | Execution Framework |
| - T1055.001.yaml  |      +----------+---------+
| - T1059.001.yaml  |                 |
| - ...              |                 v
+--------------------+      +--------------------+
                            | Target System      |
                            | (Win/Linux/macOS)  |
                            | Execute & Observe  |
                            +--------------------+
```

**Key Characteristics:**
- Each test runs in **< 5 minutes** with minimal setup
- Tests are **independent** -- no chaining by default
- Covers Windows, macOS, Linux, and **cloud** threats
- Community-maintained and continuously updated
- No built-in automation/orchestration (add-on: Invoke-AtomicRedTeam)
- **Best for:** Validating detection coverage, testing individual techniques

**Strengths:**
- Broadest technique coverage among open-source tools
- Extremely lightweight and portable
- Easy to extend with custom YAML tests

**Limitations:**
- No automated kill-chain emulation in default config
- No built-in C2 or reporting dashboard
- Requires PowerShell for execution framework

Sources:
- [Atomic Red Team](https://www.atomicredteam.io/)
- [GitHub](https://github.com/redcanaryco/atomic-red-team)
- [Red Canary ART](https://redcanary.com/atomic-red-team/)

---

### 2.2 CALDERA (MITRE)

**What:** Automated adversary emulation platform with C2 server
**License:** Apache 2.0
**Language:** Python (server), Go (agents)
**GitHub:** [mitre/caldera](https://github.com/mitre/caldera)

**Coverage:** 527 procedures (including Atomic Red Team library), focused on post-compromise techniques

**Architecture:**
```
+---------------------------------------------+
|              CALDERA Server                  |
|                                              |
|  +----------+  +----------+  +----------+   |
|  | REST API |  | Web UI   |  | Plugins  |   |
|  +----------+  +----------+  +----------+   |
|                                              |
|  +------------------------------------------+
|  | Core C2 (async command-and-control)      |
|  +------------------------------------------+
+-----+-------------------+-------------------+
      |                   |
      v                   v
+----------+       +----------+
| Sandcat  |       |  Manx    |
| Agent    |       |  Agent   |
| (Go)     |       | (TCP/    |
| HTTP(S)  |       | reverse  |
| DNS Tun. |       |  shell)  |
+----------+       +----------+

Plugins:
- Sandcat: Default agent (Go, cross-platform)
- Manx: Reverse shell / terminal
- Stockpile: TTP storehouse
- Response: Incident response
- Training: Certification courses
- SSL: HTTPS support
```

**Key Characteristics:**
- Full **C2 infrastructure** with REST API and web interface
- Agents auto-execute planned adversary emulations
- Plugin architecture for extensibility
- Supports custom tools and tailored TTPs
- **CALDERA for OT**: Industrial control systems variant
- C2 Channels: HTTP(S), DNS Tunneling
- Gocat extensions for peer-to-peer proxy, additional executors

**Strengths:**
- Most feature-rich open-source adversary emulation platform
- Real C2 infrastructure for realistic simulations
- Plugin ecosystem for custom scenarios
- MITRE-maintained, high quality

**Limitations:**
- Requires significant setup and operational expertise
- Agent deployment needed (not agentless)
- Focused on post-compromise; limited initial access testing
- Security concerns (CVE-2025-27364 patched in v5.1.0+)

Sources:
- [CALDERA Docs](https://caldera.readthedocs.io/)
- [MITRE CALDERA](https://caldera.mitre.org/)
- [GitHub](https://github.com/mitre/caldera)

---

### 2.3 Infection Monkey (Akamai/Guardicore)

**What:** Open-source breach and attack simulation with autonomous propagation
**License:** GPLv3
**Language:** Python
**GitHub:** [guardicore/monkey](https://github.com/guardicore/monkey)

**Architecture:**
```
+-------------------+         +-------------------+
|   Monkey Island   |         |   Monkey Agent    |
|   (C&C Server)    |<------->|   (Worm-like)     |
|                   |         |                   |
| - Web GUI         |         | - Scans network   |
| - Visualization   |         | - Propagates      |
| - Reports         |         | - Tests exploits  |
| - Recommendations |         | - Reports back    |
+-------------------+         +---+---------------+
                                  |
                    +-------------+-------------+
                    |             |             |
               +----v---+   +----v---+   +----v---+
               | Server |   | Server |   | Server |
               |   A    |   |   B    |   |   C    |
               +--------+   +--------+   +--------+

               Infection Monkey autonomously spreads
               through the network testing vulnerabilities
```

**Key Characteristics:**
- **Worm-like behavior**: Autonomously spreads through the network
- Environment agnostic: on-premises, containers, public/private clouds
- Tests propagation paths, lateral movement, credential harvesting
- Provides network visualization of attack paths
- Actionable remediation recommendations per server
- Supports **ransomware simulation** and **zero trust assessment**

**Scenarios:**
- Network breach
- Ransomware resilience
- Credential security
- Log4Shell simulation
- Zero trust verification

**Strengths:**
- Most "BAS-like" open-source tool (closest to commercial BAS)
- Autonomous operation after initial deployment
- Excellent visualization and reporting
- No MITRE ATT&CK expertise needed to run

**Limitations:**
- Worm-like nature may concern operations teams
- Less granular technique-level control than CALDERA
- Smaller technique library than Atomic Red Team

Sources:
- [Infection Monkey](https://www.akamai.com/infectionmonkey)
- [GitHub](https://github.com/guardicore/monkey)
- [Akamai BAS](https://www.akamai.com/infectionmonkey/breach-and-attack-simulation)

---

### 2.4 Stratus Red Team (DataDog)

**What:** "Atomic Red Team for the cloud" -- granular cloud attack emulation
**License:** Apache 2.0
**Language:** Go (self-contained binary)
**GitHub:** [DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team)

**Architecture:**
```
+---------------------+
| Stratus Red Team    |
| (Go Binary)        |
|                     |
| Lifecycle:          |
| 1. WARM UP          | ---> Create infrastructure/config
| 2. DETONATE         | ---> Execute attack technique
| 3. CLEAN UP         | ---> Remove infrastructure
+----------+----------+
           |
     +-----v-----+
     | Cloud APIs |
     +-----+-----+
           |
    +------+------+------+
    |      |      |      |
  +--+  +--+  +--+  +---+
  |AWS|  |Az |  |K8s|  |EKS|
  +---+  +---+  +---+  +---+
```

**Key Characteristics:**
- Each technique mapped to MITRE ATT&CK
- Full lifecycle management (warm-up/detonate/cleanup)
- Self-contained, no agent deployment needed
- Cloud platforms: **AWS, Azure, Kubernetes, Amazon EKS**
- Auto-generated documentation per technique

**Strengths:**
- Only open-source tool focused exclusively on cloud attacks
- Clean lifecycle management prevents leftover resources
- Perfect for cloud security validation

**Limitations:**
- Cloud-only (no on-premises network testing)
- Smaller technique library than general-purpose tools

Sources:
- [Stratus Red Team](https://stratus-red-team.cloud/)
- [GitHub](https://github.com/DataDog/stratus-red-team)
- [DataDog Blog](https://www.datadoghq.com/blog/cyber-attack-simulation-with-stratus-red-team/)

---

### 2.5 Other Notable Open-Source Tools

| Tool | Creator | Purpose | Language |
|------|---------|---------|----------|
| **Nuclei** | ProjectDiscovery | Template-based vulnerability scanning, 6500+ templates | Go |
| **Metta** | Uber | Adversarial simulation using Redis/Celery | Python |
| **BT3** | Encripto | Blue team training toolkit | Python |
| **SCYTHE Community** | SCYTHE | Limited free tier of commercial platform | N/A |
| **Mordor** | OTRF | Pre-recorded ATT&CK datasets for detection research | JSON/datasets |

**Nuclei deserves special mention** for BIGR Discovery integration:
- YAML-based DSL for defining scan templates
- Supports DNS, HTTP, TCP, SSL scanning
- 6,500+ community-contributed templates
- CVE-specific templates updated rapidly (e.g., CVE-2025-1974 template released immediately)
- Integrates with Jira, Splunk, GitHub, Elastic, GitLab
- High-concurrency parallel scanning
- **Ideal for external attack surface validation**

Sources:
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [ProjectDiscovery](https://projectdiscovery.io/nuclei)
- [Fourcore Open Source BAS Tools](https://fourcore.io/blogs/top-10-open-source-adversary-emulation-tools)

---

### Open-Source Tools Comparison Matrix

| Feature | Atomic Red Team | CALDERA | Infection Monkey | Stratus Red Team | Nuclei |
|---------|----------------|---------|-----------------|-----------------|--------|
| **ATT&CK Techniques** | 261 | 527 (w/ ART) | ~50 | ~50 (cloud) | N/A (CVE-based) |
| **Test Count** | 1,225+ | 527 procedures | Auto | Per-cloud | 6,500+ templates |
| **Automation** | Manual (+ Invoke-ART) | Automated C2 | Fully autonomous | CLI lifecycle | Fully automated |
| **Agent Required** | No (local exec) | Yes (Sandcat/Manx) | Yes (Monkey) | No (API-based) | No (external scan) |
| **C2 Server** | No | Yes | Yes (Island) | No | No |
| **Reporting** | Basic | Web UI + API | Visual + PDF | CLI output | JSON/SARIF |
| **Platforms** | Win/Linux/macOS | Win/Linux/macOS | Cross-platform | AWS/Azure/K8s | Any (network) |
| **Skill Required** | Low | High | Medium | Medium | Low-Medium |
| **Best For** | Detection testing | Red team ops | Network BAS | Cloud security | External vuln scan |
| **License** | MIT | Apache 2.0 | GPLv3 | Apache 2.0 | MIT |

---

## 3. MITRE ATT&CK Framework Integration

### 3.1 How BAS Tools Map to ATT&CK

BAS tools map their attack simulations to the MITRE ATT&CK framework at multiple levels:

```
ATT&CK Matrix
+------------------------------------------------------------------+
|                                                                  |
|  Tactic        Technique           Sub-Technique    Procedure    |
|  (WHY)         (WHAT)              (HOW specifically) (Instance) |
|                                                                  |
|  Execution --> Command & Script --> PowerShell    --> Invoke-     |
|  (TA0002)      Interpreter          (T1059.001)      Expression  |
|                (T1059)                                test #3     |
+------------------------------------------------------------------+

BAS Mapping:
- Each BAS test = 1 Procedure
- Each Procedure maps to 1 Sub-Technique or Technique
- Multiple Procedures per Technique provide breadth
- Kill-chain scenarios chain Techniques across Tactics
```

**Mapping Approach by Vendor:**
- **Picus:** Each simulation contains 30+ atomic actions, each mapped to specific ATT&CK techniques
- **Cymulate:** Maps tactics to attack vectors; same tactics tested across different vectors
- **AttackIQ:** Uses "attack flows" (attack graphs) aligned to ATT&CK
- **SafeBreach:** Hacker's Playbook entries tagged with ATT&CK IDs

### 3.2 Most Commonly Simulated Techniques (2025)

Per the Picus Red Report 2025 (analysis of 1,027,511 malware samples):

| Rank | Technique | ID | Prevalence | Category |
|------|-----------|-----|-----------|----------|
| 1 | Process Injection | T1055 | 31% (314K samples) | Defense Evasion |
| 2 | Command and Scripting Interpreter | T1059 | ~28% | Execution |
| 3 | Credentials from Password Stores | T1555 | ~15% | Credential Access |
| 4 | Application Layer Protocol | T1071 | ~12% | Command & Control |
| 5 | Impair Defenses | T1562 | ~10% | Defense Evasion |
| 6 | Data Encrypted for Impact | T1486 | ~8% | Impact |
| 7 | System Information Discovery | T1082 | ~7% | Discovery |
| 8 | Input Capture | T1056 | ~6% | Collection |
| 9 | Boot/Logon Autostart Execution | T1547 | ~5% | Persistence |
| 10 | Data from Local System | T1005 | ~4% | Collection |

**Key Insight:** The top 10 techniques account for **93% of total malicious activity**.

**For External/Internet-Facing Testing (most relevant to BIGR Discovery):**

| ATT&CK Technique | ID | Relevance |
|-------------------|-----|-----------|
| Exploit Public-Facing Application | T1190 | Critical |
| External Remote Services | T1133 | Critical |
| Phishing | T1566 | High |
| Active Scanning | T1595 | High |
| Network Service Discovery | T1046 | High |
| Valid Accounts (default creds) | T1078 | High |
| Application Layer Protocol | T1071 | Medium |

### 3.3 Standard for Reporting BAS Results

There is no single industry standard, but the de facto approaches include:

1. **MITRE ATT&CK Navigator Heatmaps** (JSON/SVG export)
   - Visual coverage maps showing tested vs. untested techniques
   - Color-coded: blocked (green), detected (yellow), missed (red)

2. **Security Posture Scores**
   - Per-technique scores, per-tactic scores, overall score
   - Benchmarking against peer organizations
   - Trend tracking over time

3. **Integration Formats:**
   - JSON export for SIEM/SOAR integration
   - Excel/CSV for compliance reporting
   - API-based real-time feeds to GRC tools
   - SARIF (Static Analysis Results Interchange Format) for some tools

4. **Key Metrics:**
   - Technique coverage percentage
   - Detection-to-containment latency
   - Regression rate post-change
   - False negative reduction after remediation
   - Mean time to detect (MTTD) per technique

Sources:
- [Picus Top 10 ATT&CK Techniques](https://www.picussecurity.com/resource/the-top-ten-mitre-attack-techniques)
- [Picus Red Report 2025](https://picussecurity.com/hubfs/red-report-2025/Picus-RedReport-2025.pdf)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Cymulate BAS and ATT&CK](https://cymulate.com/mitre-attack/)
- [SafeBreach BAS and MITRE ATT&CK](https://www.safebreach.com/blog/bas-and-mitre-attack-basics-and-beyond/)

---

## 4. Technical Architecture Patterns

### 4.1 Agent-Based vs. Agentless Approaches

```
AGENT-BASED ARCHITECTURE:
+-------------------+
|   Control Plane   |
|   (Cloud/On-Prem) |
+--------+----------+
         |
    +----v----+----v----+----v----+
    | Agent   | Agent   | Agent   |
    | (EP-1)  | (EP-2)  | (SRV-1)|
    +---------+---------+---------+

    Pros: Deep endpoint visibility, internal testing,
          lateral movement simulation, credential testing
    Cons: Deployment overhead, maintenance, endpoint impact

    Used by: Picus, AttackIQ, SafeBreach, Cymulate, CALDERA

---

AGENTLESS ARCHITECTURE:
+-------------------+
|   Scanner Engine  |
|   (External)      |
+--------+----------+
         |
    +----v-----------------------------------------+
    |  Network / Internet                          |
    |                                              |
    |  Target: Ports, Services, Web Apps, APIs     |
    +----------------------------------------------+

    Pros: No deployment, immediate results, external perspective,
          tests what attackers actually see
    Cons: Limited to external surface, no internal visibility

    Used by: Nuclei, Nmap, external BAS modules

---

HYBRID ARCHITECTURE (Recommended for BIGR):
+-------------------+         +-------------------+
|   External Engine |         |   Internal Agent  |
|   (Agentless)     |         |   (Optional)      |
+--------+----------+         +--------+----------+
         |                             |
    +----v----+                   +----v----+
    | Internet|                   | Internal|
    | Surface |                   | Network |
    +---------+                   +---------+

    Phase 1: External only (agentless)
    Phase 2: Optional internal agent for deeper testing
```

### 4.2 Safe Simulation Techniques

BAS tools use several approaches to ensure **production safety**:

| Technique | Description | Example |
|-----------|-------------|---------|
| **Non-destructive payloads** | Modified malware that mimics behavior without actual damage | Picus uses "safe mode" payloads |
| **Simulated exploits** | Test if vulnerability exists without actually exploiting | Check for open port + vulnerable version, don't execute RCE |
| **Containment scoping** | Strict boundary controls on what agents can access | Cymulate limits blast radius per test |
| **Sandboxed execution** | Run tests in isolated environment | Digital twin / shadow environment |
| **Controlled detonation** | Execute only specific phases of kill chain | Test payload delivery without execution |
| **Rollback capability** | Undo any changes made during testing | Stratus Red Team cleanup phase |
| **Rate limiting** | Throttle scan/test intensity | Prevent DoS of own systems |
| **Allowlisting** | Pre-register test traffic with security tools | Prevent false alerts in SOC |

**Critical Safety Principle:** BAS tools should behave like an attacker in reconnaissance but stop short of exploitation that causes damage. The goal is to **validate detection and response**, not to actually compromise systems.

### 4.3 Protocols and Services Typically Tested

**Network Layer:**
- TCP/UDP port scanning and service discovery
- DNS resolution and zone transfer
- ICMP probing
- Network segmentation validation

**Application Layer:**
- HTTP/HTTPS (web applications, APIs)
- SMTP/IMAP/POP3 (email security)
- FTP/SFTP (file transfer)
- SSH/RDP (remote access)
- DNS (tunneling, exfiltration)
- SMB (file sharing, lateral movement)
- LDAP (directory services)

**Security Controls Tested:**
- NGFW (Next-Gen Firewall) rule validation
- WAF (Web Application Firewall) bypass
- IPS/IDS detection capabilities
- EDR/XDR endpoint detection
- DLP (Data Loss Prevention) exfiltration tests
- Email gateway filtering
- URL/content filtering
- SIEM log collection and alerting
- SSL/TLS configuration

### 4.4 False Positive Handling

| Strategy | Implementation |
|----------|---------------|
| **Baseline establishment** | Run initial tests to establish normal detection patterns |
| **Test signature registration** | Register BAS test signatures with security tools to differentiate |
| **Controlled scheduling** | Run tests during known windows, cross-reference with SOC alerts |
| **Result correlation** | Match BAS test IDs with security tool alerts for validation |
| **Iterative tuning** | Use BAS results to tune detection rules, reducing false positives in production |
| **Vendor-specific guidance** | Picus/Cymulate provide specific remediation steps per vendor (e.g., "add this Snort rule") |

Sources:
- [Palo Alto Agent-Based vs Agentless](https://www.paloaltonetworks.com/cyberpedia/what-is-the-difference-between-agent-based-and-agentless-security)
- [Microsoft BAS Guidance](https://learn.microsoft.com/en-us/defender-endpoint/guidance-for-pen-testing-and-bas)
- [BAS Safety](https://www.deepwatch.com/glossary/breach-attack-simulation/)

---

## 5. Lightweight BAS for SMBs

### 5.1 What a Simplified BAS Looks Like

A lightweight BAS for SMBs should focus on **maximum value with minimum complexity**:

```
LIGHTWEIGHT BAS ARCHITECTURE (BIGR Discovery Target):

+---------------------------+
|    BIGR Discovery         |
|    Dashboard              |
|                           |
|  +-----+ +-----+ +-----+ |
|  |Asset| |Vuln | |BAS  | |
|  |Disc.| |Scan | |Lite | |
|  +--+--+ +--+--+ +--+--+ |
|     |       |       |     |
+-----|-------|-------|-----+
      |       |       |
      v       v       v
+---------------------------+
|    External Scan Engine    |
|                            |
| 1. Port/Service Discovery  |
| 2. SSL/TLS Validation      |
| 3. Known CVE Check         |
| 4. Default Cred Test       |
| 5. WAF/Firewall Bypass     |
| 6. Email Security Check    |
| 7. DNS Security Audit      |
| 8. Web App Common Vulns    |
+----------------------------+
         |
    Internet
         |
+--------v---------+
| Customer's Assets |
| (Internet-facing) |
+------------------+
```

### 5.2 Highest-Value Tests for SMBs

**Tier 1 -- External Perimeter (Start Here):**

| Test | Complexity | Value | Implementation |
|------|-----------|-------|----------------|
| Port scan & service fingerprint | Low | Very High | nmap/masscan equivalent |
| SSL/TLS configuration | Low | Very High | Check cert validity, cipher suites, protocol versions |
| Known CVE matching | Low | Very High | Match service versions to CVE/NVD database |
| Default credentials | Low | High | Test common default passwords on discovered services |
| DNS security (SPF/DKIM/DMARC) | Low | High | DNS record validation |
| HTTP security headers | Low | High | Check HSTS, CSP, X-Frame-Options, etc. |
| Open database ports | Low | Very High | MongoDB, Redis, Elasticsearch, MySQL exposed? |

**Tier 2 -- Application Layer:**

| Test | Complexity | Value | Implementation |
|------|-----------|-------|----------------|
| OWASP Top 10 basics | Medium | Very High | SQL injection, XSS, SSRF probes |
| API security | Medium | High | Auth bypass, rate limiting, IDOR |
| Email gateway test | Medium | High | Send test phishing payloads |
| WAF bypass | Medium | High | Common WAF evasion techniques |
| Subdomain enumeration | Low | Medium | Find forgotten/shadow assets |

**Tier 3 -- Advanced (Future):**

| Test | Complexity | Value | Implementation |
|------|-----------|-------|----------------|
| Lateral movement simulation | High | High | Requires internal agent |
| Endpoint security validation | High | High | Requires internal agent |
| Data exfiltration testing | High | Medium | Requires internal agent |
| Full kill chain | Very High | Very High | Full BAS capability |

### 5.3 External-Only vs. Internal Testing

**External-Only (Phase 1 - Recommended Start):**
- Tests what attackers actually see from the internet
- No agent deployment required
- Immediate value, minimal setup
- Legal simplicity (testing your own internet-facing assets)
- Covers **70-80% of initial breach vectors**

**Internal (Phase 2 - Future):**
- Tests lateral movement, privilege escalation
- Requires agent deployment inside network
- More complex setup, maintenance
- Covers post-breach scenarios
- Needed for compliance frameworks (PCI-DSS, HIPAA)

### 5.4 Legal and Ethical Considerations

**Critical Requirements:**

1. **Written Authorization**: Must have explicit written permission from system owner
   - Even for self-testing, document authorization
   - If testing third-party hosted systems (cloud), both customer AND provider must authorize

2. **Scope Definition**: Clearly define:
   - Which systems/IPs are in scope
   - What types of tests are allowed
   - Time windows for testing
   - Escalation procedures if something breaks

3. **Cloud Provider Policies**:
   - AWS: Requires notification for certain test types
   - Azure: Penetration testing allowed with rules of engagement
   - GCP: Testing allowed on own resources
   - Most cloud providers have specific policies

4. **Data Handling**:
   - Any discovered vulnerabilities must remain confidential
   - Test data must not include real customer PII
   - Results storage must be secure

5. **Regulatory Compliance**:
   - GDPR considerations if scanning EU systems
   - Industry-specific (PCI-DSS, HIPAA) testing requirements
   - Country-specific cybercrime laws

**For BIGR Discovery - Recommended Approach:**
- Users explicitly authorize scanning of their own assets
- Clear Terms of Service covering testing scope
- Rate limiting to prevent disruption
- Test payloads are non-destructive by design
- Results encrypted in transit and at rest
- Option to generate authorization document for compliance

Sources:
- [Ethical Penetration Testing](https://www.pixelqa.com/blog/post/ethical-legal-considerations-penetration-testing)
- [Legal Issues in Pentesting](https://securitycurrent.com/legal-issues-in-penetration-testing/)
- [Ekaru SMB Pentesting](https://www.ekaru.com/blog/what-is-a-pen-test-and-why-small-businesses-cant-ignore-it)

---

## 6. Integration with Asset Discovery

### 6.1 How Asset Knowledge Improves BAS Effectiveness

```
ASSET DISCOVERY + BAS INTEGRATION FLOW:

+---------------------+
| 1. ASSET DISCOVERY  |
| - IP addresses      |
| - Open ports        |
| - Service versions  |
| - Technologies      |
| - Certificates      |
| - DNS records       |
+----------+----------+
           |
           v
+---------------------+
| 2. ENRICHMENT       |
| - CVE matching      |
| - EPSS scoring      |
| - KEV lookup        |
| - Technology stack   |
| - End-of-life check |
+----------+----------+
           |
           v
+---------------------+
| 3. PRIORITIZATION   |
| - CVSS + EPSS + KEV |
| - Asset criticality  |
| - Exposure level     |
| - Exploitability     |
+----------+----------+
           |
           v
+---------------------+
| 4. BAS TARGETING    |
| - Test specific CVEs |
| - Test service vulns |
| - Test config issues |
| - Validate controls  |
+----------+----------+
           |
           v
+---------------------+
| 5. REPORTING        |
| - ATT&CK heatmap    |
| - Risk score         |
| - Remediation steps  |
| - Trend tracking     |
+---------------------+
```

**Key Insight:** Asset discovery transforms BAS from "test everything" to **"test what matters"**. Knowing that a specific server runs Apache 2.4.49 (vulnerable to CVE-2021-41773) means BAS can immediately test path traversal rather than running 6,500 generic tests.

### 6.2 CVE-to-Exploit Mapping Approaches

**Vulnerability Prioritization Stack:**

| Data Source | What It Provides | Integration Priority |
|------------|------------------|---------------------|
| **NVD/CVE** | Vulnerability catalog, CVSS scores | Must-have |
| **EPSS** | Exploitation probability (ML-predicted) | Must-have |
| **CISA KEV** | Confirmed actively exploited vulns | Must-have |
| **Exploit-DB** | Public exploit code availability | High |
| **Nuclei Templates** | Ready-to-run detection templates | High |
| **GitHub PoCs** | Proof-of-concept exploits | Medium |
| **MITRE ATT&CK** | Technique-to-CVE mapping | Medium |

**EPSS + CVSS + KEV Combined Approach:**
```
Priority Score = f(CVSS_severity, EPSS_probability, KEV_status, Asset_criticality)

Example:
  CVE-2024-XXXX:
    CVSS: 9.8 (Critical)
    EPSS: 0.95 (95% chance of exploitation in 30 days)
    KEV: YES (actively exploited)
    Asset: Internet-facing web server

    => PRIORITY: CRITICAL - Test immediately

  CVE-2024-YYYY:
    CVSS: 7.5 (High)
    EPSS: 0.02 (2% chance)
    KEV: NO
    Asset: Internal backup server

    => PRIORITY: MEDIUM - Schedule test
```

### 6.3 Defense Validation Reporting

**Report Structure for Asset Discovery + BAS:**

```
BIGR Discovery - Security Validation Report
============================================

ASSET INVENTORY SUMMARY:
- Total assets discovered: 47
- Internet-facing: 12
- Critical services: 5
- New assets since last scan: 3

VULNERABILITY ASSESSMENT:
- Total CVEs found: 89
- Critical (CVSS >= 9.0): 4
- Actively exploited (KEV): 2
- High EPSS (> 0.7): 7

BAS VALIDATION RESULTS:
+----------+--------+----------+--------+
| Test     | Total  | Blocked  | Missed |
+----------+--------+----------+--------+
| CVE      |   89   |    72    |   17   |
| Config   |   23   |    18    |    5   |
| Default  |   12   |    10    |    2   |
| SSL/TLS  |   12   |    11    |    1   |
+----------+--------+----------+--------+

MITRE ATT&CK COVERAGE:
[Heatmap visualization]

TOP RECOMMENDATIONS:
1. Patch CVE-2024-XXXX on web-server-01 (CRITICAL)
2. Update TLS to 1.3 on api-gateway (HIGH)
3. Remove default credentials on admin-panel (HIGH)
```

Sources:
- [EPSS Model](https://www.first.org/epss/model)
- [CISA KEV](https://www.picussecurity.com/resource/blog/what-is-kev-known-exploited-vulnerabilities-catalog)
- [CVSS/EPSS/KEV Comparison](https://www.picussecurity.com/resource/blog/comparing-cvss-epss-kev-ssvc-lev-and-pxs-from-scores-to-security-proof)
- [Picus BAS + Vulnerability Management](https://www.picussecurity.com/resource/blog/how-to-build-an-effective-vulnerability-management-program-with-bas)

---

## 7. Recent Trends (2025-2026)

### 7.1 Continuous Threat Exposure Management (CTEM)

Gartner prediction: **By 2026, organizations that prioritize security investments based on CTEM will be 3x less likely to suffer a breach.**

**CTEM Five Phases:**
```
+--------+    +-----------+    +---------------+    +------------+    +------------+
| Scope  |--->| Discovery |--->| Prioritization|--->| Validation |--->|Mobilization|
+--------+    +-----------+    +---------------+    +-----+------+    +------------+
                                                          |
                                                    BAS lives here
                                                    (Phase 4)
```

**Market Convergence:** Previously separate categories are merging:
- Vulnerability Management (VM)
- Risk-Based VM (RBVM)
- Attack Surface Management (ASM)
- Cyber Asset ASM (CAASM)
- Application Security Posture Management (ASPM)
- Breach and Attack Simulation (BAS)
- CNAPP

All converging into **unified Risk and Exposure Management platforms** under CTEM.

**Implication for BIGR Discovery:** Building asset discovery + BAS together is aligned with the market direction. The separation between "discover assets" and "test them" is dissolving.

### 7.2 Automated Penetration Testing vs. BAS

The industry now recognizes both as part of **Adversarial Exposure Validation (AEV)**:

| Dimension | BAS | Automated Pentesting |
|-----------|-----|---------------------|
| **Focus** | Breadth (many techniques, continuous) | Depth (multi-step attack chains) |
| **Frequency** | Continuous / daily | Periodic / on-demand |
| **Automation** | Fully automated, repeatable | Autonomous after launch |
| **Output** | Detection coverage metrics | Exploitable attack paths |
| **Config Drift** | Strong (catches regressions) | Moderate |
| **Compliance** | Continuous evidence | Point-in-time reports |
| **Skill Required** | Low-Medium | Medium-High |

**Key Players in Automated Pentesting:**
- **Pentera**: Category leader, safe production emulation
- **Horizon3.ai (NodeZero)**: Dynamic network traversal, chains vulnerabilities
- Both complement BAS rather than replace it

### 7.3 AI-Powered Attack Simulation

**Current State (2026):**

The shift from **Automation to Autonomy** is defining the 2026 landscape:

- **OpenAI Aardvark (GPT-5)**: Scans, exploits, and patches flaws autonomously. Continuously analyzes source code for vulnerabilities, assesses exploitability, prioritizes severity, and proposes patches.

- **LLM Agent Performance**: AI agents can outperform 9/10 human pentesters in controlled environments, identifying vulnerabilities with **82% precision**.

- **AutoPentester Framework**: LLM agent-based automated pentesting framework outperforming PentestGPT baseline in nearly all tasks.

- **Picus AI Multi-Agent**: Uses AI to generate adversary emulation plans from live threat intelligence feeds. Multi-agent orchestration automates research, payload creation, and TTP mapping.

**Prediction (Industry Consensus):** By 2027, "Manual Pentesting" will be a boutique service. 99% of vulnerability assessments will be agentic AI-driven.

**Implication for BIGR Discovery:** AI-powered test generation is becoming table stakes. Using LLMs to:
1. Analyze discovered assets and generate targeted test plans
2. Interpret results and provide natural-language remediation guidance
3. Adapt test strategies based on discovered defense behaviors

Sources:
- [Gartner CTEM](https://www.gartner.com/en/articles/how-to-manage-cybersecurity-threats-not-episodes)
- [SafeBreach CTEM](https://www.safebreach.com/blog/gartner-implement-a-ctem-program/)
- [Picus BAS vs Automated Pentesting](https://www.picussecurity.com/resource/blog/bas-vs-automated-pentesting-scaling-red-team-operations-with-automation)
- [AI Pentesting 2026 Guide](https://www.penligent.ai/hackinglabs/the-2026-ultimate-guide-to-ai-penetration-testing-the-era-of-agentic-red-teaming/)
- [AutoPentester](https://arxiv.org/html/2510.05605v1)
- [Cymulate vs Automated Pentesting](https://cymulate.com/blog/automated-pen-testing-vs-breach-attack-simulation/)
- [Market Evolution](https://softwareanalyst.substack.com/p/market-guide-2025-evolution-of-modern)

---

## 8. Actionable Recommendations for BIGR Discovery

### 8.1 Phased Implementation Strategy

```
PHASE 1: EXTERNAL BAS LITE (MVP - 2-3 months)
=============================================
Goal: Validate internet-facing defenses using discovered assets

Components:
- Port/service scanning (already in BIGR Discovery)
- SSL/TLS validation
- Known CVE matching (NVD + EPSS + KEV)
- HTTP security headers check
- DNS security audit (SPF/DKIM/DMARC)
- Default credential testing (common services)
- Open database exposure check

Tech Stack:
- Nuclei (Go) for template-based scanning
- nmap/masscan for port discovery (existing)
- Custom Python modules for CVE/EPSS/KEV enrichment

Differentiator: "Discover your assets, then validate their security"

---

PHASE 2: APPLICATION-LAYER BAS (3-6 months)
===========================================
Goal: Test application-level defenses

Components:
- OWASP Top 10 testing (SQLi, XSS, SSRF)
- WAF bypass validation
- API security testing
- Email gateway simulation
- Subdomain takeover detection
- Cloud misconfiguration checks

Tech Stack:
- Nuclei templates (6,500+ available)
- Custom YAML templates for specific tests
- Integration with Atomic Red Team test definitions

---

PHASE 3: FULL BAS CAPABILITY (6-12 months)
==========================================
Goal: Comprehensive security validation

Components:
- Internal agent deployment (optional)
- Lateral movement simulation
- Data exfiltration testing
- Full kill-chain scenarios
- MITRE ATT&CK heatmap reporting
- Continuous monitoring/scheduling
- AI-powered test generation

Tech Stack:
- Custom lightweight agent (Go or Rust)
- CALDERA integration for advanced scenarios
- LLM-based test plan generation
```

### 8.2 Recommended Architecture

```
+-------------------------------------------------------+
|                 BIGR Discovery Platform                 |
+-------------------------------------------------------+
|                                                         |
|  +------------------+  +------------------+             |
|  |  Asset Discovery |  |  BAS Engine      |             |
|  |  (Scanner)       |  |                  |             |
|  |                  |  |  +------------+  |             |
|  | - Port Scan      |  |  | Test       |  |             |
|  | - Service ID     +---->| Orchestrator|  |             |
|  | - SSL Check      |  |  +-----+------+  |             |
|  | - Tech Stack     |  |        |          |             |
|  +------------------+  |  +-----v------+   |             |
|                        |  | Test Runners|  |             |
|  +------------------+  |  |            |   |             |
|  |  Enrichment      |  |  | - Nuclei   |   |             |
|  |                  |  |  | - Custom   |   |             |
|  | - CVE/NVD       |  |  | - ART      |   |             |
|  | - EPSS          +---->| Templates  |   |             |
|  | - CISA KEV      |  |  +-----+------+   |             |
|  | - Exploit-DB    |  |        |          |             |
|  +------------------+  |  +-----v------+   |             |
|                        |  | Results    |   |             |
|  +------------------+  |  | Analyzer   |   |             |
|  |  Reporting       |  |  |            |   |             |
|  |                  |<----| - ATT&CK   |   |             |
|  | - ATT&CK Heatmap|  |  |   mapping  |   |             |
|  | - Risk Score     |  |  | - Scoring  |   |             |
|  | - Remediation    |  |  | - Compare  |   |             |
|  | - Trend Analysis |  |  +------------+   |             |
|  +------------------+  +------------------+             |
|                                                         |
+-------------------------------------------------------+
                          |
                     Internet
                          |
              +-----------v-----------+
              | Customer's Assets     |
              | (Internet-facing)     |
              +-----------------------+
```

### 8.3 Key Technical Decisions

| Decision | Recommendation | Rationale |
|----------|---------------|-----------|
| **Agent vs Agentless** | Start agentless (Phase 1-2) | Lower barrier to adoption, faster time-to-value |
| **Scan Engine** | Nuclei + custom modules | 6,500+ templates, Go-based (fast), MIT license, active community |
| **CVE Database** | NVD + EPSS + CISA KEV | Comprehensive prioritization (severity + probability + confirmation) |
| **ATT&CK Mapping** | Custom mapping layer | Map test results to ATT&CK techniques for standard reporting |
| **Reporting** | ATT&CK heatmap + risk score | Industry standard, easy to understand, benchmark-able |
| **Scheduling** | On-demand + continuous option | SMBs want on-demand; enterprises want continuous |
| **Safety** | Non-destructive only, rate-limited | Production safety is paramount for self-service |
| **Authorization** | In-app consent + ToS | Legal compliance without friction |

### 8.4 Competitive Positioning

```
MARKET POSITIONING:

                High Complexity
                     |
      CALDERA        |        Picus / AttackIQ
      (open source)  |        SafeBreach / Cymulate
                     |        (enterprise BAS)
                     |
   Low Cost ---------+--------- High Cost
                     |
      Nuclei /       |        Pentera / NodeZero
      nmap           |        (automated pentest)
      (point tools)  |
                     |
                Low Complexity

   BIGR Discovery Target:
   LOW COST + MEDIUM COMPLEXITY

   "The BAS that comes with your asset discovery"

   Key differentiator: No separate tool needed.
   Discover assets -> Automatically validate security.
```

### 8.5 Picus-Like Feature Parity Roadmap

| Picus Feature | BIGR Phase | Implementation |
|--------------|-----------|----------------|
| Network infiltration testing | Phase 1 | Nuclei + custom port/service tests |
| SSL/TLS validation | Phase 1 | Custom module |
| CVE-based testing | Phase 1 | NVD + EPSS + Nuclei templates |
| Email security testing | Phase 2 | SMTP test module |
| WAF bypass testing | Phase 2 | Nuclei WAF templates |
| OWASP Top 10 testing | Phase 2 | Nuclei web app templates |
| Endpoint testing | Phase 3 | Internal agent |
| Lateral movement | Phase 3 | Internal agent |
| Data exfiltration | Phase 3 | DLP test module |
| MITRE ATT&CK heatmap | Phase 1 | Reporting module |
| Vendor-specific remediation | Phase 2 | Remediation database |
| AI-powered test generation | Phase 3 | LLM integration |
| Continuous monitoring | Phase 2 | Scheduled scans |

### 8.6 Open Source Components to Leverage

| Component | License | Use In BIGR |
|-----------|---------|-------------|
| **Nuclei** | MIT | Core scanning engine for external tests |
| **Nuclei Templates** | MIT | 6,500+ ready-to-use test templates |
| **Atomic Red Team** | MIT | ATT&CK technique definitions and test logic |
| **MITRE ATT&CK** | Apache 2.0 | Framework for mapping and reporting |
| **ATT&CK Navigator** | Apache 2.0 | Heatmap visualization |
| **nmap** | Custom (free) | Port scanning (already likely in use) |
| **EPSS Data** | Open | Exploitation probability scores |
| **CISA KEV** | Public | Known exploited vulnerabilities list |
| **NVD/CVE** | Public | Vulnerability database |

### 8.7 Revenue Model Considerations

| Tier | Features | Target Price |
|------|----------|-------------|
| **Free** | Asset discovery + basic vuln check (5 assets) | $0 |
| **Starter** | External BAS (Phase 1 tests, 25 assets) | $99-199/mo |
| **Pro** | Full external BAS (Phase 1+2, 100 assets, scheduling) | $499-999/mo |
| **Enterprise** | Everything + internal agent + API + custom tests | $2,000+/mo |

**Pricing Rationale:** Cymulate starts at $7,000/mo for enterprise. BIGR targets the gap between free open-source tools (high effort) and enterprise BAS (high cost). The $99-999/mo range serves the **28% SMB market** that current vendors underserve.

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| **BAS** | Breach and Attack Simulation |
| **CTEM** | Continuous Threat Exposure Management |
| **AEV** | Adversarial Exposure Validation |
| **EASM** | External Attack Surface Management |
| **TTP** | Tactics, Techniques, and Procedures |
| **EPSS** | Exploit Prediction Scoring System |
| **KEV** | Known Exploited Vulnerabilities (CISA) |
| **CVSS** | Common Vulnerability Scoring System |
| **CART** | Continuous Automated Red Teaming |
| **ATT&CK** | Adversarial Tactics, Techniques & Common Knowledge (MITRE) |

## Appendix B: Key URLs and Resources

- MITRE ATT&CK: https://attack.mitre.org/
- MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- Nuclei: https://github.com/projectdiscovery/nuclei
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- CALDERA: https://github.com/mitre/caldera
- Infection Monkey: https://github.com/guardicore/monkey
- Stratus Red Team: https://github.com/DataDog/stratus-red-team
- EPSS: https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: https://nvd.nist.gov/

---

*Report generated: 2026-02-09 | Research scope: BAS market, open-source tools, architecture patterns, SMB approach*
*For BIGR Discovery integration planning*

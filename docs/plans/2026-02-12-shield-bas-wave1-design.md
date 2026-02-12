# BİGR Shield BAS — Wave 1 Implementation Design

**Date:** 2026-02-12
**Status:** APPROVED
**Base Design:** [Shield Full Design](2026-02-09-bigr-shield-design.md) (9.8/10 NotebookLM)
**Scope:** Wave 1 — Scan altyapisi + TLS validation + Port scan

---

## Kararlar

| Karar | Secim | Neden |
|-------|-------|-------|
| Mevcut altyapi vs bagimsiz | Mevcut altyapiyi genislet | Cert kodu var, TLS module bunu kullanir. Hizli MVP. |
| External deps (Nmap/Nuclei) | Pure Python | Kurulum bariyeri sifir. Nmap/Nuclei Wave 3'te gelir. |
| AI entegrasyonu | AI olmadan baslat | Wave 1-2 saf scan + score. AI Wave 3'te CVE analysis ile. |
| Demo mode | Demo + gercek scan paralel | Frontend mock data, backend gercek tarama. |

---

## Mimari

```
bigr/shield/
├── __init__.py
├── models.py            # ShieldScanDB, ShieldFindingDB, ShieldScoreHistoryDB
├── orchestrator.py      # Async scan job manager (asyncio.Queue)
├── scorer.py            # Shield Score hesaplama (weighted module scores)
├── api.py               # FastAPI router: /api/shield/*
├── modules/
│   ├── __init__.py
│   ├── base.py          # Abstract ScanModule class
│   ├── tls_check.py     # TLS/SSL validation (ssl + socket, mevcut cert kodunu genisletir)
│   └── port_scan.py     # TCP port tarayici (pure Python asyncio socket)
└── mock_data.py         # DEMO_MODE icin mock scan sonuclari
```

Mevcut `bigr/dashboard/app.py`'ye router eklenir. Ayri deploy yok.

---

## Data Model

### ShieldScanDB

| Alan | Tip | Aciklama |
|------|-----|----------|
| id | str | UUID (sh_xxx format) |
| target | str | IP, domain, veya CIDR |
| target_type | str | "ip" / "domain" / "cidr" |
| status | str | "queued" / "running" / "completed" / "failed" |
| scan_depth | str | "quick" / "standard" |
| shield_score | float? | 0-100 |
| grade | str? | A+ to F |
| total_checks | int | |
| passed_checks | int | |
| failed_checks | int | |
| warning_checks | int | |
| module_scores | JSON | {"tls": 85, "ports": 70} |
| created_at | datetime | |
| started_at | datetime? | |
| completed_at | datetime? | |

### ShieldFindingDB

| Alan | Tip | Aciklama |
|------|-----|----------|
| id | str | UUID |
| scan_id | str | FK -> ShieldScanDB |
| module | str | "tls" / "ports" / "headers" / "dns" |
| severity | str | "critical" / "high" / "medium" / "low" / "info" |
| title | str | "TLS 1.0 Enabled" |
| description | str | Turkce aciklama |
| remediation | str | Statik template remediation |
| target_ip | str | |
| target_port | int? | |
| evidence | JSON | Raw scan output |

### ShieldScoreHistoryDB

| Alan | Tip | Aciklama |
|------|-----|----------|
| id | str | UUID |
| target | str | |
| scan_id | str | FK -> ShieldScanDB |
| score | float | |
| grade | str | |
| scanned_at | datetime | |
| breakdown | JSON | Per-module scores |

### Score Hesaplama

```
Shield Score = Σ(module_weight × module_score) / Σ(module_weight)

Wave 1 Weights:
  tls:   30  (encryption)
  ports: 25  (attack surface)
  → Normalize: tls=54.5%, ports=45.5%

Grade Mapping:
  A+: 95-100  |  A: 90-94  |  B+: 85-89  |  B: 75-84
  C+: 70-74   |  C: 60-69  |  D: 40-59   |  F: 0-39
```

---

## Scan Modulleri

### Base Interface

```python
class ScanModule(ABC):
    name: str
    weight: int

    @abstractmethod
    async def run(self, target: str, resolved_ips: list[str]) -> ModuleResult:
        ...

@dataclass
class ModuleResult:
    module_name: str
    score: float           # 0-100
    findings: list[Finding]
    checks_total: int
    checks_passed: int
```

### TLS Module — 8 check

| Check | Pass | Fail | Severity |
|-------|------|------|----------|
| Sertifika gecerli mi | valid_to > now | Suresi dolmus | critical |
| 30 gun icinde doluyor mu | >30 gun | <30 gun | medium |
| Zincir tam mi | Full chain | Incomplete | high |
| TLS protokol | 1.2+ | 1.0/1.1 | high |
| Cipher strength | Strong (AES-GCM) | Weak (RC4, DES) | high |
| HSTS header | Var | Yok | medium |
| Key size | >=2048 bit | <2048 | medium |
| Self-signed | Hayir | Evet | low |

Pure Python: `ssl.SSLContext` + `socket` + `httpx` (HSTS icin).

### Port Scan Module

Pure Python `asyncio.open_connection` ile TCP connect scan.

- Quick: Top 100 port
- Standard: Top 1000 port
- Banner grabbing (ilk 1024 byte)
- Tehlikeli port tespiti: FTP(21), Telnet(23), SMB(445), RDP(3389), MongoDB(27017), Redis(6379)
- Service fingerprint: HTTP header, SSH banner

---

## API Endpoints

```
POST   /api/shield/scan                    # Yeni tarama baslat
GET    /api/shield/scan/{scan_id}          # Tarama durumu + sonuclar
GET    /api/shield/scan/{scan_id}/findings # Tum bulgular
GET    /api/shield/scans                   # Son taramalar listesi
DELETE /api/shield/scan/{scan_id}          # Calisan taramayi iptal et
GET    /api/shield/history/{target}        # Score gecmisi
GET    /api/shield/modules                 # Mevcut moduller
```

Scan async calisir — POST aninda "queued" doner, client polling ile bekler.
DEMO_MODE aktifken tum endpoint'ler mock data doner.

---

## Frontend

### Routes

```
/shield                    # Ana Shield sayfasi
/shield/scan/:id           # Tarama sonuc detayi
```

### Components

```
src/views/ShieldView.vue              # Ana sayfa: ScanForm + son taramalar
src/views/ShieldScanView.vue          # Tekil scan sonuc sayfasi
src/components/shield/
├── ScanForm.vue                      # Target input + depth toggle + "Tara" butonu
├── ShieldScoreGauge.vue              # Skor daire gostergesi (72/B)
├── ModuleScoreCards.vue              # TLS: 85, Ports: 70 — kart grid
├── FindingsList.vue                  # Severity + baslik + remediation accordion
└── ScanHistory.vue                   # Gecmis taramalar listesi
```

### Reuse

- `SeverityBadge.vue` — finding severity gosterimi
- `KalkanShield.vue` pattern — score gauge tasarimi
- Sidebar'a "Shield" itemi eklenir (Certificates sonrasi)

---

## Test Stratejisi

### Backend (pytest) — ~25 test

| Alan | Test | Kapsam |
|------|------|--------|
| TLS module | 8 | Valid/expired cert, weak cipher, self-signed, HSTS, key size, protocol, chain |
| Port scan module | 6 | Open/closed port, banner grab, dangerous port, timeout |
| Orchestrator | 5 | Queue, start, complete, fail, timeout |
| Scorer | 3 | Tek modul, multi-modul, grade mapping |
| API routes | 3 | Scan create, get status, list scans |

### Frontend (vitest) — ~15 test

| Alan | Test | Kapsam |
|------|------|--------|
| ScanForm | 3 | Validation, submit, depth toggle |
| ShieldScoreGauge | 3 | Renk state, grade |
| FindingsList | 3 | Severity badge, render, bos liste |
| ShieldView | 3 | Loading, sonuc, error |
| Mock data | 3 | Demo mode fonksiyonlari |

**Toplam:** ~40 test

---

## Wave 1 Deliverable

Kullanici bir domain/IP girer → TLS score + port scan sonucu + toplam Shield Score gorur.
Finding'lere tiklarsa Turkce aciklama + statik remediation template gorur.
DEMO_MODE'da mock sonuclarla calisir, demo kapali iken gercek tarama yapar.

---

*Designed by: MAX + Okan | 2026-02-12*

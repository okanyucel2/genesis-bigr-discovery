# Network Security Management Roadmap

**Tarih:** 2026-02-12
**Proje:** BİGR Discovery
**Konu:** Ev ağındaki tüm cihazlar için güvenlik kurallarını yönetme stratejisi

---

## Problem

BİGR ajanı tek bir makinede çalışıyor. Sadece kendi makinesinde iptables/pf kuralları uygulayabiliyor. Ağdaki diğer cihazların (akıllı TV, telefon, IoT) trafiğini doğrudan engelleyemiyor.

**Mevcut durum:**
- Lokal cihaz: Doğrudan engelleme (iptables/pf)
- Diğer cihazlar: Sadece izleme + kullanıcıya öneri

**Hedef:**
- Tüm ağ cihazlarını tek noktadan koruma
- Router bağımsız çalışabilme
- Router entegrasyonu mümkün olduğunda tam kontrol

---

## Temel Mimari: Discovery + Shield

BİGR iki bağımsız katman olarak çalışır. Kullanıcı ilk kurulumda sadece Discovery alır. Shield isteğe bağlı, ayrı bir kurulum adımı.

```
┌─────────────────────────────────────────────────────────────┐
│                      BİGR Discovery                         │
│  (Herhangi bir makinede — laptop, masaüstü)                 │
│                                                             │
│  ● Ağ tarama (ARP, mDNS, SSDP)                             │
│  ● Cihaz tespiti ve sınıflandırma                           │
│  ● Trafik izleme (pasif)                                    │
│  ● Tehdit istihbaratı (collective signal)                   │
│  ● Lokal koruma (iptables/pf — sadece kendi makinesi)       │
│  ● Dashboard + raporlama                                    │
└────────────────────────────┬────────────────────────────────┘
                             │ İsteğe bağlı
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                        BİGR Shield                          │
│  (Always-on cihaz — Raspberry Pi, NAS, router, Docker)      │
│                                                             │
│  ● DNS filtreleme (ağ geneli engelleme)                     │
│  ● Blocklist yönetimi (malware, reklam, tracker)            │
│  ● Router entegrasyonu (firewall kuralları)                 │
│  ● Kullanıcı özel kuralları                                 │
│  ● Otomatik güncelleme                                      │
└─────────────────────────────────────────────────────────────┘
```

### Neden Ayrı?

| Endişe | Discovery (tek başına) | Shield (ek koruma) |
|--------|------------------------|--------------------|
| Kurulum bariyeri | Düşük (tek binary/pip) | Orta (ek cihaz/yapılandırma) |
| Availability | Laptop kapanınca durur — sorun değil (sadece izleme) | 7/24 çalışmalı (koruma aktif) |
| Risk | Sıfır (pasif izleme) | Düşük (DNS yanlış yapılandırma → internet kesilir) |
| Değer | Görünürlük + farkındalık | Aktif koruma + engelleme |

**İlk kurulumda:** Kullanıcı ağını tarar, cihazlarını görür, tehditleri izler. Shield kurulmadan da BİGR değerli.

**Shield ne zaman önerilir:**
- İlk tehdit tespit edildiğinde: "Bu tehdidi kalıcı olarak engellemek ister misiniz? → Shield Kur"
- Uzak cihaz olayında: "Bu cihazı korumak için Shield gerekli → Shield Kur"
- Dashboard'da belirli bir cihaz sayısına ulaşıldığında

---

## Shield Durumu ve Timeline Aksiyonları

Timeline'daki aksiyonlar Shield durumuna göre değişir:

```
ShieldStatus:
  installed: boolean     // Shield kuruldu mu?
  online: boolean        // Shield şu an erişilebilir mi?
  deployment: 'router' | 'standalone' | 'docker' | 'none'
  capabilities: { dns: boolean, firewall: boolean }
```

### Aksiyon Matrisi

| Cihaz | Shield Durumu | Aksiyon Tipi |
|-------|---------------|--------------|
| Lokal | N/A | Doğrudan: "Kalıcı Engelle" (iptables/pf) |
| Uzak | Shield yok | Önerilen: "Shield Kur" CTA + "DNS ile Engelle" + "Router'da Engelle" |
| Uzak | Shield kurulu + çevrimiçi + firewall | Doğrudan: "Shield ile Engelle" |
| Uzak | Shield kurulu + çevrimiçi + sadece DNS | Doğrudan: "DNS ile Engelle" |
| Uzak | Shield kurulu + çevrimdışı | Uyarı: "Shield çevrimdışı" + Önerilen aksiyonlar |

---

## Phase 1: Discovery Katmanı (Mevcut)

**Durum:** Uygulandı

- Ajan makinesi üzerinde iptables/pf kuralları
- Ağ trafiği izleme (pasif)
- Diğer cihazlar için "Önerilen Aksiyon" UI
- Tehdit istihbaratı + topluluk sinyalleri
- Kural açıklama sistemi (reklam, tehdit, port koruması)
- Lokal/uzak cihaz ayrımı ile farklı mesajlar

**Kapsam:** Sadece ajanın çalıştığı makine (aktif koruma), tüm ağ (pasif izleme)

---

## Phase 2: Shield — DNS Koruma Katmanı

**Hedef:** Always-on cihaz üzerinde DNS filtreleme ile tüm ağı koruma

### Deployment Seçenekleri

| Yöntem | Hedef Kitle | Zorluk | Notlar |
|--------|-------------|--------|--------|
| **Raspberry Pi** | Teknik kullanıcılar | Düşük | Özel kurulum scripti, ~$35 donanım |
| **Docker** | Geliştiriciler / NAS sahipleri | Düşük | `docker run bigr/shield` |
| **Router üzerinde** | OpenWrt kullanıcıları | Orta | Router'ın kendi üzerinde çalışır |
| **Aynı makine** | Test / geliştirme | Düşük | Discovery ile aynı makinede (laptop kapanınca Shield de durur) |

### Mimari

```
İnternet
    │
    ▼
[Router/Modem]
    │
    ├── [BİGR Shield] ◄── DNS sunucu (port 53) — always-on cihaz
    │       │
    │       ├── Blocklist (malware, tracker, reklam)
    │       ├── Threat Intelligence feed
    │       ├── Kullanıcı kuralları (Discovery'den sync)
    │       └── Health check + fallback
    │
    ├── [BİGR Discovery] ◄── Laptop/masaüstü (izleme + yerel koruma)
    │
    ├── [Akıllı TV]     → DNS: Shield IP
    ├── [Telefon]        → DNS: Shield IP
    └── [IoT Cihazlar]   → DNS: Shield IP
```

### Discovery ↔ Shield İletişim

```
Discovery                              Shield
    │                                      │
    ├── GET /api/shield/status ────────────┤  (health check)
    ├── POST /api/shield/rules ────────────┤  (kural sync)
    ├── GET /api/shield/stats ─────────────┤  (engelleme istatistikleri)
    └── WS /api/shield/events ─────────────┤  (gerçek zamanlı olaylar)
```

### DNS Dağıtım Yöntemleri

| Yöntem | Zorluk | Kapsam | Notlar |
|--------|--------|--------|--------|
| **Manuel DNS ayarı** | Düşük | Cihaz bazlı | Kullanıcı her cihazda DNS'i Shield IP'ye ayarlar |
| **DHCP Option 6** | Orta | Tüm ağ | Router DHCP ayarından DNS sunucusunu Shield olarak belirler |
| **mDNS/DNS-SD** | Orta | Otomatik | Shield kendini DNS sunucu olarak ilan eder |
| **Router DNS override** | Düşük | Tüm ağ | Router'ın DNS forwarding'ini Shield'a yönlendirir |

### Blocklist Kaynakları

| Kaynak | İçerik | Güncelleme |
|--------|--------|------------|
| [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | Reklam + malware + tracker | Günlük |
| [OISD](https://oisd.nl/) | Kapsamlı reklam + tracker | Günlük |
| [URLhaus](https://urlhaus.abuse.ch/) | Aktif malware dağıtım URL'leri | Saatlik |
| [PhishTank](https://phishtank.org/) | Phishing URL'leri | Saatlik |
| BİGR Threat Intel | Topluluk sinyalleri + kendi istihbaratı | Gerçek zamanlı |

### Güvenli Fallback Stratejisi

**Problem:** Shield kapandığında DNS çözümleme durur → ağ internetsiz kalır.

```
DNS Çözümleme Zinciri:
┌─────────────────────────────────────────────┐
│  Primary:   BİGR Shield (192.168.1.200)     │ ← Tam koruma
│  Secondary: Quad9 (9.9.9.9)                 │ ← Temel malware koruması
│  Tertiary:  Cloudflare Family (1.1.1.3)     │ ← Temel malware + adult koruması
└─────────────────────────────────────────────┘
```

| Shield Durumu | Koruma Seviyesi | Kullanıcı Etkisi |
|---------------|-----------------|-------------------|
| Çalışıyor | Tam (blocklist + özel kurallar + threat intel) | Yok |
| Kapalı, fallback aktif | Temel (Quad9/CF malware koruması) | Özel kurallar devre dışı |
| Her şey kapalı | Yok | İnternet erişimi devam eder ama korumasız |

**Ek Önlemler:**
- **Kısa DHCP lease süresi** (5-10 dk) → Cihazlar hızla fallback DNS'e geçer
- **Discovery dashboard uyarısı** → "Shield çevrimdışı — temel koruma aktif"
- **Blocklist sync** → Shield açıkken kritik kuralları router'a da push eder (Phase 3)

### DNS Güvenliği

| Protokol | Destek | Neden Önemli |
|----------|--------|--------------|
| **DNS-over-HTTPS (DoH)** | Upstream sorgular için | ISP'nin DNS trafiğini görmesini engeller |
| **DNS-over-TLS (DoT)** | Upstream sorgular için | Alternatif şifreleme |
| **DNSSEC** | Doğrulama | DNS yanıt bütünlüğü |

### Teknik Bileşenler

```
bigr_shield/
├── dns/
│   ├── server.py           # DNS sunucu (port 53, UDP+TCP)
│   ├── blocklist.py         # Blocklist yönetimi + güncelleme
│   ├── resolver.py          # Upstream DNS çözümleme (DoH/DoT)
│   ├── cache.py             # DNS önbellek
│   └── rules.py             # Kullanıcı özel kuralları
├── api/
│   ├── status.py            # /api/shield/status endpoint
│   ├── rules.py             # /api/shield/rules endpoint
│   └── stats.py             # /api/shield/stats endpoint
├── health.py                # Servis durumu + fallback kontrolü
└── config.py                # Deployment yapılandırması
```

### Tahmini Süre: 4-5 hafta

| Hafta | Çıktı |
|-------|-------|
| 1 | Shield API + DNS sunucu + temel blocklist |
| 2 | Discovery ↔ Shield iletişim + kural sync |
| 3 | Fallback mekanizması + DHCP entegrasyonu |
| 4 | Dashboard entegrasyonu (ShieldStatus UI) |
| 5 | Docker image + Raspberry Pi kurulum scripti + test |

---

## Phase 3: Shield — Router Adapter Framework

**Hedef:** Router'ın kendi güvenlik kurallarını Shield üzerinden yönetme

### Açık Standartlar

#### TR-069 / TR-369 (USP)

- **Standart:** Broadband Forum CPE yönetim protokolü
- **Yapabilecekleri:** Firewall kuralları, DNS ayarları, WiFi yapılandırması, firmware güncelleme
- **Kullanım:** ISP'ler tarafından yaygın kullanılıyor (Türk Telekom dahil)
- **Kısıt:** Genellikle ISP kontrolünde — son kullanıcı erişimi sınırlı
- **Fırsat:** TR-369 (USP) "local agent" modunu destekliyor — ISP bağımsız kullanım mümkün
- **BİGR için:** Uzun vadede ISP ortaklığı ile en güçlü entegrasyon

#### UPnP IGD v2

- **Standart:** Universal Plug and Play Internet Gateway Device
- **Yapabilecekleri:** Port yönlendirme, bazı firewall kuralları (WANIPConnection)
- **Destek:** Çoğu consumer router destekler
- **Kısıt:** Firewall block rule desteği sınırlı — çoğunlukla port forwarding
- **Güvenlik:** UPnP güvenlik riski taşıyor — birçok router'da varsayılan kapalı
- **BİGR için:** Düşük öncelik (sınırlı yetenek + güvenlik endişesi)

#### IETF MUD (Manufacturer Usage Description - RFC 8520)

- **Standart:** IoT cihazları için ağ erişim politikası
- **Yapabilecekleri:** Cihaz üreticisi hangi domain/port'lara erişim gerektiğini belirtir
- **Destek:** Büyüyen standart, özellikle enterprise IoT'de
- **BİGR için:** IoT cihazlarına otomatik kural uygulama — BİGR MUD dosyasını okur ve uygun DNS/firewall kuralları oluşturur

### Router-Specific API'ler

| Platform | API Tipi | Firewall Kontrolü | Pazar | Öncelik |
|----------|----------|-------------------|-------|---------|
| **OpenWrt** | ubus (JSON-RPC) | Tam (iptables/nftables) | Teknik kullanıcılar, büyüyen | Yüksek |
| **Mikrotik** | REST API | Tam | SOHO/SMB | Orta |
| **UniFi** | REST API | Tam | Prosumer | Orta |
| **pfSense/OPNsense** | REST API | Tam | Power user | Orta |
| **ASUS Merlin** | SSH + nvram | Kısmi | Consumer premium | Düşük |
| **TP-Link** | Proprietary web API | Kısmi | Consumer yaygın | Düşük |
| **Türk Telekom Modem** | TR-069 (ISP kontrollü) | ISP bağımlı | TR'de yaygın | Gelecek (ISP ortaklığı) |

### Adapter Mimarisi

```typescript
interface RouterAdapter {
  // Tanıma
  detect(): Promise<RouterInfo | null>
  getCapabilities(): RouterCapabilities

  // Firewall
  addBlockRule(ip: string, direction: 'in' | 'out'): Promise<boolean>
  removeBlockRule(ruleId: string): Promise<boolean>
  listBlockRules(): Promise<BlockRule[]>

  // DNS
  setDnsServers(primary: string, secondary: string): Promise<boolean>
  getDnsServers(): Promise<string[]>

  // Bilgi
  getConnectedDevices(): Promise<Device[]>
  getTrafficStats(): Promise<TrafficStats>
}

interface RouterCapabilities {
  canManageFirewall: boolean
  canManageDns: boolean
  canListDevices: boolean
  canManageDhcp: boolean
  canMonitorTraffic: boolean
}
```

### Auto-Discovery Akışı

```
1. Shield başlatılır
2. Gateway IP tespit edilir (default route)
3. Router'a HTTP/HTTPS bağlantısı denenir
4. Yanıt header'larından / login sayfasından platform tespiti:
   - "OpenWrt" → OpenWrtAdapter
   - "UniFi" → UniFiAdapter
   - "ASUS" → AsusAdapter
   - Bilinmiyor → GenericAdapter (UPnP denemesi)
5. Discovery dashboard'a bildirim: "Router'ınız [X] olarak tespit edildi."
6. Router kimlik bilgileri istenir (bir kez, güvenli saklanır)
7. Adapter aktif → Shield capabilities güncellenir (firewall: true)
```

### UI Entegrasyonu — Capability-Based Actions

Shield + Router adapter'ın yeteneklerine göre timeline aksiyonları değişir:

```
Shield yok:
  └── Önerilen: "Shield Kur" CTA
  └── Önerilen: DNS ile Kalıcı Engelle | Router'da Kalıcı Engelle

Shield var, sadece DNS:
  └── Doğrudan: DNS ile Engelle (⚡ anında)
  └── Önerilen: Router'da Engelle (manuel)

Shield var, router adapter aktif:
  └── Doğrudan: Shield ile Engelle (⚡ anında — firewall kuralı)
  └── Doğrudan: DNS ile Engelle (⚡ anında)

Shield çevrimdışı:
  └── ⚠️ "Shield çevrimdışı" uyarısı
  └── Önerilen: Shield'ı kontrol edin
```

### Tahmini Süre: 4-6 hafta

| Hafta | Çıktı |
|-------|-------|
| 1-2 | RouterAdapter interface + auto-discovery + OpenWrt adapter |
| 3 | Shield ↔ Router adapter entegrasyonu + capability propagation |
| 4 | UI entegrasyonu (capability-based actions) + UniFi adapter |
| 5-6 | Test, ek adapter'lar (Mikrotik, pfSense), stabilizasyon |

---

## Phase 4: ISP Ortaklığı ve Gelişmiş Entegrasyon

**Hedef:** ISP router'larıyla doğrudan entegrasyon (TR-069/USP)

### Fırsatlar

- **Türk Telekom / Superonline / TurkNet:** ISP ortaklığı ile modem üzerinde BİGR Shield
- **TR-369 (USP) Local Agent:** ISP bağımsız yerel yönetim modu
- **Matter/Thread:** IoT cihaz güvenlik politikası (MUD entegrasyonu)

### Gereksinimler

- ISP ile teknik ortaklık anlaşması
- TR-069 ACS (Auto Configuration Server) veya USP Controller geliştirme
- Sertifikasyon süreci

### Tahmini Süre: 3-6 ay (iş geliştirme dahil)

---

## Kullanıcı Yolculuğu

```
1. Kurulum (5 dk)
   └── pip install bigr-discovery / docker run bigr/discovery
   └── bigr scan → Ağ taranır, cihazlar listelenir
   └── Dashboard açılır → "Evinizde 12 cihaz tespit edildi"

2. İlk Tehdit (organik)
   └── Timeline: "45.33.32.156 adresinden Akıllı TV'ye yönelik bağlantı tespit edildi"
   └── CTA: "Bu tehdidi kalıcı olarak engellemek ister misiniz? → Shield Kur"

3. Shield Kurulumu (15 dk)
   └── "Shield'ı nereye kurmak istiyorsunuz?"
       ├── Raspberry Pi (önerilen — $35, 7/24 çalışır)
       ├── Docker (NAS, sunucu)
       └── Bu makine (test için — laptop kapanınca durur)
   └── kurulum wizard → DNS yapılandırma → "Shield aktif!"

4. Aktif Koruma
   └── Timeline: "45.33.32.156 Shield ile engellendi ⚡"
   └── Tüm ağ cihazları DNS ile korunuyor
   └── Engelleme istatistikleri dashboard'da

5. Router Entegrasyonu (isteğe bağlı)
   └── "Router'ınız OpenWrt olarak tespit edildi. Entegrasyon kurmak ister misiniz?"
   └── Router credentials → tam firewall kontrolü
   └── Timeline: "Shield ile Engelle ⚡" (DNS + firewall)
```

---

## Önceliklendirme Matrisi

```
Etki
  ▲
  │  Phase 4            Phase 2
  │  (ISP ortaklığı)    (Shield: DNS)
  │   ○ Uzun vade        ● EN YÜKSEK ÖNCELİK
  │
  │  Phase 3            Phase 1
  │  (Shield: Router)    (Discovery)
  │   ○ Orta vade        ✓ Tamamlandı
  │
  └──────────────────────────▶ Yapılabilirlik
```

**Önerilen sıralama:**
1. Phase 2 (Shield: DNS) — En düşük bariyerle en büyük etki, router bağımsız
2. Phase 3 (Shield: Router Adapter) — OpenWrt ile başla, genişlet
3. Phase 4 (ISP) — İş geliştirme paralel başlayabilir

---

## Başarı Metrikleri

| Metrik | Phase 1 (Discovery) | Phase 2 (Shield: DNS) | Phase 3 (Shield: Router) |
|--------|---------------------|-----------------------|--------------------------|
| Korunan cihaz sayısı | 1 (lokal) | Tüm ağ | Tüm ağ |
| Engelleme yöntemi | iptables/pf | DNS sinkhole | Firewall kuralları |
| Availability | %100 (lokal) | %95+ (fallback ile) | %99+ (router üzerinde) |
| Kullanıcı etkileşimi | Manuel kural | Otomatik blocklist | Otomatik + manuel |
| Router bağımlılığı | Yok | Yok | Var (adapter gerekli) |
| Kurulum bariyeri | Düşük | Orta (ek cihaz) | Orta (router credentials) |

---

## Riskler ve Azaltma

| Risk | Etki | Azaltma |
|------|------|---------|
| Shield cihazı kapandığında DNS kesilir | Ağ kesintisi | Güvenli fallback DNS (Quad9/CF Family) |
| DNS port 53 erişim kısıtlaması | DNS çalışmaz | DoH (443 portu) alternatifi |
| Router API değişiklikleri | Adapter bozulur | Versiyon pinleme + adapter test suite |
| ISP DNS zorlama (DNS hijacking) | Shield DNS bypass edilir | DoH/DoT ile şifreleme |
| Çok sayıda blocklist = yavaşlık | Performans | Bloom filter + önbellek + incremental güncelleme |
| Router kimlik bilgileri güvenliği | Bilgi sızıntısı | OS keychain + şifreleme |
| Discovery ↔ Shield bağlantı kopması | Kural sync duraklar | Local cache + retry + offline indicator |

---

*Hazırlayan: MAX | Tarih: 2026-02-12 | Güncelleme: Discovery/Shield mimarisi*

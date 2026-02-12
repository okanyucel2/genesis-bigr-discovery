# BİGR Discovery — Kayıp Halkalar Tasarım Dokümanı

**Tarih:** 2026-02-11
**Durum:** TASARIM TASLAĞI
**Kaynak:** Council Thread `council_92e5da2bad63` — Sektörel Liderler DNA Analizi
**Katkıda Bulunan:** StrategyOps (Gemini), MAX (Claude Code)

---

## Bağlam

Bu doküman, StrategyOps'un sektörel benchmark analizinde tespit ettiği 5 kritik boşluğu ve Family Mesh mimari önerisini teknik tasarıma dönüştürür. Her boşluk için: problem, referans lider, mevcut BİGR durumu, teknik çözüm ve implementasyon detayı sunulur.

**Referans Liderler:** Fing, Little Snitch, Picus/Cymulate, Waze, Duolingo

---

## Gap 1 — Passive mDNS Discovery (Fing Kalitesi)

### Problem
BİGR şu anda cihaz keşfinde ARP sweep + Nmap kullanıyor. Bu yöntem IP/MAC/OS bulur ama cihazın gerçek kimliğini ("Salon Apple TV'si", "Philips Hue Bridge v2") ortaya çıkaramaz. Fing bunu mDNS (Bonjour) ve UPnP yayınlarını dinleyerek çözer.

### Mevcut Durum
- `bigr/scanner/arp_scanner.py` — ARP sweep, MAC vendor lookup
- `bigr/scanner/port_scanner.py` — Nmap tabanlı port/OS tespiti
- `bigr/core/classifier.py` — MAC OUI + port pattern ile sınıflandırma
- Eksik: mDNS/UPnP pasif dinleme yok

### Teknik Tasarım

#### Yeni Modül: `bigr/scanner/mdns_listener.py`

**Yaklaşım:** Pasif mDNS listener (zeroconf kütüphanesi). Ağdaki `_tcp.local.` servis yayınlarını dinler, cihaz kimliği çıkarır.

**Desteklenen Servis Tipleri:**
| mDNS Servis | Cihaz Tipi | Örnek |
|---|---|---|
| `_googlecast._tcp` | Chromecast / Google TV | "Salon TV" |
| `_airplay._tcp` | Apple TV / AirPlay cihaz | "Apple TV 4K" |
| `_ipp._tcp` / `_printer._tcp` | Yazıcı | "HP LaserJet Pro" |
| `_hap._tcp` | HomeKit aksesuar | "Philips Hue Bridge" |
| `_spotify-connect._tcp` | Spotify cihaz | "Sonos One" |
| `_raop._tcp` | AirPlay ses | "HomePod Mini" |
| `_smb._tcp` | NAS / dosya paylaşımı | "Synology DS220+" |
| `_http._tcp` (with "tname") | Genel IoT | Çeşitli |

**Veri Akışı:**
```
mDNS Listener (pasif, 30sn)
  ↓
ServiceDiscovery { ip, mac, service_type, device_name, model, manufacturer }
  ↓
Classifier enrichment (mevcut MAC OUI'ye ek olarak)
  ↓
AssetDB güncelleme (friendly_name, device_model, device_manufacturer)
```

**AssetDB Yeni Alanlar:**
| Alan | Tip | Açıklama |
|---|---|---|
| `friendly_name` | String, nullable | mDNS'den gelen cihaz adı ("Salon TV") |
| `device_model` | String, nullable | Model bilgisi ("Chromecast with Google TV") |
| `device_manufacturer` | String, nullable | Üretici (mDNS > MAC OUI fallback) |
| `mdns_services` | JSON, nullable | Bulunan servis listesi |

**Daemon Entegrasyonu:**
```python
# bigr/agent/daemon.py — _run_single_cycle() içinde
# ARP sweep SONRASI, Nmap ÖNCESI çalışır (30 saniye timeout)
mdns_results = await mdns_listener.discover(timeout=30)
for result in mdns_results:
    enrich_asset(result)  # Mevcut asset'i zenginleştirir
```

**Bağımlılık:** `zeroconf>=0.131.0` (pure Python, no native deps)

**Dashboard Etkisi:**
- Onboarding'de "Samsung cihazı" yerine "Samsung Galaxy S24" gösterilir
- "Evim" kartında gerçek cihaz isimleri ve modelleri
- Cihaz grid'de zengin ikonlar + model bilgisi

---

## Gap 2 — Privacy Visibility / Tracker Blocker (Little Snitch Etkisi)

### Problem
Kullanıcılar BİGR'i "güvenlik" için değil "gizlilik" için de kullanmak ister. "Port 445 kapalı" değil, "Akıllı TV'niz Çin'deki reklam sunucusuna bağlanmaya çalıştı ve engellendi" mesajı etki yaratır.

### Mevcut Durum
- `bigr/firewall/service.py` — IP bazlı engelleme mevcut
- `bigr/shield/modules/tls_check.py` — TLS bağlantı kontrolü mevcut
- `bigr/language/humanizer.py` — Doğal dil çevirisi mevcut
- Eksik: Tracker/reklam domain listesi, outbound traffic analizi, tracker sayacı

### Teknik Tasarım

#### Yeni Modül: `bigr/privacy/tracker_intelligence.py`

**Tracker Veritabanı Kaynakları (açık kaynak):**
| Kaynak | İçerik | Güncelleme |
|---|---|---|
| [EasyList](https://easylist.to/) | Reklam domainleri | Günlük |
| [Disconnect.me](https://disconnect.me/trackerprotection) | Tracker kategorileri | Haftalık |
| [Peter Lowe's List](https://pgl.yoyo.org/adservers/) | Ad server listesi | Günlük |
| [NextDNS CNAME cloaking](https://github.com/nickoala/cname-tracker) | CNAME gizleme | Aylık |

**Veri Modeli:**
```python
class TrackerDB(Base):
    __tablename__ = "trackers"
    id = Column(String, primary_key=True)
    domain = Column(String, unique=True, nullable=False)
    category = Column(String)  # "advertising", "analytics", "social", "fingerprinting"
    company = Column(String)   # "Google", "Facebook", "Adobe"
    risk_level = Column(String) # "low", "medium", "high"

class TrackerEvent(Base):
    __tablename__ = "tracker_events"
    id = Column(String, primary_key=True)
    asset_ip = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    category = Column(String)
    action = Column(String)  # "blocked", "detected", "allowed"
    timestamp = Column(String, nullable=False)
```

**Firewall Entegrasyonu:**
```python
# bigr/firewall/service.py — mevcut sync_threat_rules() yanına
async def sync_tracker_rules(self) -> int:
    """EasyList + Disconnect.me'den tracker domainlerini firewall'a ekle."""
    tracker_domains = await tracker_intelligence.get_block_list()
    rules_created = 0
    for domain in tracker_domains:
        rule = self._create_dns_block_rule(domain, source="tracker_intelligence")
        rules_created += 1
    return rules_created
```

**Dashboard "Verilerim" Kartı Zenginleştirmesi:**
```
🔐 Verilerim
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Tüm bağlantılarınız şifreli
🚫 Bu hafta 127 takipçi engellendi
   ├─ 42 reklam sunucusu
   ├─ 61 analitik takipçi
   ├─ 18 sosyal medya pikseli
   └─ 6 parmak izi okuyucu

⚠️ Akıllı TV'niz (Samsung) dün gece
   3 farklı reklam sunucusuna bağlanmaya çalıştı.
   [Detaylar →]
```

**Timeline Olayı (Humanizer ile):**
```
🛡 1 saat önce
"Buzdolabınız (Samsung) Çin'deki bir analitik sunucuya
 veri göndermeye çalıştı. Engellendi."          [Detay →]
```

**API Endpoint'leri:**
| Method | Path | Açıklama |
|---|---|---|
| GET | `/api/privacy/stats` | Engellenen tracker istatistikleri |
| GET | `/api/privacy/events` | Son tracker olayları (timeline için) |
| POST | `/api/privacy/sync` | Tracker listelerini güncelle |
| GET | `/api/privacy/device/{ip}` | Cihaz bazlı tracker raporu |

---

## Gap 3 — IoT Safe Mode (Picus Güvenliği)

### Problem
Shield Engine, Nuclei ile enterprise kalitesinde güvenlik taraması yapıyor. Ancak evdeki eski bir IP kameraya veya akıllı buzdolabına aktif exploit göndermek cihazı kilitleyebilir (brick). Picus/Cymulate bunu "non-destructive testing" ile çözer.

### Mevcut Durum
- `bigr/shield/orchestrator.py` — Modül bazlı tarama orkestasyonu
- `bigr/shield/modules/nuclei_check.py` — Aktif vulnerability tarama
- `bigr/shield/modules/port_check.py` — Port tarama
- `bigr/shield/modules/tls_check.py` — TLS kontrol
- `bigr/core/classifier.py` — Cihaz tipi sınıflandırma (iot, ag_ve_sistemler, vb.)
- Eksik: Cihaz hassasiyet profili, modül bazlı güvenli mod

### Teknik Tasarım

#### Cihaz Hassasiyet Profili

**Hassas Cihaz Kategorileri:**
| Kategori | Örnekler | Risk |
|---|---|---|
| `iot_camera` | IP kamera, bebek monitörü | Firmware crash, brick |
| `iot_appliance` | Buzdolabı, çamaşır makinesi | Factory reset riski |
| `iot_sensor` | Sıcaklık, nem sensörü | Kalibrasyon kaybı |
| `iot_hub` | Hue Bridge, SmartThings | Tüm bağlı cihazları etkiler |
| `medical` | Sağlık cihazları | Hayati risk |
| `legacy` | Eski OS, güncellenmemiş | Exploit'e kırılgan |

**Classifier Güncelleme:**
```python
# bigr/core/classifier.py — mevcut sınıflandırmaya ek
def get_device_sensitivity(device_type: str, os_info: str | None) -> str:
    """Return 'safe', 'cautious', or 'fragile'."""
    FRAGILE = {"iot_camera", "iot_appliance", "iot_sensor", "iot_hub", "medical"}
    CAUTIOUS = {"iot", "legacy", "printer"}

    if device_type in FRAGILE:
        return "fragile"
    if device_type in CAUTIOUS:
        return "cautious"
    return "safe"
```

**Shield Orchestrator Güncelleme:**
```python
# bigr/shield/orchestrator.py — modül seçim mantığı
def _select_modules(self, target: str, depth: str, sensitivity: str) -> list:
    modules = []

    if sensitivity == "fragile":
        # Sadece pasif tarama
        modules = ["port_check", "tls_check", "banner_grab"]
        # Nuclei, exploit, fuzzing ASLA çalışmaz
    elif sensitivity == "cautious":
        # Port + TLS + info-level Nuclei (exploit yok)
        modules = ["port_check", "tls_check", "nuclei_info_only"]
    else:
        # Tam tarama (mevcut davranış)
        modules = self._get_all_modules(depth)

    return modules
```

**Dashboard Gösterimi:**
```
🏠 Evim
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📷 IP Kamera (Xiaomi) — 🛡 Güvenli Mod
   "Hassas cihaz — sadece pasif tarama yapılıyor"

🖨 Yazıcı (HP) — ⚡ Normal Tarama
   Son tarama: 2 saat önce ✅

🧊 Buzdolabı (Samsung) — 🛡 Güvenli Mod
   "Firmware hassasiyeti nedeniyle dikkatli taranıyor"
```

**Kullanıcı Kontrolü:**
Cihaz detay sayfasında toggle:
```
Tarama Modu: [Güvenli 🛡] [Normal ⚡] [Tam 🔬]
⚠️ "Tam mod" IoT cihazlarda firmware sorununa neden olabilir.
```

---

## Gap 4 — Guest Network Loop (Waze Viral Büyümesi)

### Problem
BİGR'in organik büyüme mekanizması yok. Waze her kullanıcıyı bir "trafik polisi"ne dönüştürüyor. BİGR de her ev sahibini bir "güvenlik elçisi"ne dönüştürmeli.

### Mevcut Durum
- `bigr/agent/network_fingerprint.py` — Ağ parmak izi (gateway MAC + SSID)
- `bigr/collective/` — Waze Effect topluluk istihbaratı zaten mevcut
- `bigr/family/` — Family Shield aile cihaz yönetimi mevcut
- Eksik: Misafir algılama, davet mekanizması, referral tracking

### Teknik Tasarım

#### Yeni Modül: `bigr/growth/guest_network.py`

**Akış:**
```
1. Yeni cihaz ağa bağlanır (mevcut asset discovery algılar)
   ↓
2. Cihaz "tanınmıyor" → Kullanıcıya bildirim:
   "Ağınıza yeni bir iPhone 16 bağlandı.
    [Tanıyorum] [Misafirim] [Engelle]"
   ↓
3. "Misafirim" seçilirse:
   → 24 saatlik güvenli misafir profili oluşturulur
   → Paylaşım linki üretilir:
     "Misafirinize güvenli internet hediye edin!
      bigr.app/guest/abc123"
   ↓
4. Misafir linke tıklar:
   → BİGR landing page: "Ev sahibiniz size güvenli internet sağlıyor"
   → "Kendi evinizi de koruyun" CTA
   → App store yönlendirmesi
   ↓
5. Tracking:
   → GuestInvite { host_id, guest_device_mac, invite_link, claimed, converted }
```

**Veri Modeli:**
```python
class GuestInvite(Base):
    __tablename__ = "guest_invites"
    id = Column(String, primary_key=True)
    host_subscription_id = Column(String, nullable=False)
    guest_device_mac = Column(String)
    guest_device_name = Column(String)
    invite_code = Column(String, unique=True)
    status = Column(String)  # "pending", "claimed", "converted", "expired"
    expires_at = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    claimed_at = Column(String, nullable=True)
```

**Gamification — Referral Rewards:**
```
🎖 Güvenlik Elçisi Seviyesi
━━━━━━━━━━━━━━━━━━━━━━━━━━━
🥉 Bronz: 1 davet → +1 hafta Pro özellik
🥈 Gümüş: 5 davet → +1 ay Pro özellik
🥇 Altın: 10 davet → Kalıcı %20 indirim
💎 Elmas: 25 davet → 1 ay ücretsiz Family Shield
```

**API Endpoint'leri:**
| Method | Path | Açıklama |
|---|---|---|
| POST | `/api/growth/guest-invite` | Misafir daveti oluştur |
| GET | `/api/growth/guest-invite/{code}` | Davet detayı (landing page) |
| POST | `/api/growth/guest-invite/{code}/claim` | Daveti kabul et |
| GET | `/api/growth/referral-stats` | Referral istatistikleri |

---

## Gap 5 — Safety Streak (Duolingo Bağımlılığı)

### Problem
Dashboard'daki güvenlik skoru statik. Kullanıcının uygulamayı silmemesi için "kaybetme korkusu" (loss aversion) yok. Duolingo'nun "streak" mekanizması insanları dil öğrenmekten çok seriyi bozmamak için motive ediyor.

### Mevcut Durum
- Güvenlik skoru mevcut (Shield + Compliance + Risk birleşimi)
- Timeline mevcut (olaylar kronolojik)
- Eksik: Streak sayacı, streak kırılma uyarıları, gamification

### Teknik Tasarım

#### Yeni Modül: `bigr/engagement/streak.py`

**Streak Kuralları:**
```python
@dataclass
class StreakConfig:
    # Streak DEVAM eder eğer:
    # - Son 24 saatte en az 1 başarılı tarama yapıldıysa
    # - Kritik güvenlik açığı 48 saat içinde ele alındıysa
    # - Bilinmeyen cihaz 24 saat içinde onaylandı/engellendiyse

    # Streak KIRILIR eğer:
    # - 48+ saat tarama yapılmadıysa (agent offline)
    # - Kritik açık 72 saat boyunca ele alınmadıysa
    # - Kırmızı alarm 48 saat boyunca görmezden gelindiyse

    scan_interval_hours: int = 48
    critical_response_hours: int = 72
    alert_response_hours: int = 48
```

**Veri Modeli:**
```python
class SafetyStreak(Base):
    __tablename__ = "safety_streaks"
    id = Column(String, primary_key=True)
    subscription_id = Column(String, nullable=False)
    current_streak_days = Column(Integer, default=0)
    longest_streak_days = Column(Integer, default=0)
    streak_start_date = Column(String)
    last_check_date = Column(String)
    streak_broken_count = Column(Integer, default=0)
    total_safe_days = Column(Integer, default=0)
```

**Streak Gösterimi (Kalkan alanı):**
```
🛡 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Aileniz güvende.

   🔥 42 Gün Kesintisiz Güvende
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   En uzun seri: 67 gün | Toplam: 128 güvenli gün
```

**Push Notification'lar (streak motivasyonu):**
```
🔥 "35 günlük seriniz devam ediyor! Harika gidiyorsunuz."

⚠️ "Dikkat! Tarama 36 saattir yapılamadı.
    Seriniz 6 saat içinde kırılacak.
    [Şimdi Tara]"

💔 "42 günlük seriniz kırıldı.
    Endişelenmeyin, yeniden başlayabilirsiniz!
    [Yeni Seri Başlat]"

🎉 "Tebrikler! 100 gün kesintisiz güvende!
    Ailenizi koruyan bir şampiyon gibisiniz. 🏆"
```

**Milestone Rozetleri:**
| Gün | Rozet | Başlık |
|---|---|---|
| 7 | 🛡 | İlk Hafta |
| 30 | 🔥 | Aylık Koruyucu |
| 90 | ⭐ | Çeyrek Şampiyonu |
| 180 | 🏅 | Yarı Yıl Kahramanı |
| 365 | 🏆 | Yılın Kalkanı |

**API Endpoint'leri:**
| Method | Path | Açıklama |
|---|---|---|
| GET | `/api/engagement/streak` | Mevcut streak durumu |
| GET | `/api/engagement/streak/history` | Streak geçmişi |
| GET | `/api/engagement/badges` | Kazanılan rozetler |
| POST | `/api/engagement/streak/check` | Manuel streak kontrolü |

---

## Mimari Gap — Family Mesh Protocol

### Problem
Family Shield vaadi: "Baba ofiste, çocuk okulda, anne evde = Tek dashboard". Ancak Roaming belgesi (`network_fingerprint`) cihazın hangi ağda olduğunu buluyor ama farklı fiziksel ağlardaki cihazları birleştirmiyor.

### Mevcut Durum
- `bigr/agent/network_fingerprint.py` — Ağ kimliği (gateway MAC + SSID)
- `bigr/family/` — Family Shield (cihaz-aile eşleştirme)
- `bigr/agent/routes.py` — Ingest endpoint (scan sonuçları)
- Eksik: Cross-network heartbeat, family_uuid propagation

### Teknik Tasarım

#### Family Mesh Heartbeat

**Konsept:** Her BİGR agent'ı kurulumda bir `family_uuid` alır. Agent scan sonuçlarıyla birlikte heartbeat gönderir. Backend farklı ağlardaki agent'ları aynı aile altında birleştirir.

**Onboarding Akışı:**
```
1. İlk cihaz (Baba'nın telefonu) BİGR kurar
   → family_uuid üretilir: "fam_abc123"
   → QR kod gösterilir

2. İkinci cihaz (Anne'nin telefonu) BİGR kurar
   → "Mevcut bir aileye katılmak ister misiniz?"
   → QR kod tarar veya davet kodu girer
   → Aynı family_uuid ile bağlanır

3. Her cihaz kendi ağında bağımsız tarama yapar
   → Heartbeat: { family_uuid, agent_id, network_id, devices[], timestamp }
```

**Heartbeat Payload (IngestDiscoveryRequest'e ek):**
```python
class FamilyHeartbeat(BaseModel):
    family_uuid: str
    agent_id: str
    network_id: str | None
    network_name: str | None  # "Ev WiFi", "Ofis WiFi"
    device_count: int
    shield_status: str  # "green", "yellow", "red"
    last_scan_at: str
    streak_days: int
```

**Backend Birleştirme:**
```python
# bigr/family/mesh.py
async def get_family_dashboard(family_uuid: str) -> FamilyMeshView:
    """Tüm family agent'larından gelen heartbeat'leri birleştir."""
    agents = await get_family_agents(family_uuid)

    return FamilyMeshView(
        family_uuid=family_uuid,
        locations=[
            MeshLocation(
                name=agent.network_name,  # "Ev", "Ofis", "Okul"
                agent_id=agent.agent_id,
                status=agent.shield_status,
                device_count=agent.device_count,
                last_seen=agent.last_heartbeat,
                devices=agent.devices
            )
            for agent in agents
        ],
        total_devices=sum(a.device_count for a in agents),
        family_streak=min(a.streak_days for a in agents),
        overall_status=worst_status(agents)
    )
```

**Dashboard "Ailem" Kartı (Mesh ile):**
```
👨‍👩‍👧‍👦 Ailem
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🏠 Ev (5 cihaz) ✅ güvende
   Anne'nin iPhone'u, Ali'nin iPad'i, TV, yazıcı, buzdolabı

🏢 Ofis (2 cihaz) ✅ güvende
   Baba'nın MacBook'u, Baba'nın iPhone'u

🏫 Okul (1 cihaz) ⚠️ 1 uyarı
   Ali'nin okul tablet'i — güncelleme gerekiyor

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Toplam: 3 lokasyon, 8 cihaz | 🔥 42 gün güvende
```

**API Endpoint'leri:**
| Method | Path | Açıklama |
|---|---|---|
| POST | `/api/family/mesh/heartbeat` | Agent heartbeat gönder |
| GET | `/api/family/mesh/dashboard` | Birleşik aile dashboard |
| POST | `/api/family/mesh/join` | Aileye katıl (QR/kod) |
| GET | `/api/family/mesh/locations` | Aktif lokasyonlar |

---

## Implementasyon Önceliklendirme

| Öncelik | Gap | Etki | Efor | Bağımlılık |
|---|---|---|---|---|
| P0 | **IoT Safe Mode** (Gap 3) | Kritik — cihaz brick riski | Düşük | Classifier + Orchestrator |
| P1 | **mDNS Discovery** (Gap 1) | Yüksek — UX kalitesi | Orta | zeroconf kütüphanesi |
| P1 | **Safety Streak** (Gap 5) | Yüksek — retention | Orta | Timeline + Push altyapısı |
| P2 | **Tracker Blocker** (Gap 2) | Yüksek — değer algısı | Orta | Firewall + DNS bloklama |
| P2 | **Family Mesh** (Mimari) | Yüksek — ürün vaadi | Yüksek | Heartbeat + multi-agent |
| P3 | **Guest Loop** (Gap 4) | Orta — büyüme | Orta | Landing page + referral |

**Faz 1 (Hemen):** IoT Safe Mode + Safety Streak
**Faz 2 (Kısa vadeli):** mDNS Discovery + Tracker Blocker
**Faz 3 (Orta vadeli):** Family Mesh Protocol
**Faz 4 (Uzun vadeli):** Guest Network Loop + Referral sistemi

---

## BİGR Altyapı Eşleştirmesi

| Gap | Kullanan Dashboard Elementi | Mevcut Altyapı | Yeni Altyapı |
|---|---|---|---|
| mDNS Discovery | Onboarding + Evim kartı | ARP scanner, classifier | mdns_listener |
| Tracker Blocker | Verilerim kartı + Timeline | Firewall, TLS check | tracker_intelligence |
| IoT Safe Mode | Evim kartı (cihaz detay) | Shield orchestrator | sensitivity profili |
| Guest Loop | Evim kartı (yeni cihaz) | Asset discovery | guest_network, referral |
| Safety Streak | Kalkan alanı (üst) | Shield skoru | streak engine |
| Family Mesh | Ailem kartı | Family Shield, roaming | mesh heartbeat |

---

## Sonuç

Bu 6 ekleme, BİGR'i teknik bir "araç"tan büyüyen, koruyan ve vazgeçilmeyen bir "ürün"e dönüştürecektir:

1. **mDNS** → "Cihazlarınızı biz tanırız" (Fing kalitesi)
2. **Tracker Blocker** → "Gizliliğinizi biz koruruz" (Little Snitch etkisi)
3. **IoT Safe Mode** → "Cihazlarınıza zarar vermeyiz" (Picus güvenliği)
4. **Guest Loop** → "Arkadaşlarınızı da koruyun" (Waze büyümesi)
5. **Safety Streak** → "Serinizi bozmayın" (Duolingo bağımlılığı)
6. **Family Mesh** → "Aileniz nerede olursa olsun" (Benzersiz değer)

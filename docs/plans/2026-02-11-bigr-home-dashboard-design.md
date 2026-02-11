# BİGR Discovery — Ev Kullanıcısı Dashboard Tasarımı

**Tarih:** 2026-02-11
**Durum:** TASARIM ONAYLI
**Felsefe:** Enterprise altyapı, ev kullanıcısı yüzeyi. Progressive disclosure ile herkesin seviyesine uyum.

---

## Temel İlkeler

1. **İnsan merkezli, altyapı merkezli değil.** "12 açık port" yerine "Ali'nin tableti güvende mi?"
2. **Basit başla, derinleş.** Varsayılan = ev kullanıcısı. Gelişmiş mod = toggle ile açılır.
3. **Tek dashboard, adaptif karmaşıklık.** Ayrı modlar/persona yok. Tek arayüz, kademeli açılım.
4. **Mobil öncelikli.** %70 kullanım telefondan. Ebeveyn okuldan çocuğunu alırken bakar.

---

## 1. Onboarding — "AI Rehberli Tanışma"

### Adım 1 — Otomatik Keşif (~30 saniye)

Animasyonlu radar/pulse efekti. "Evinizi tanıyorum..." mesajı. Arka planda hibrit tarama çalışır. Bulunan cihazlar birer birer ekrana düşer — her biri MAC vendor'dan tahmin edilen ikonla belirir (telefon, laptop, TV, yazıcı, robot süpürge, akıllı buzdolabı, güvenlik kamerası, vb.).

### Adım 2 — AI Sohbet ile Cihaz Eşleştirme

Klasik form yerine sohbet formatında tanımlama:

> 🛡 BİGR: "Evinizde 11 cihaz buldum! Birkaç soru sorarak onları tanımak istiyorum."
>
> "Bu Samsung cihazı büyük ihtimalle bir akıllı TV. Salon TV'niz mi?"
>
> Kullanıcı: [Evet, salonumuzda] [Hayır, yatak odası] [Bu ne bilmiyorum]
>
> 🛡 BİGR: "Tamam! Bir de bu Apple cihazı — muhtemelen iPhone. Kimin telefonu?"
>
> Kullanıcı: [Benim] [Eşimin] [Çocuğumun] [İsim yazayım...]

**Tasarım kuralları:**
- Tek tek sorular, bunaltmaz (11 cihaz formu vs 11 kısa sohbet)
- AI tahminleri MAC vendor + cihaz tipinden %80 doğru başlar
- "Bilmiyorum" her zaman geçerli, baskı yok
- Hiçbir şey yazmak zorunda değil, sadece seçim butonları

**IoT zenginliği:** Yazıcı, robot süpürge, akıllı buzdolabı, bebek monitörü, güvenlik kamerası, akıllı priz, AI robot — hepsi kendi ikonuyla gelir.

### Adım 3 — "Koruma Başladı"

Yeşil kalkan animasyonu. "4 kişi, 11 cihaz. Aileniz artık koruma altında." İlk Shield taraması otomatik başlar. Doğrudan dashboard'a geçiş.

**Toplam süre:** ~2 dakika. Tek bir teknik terim yok.

---

## 2. Ana Dashboard — "Ev Kalkanı"

Tek sayfa, scroll ile derinleşiyor. 3 alan: Kalkan (üst), Hayat Kartları (orta), Zaman Çizelgesi (alt).

### 2.1 Üst Alan — "Kalkan" (Ekranın ~%40'ı)

Büyük, nefes alan alan. Ortasında tek element:

**Kalkan görseli** — Canlı, animasyonlu kalkan ikonu:
- **Yeşil + parlama:** Her şey yolunda. Hafif pulse (canlı hissiyat).
- **Sarı + yavaş titreşim:** Dikkat gerektiren şeyler var.
- **Kırmızı + alarm pulse:** Acil aksiyon gerekli.

**Doğal dil durum cümlesi** (kalkanın altında):

> ✅ "Aileniz güvende. 12 cihaz korunuyor, son 24 saatte 3 tehdit engellendi."

> ⚠️ "Ali'nin tabletinde güvenlik güncellemesi gerekiyor. 1 dakikanızı alır."

> 🔴 "Ağınıza tanımadığınız bir cihaz bağlandı. Kontrol edin."

**Mikro-veri** (subtle, küçük font, kalkan altında):

```
Güvenlik Skoru: 87/100  |  Cihazlar: 12  |  Bu ay engellenen: 47 tehdit
```

Görmek isteyen görür, görmek istemeyen rahatsız olmaz.

### 2.2 Orta Alan — "Hayatım" (4 Kart, 2x2 Grid)

Her kart bir hayat alanını kapsıyor. Mobilde dikey liste.

#### Kart 1 — "Verilerim" 🔐

Kullanıcının kişisel veri güvenliği.

> **Korunaklı** — Tüm bağlantılarınız şifreli. 3 cihazda HTTPS doğrulandı.

**Arka plan:** TLS sertifika kontrolü, DNS güvenliği, şifresiz trafik tespiti.
**Tıklarsa:** Hangi cihazda hangi bağlantı şifreli/şifresiz, sertifika detayları.

#### Kart 2 — "Ailem" 👨‍👩‍👧‍👦

Aile üyelerinin cihaz durumu.

> **Ali** — iPad ✅ güvende
> **Ayşe** — iPhone ⚠️ 1 uyarı
> **Misafir ağı** — 2 cihaz bağlı

**Arka plan:** Family Shield, cihaz bazlı Shield tarama, credential check.
**Tıklarsa:** Kişi bazlı cihaz listesi, her cihazın detaylı güvenlik raporu.

#### Kart 3 — "Evim" 🏠

Akıllı ev ve IoT cihazları.

> **11 cihaz ağda** — Hepsi tanınıyor ✅
> Yazıcı, TV, buzdolabı, robot süpürge, 2 kamera...

Uyarı durumunda:

> **⚠️ Tanımadığınız bir cihaz bağlandı**
> Xiaomi cihazı — 14:32'de ağınıza katıldı. [Tanıyorum] [Engelle]

**Arka plan:** Asset discovery, MAC vendor lookup, yeni cihaz alertleri, açık port tarama.
**Tıklarsa:** Cihaz grid'i, her cihazın detayı.

#### Kart 4 — "Bölgem" 🌍

Mahalle/şehir bazlı tehdit durumu.

> **İstanbul'da bu hafta:** 1.2K phishing saldırısı engellendi
> Sizin bölgenizde aktif tehdit yok ✅

**Arka plan:** Collective Intelligence (Waze Effect), AbuseIPDB bölgesel veri, anonim topluluk sinyalleri.
**Tıklarsa:** Harita görünümü, trend grafikleri, topluluk katkı durumu.

### 2.3 Alt Alan — "Zaman Çizelgesi" (Timeline)

Sosyal medya feed'i gibi ama güvenlik olayları için. BİGR Guardian personası konuşuyor:

```
🛡 Şimdi
"Rutin tarama tamamlandı. Her şey yolunda."

🛡 2 saat önce
"Ali'nin iPad'inde bir uygulama konum verinizi paylaşmak istedi.
 Engellendi."                                          [Detay →]

🛡 Bugün 09:14
"Misafir ağınıza yeni bir Samsung telefon bağlandı.
 Siz onaylayana kadar internet erişimi kısıtlandı."   [Tanıyorum] [Engelle]

🛡 Dün
"Komşularınızdan 3 kişi bu hafta aynı phishing sitesini
 bildirdi. Siz zaten korunuyorsunuz."                  [Detaylar →]

🛡 2 gün önce
"Aylık güvenlik raporunuz hazır. Skor: 87 → 91 🎉
 Geçen ay 47 tehdit engellendi."                       [Raporu Gör →]
```

**Progressive Disclosure:** Her olayda [Detay →] butonu. Tıklayınca teknik detay açılır — IP adresi, port, kural adı, MITRE ATT&CK tekniği. Ev kullanıcısı asla tıklamaz, ileri kullanıcı her zaman tıklar.

**Arka plan:** Language Engine (Humanizer) her firewall olayını, Shield bulgusunu, asset değişikliğini doğal dile çeviriyor. Altyapı zaten mevcut.

---

## 3. Navigasyon — "Basit Başla, Derinleş"

### 3.1 Varsayılan Sidebar (Basit Mod) — 5 item

```
🛡  Ana Ekran          ← Kalkan + 4 kart + timeline
👨‍👩‍👧‍👦  Ailem              ← Aile üyeleri ve cihazları
🏠  Cihazlarım         ← Tüm ev cihazları grid görünümü
🔔  Bildirimler        ← Okunmamış uyarılar
⚙️  Ayarlar            ← Profil, entegrasyonlar, tercihler
```

Kullanıcı asla kaybolmaz. 5 item, hepsi Türkçe, hepsi anlaşılır.

### 3.2 Gelişmiş Mod Toggle

Ayarlar sayfasında veya sidebar'ın en altında:

```
◻ Gelişmiş Görünüm
```

Açıldığında sidebar kademeli olarak genişler:

```
🛡  Ana Ekran
👨‍👩‍👧‍👦  Ailem
🏠  Cihazlarım

── GÜVENLİK ──────────
🔍  Shield Tarama
🧱  Güvenlik Duvarı
📋  Sertifikalar
⚡  Güvenlik Açıkları

── İSTİHBARAT ────────
🌍  Topluluk
📊  Analitik
⚠️  Risk Haritası

── YÖNETİM ───────────
🤖  Ajanlar
🔧  Onarım
💳  Abonelik
⚙️  Ayarlar
```

**Kritik:** Gelişmiş modu açmak geri dönüşü olan, korkutucu olmayan bir aksiyon. Açtın, karmaşık geldi, kapattın — 2 saniye.

**Enterprise geçişi:** Gelişmiş mod varsayılan açık + RBAC ile menü kontrolü. Aynı sidebar, farklı varsayılan.

---

## 4. Mobil Deneyim

### Mobil Öncelikler

**Kalkan** ekranın tamamını kaplar. Yeşil = kapat devam et. Sarı/kırmızı = kaydır, ne olmuş gör.

**4 kart** dikey liste. En önemli (uyarısı olan) en üstte.

**Timeline** sonsuz scroll. Push notification'dan tıklayınca doğrudan ilgili olaya gider.

**Sidebar yok.** Alt tab bar:

```
🛡 Ana    👨‍👩‍👧‍👦 Ailem    🏠 Cihazlar    ⚙️ Ayarlar
```

### Push Notification Örnekleri

> 🛡 BİGR: "Evinize yeni bir cihaz bağlandı. Tanıyor musunuz?"
> → Tıkla → doğrudan cihaz onay ekranı

> 🛡 BİGR: "Ali'nin tabletinde güncelleme gerekiyor."
> → Tıkla → Ali'nin cihaz detayı

> 🛡 BİGR: "Aylık raporunuz hazır. Skorunuz 91! 🎉"
> → Tıkla → rapor özeti

Her zaman doğal dil, her zaman aksiyon, asla teknik jargon.

---

## 5. BİGR Altyapı → Kullanıcı Değer Eşleştirmesi

| Kullanıcının Sorusu | Dashboard Elementi | BİGR Altyapısı |
|---|---|---|
| "Verim güvende mi?" | Verilerim kartı | TLS check, DNS security, şifresiz trafik tespiti |
| "Ailemin cihazları güvende mi?" | Ailem kartı | Family Shield, cihaz profilleri, Shield tarama |
| "Evimde tanımadığım cihaz var mı?" | Evim kartı + timeline | Asset discovery, MAC vendor, yeni cihaz alertleri |
| "Bölgemde tehdit var mı?" | Bölgem kartı | Collective Intelligence, AbuseIPDB bölgesel veri |
| "Ne oldu bugün?" | Timeline | Firewall events + Language Engine (Humanizer) |
| "Ne yapmalıyım?" | Kalkan durum cümlesi | Remediation engine, Shield önceliklendirme |
| "Genel durumum nasıl?" | Kalkan skoru | Compliance + Risk + Shield score birleşimi |

---

## 6. Enterprise Geçiş Stratejisi

Aynı kod tabanı, farklı varsayılanlar:

| Parametre | Ev Kullanıcısı | Enterprise |
|---|---|---|
| Varsayılan sidebar | Basit (5 item) | Gelişmiş (tümü) |
| Onboarding | AI sohbet | Bulk import + AD/LDAP |
| Dil | Doğal Türkçe | Teknik + doğal seçenekli |
| Timeline | Humanize edilmiş | Raw log + humanize toggle |
| Bildirimler | Push + in-app | SIEM webhook + email + push |
| Erişim kontrolü | Tek kullanıcı | RBAC, multi-tenant |

Ayrı ürün değil, aynı ürünün farklı konfigürasyonu.

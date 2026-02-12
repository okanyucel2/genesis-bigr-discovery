# Timeline Detay Kismi Gelistirme Plani

## Context

Timeline'daki "Detay" kismi su an duz monospace text: `Protokol: TCP | Yon: Gelen | Kural: rule_threat_001`. Ev kullanicisi icin anlamsiz. 4 boyutlu iyilestirme yapiyoruz:

1. **Dogal dil ozeti** — Turkce aciklama
2. **Gorsel yapi** — Ikon + label/value grid
3. **Tehdit baglami** — Bilinen kotu IP uyarisi
4. **Aksiyon butonlari** — "Kalici Engelle" / "Kural Detayi"

## Degisiklikler

### 1. `src/types/home-dashboard.ts` — Yeni tipler

```ts
export interface TimelineDetailField {
  icon: string       // '🔌', '↗️'
  label: string      // 'Protokol', 'Yon'
  value: string
}

export interface TimelineDetailAction {
  label: string
  variant: 'primary' | 'secondary' | 'danger'
  icon?: string
  handler: 'block-permanent' | 'view-device' | 'view-rule'
  metadata?: Record<string, string>
}

export interface TimelineRichDetail {
  summary: string
  fields: TimelineDetailField[]
  actions: TimelineDetailAction[]
  threatContext?: {
    isKnownMalicious: boolean
    threatType?: string
    reputation: 'malicious' | 'suspicious' | 'unknown'
  }
}

// detail tipi guncellenir:
detail: string | TimelineRichDetail | null

// Type guard:
export function isRichDetail(d): d is TimelineRichDetail
```

### 2. `src/lib/threat-intel.ts` — YENI DOSYA

Bilinen kotu IP listesi + lookup fonksiyonu. Mock data'daki IP'ler kullanilir:
- `45.33.32.156` → malicious, "Bilinen Saldirgan"
- `89.248.167.131` → malicious, "Port Tarayici"
- `185.220.101.42` → suspicious, "Tor Cikis Noktasi"

Fonksiyonlar:
- `checkIpReputation(ip)` → entry veya null
- `getThreatContext(sourceIp, destIp, direction)` → threat context objesi

### 3. `src/composables/useTimeline.ts` — Rich detail builder

`firewallToTimeline` icinde `detail` alani artik `TimelineRichDetail` donecek:

- **summary**: "45.33.32.156 adresindan Intel Corporate Cihaz:8443 portuna gelen TCP baglantisi engelendi."
- **fields**: Protokol, Yon, Islem (varsa), Kural (varsa) — ikon + label/value
- **threatContext**: `getThreatContext()` ile kontrol
- **actions**: Block → "Kalici Engelle" (danger) + "Kural Detayi" (secondary); Allow → sadece bilgi

Diger event tipleri (family, change, collective) degismez — string detail kalir.

### 4. `src/components/home/TimelineItem.vue` — UI guncelleme

Detay alani `isRichDetail` kontrolu ile iki modda calisir:

**Rich Detail (firewall):**
```
┌─ Tehdit Banneri (kirmizi, sadece malicious IP) ─────────┐
│ ⚠️ Bilinen Tehdit — Port Tarayici                       │
└─────────────────────────────────────────────────────────┘
┌─ Ozet ─────────────────────────────────────────────────┐
│ 45.33.32.156 adresindan gelen TCP baglantisi           │
│ engellendi.                                             │
└─────────────────────────────────────────────────────────┘
┌─ Alanlar (2x2 grid) ──────────────────────────────────┐
│ 🔌 Protokol   │ ↙️ Yon                                │
│    TCP         │    Gelen                               │
│ ⚙️ Islem      │ 📋 Kural                              │
│    smarttv-app │    rule_threat_001                     │
└─────────────────────────────────────────────────────────┘
┌─ Aksiyonlar ───────────────────────────────────────────┐
│ [🚫 Kalici Engelle]  [📋 Kural Detayi]                │
└─────────────────────────────────────────────────────────┘
```

**String Detail (fallback):**
Mevcut monospace render aynen kalir.

**CSS:** `max-height: 100px → 400px`

**Emit'ler:** `blockIp`, `viewRule` eklenir (parent'a iletilir)

### 5. Testler

**`src/tests/lib/threat-intel.test.ts`** — YENI:
- Bilinen IP → malicious donmeli
- Bilinmeyen IP → null donmeli
- Direction-aware kontrol (inbound → source, outbound → dest)

**`src/tests/components/TimelineItem.test.ts`** — Ek testler:
- Rich detail summary render
- Threat banner gorunurlugu
- Field grid render
- Aksiyon butonu render + emit

**`src/tests/composables/useTimeline.test.ts`** — Ek testler:
- Firewall event → rich detail donmeli
- Malicious IP → threatContext.isKnownMalicious = true
- Allow event → "Kalici Engelle" aksiyonu olmamali

## Dogrulama

1. `npm run typecheck` — temiz
2. `npm run test` — tum testler gecer
3. `VITE_DEMO_MODE=true` dev server:
   - Firewall block event → tehdit banneri + aksiyonlar gorunur
   - Allow event → sadece ozet + alanlar
   - Family/change events → eski string format korunur
   - Mobilde responsive (grid 2→1 kolon)

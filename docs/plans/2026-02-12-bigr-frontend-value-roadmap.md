# BİGR Frontend Value Roadmap

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bridge the gap between BİGR's comprehensive backend (~130 endpoints) and user-facing value. Make every user feel "BİGR is protecting me."

**Architecture:** Leverage existing AI analysis, remediation, and threat intelligence APIs that have 0% frontend usage. Transform technical data into actionable Turkish-language guidance for home users.

**Tech Stack:** Vue 3, TypeScript, existing bigrApi client, Tailwind CSS

---

## Current State (2026-02-12)

### Completed
- [x] Toast notification system (useToast + ToastContainer)
- [x] Cihazlarım card redesign (DeviceCard + status badges)
- [x] MAC-based device actions (persists across IP changes)
- [x] Acknowledge/Block with reactive UI + toast feedback
- [x] genesis.yaml for process manager
- [x] Engagement streak graceful degradation

### Gap Analysis Summary
- **130 backend endpoints**, 24 frontend views
- **AI Analysis (10 endpoints):** 0% frontend usage
- **Threat Intelligence (5 endpoints):** 0% frontend usage
- **Remediation Engine:** Backend ready, frontend shows plan but no inline guidance
- **Asset Sensitivity:** Backend PATCH exists, no frontend UI
- **Language Engine:** humanize used, but templates/preview unused

---

## Dalga 1: "Anla ve Harekete Gec" (ACTIVE)

The highest-value wave. Users understand WHY things are risky and WHAT to do.

### Task 1: AI-Powered Device Insight on Device Cards

**Goal:** Each device card shows a 1-line AI insight ("Bu yazıcı internete açık, risk oluşturabilir")

**Files:**
- Modify: `frontend/src/components/assets/DeviceCard.vue`
- Modify: `frontend/src/stores/assets.ts`
- Modify: `frontend/src/lib/api.ts` (add AI analyze call)

**Backend endpoints (EXISTING, unused):**
- `POST /api/ai/analyze/network` - Takes device fingerprint, returns risk analysis
- `POST /api/ai/analyze/port` - Analyzes open port risk

**Steps:**
1. Add `analyzeDevice(ip)` to api.ts → calls `/api/ai/analyze/network`
2. In DeviceCard, add "AI Insight" section in expanded area
3. Lazy-load insight on card expand (don't call for all devices at once)
4. Show Turkish-language 1-liner from AI response
5. Cache results in store to avoid re-fetching

---

### Task 2: Inline Remediation Suggestions

**Goal:** Devices with issues show actionable fix suggestions ("Yazıcı portunu kapatın")

**Files:**
- Create: `frontend/src/components/assets/RemediationBadge.vue`
- Modify: `frontend/src/components/assets/DeviceCard.vue`
- Modify: `frontend/src/stores/assets.ts`

**Backend endpoints (EXISTING, unused in device context):**
- `GET /api/remediation/plan/{ip}` - Returns remediation plan for specific asset
- `POST /api/remediation/execute/{action_id}` - Execute remediation action

**Steps:**
1. Add `getDeviceRemediation(ip)` to api.ts
2. Create RemediationBadge showing action count ("2 öneri")
3. On expand, show remediation steps in Turkish
4. Add "Uygula" button for each action → calls execute endpoint
5. Show toast on success/failure

---

### Task 3: Sensitivity Tagging UI

**Goal:** Users can mark devices as "Hassas" (baby camera, NAS with photos, etc.)

**Files:**
- Modify: `frontend/src/components/assets/DeviceCard.vue`
- Modify: `frontend/src/stores/assets.ts`
- Modify: `frontend/src/lib/api.ts`

**Backend endpoint (EXISTING, unused):**
- `PATCH /api/assets/{ip}/sensitivity` - Sets fragile/cautious/safe

**Steps:**
1. Add `setSensitivity(ip, level)` to api.ts
2. In DeviceCard expanded area, add sensitivity selector (3 buttons: Hassas/Dikkatli/Normal)
3. Update local state on success + toast
4. Show sensitivity badge on card (like status badge)

---

## Dalga 2: "Koru" (BACKLOG)

Visible protection layer. Users see BİGR actively defending them.

### Task 4: Guardian DNS Quick Toggle on Home Dashboard
- Add "Çocuk Koruması" toggle to KalkanShield or as standalone card
- Calls `/api/guardian/status` and shows on/off state
- Toggle calls guardian enable/disable (may need new endpoint)

### Task 5: Threat Intelligence Summary Card
- New card on Ana Ekran: "Bu hafta engellenen tehditler"
- Uses `/api/threat/stats` + `/api/firewall/stats/daily`
- Drill-down to threat feed list

### Task 6: Collective Intelligence Contribution
- "Bölgem" card → "Katkıda Bulun" button
- Calls `POST /api/collective/signal` to share anonymized threat data
- Show contribution badge/level

### Task 7: Threat Feed Management
- Settings or dedicated view for threat feed sync
- List feeds with last sync time
- Manual "Güncelle" button per feed

---

## Dalga 3: "Güvende Hisset" (BACKLOG)

Engagement and proactive communication.

### Task 8: AI-Powered Smart Notifications
- Combine Language Engine + AI Analysis + Remediation
- Generate human-readable Turkish alerts: "Yazıcınız internete açık. Kapatmanızı öneriyoruz."
- Push to Bildirimler view with action buttons

### Task 9: Weekly Security Report
- New view or modal: "Bu hafta neler oldu?"
- Aggregates: new devices, blocked threats, remediation actions, streak
- Shareable (screenshot/PDF)

### Task 10: Language Engine Template Browser
- Settings → "Bildirim Şablonları" section
- Browse available templates
- Preview with tone selector
- Customize notification style

---

## Technical Notes

### AI Endpoint Availability
- AI endpoints use L0/L1/L2 routing (L0=local Ollama, L1=small cloud, L2=full cloud)
- Check `/api/ai/status` before calling - gracefully degrade if AI unavailable
- Budget tracking via `/api/ai/router/budget`

### Demo Mode Compatibility
- All new api.ts functions need `DEMO_MODE` mock responses
- Keep demo mode functional for presentations

### Caching Strategy
- AI insights: cache in store, TTL 5 minutes
- Remediation plans: cache per IP, invalidate on acknowledge/block
- Threat stats: cache 1 minute

---

*Created: 2026-02-12 | Author: MAX + Okan*

# BİGR Shield Frontend — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the frontend views and components for BİGR Shield BAS (security scanning). Backend is fully built — this is frontend-only work.

**Architecture:** 2 views, 5 components, 1 composable, frontend tests. All API methods, types, mock data, Pinia store, and router routes already exist.

**Tech Stack:** Vue 3.5 + TypeScript + Tailwind CSS + Vitest

---

## Context

Backend Shield module is complete: 7 scan modules (tls, ports, headers, dns, cve, creds, owasp), orchestrator, scorer, API routes — all with 89 passing tests. Frontend has types (`shield.ts`), Pinia store (`stores/shield.ts`), API methods (`api.ts`), mock data (`mock-data.ts`), and router routes — but **zero views or components**. The router references `ShieldView.vue` and `ShieldFindingsView.vue` which don't exist yet.

## Existing Code (DO NOT recreate)

| Asset | File | Status |
|-------|------|--------|
| Types | `frontend/src/types/shield.ts` | Complete |
| Store | `frontend/src/stores/shield.ts` | Complete (addScan, updateScan) |
| API | `frontend/src/lib/api.ts:369-387` | Complete (startShieldScan, getShieldScan, getShieldFindings, getShieldModules) |
| Mock data | `frontend/src/lib/mock-data.ts:1583-2090` | Complete (mockShieldScan, mockShieldFindings, mockShieldModules) |
| Router | `frontend/src/router/index.ts:63-76` | Complete (/shield, /shield/scan/:id, /shield-findings) |
| Sidebar | `frontend/src/components/layout/AppSidebar.vue:80-81` | Complete (Kalkan + Bulgular entries) |
| SeverityBadge | `frontend/src/components/common/SeverityBadge.vue` | Reuse for finding severity |

## Reuse Patterns

- **KalkanShield.vue** pattern → ShieldScoreGauge (circular score display with glow)
- **SeverityBadge.vue** → Finding severity badges (critical/high/medium/low/info)
- **useShieldStore** → State management for scans
- **bigrApi.startShieldScan/getShieldScan** → Already wired with DEMO_MODE support

---

## Wave A: Core Views + ScanForm (Tasks 1-3)

### Task 1: Create useShield composable

**Files:**
- Create: `frontend/src/composables/useShield.ts`
- Test: `frontend/src/tests/composables/useShield.test.ts`

Composable wraps bigrApi + useShieldStore. Manages scan lifecycle:

```typescript
export function useShield() {
  const store = useShieldStore()
  const loading = ref(false)
  const error = ref<string | null>(null)
  const polling = ref(false)

  async function startScan(target: string, depth: ScanDepth = 'quick') { ... }
  async function pollScan(scanId: string) { ... }  // poll every 2s until completed/failed
  async function fetchModules() { ... }

  return { loading, error, polling, currentScan: store.currentScan, recentScans: store.recentScans, startScan, pollScan, fetchModules }
}
```

**Tests (6):**
- startScan calls API and adds to store
- pollScan updates store on completion
- pollScan stops on failure
- loading state during startScan
- error state on API failure
- DEMO_MODE returns mock data

**Verification:** `npx vitest run src/tests/composables/useShield.test.ts`

---

### Task 2: Create ScanForm component

**Files:**
- Create: `frontend/src/components/shield/ScanForm.vue`
- Test: `frontend/src/tests/components/ScanForm.test.ts`

Simple form: text input (target), depth toggle (Hızlı/Standart), submit button. Emits `scan-start` with `{ target, depth }`.

```
┌─────────────────────────────────────────────────┐
│  Hedef (IP veya Domain)                         │
│  ┌─────────────────────────────────────────┐    │
│  │ example.com                              │    │
│  └─────────────────────────────────────────┘    │
│                                                  │
│  Tarama Derinligi:  [Hızlı] [Standart]          │
│                                                  │
│  [🛡️ Taramayı Başlat]                           │
└─────────────────────────────────────────────────┘
```

- Input validation: non-empty, basic format check
- Disabled state while scan is loading
- Tailwind dark theme (slate-800/900 background, cyan accents)

**Tests (4):**
- Renders input and button
- Emits scan-start on submit with target + depth
- Button disabled when loading prop is true
- Empty target shows validation

**Verification:** `npx vitest run src/tests/components/ScanForm.test.ts`

---

### Task 3: Create ShieldView (main page)

**Files:**
- Create: `frontend/src/views/ShieldView.vue`
- Test: `frontend/src/tests/views/ShieldView.test.ts`

Main Shield page. Two states based on route:
- `/shield` → Scan form + recent scans list
- `/shield/scan/:id` → Scan result detail (Task 5-7)

For Wave A, only the scan form + recent scans list. Result detail is placeholder until Wave B.

Layout:
```
┌─ Shield ────────────────────────────────────────┐
│                                                  │
│  [ScanForm]                                      │
│                                                  │
│  ── Son Taramalar ──────────────────────────────│
│  example.com    B (72)    22s ago    completed   │
│  192.168.1.1    A (95)    1h ago     completed   │
│  test.local     —         running... ⏳          │
└─────────────────────────────────────────────────┘
```

- Uses `useShield()` composable
- On `scan-start`: calls `startScan`, navigates to `/shield/scan/{id}`
- Recent scans from store — click navigates to scan detail
- Loading spinner while scan is running

**Tests (4):**
- Renders scan form
- Shows recent scans list from mock store
- Navigates to scan detail on click
- Shows loading state

**Verification:** `npx vitest run src/tests/views/ShieldView.test.ts`

**Wave A Commit:** `feat(shield): add Shield view with scan form and composable`

---

## Wave B: Scan Results (Tasks 4-6)

### Task 4: Create ShieldScoreGauge component

**Files:**
- Create: `frontend/src/components/shield/ShieldScoreGauge.vue`
- Test: `frontend/src/tests/components/ShieldScoreGauge.test.ts`

Large circular score display. Pattern from `KalkanShield.vue` (SVG circle with stroke-dashoffset).

Props: `score: number | null`, `grade: ShieldGrade | null`, `status: ScanStatus`

```
       ╭───────╮
       │       │
       │  72   │
       │  B    │
       ╰───────╯
    Shield Score
```

Color logic:
- A+/A: emerald-400 (green)
- B+/B: cyan-400 (blue)
- C+/C: amber-400 (yellow)
- D/F: rose-400 (red)
- Running: pulse animation, slate-400

**Tests (4):**
- Shows score and grade
- Green color for A grade
- Red color for F grade
- Shows spinner for running status

**Verification:** `npx vitest run src/tests/components/ShieldScoreGauge.test.ts`

---

### Task 5: Create ModuleScoreCards component

**Files:**
- Create: `frontend/src/components/shield/ModuleScoreCards.vue`
- Test: `frontend/src/tests/components/ModuleScoreCards.test.ts`

Grid of module score cards. Each card shows module name, score bar, findings count.

Props: `moduleScores: Record<string, ModuleScore>`

```
┌─ TLS ──────┐  ┌─ Ports ────┐  ┌─ Headers ──┐
│  85/100     │  │  70/100    │  │  50/100    │
│  ████████░░ │  │  ███████░░ │  │  █████░░░░ │
│  1 bulgu    │  │  4 bulgu   │  │  4 bulgu   │
└─────────────┘  └─────────────┘  └────────────┘
```

Module label map (Turkish):
```typescript
const moduleLabels: Record<string, string> = {
  tls: 'TLS/SSL', ports: 'Portlar', headers: 'HTTP Başlıkları',
  dns: 'DNS Güvenliği', cve: 'CVE Zafiyet', creds: 'Kimlik Bilgileri', owasp: 'OWASP'
}
```

Score bar color: same grade-based color logic as ShieldScoreGauge.

**Tests (3):**
- Renders cards for each module
- Shows correct score and bar width
- Shows finding count

**Verification:** `npx vitest run src/tests/components/ModuleScoreCards.test.ts`

---

### Task 6: Create FindingsList component + wire scan result page

**Files:**
- Create: `frontend/src/components/shield/FindingsList.vue`
- Test: `frontend/src/tests/components/FindingsList.test.ts`
- Modify: `frontend/src/views/ShieldView.vue` — add scan result detail section

FindingsList shows findings grouped by severity. Each finding has expandable remediation.

Props: `findings: ShieldFinding[]`

```
┌─ 2 Kritik  4 Yüksek  5 Orta  2 Düşük ──────────┐
│                                                    │
│  🔴 CRITICAL  CVE-2024-6387 (RegreSSHion)         │
│     OpenSSH 8.9p1 — Remote Code Execution          │
│     ▸ Nasıl düzeltilir?                            │
│                                                    │
│  🟠 HIGH  TLS 1.0 Protocol Enabled                │
│     :443 — Deprecated protocol in use               │
│     ▸ Nasıl düzeltilir?                            │
│                                                    │
│  🟠 HIGH  MySQL (3306) Exposed                     │
│     :3306 — Database port publicly accessible       │
│     ▾ Nasıl düzeltilir?                            │
│     ┌──────────────────────────────────────┐       │
│     │ Block port 3306 at the firewall.     │       │
│     │ Use SSH tunneling for remote access. │       │
│     └──────────────────────────────────────┘       │
└────────────────────────────────────────────────────┘
```

- Uses `SeverityBadge.vue` for badges
- Accordion for remediation text
- Filter by severity (tabs or chips)
- Sort by severity (critical first)

**Wire ShieldView scan result:**
When route is `/shield/scan/:id`, ShieldView shows:
- ShieldScoreGauge (top)
- ModuleScoreCards (middle)
- FindingsList (bottom)
- Back button to `/shield`
- Poll for updates if scan is still running

**Tests (5):**
- Renders findings list with severity badges
- Shows severity summary counts
- Expands remediation on click
- Filters by severity
- Empty state when no findings

**Verification:** `npx vitest run src/tests/components/FindingsList.test.ts`

**Wave B Commit:** `feat(shield): add scan results — score gauge, module cards, findings list`

---

## Wave C: Findings View + Polish (Tasks 7-8)

### Task 7: Create ShieldFindingsView

**Files:**
- Create: `frontend/src/views/ShieldFindingsView.vue`
- Test: `frontend/src/tests/views/ShieldFindingsView.test.ts`

Standalone findings page at `/shield-findings`. Shows all findings across all scans, filterable by severity and module.

Uses same FindingsList component but with aggregate data from store + optional API call for agent-wide findings (`getAgentShieldFindings` already in api.ts).

**Tests (3):**
- Renders findings from store
- Filters by module
- Shows empty state

**Verification:** `npx vitest run src/tests/views/ShieldFindingsView.test.ts`

---

### Task 8: Polish + vue-tsc + full vitest

**Files:**
- Modify: Various — fix any type errors, missing imports
- No new files

**Steps:**
1. Run `npx vue-tsc --noEmit` — fix all type errors
2. Run `npx vitest run` — all tests pass (243 existing + ~29 new)
3. Run `VITE_DEMO_MODE=true` dev server — verify:
   - `/shield` renders scan form + recent scans
   - Submit scan → navigates to results with score gauge, module cards, findings
   - `/shield-findings` shows aggregated findings
   - Mobile responsive
4. Verify sidebar navigation works

**Wave C Commit:** `feat(shield): add findings view + polish`

---

## Verification

1. `npx vitest run` — all tests pass
2. `npx vue-tsc --noEmit` — zero errors
3. DEMO_MODE dev server:
   - `/shield` → scan form visible, submit works
   - Score gauge shows 72/B with cyan glow
   - Module score cards render TLS, Ports, Headers, DNS, CVE, Creds, OWASP
   - Findings list shows 13 mock findings with severity badges
   - Remediation accordion expands/collapses
   - `/shield-findings` shows aggregate view
   - Sidebar "Kalkan" and "Bulgular" links work

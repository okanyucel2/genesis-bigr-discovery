# BİGR Discovery - Vue 3 SPA Frontend

## Context

BİGR Discovery has grown from a CLI tool to a full-featured network security platform (669 tests, 6 phases). The current dashboard is 1489 lines of inline HTML in `bigr/dashboard/app.py`. The project is "going to important places" and needs a professional SPA frontend that leverages the Genesis ecosystem.

**Goal:** Replace inline HTML dashboard with a Vue 3 SPA that matches Genesis's "Deep Space Glass" design system, uses shared monorepo packages, and provides a world-class network security dashboard.

## Stack Decision

| Choice | Why |
|--------|-----|
| **Vue 3 + TypeScript + Vite** | Genesis standard stack |
| **shadcn-vue** (Radix Vue) | Same as sendikaos project, copy-paste components |
| **Tailwind + Deep Space Glass** | Genesis design system, dark security aesthetic |
| **Pinia** | Genesis standard state management |
| **Chart.js** (vue-chartjs) | Already in Genesis, good for line/bar/pie |
| **D3.js** | Already used in current topology, best for force graphs |
| **Lucide Vue Next** | Genesis standard icons |
| **pnpm workspace:\*** | Shared configs from `packages/` |

## Backend: Zero Changes Needed

All 13 API endpoints already exist and return JSON:

```
GET /api/data           GET /api/assets/{ip}     GET /api/scans
GET /api/changes        GET /api/subnets         GET /api/switches
GET /api/topology       GET /api/compliance      GET /api/analytics
GET /api/risk           GET /api/vulnerabilities GET /api/certificates
GET /api/health
```

Only change: mount `frontend/dist` as static files for production serving.

## File Structure

```
frontend/
  index.html, package.json, vite.config.ts, vitest.config.ts
  tsconfig.json, tailwind.config.js, eslint.config.js, postcss.config.js
  src/
    main.ts, App.vue
    router/index.ts                  # 11 routes, lazy-loaded
    styles/index.css                 # shadcn vars + Deep Space Glass + BİGR colors
    types/
      api.ts                         # All 13 API response interfaces
      bigr.ts                        # BigrCategory type + color/label/icon maps
    lib/
      api.ts                         # Axios client, typed bigrApi object
      utils.ts                       # cn() helper (clsx + tailwind-merge)
    composables/                     # 11 composables (useAssets, useTopology, etc.)
    stores/                          # Pinia: assets, topology, ui, settings
    components/
      layout/                        # AppLayout, AppSidebar, AppHeader
      ui/                            # shadcn-vue: button, card, badge, table, input, etc.
      charts/                        # ComplianceGauge, CategoryPie, TrendLine, Bar
      shared/                        # BigrBadge, RiskBadge, DataTable, IpLink, etc.
      dashboard/                     # StatCard, CategoryCard, RecentChanges
      topology/                      # TopologyCanvas (D3), Legend, Controls
      assets/                        # AssetTable, AssetFilters, AssetDetail
      compliance/                    # ScoreCard, Breakdown, Distribution
      risk/                          # RiskScoreCard, RiskTable
      vulnerabilities/               # VulnTable, SummaryCards
      certificates/                  # CertTable, ExpiryWarning
      settings/                      # SubnetManager, SwitchManager
    views/                           # 11 view pages
    tests/                           # Vitest unit tests
  e2e/                               # Playwright E2E tests
```

## Phases (6 phases, parallel agents per phase)

### Phase 1: Foundation (scaffold + layout + API client)

**Agent 1A: Project Scaffold**
- Create all config files (package.json, vite.config.ts, tsconfig, tailwind, eslint, etc.)
- Reference: `/projects/sendikaos/frontend/package.json` for workspace:\* pattern
- Vite dev server on port **18090**, proxy `/api` to `localhost:8090`
- Add `'projects/genesis-bigr-discovery/frontend'` to `/pnpm-workspace.yaml`
- Install deps: vue, vue-router, pinia, axios, chart.js, vue-chartjs, d3, radix-vue, lucide-vue-next, cva, clsx, tailwind-merge
- Dev deps: @genesis/eslint-config, @genesis/tsconfig, @genesis/vitest-config, @genesis/playwright-config workspace:\*

**Agent 1B: Types + API + Router + Layout**
- `types/api.ts` - TypeScript interfaces for all 13 endpoints (derived from `bigr/dashboard/app.py`)
- `types/bigr.ts` - BigrCategory type, BIGR_CATEGORIES map (colors, labels, icons)
- `lib/api.ts` - Axios instance + typed `bigrApi` object with all 13 methods
- `lib/utils.ts` - `cn()` helper
- `router/index.ts` - 11 lazy-loaded routes
- `styles/index.css` - shadcn CSS vars + Deep Space Glass (from `/frontend/src/styles/theme.css`) + BİGR category colors
- `components/layout/` - AppLayout (sidebar + content), AppSidebar (nav links), AppHeader (title + health)
- 11 placeholder views (title only)

**Exit:** `pnpm dev` starts, all routes render, `pnpm typecheck` passes

### Phase 2: UI Components + Dashboard

**Agent 2A: shadcn-vue + Shared Components**
- Initialize shadcn-vue components in `components/ui/`: button, card, badge, table, input, select, dialog, tabs, tooltip, separator, dropdown-menu
- Shared BİGR components: BigrBadge, ConfidenceBadge, RiskBadge, SeverityBadge, IpLink, DataTable, EmptyState, LoadingState, ExportButtons, SearchInput
- Unit tests for BigrBadge, DataTable

**Agent 2B: Composables + Stores + Dashboard Page**
- Composables: useAssets, useChanges, useHealth, useBigrCategories
- Pinia stores: assets (list + filters), ui (sidebar state)
- Chart components: CategoryPieChart, BarChart
- Dashboard components: StatCard, CategoryCard, RecentChanges, QuickStats
- Assemble DashboardView with real API data
- Unit tests for useAssets, assets store

**Exit:** Dashboard shows category cards, stats, pie chart, recent changes from live API

### Phase 3: Asset Pages

**Agent 3A: Assets List**
- useSubnets composable
- AssetTable (sortable, all 8 columns), AssetFilters (category + subnet + search)
- AssetsView with pagination + export

**Agent 3B: Asset Detail**
- useAssetDetail composable
- AssetDetailCard, AssetHistory, AssetPorts
- AssetDetailView with tabs (History, Ports, Changes)

**Exit:** Full asset browsing, click IP -> detail page, back navigation

### Phase 4: Complex Visualizations

**Agent 4A: Topology**
- useTopology composable, topology Pinia store
- TopologyCanvas (D3.js force-directed, port existing JS from app.py)
- TopologyLegend, TopologyControls, TopologyTooltip
- TopologyView (full-screen canvas + overlaid controls)

**Agent 4B: Compliance**
- useCompliance composable
- ComplianceGauge (radial), ComplianceScoreCard, ComplianceBreakdown, ComplianceDistribution, SubnetCompliance, ActionItems
- ComplianceView

**Agent 4C: Analytics**
- useAnalytics composable
- TrendLineChart (Chart.js line), day range selector
- AnalyticsView (trends, category trends, most changed, scan frequency)

**Exit:** Topology renders interactive D3 graph, compliance shows gauge + breakdown, analytics shows trends

### Phase 5: Security Pages

**Agent 5A: Risk**
- useRisk composable
- RiskScoreCard, RiskTable (top 10), RiskDistributionChart
- RiskView

**Agent 5B: Vulnerabilities**
- useVulnerabilities composable
- VulnSummaryCards, VulnTable
- VulnerabilitiesView

**Agent 5C: Certificates**
- useCertificates composable
- CertTable, CertExpiryWarning
- CertificatesView

**Exit:** All security pages render with live data, badges color-coded correctly

### Phase 6: Settings + Production + E2E

**Agent 6A: Settings + Backend SPA Mount**
- SettingsView (read-only subnet + switch list)
- Modify `bigr/dashboard/app.py`: mount `frontend/dist` as static files, catch-all serves `index.html`
- `bigr serve` serves SPA in production

**Agent 6B: E2E Tests + Polish**
- Playwright E2E: dashboard, assets, topology, compliance, navigation (5 specs)
- Loading skeletons, error states, page transitions
- Responsive sidebar (mobile collapse)
- Keyboard nav for topology

**Exit:** `pnpm build` produces dist, `bigr serve` serves SPA, all E2E pass

## Key Patterns to Reuse from Genesis

| Source | Reuse As |
|--------|----------|
| `sendikaos/frontend/package.json` | workspace:\* dep pattern |
| `sendikaos/frontend/tsconfig.json` | TS config extending @genesis/tsconfig |
| `sendikaos/frontend/eslint.config.js` | ESLint extending @genesis/eslint-config |
| `/frontend/src/styles/theme.css` | Deep Space Glass CSS vars (copy + adapt) |
| `/packages/vitest-config` | createVitestConfig() |
| `/packages/playwright-config` | createPlaywrightConfig() |

## BİGR Category Color Map (used everywhere)

```
ag_ve_sistemler  → #3b82f6 (blue)    → "Ag ve Sistemler"    → Network icon
uygulamalar      → #8b5cf6 (purple)   → "Uygulamalar"        → Globe icon
iot              → #10b981 (green)    → "IoT"                → Camera icon
tasinabilir      → #f59e0b (amber)    → "Tasinabilir"        → Laptop icon
unclassified     → #6b7280 (gray)     → "Siniflandirilmamis" → HelpCircle icon
```

## Verification

After each phase:
1. `pnpm --filter @genesis/bigr-discovery-frontend typecheck` - Type safety
2. `pnpm --filter @genesis/bigr-discovery-frontend test` - Unit tests pass
3. Manual browser check at `http://localhost:18090` - Visual verification
4. Backend running at 8090 for API data

After Phase 6:
5. `pnpm --filter @genesis/bigr-discovery-frontend build` - Production build
6. `bigr serve` - Serves SPA from dist/
7. `pnpm --filter @genesis/bigr-discovery-frontend test:e2e` - All E2E pass

## Critical Files

- `bigr/dashboard/app.py` - 13 API endpoints (type against), SPA mount point (Phase 6)
- `sendikaos/frontend/package.json` - Reference for workspace setup
- `frontend/src/styles/theme.css` - Deep Space Glass CSS to adapt
- `pnpm-workspace.yaml` - Register new frontend package

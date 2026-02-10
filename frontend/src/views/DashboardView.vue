<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import {
  Server,
  ShieldCheck,
  Network,
  Activity,
  Loader2,
  AlertTriangle,
  RefreshCw,
} from 'lucide-vue-next'
import { bigrApi } from '@/lib/api'
import type { AssetsResponse, ChangesResponse, ComplianceResponse } from '@/types/api'
import { BIGR_CATEGORY_LIST } from '@/types/bigr'
import type { BigrCategory } from '@/types/bigr'
import StatCard from '@/components/dashboard/StatCard.vue'
import CategoryCard from '@/components/dashboard/CategoryCard.vue'
import CategoryPieChart from '@/components/charts/CategoryPieChart.vue'
import RecentChanges from '@/components/dashboard/RecentChanges.vue'
import SiteFilter from '@/components/dashboard/SiteFilter.vue'
import NetworkFilter from '@/components/dashboard/NetworkFilter.vue'
import { useUiStore } from '@/stores/ui'

const ui = useUiStore()

const loading = ref(true)
const error = ref<string | null>(null)

const assetsData = ref<AssetsResponse | null>(null)
const changesData = ref<ChangesResponse | null>(null)
const complianceData = ref<ComplianceResponse | null>(null)

const categorySummary = computed(() => assetsData.value?.category_summary ?? {})

const totalAssets = computed(() => assetsData.value?.total_assets ?? 0)

const classifiedPercent = computed(() => {
  if (!complianceData.value) return 0
  const { total_assets, unclassified } = complianceData.value.breakdown
  if (total_assets === 0) return 0
  return Math.round(((total_assets - unclassified) / total_assets) * 100)
})

const networkSystemsCount = computed(() => categorySummary.value['ag_ve_sistemler'] ?? 0)

const recentChangesCount = computed(() => changesData.value?.changes.length ?? 0)

const complianceGrade = computed(() => complianceData.value?.grade ?? '-')

const categoryCountsForCards = computed(() => {
  return BIGR_CATEGORY_LIST.map((cat: BigrCategory) => ({
    category: cat,
    count: categorySummary.value[cat] ?? 0,
  }))
})

async function loadDashboard() {
  loading.value = true
  error.value = null
  try {
    const site = ui.selectedSite ?? undefined
    const network = ui.selectedNetwork ?? undefined
    const [assetsRes, changesRes, complianceRes] = await Promise.all([
      bigrApi.getAssets(undefined, site, network),
      bigrApi.getChanges(50, site),
      bigrApi.getCompliance(),
    ])
    assetsData.value = assetsRes.data
    changesData.value = changesRes.data
    complianceData.value = complianceRes.data
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : 'Failed to load dashboard data'
    error.value = message
  } finally {
    loading.value = false
  }
}

watch(() => ui.selectedSite, () => loadDashboard())
watch(() => ui.selectedNetwork, () => loadDashboard())

onMounted(() => {
  loadDashboard()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Dashboard</h1>
        <p class="mt-1 text-sm text-slate-400">
          Asset discovery and classification overview
        </p>
      </div>
      <div class="flex items-center gap-3">
        <SiteFilter />
        <NetworkFilter />
        <button
          class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
          :disabled="loading"
          @click="loadDashboard"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          Refresh
        </button>
      </div>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && !assetsData"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Loading dashboard data...</p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error && !assetsData"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">
        Unable to Load Data
      </h2>
      <p class="mt-2 text-sm text-slate-400">
        {{ error }}
      </p>
      <button
        class="mt-4 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
        @click="loadDashboard"
      >
        Try Again
      </button>
    </div>

    <!-- Dashboard Content -->
    <template v-else>
      <!-- Stat Cards Row -->
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Total Assets"
          :value="totalAssets"
          :icon="Server"
          color="#06b6d4"
        />
        <StatCard
          label="Classified"
          :value="`${classifiedPercent}%`"
          :icon="ShieldCheck"
          color="#10b981"
        />
        <StatCard
          label="Network & Systems"
          :value="networkSystemsCount"
          :icon="Network"
          color="#3b82f6"
        />
        <StatCard
          label="Recent Changes"
          :value="recentChangesCount"
          :icon="Activity"
          color="#f59e0b"
        />
      </div>

      <!-- Category Cards Grid -->
      <div>
        <h2 class="mb-3 text-sm font-medium uppercase tracking-wider text-slate-400">
          Asset Categories
        </h2>
        <div class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <CategoryCard
            v-for="item in categoryCountsForCards"
            :key="item.category"
            :category="item.category"
            :count="item.count"
          />
        </div>
      </div>

      <!-- Charts & Recent Changes Side-by-Side -->
      <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <!-- Category Distribution Chart -->
        <div class="glass-panel rounded-xl p-5">
          <h3 class="mb-4 text-sm font-medium text-slate-300">
            Category Distribution
          </h3>
          <CategoryPieChart :data="categorySummary" />
        </div>

        <!-- Recent Changes List -->
        <div class="glass-panel rounded-xl p-5">
          <div class="mb-4 flex items-center justify-between">
            <h3 class="text-sm font-medium text-slate-300">
              Recent Changes
            </h3>
            <RouterLink
              to="/analytics"
              class="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              View all
            </RouterLink>
          </div>
          <RecentChanges :changes="changesData?.changes ?? []" />
        </div>
      </div>

      <!-- Compliance Summary -->
      <div
        v-if="complianceData"
        class="glass-panel rounded-xl p-5"
      >
        <div class="mb-4 flex items-center justify-between">
          <h3 class="text-sm font-medium text-slate-300">
            Compliance Overview
          </h3>
          <RouterLink
            to="/compliance"
            class="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            Full report
          </RouterLink>
        </div>
        <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div class="text-center">
            <p class="text-3xl font-bold text-neon-cyan tabular-nums">
              {{ complianceData.compliance_score }}%
            </p>
            <p class="mt-1 text-xs text-slate-400">Compliance Score</p>
          </div>
          <div class="text-center">
            <p
              class="text-3xl font-bold tabular-nums"
              :class="{
                'text-emerald-400': complianceGrade === 'A' || complianceGrade === 'A+',
                'text-cyan-400': complianceGrade === 'B',
                'text-amber-400': complianceGrade === 'C',
                'text-rose-400': complianceGrade === 'D' || complianceGrade === 'F',
                'text-slate-400': complianceGrade === '-',
              }"
            >
              {{ complianceGrade }}
            </p>
            <p class="mt-1 text-xs text-slate-400">Grade</p>
          </div>
          <div class="text-center">
            <p class="text-3xl font-bold text-emerald-400 tabular-nums">
              {{ complianceData.breakdown.fully_classified }}
            </p>
            <p class="mt-1 text-xs text-slate-400">Fully Classified</p>
          </div>
          <div class="text-center">
            <p class="text-3xl font-bold text-amber-400 tabular-nums">
              {{ complianceData.breakdown.unclassified }}
            </p>
            <p class="mt-1 text-xs text-slate-400">Unclassified</p>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

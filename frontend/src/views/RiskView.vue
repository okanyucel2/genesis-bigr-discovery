<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { RefreshCw, Loader2, AlertTriangle, X } from 'lucide-vue-next'
import { useRisk } from '@/composables/useRisk'
import type { RiskProfile } from '@/types/api'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import RiskOverviewCards from '@/components/risk/RiskOverviewCards.vue'
import RiskHeatmap from '@/components/risk/RiskHeatmap.vue'
import TopRisksTable from '@/components/risk/TopRisksTable.vue'
import RiskFactorsChart from '@/components/risk/RiskFactorsChart.vue'

const { data, loading, error, fetchRisk } = useRisk()

const selectedAssetIp = ref<string | null>(null)

const selectedProfile = computed<RiskProfile | null>(() => {
  if (!selectedAssetIp.value || !data.value) return null
  return data.value.profiles.find((p) => p.ip === selectedAssetIp.value) ?? null
})

function handleAssetClick(ip: string) {
  selectedAssetIp.value = ip
}

function closeDetail() {
  selectedAssetIp.value = null
}

onMounted(() => {
  fetchRisk()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Risk Assessment</h1>
        <p class="mt-1 text-sm text-slate-400">
          Asset risk profiles and threat analysis
        </p>
      </div>
      <button
        class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
        :disabled="loading"
        @click="fetchRisk"
      >
        <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
        Refresh
      </button>
    </div>

    <!-- Loading State -->
    <div
      v-if="loading && !data"
      class="flex flex-col items-center justify-center py-20"
    >
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Loading risk data...</p>
    </div>

    <!-- Error State -->
    <div
      v-else-if="error && !data"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Unable to Load Data</h2>
      <p class="mt-2 text-sm text-slate-400">{{ error }}</p>
      <button
        class="mt-4 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
        @click="fetchRisk"
      >
        Try Again
      </button>
    </div>

    <!-- Content -->
    <template v-else-if="data">
      <!-- Overview Cards -->
      <RiskOverviewCards :data="data" />

      <!-- Main Content Area -->
      <div class="flex gap-6">
        <!-- Left: Tabs with Heatmap / Table -->
        <div class="flex-1 min-w-0">
          <Tabs default-value="heatmap">
            <TabsList>
              <TabsTrigger value="heatmap">Heatmap</TabsTrigger>
              <TabsTrigger value="table">Top Risks</TabsTrigger>
            </TabsList>

            <TabsContent value="heatmap">
              <RiskHeatmap
                :profiles="data.profiles"
                @asset-click="handleAssetClick"
              />
            </TabsContent>

            <TabsContent value="table">
              <TopRisksTable :risks="data.top_risks" />
            </TabsContent>
          </Tabs>
        </div>

        <!-- Right: Detail Panel -->
        <div
          v-if="selectedProfile"
          class="w-80 shrink-0"
        >
          <div class="glass-panel sticky top-4 rounded-xl p-5">
            <div class="mb-4 flex items-center justify-between">
              <h3 class="text-sm font-medium text-white">Asset Detail</h3>
              <button
                class="rounded-md p-1 text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
                @click="closeDetail"
              >
                <X :size="16" />
              </button>
            </div>

            <div class="space-y-3 text-sm">
              <div>
                <span class="text-slate-500">IP:</span>
                <span class="ml-2 font-mono text-white">{{ selectedProfile.ip }}</span>
              </div>
              <div v-if="selectedProfile.hostname">
                <span class="text-slate-500">Hostname:</span>
                <span class="ml-2 text-slate-300">{{ selectedProfile.hostname }}</span>
              </div>
              <div v-if="selectedProfile.vendor">
                <span class="text-slate-500">Vendor:</span>
                <span class="ml-2 text-slate-300">{{ selectedProfile.vendor }}</span>
              </div>
              <div>
                <span class="text-slate-500">Risk Score:</span>
                <span
                  class="ml-2 font-mono font-semibold"
                  :class="{
                    'text-rose-400': selectedProfile.risk_score >= 80,
                    'text-amber-400': selectedProfile.risk_score >= 60 && selectedProfile.risk_score < 80,
                    'text-cyan-400': selectedProfile.risk_score >= 40 && selectedProfile.risk_score < 60,
                    'text-emerald-400': selectedProfile.risk_score < 40,
                  }"
                >
                  {{ selectedProfile.risk_score }}
                </span>
              </div>
              <div v-if="selectedProfile.top_cve">
                <span class="text-slate-500">Top CVE:</span>
                <span class="ml-2 font-mono text-xs text-rose-300">{{ selectedProfile.top_cve }}</span>
              </div>
            </div>

            <div class="mt-5 border-t border-white/5 pt-5">
              <RiskFactorsChart :factors="selectedProfile.factors" />
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RefreshCw, Loader2, AlertTriangle } from 'lucide-vue-next'
import { useVulnerabilities } from '@/composables/useVulnerabilities'
import type { CveEntry } from '@/types/api'
import SearchInput from '@/components/shared/SearchInput.vue'
import VulnSummaryCards from '@/components/vulnerabilities/VulnSummaryCards.vue'
import VulnAssetTable from '@/components/vulnerabilities/VulnAssetTable.vue'
import CveDetailPanel from '@/components/vulnerabilities/CveDetailPanel.vue'

const { data, loading, error, fetchVulnerabilities } = useVulnerabilities()

const search = ref('')
const selectedCve = ref<CveEntry | null>(null)

function handleCveClick(cveId: string) {
  if (!data.value) return
  // Find the CVE across all summaries
  for (const summary of data.value.summaries) {
    for (const match of summary.matches) {
      if (match.cve.cve_id === cveId) {
        selectedCve.value = match.cve
        return
      }
    }
  }
}

function closeCveDetail() {
  selectedCve.value = null
}

onMounted(() => {
  fetchVulnerabilities()
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Vulnerabilities</h1>
        <p class="mt-1 text-sm text-slate-400">
          CVE matching and vulnerability analysis
        </p>
      </div>
      <button
        class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
        :disabled="loading"
        @click="fetchVulnerabilities"
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
      <p class="mt-3 text-sm text-slate-400">Loading vulnerability data...</p>
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
        @click="fetchVulnerabilities"
      >
        Try Again
      </button>
    </div>

    <!-- Content -->
    <template v-else-if="data">
      <!-- Summary Cards -->
      <VulnSummaryCards :summaries="data.summaries" />

      <!-- Search -->
      <SearchInput
        v-model="search"
        placeholder="Search by IP, CVE ID, or description..."
        class="max-w-md"
      />

      <!-- Main Content Area -->
      <div class="flex gap-6">
        <!-- Table -->
        <div class="flex-1 min-w-0">
          <VulnAssetTable
            :summaries="data.summaries"
            :search="search"
            @cve-click="handleCveClick"
          />
        </div>

        <!-- CVE Detail Slide Panel -->
        <Transition
          enter-active-class="transition-all duration-300 ease-out"
          enter-from-class="translate-x-4 opacity-0"
          enter-to-class="translate-x-0 opacity-100"
          leave-active-class="transition-all duration-200 ease-in"
          leave-from-class="translate-x-0 opacity-100"
          leave-to-class="translate-x-4 opacity-0"
        >
          <div v-if="selectedCve" class="w-80 shrink-0">
            <div class="sticky top-4">
              <CveDetailPanel
                :cve="selectedCve"
                @close="closeCveDetail"
              />
            </div>
          </div>
        </Transition>
      </div>
    </template>
  </div>
</template>

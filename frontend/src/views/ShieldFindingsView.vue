<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { ShieldAlert, Loader2, AlertTriangle, RefreshCw } from 'lucide-vue-next'
import { bigrApi } from '@/lib/api'
import type { ShieldFindingsListResponse } from '@/types/api'
import SiteFilter from '@/components/dashboard/SiteFilter.vue'
import { useUiStore } from '@/stores/ui'

const ui = useUiStore()
const loading = ref(true)
const error = ref<string | null>(null)
const data = ref<ShieldFindingsListResponse | null>(null)
const severityFilter = ref<string | null>(null)

const severityOrder = ['critical', 'high', 'medium', 'low', 'info']

const severityColor: Record<string, string> = {
  critical: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  low: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  info: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
}

const severityDot: Record<string, string> = {
  critical: 'bg-rose-400',
  high: 'bg-orange-400',
  medium: 'bg-amber-400',
  low: 'bg-cyan-400',
  info: 'bg-slate-400',
}

const sortedFindings = computed(() => {
  if (!data.value) return []
  return [...data.value.findings].sort((a, b) => {
    const ai = severityOrder.indexOf(a.severity)
    const bi = severityOrder.indexOf(b.severity)
    return ai - bi
  })
})

async function loadFindings() {
  loading.value = true
  error.value = null
  try {
    const site = ui.selectedSite ?? undefined
    const sev = severityFilter.value ?? undefined
    const res = await bigrApi.getAgentShieldFindings(site, sev)
    data.value = res.data
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to load findings'
  } finally {
    loading.value = false
  }
}

function setSeverity(sev: string | null) {
  severityFilter.value = sev
}

watch(() => ui.selectedSite, () => loadFindings())
watch(severityFilter, () => loadFindings())

onMounted(() => loadFindings())
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Shield Findings</h1>
        <p class="mt-1 text-sm text-slate-400">
          Security findings from remote agent scans
        </p>
      </div>
      <div class="flex items-center gap-3">
        <SiteFilter />
        <button
          class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
          :disabled="loading"
          @click="loadFindings"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          Refresh
        </button>
      </div>
    </div>

    <!-- Loading -->
    <div v-if="loading && !data" class="flex flex-col items-center justify-center py-20">
      <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-400">Loading findings...</p>
    </div>

    <!-- Error -->
    <div v-else-if="error && !data" class="glass-card mx-auto max-w-md rounded-xl p-8 text-center">
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Unable to Load</h2>
      <p class="mt-2 text-sm text-slate-400">{{ error }}</p>
      <button
        class="mt-4 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
        @click="loadFindings"
      >
        Try Again
      </button>
    </div>

    <!-- Content -->
    <template v-else-if="data">
      <!-- Severity Summary Chips -->
      <div class="flex flex-wrap items-center gap-2">
        <button
          class="rounded-full border px-3 py-1 text-xs font-medium transition-all"
          :class="severityFilter === null
            ? 'bg-white/10 text-white border-white/20'
            : 'bg-white/5 text-slate-400 border-transparent hover:bg-white/10'"
          @click="setSeverity(null)"
        >
          All ({{ data.total }})
        </button>
        <button
          v-for="sev in severityOrder"
          :key="sev"
          class="rounded-full border px-3 py-1 text-xs font-medium transition-all"
          :class="severityFilter === sev
            ? severityColor[sev] + ' border'
            : 'bg-white/5 text-slate-400 border-transparent hover:bg-white/10'"
          @click="setSeverity(severityFilter === sev ? null : sev)"
        >
          {{ sev }} ({{ data.severity_counts[sev] ?? 0 }})
        </button>
      </div>

      <!-- Empty state -->
      <div v-if="sortedFindings.length === 0" class="glass-panel rounded-xl p-12 text-center">
        <ShieldAlert class="mx-auto h-12 w-12 text-emerald-400" />
        <h3 class="mt-4 text-lg font-medium text-white">No Findings</h3>
        <p class="mt-2 text-sm text-slate-400">
          No security findings from agent scans yet. Findings will appear here after agents run shield modules.
        </p>
      </div>

      <!-- Findings List -->
      <div v-else class="space-y-3">
        <div
          v-for="finding in sortedFindings"
          :key="finding.id"
          class="glass-panel rounded-xl p-4 transition-colors hover:bg-white/[0.03]"
        >
          <div class="flex items-start gap-3">
            <!-- Severity dot -->
            <div class="mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full" :class="severityDot[finding.severity]" />

            <div class="min-w-0 flex-1">
              <!-- Title + Severity badge -->
              <div class="flex items-center gap-2">
                <h4 class="text-sm font-medium text-white">
                  {{ finding.title || 'Untitled Finding' }}
                </h4>
                <span
                  class="rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase"
                  :class="severityColor[finding.severity]"
                >
                  {{ finding.severity }}
                </span>
              </div>

              <!-- Detail -->
              <p v-if="finding.detail" class="mt-1 text-xs text-slate-400 line-clamp-2">
                {{ finding.detail }}
              </p>

              <!-- Meta row -->
              <div class="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-500">
                <span v-if="finding.target_ip">IP: <span class="text-slate-300">{{ finding.target_ip }}</span></span>
                <span>Target: <span class="text-slate-300">{{ finding.target }}</span></span>
                <span>Module: <span class="text-slate-300">{{ finding.module }}</span></span>
                <span v-if="finding.site_name">Site: <span class="text-slate-300">{{ finding.site_name }}</span></span>
                <span>{{ new Date(finding.scanned_at).toLocaleString() }}</span>
              </div>

              <!-- Remediation -->
              <div v-if="finding.remediation" class="mt-2 rounded-md bg-emerald-500/5 border border-emerald-500/10 px-3 py-2">
                <p class="text-[11px] font-medium text-emerald-400">Remediation</p>
                <p class="text-xs text-slate-400">{{ finding.remediation }}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

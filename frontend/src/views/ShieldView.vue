<script setup lang="ts">
import { computed } from 'vue'
import {
  Shield,
  Loader2,
  AlertTriangle,
  RefreshCw,
  CheckCircle,
  XCircle,
} from 'lucide-vue-next'
import { useShield } from '@/composables/useShield'
import type { ScanDepth } from '@/types/shield'
import ScanForm from '@/components/shield/ScanForm.vue'
import ShieldScore from '@/components/shield/ShieldScore.vue'
import ModuleScoreCards from '@/components/shield/ModuleScoreCards.vue'
import FindingsList from '@/components/shield/FindingsList.vue'

const {
  currentScan,
  findings,
  loading,
  scanning,
  error,
  startScan,
  fetchScan,
} = useShield()

async function handleScan(target: string, depth: ScanDepth) {
  await startScan(target, depth)
}

function handleRefresh() {
  if (currentScan.value?.id) {
    fetchScan(currentScan.value.id)
  }
}

const statusText = computed(() => {
  if (!currentScan.value) return ''
  switch (currentScan.value.status) {
    case 'queued':
      return 'Scan queued, waiting to start...'
    case 'running':
      return `Scanning ${currentScan.value.target}...`
    case 'completed':
      return `Scan completed in ${currentScan.value.duration_seconds ?? '?'}s`
    case 'failed':
      return 'Scan failed'
    default:
      return ''
  }
})

const isComplete = computed(() => currentScan.value?.status === 'completed')
const isFailed = computed(() => currentScan.value?.status === 'failed')
const hasModuleScores = computed(
  () =>
    currentScan.value?.module_scores &&
    Object.keys(currentScan.value.module_scores).length > 0,
)
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Shield - Security Validation</h1>
        <p class="mt-1 text-sm text-slate-400">
          Comprehensive security scanning and vulnerability assessment
        </p>
      </div>
      <button
        class="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
        :disabled="loading || scanning"
        @click="handleRefresh"
      >
        <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
        Refresh
      </button>
    </div>

    <!-- Scan Form -->
    <ScanForm :scanning="scanning" @scan="handleScan" />

    <!-- Error State -->
    <div
      v-if="error && !currentScan"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <AlertTriangle class="mx-auto h-10 w-10 text-amber-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Unable to Start Scan</h2>
      <p class="mt-2 text-sm text-slate-400">{{ error }}</p>
    </div>

    <!-- Empty State (no scan yet) -->
    <div
      v-if="!currentScan && !error"
      class="flex flex-col items-center justify-center py-20"
    >
      <Shield class="h-16 w-16 text-slate-600" />
      <h2 class="mt-4 text-lg font-medium text-slate-400">Enter a target to begin</h2>
      <p class="mt-1 text-sm text-slate-500">
        Provide an IP address, domain, or CIDR range to start a security scan
      </p>
    </div>

    <!-- Scanning State -->
    <div
      v-if="currentScan && scanning"
      class="glass-card rounded-xl p-8 text-center"
    >
      <Loader2 class="mx-auto h-10 w-10 animate-spin text-cyan-400" />
      <p class="mt-3 text-sm text-slate-300">{{ statusText }}</p>
      <div class="mx-auto mt-4 flex max-w-xs items-center gap-3">
        <div class="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
          <div class="h-full w-1/3 animate-pulse rounded-full bg-cyan-500/50" />
        </div>
        <span class="text-xs text-slate-500">{{ currentScan.status }}</span>
      </div>
      <div v-if="currentScan.modules_enabled.length > 0" class="mt-3">
        <span class="text-xs text-slate-500">
          Modules: {{ currentScan.modules_enabled.join(', ') }}
        </span>
      </div>
    </div>

    <!-- Failed State -->
    <div
      v-if="isFailed && !scanning"
      class="glass-card mx-auto max-w-md rounded-xl p-8 text-center"
    >
      <XCircle class="mx-auto h-10 w-10 text-rose-400" />
      <h2 class="mt-3 text-lg font-semibold text-white">Scan Failed</h2>
      <p class="mt-2 text-sm text-slate-400">
        The scan for {{ currentScan?.target }} could not be completed.
      </p>
    </div>

    <!-- Completed State -->
    <template v-if="isComplete && !scanning">
      <!-- Score + Module Scores -->
      <div class="flex flex-col gap-6 lg:flex-row">
        <!-- Left: Shield Score -->
        <div class="glass-card flex items-center justify-center rounded-xl p-6 lg:w-72">
          <ShieldScore
            :score="currentScan?.shield_score ?? null"
            :grade="currentScan?.grade ?? null"
            :loading="loading"
          />
        </div>

        <!-- Right: Module Score Cards -->
        <div class="min-w-0 flex-1">
          <div class="mb-3 flex items-center justify-between">
            <h2 class="text-sm font-medium text-white">Module Scores</h2>
            <div class="flex items-center gap-3 text-xs text-slate-500">
              <span class="flex items-center gap-1">
                <CheckCircle class="h-3 w-3 text-emerald-400" />
                {{ currentScan?.passed_checks ?? 0 }} passed
              </span>
              <span class="flex items-center gap-1">
                <XCircle class="h-3 w-3 text-rose-400" />
                {{ currentScan?.failed_checks ?? 0 }} failed
              </span>
            </div>
          </div>

          <ModuleScoreCards
            v-if="hasModuleScores"
            :scores="currentScan!.module_scores"
          />
          <div v-else class="glass-card rounded-xl p-6 text-center">
            <p class="text-sm text-slate-500">No module breakdown available</p>
          </div>
        </div>
      </div>

      <!-- Scan Info Bar -->
      <div class="glass-card flex flex-wrap items-center gap-4 rounded-lg px-4 py-2.5 text-xs text-slate-500">
        <span>
          Target:
          <span class="font-mono text-slate-300">{{ currentScan?.target }}</span>
        </span>
        <span>
          Depth:
          <span class="text-slate-300">{{ currentScan?.scan_depth }}</span>
        </span>
        <span>
          Duration:
          <span class="font-mono text-slate-300">{{ currentScan?.duration_seconds ?? '?' }}s</span>
        </span>
        <span>
          Checks:
          <span class="font-mono text-slate-300">{{ currentScan?.total_checks }}</span>
        </span>
      </div>

      <!-- Findings -->
      <FindingsList :findings="findings" />
    </template>
  </div>
</template>

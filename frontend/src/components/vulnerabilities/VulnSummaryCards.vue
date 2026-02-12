<script setup lang="ts">
import { computed } from 'vue'
import { Bug, AlertTriangle, AlertCircle, Info, Shield, Server } from 'lucide-vue-next'
import type { AssetVulnSummary } from '@/types/api'

const props = defineProps<{
  summaries: AssetVulnSummary[]
}>()

const stats = computed(() => {
  let totalVulns = 0
  let critical = 0
  let high = 0
  let medium = 0
  let low = 0
  const affectedAssets = props.summaries.filter((s) => s.total_vulns > 0).length

  for (const s of props.summaries) {
    totalVulns += s.total_vulns
    critical += s.critical_count
    high += s.high_count
    medium += s.medium_count
    low += s.low_count
  }

  return { totalVulns, critical, high, medium, low, affectedAssets }
})
</script>

<template>
  <div class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
    <!-- Total Vulns -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Toplam Açık</p>
          <p class="mt-2 text-2xl font-bold text-white tabular-nums">{{ stats.totalVulns }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10">
          <Bug class="h-5 w-5 text-cyan-400" />
        </div>
      </div>
    </div>

    <!-- Critical -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Kritik</p>
          <p class="mt-2 text-2xl font-bold text-rose-400 tabular-nums">{{ stats.critical }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-rose-500/10">
          <AlertTriangle class="h-5 w-5 text-rose-400" />
        </div>
      </div>
    </div>

    <!-- High -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Yüksek</p>
          <p class="mt-2 text-2xl font-bold text-amber-400 tabular-nums">{{ stats.high }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-500/10">
          <AlertCircle class="h-5 w-5 text-amber-400" />
        </div>
      </div>
    </div>

    <!-- Medium -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Orta</p>
          <p class="mt-2 text-2xl font-bold text-cyan-400 tabular-nums">{{ stats.medium }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10">
          <Info class="h-5 w-5 text-cyan-400" />
        </div>
      </div>
    </div>

    <!-- Low -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Düşük</p>
          <p class="mt-2 text-2xl font-bold text-slate-400 tabular-nums">{{ stats.low }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-slate-500/10">
          <Shield class="h-5 w-5 text-slate-400" />
        </div>
      </div>
    </div>

    <!-- Affected Assets -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Etkilenen</p>
          <p class="mt-2 text-2xl font-bold text-purple-400 tabular-nums">{{ stats.affectedAssets }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-purple-500/10">
          <Server class="h-5 w-5 text-purple-400" />
        </div>
      </div>
    </div>
  </div>
</template>

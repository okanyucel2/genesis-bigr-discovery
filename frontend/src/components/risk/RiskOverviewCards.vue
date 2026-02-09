<script setup lang="ts">
import { computed } from 'vue'
import { Gauge, AlertTriangle, AlertCircle, Info } from 'lucide-vue-next'
import type { RiskResponse } from '@/types/api'

const props = defineProps<{
  data: RiskResponse
}>()

const averageRiskColor = computed(() => {
  const score = props.data.average_risk
  if (score >= 80) return { text: 'text-rose-400', bg: 'bg-rose-500/10', accent: '#fb7185' }
  if (score >= 60) return { text: 'text-amber-400', bg: 'bg-amber-500/10', accent: '#fbbf24' }
  if (score >= 40) return { text: 'text-cyan-400', bg: 'bg-cyan-500/10', accent: '#22d3ee' }
  return { text: 'text-emerald-400', bg: 'bg-emerald-500/10', accent: '#34d399' }
})

const gaugePercent = computed(() => Math.min(100, Math.max(0, props.data.average_risk)))
</script>

<template>
  <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
    <!-- Average Risk -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">
            Average Risk
          </p>
          <p class="mt-2 text-2xl font-bold tabular-nums" :class="averageRiskColor.text">
            {{ data.average_risk.toFixed(1) }}
          </p>
          <!-- Gauge bar -->
          <div class="mt-2 h-1.5 w-full rounded-full bg-white/5">
            <div
              class="h-full rounded-full transition-all duration-700"
              :style="{
                width: `${gaugePercent}%`,
                backgroundColor: averageRiskColor.accent,
              }"
            />
          </div>
        </div>
        <div
          class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg"
          :class="averageRiskColor.bg"
        >
          <Gauge class="h-5 w-5" :class="averageRiskColor.text" />
        </div>
      </div>
    </div>

    <!-- Critical Count -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">
            Critical
          </p>
          <p class="mt-2 text-2xl font-bold text-rose-400 tabular-nums">
            {{ data.critical_count }}
          </p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-rose-500/10">
          <AlertTriangle class="h-5 w-5 text-rose-400" />
        </div>
      </div>
    </div>

    <!-- High Count -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">
            High
          </p>
          <p class="mt-2 text-2xl font-bold text-amber-400 tabular-nums">
            {{ data.high_count }}
          </p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-500/10">
          <AlertCircle class="h-5 w-5 text-amber-400" />
        </div>
      </div>
    </div>

    <!-- Medium Count -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">
            Medium
          </p>
          <p class="mt-2 text-2xl font-bold text-cyan-400 tabular-nums">
            {{ data.medium_count }}
          </p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10">
          <Info class="h-5 w-5 text-cyan-400" />
        </div>
      </div>
    </div>
  </div>
</template>

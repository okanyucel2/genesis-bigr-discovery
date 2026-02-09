<script setup lang="ts">
import { computed } from 'vue'
import type { ModuleScore } from '@/types/shield'

const props = defineProps<{
  scores: Record<string, ModuleScore>
}>()

const moduleLabels: Record<string, string> = {
  tls: 'TLS',
  ports: 'Ports',
  cve: 'CVE',
  headers: 'Headers',
  dns: 'DNS',
  creds: 'Creds',
  owasp: 'OWASP',
}

const moduleList = computed(() => {
  return Object.entries(props.scores).map(([key, score]) => ({
    key,
    label: moduleLabels[key] ?? key.toUpperCase(),
    ...score,
  }))
})

function scoreColor(score: number) {
  if (score >= 80) return { bar: 'bg-emerald-400', text: 'text-emerald-400' }
  if (score >= 60) return { bar: 'bg-amber-400', text: 'text-amber-400' }
  return { bar: 'bg-rose-400', text: 'text-rose-400' }
}
</script>

<template>
  <div v-if="moduleList.length === 0" class="glass-card rounded-xl p-6 text-center">
    <p class="text-sm text-slate-500">No module scores available</p>
  </div>

  <div v-else class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
    <div
      v-for="mod in moduleList"
      :key="mod.key"
      class="glass-card rounded-lg p-4"
    >
      <!-- Module name and score -->
      <div class="mb-2 flex items-center justify-between">
        <span class="text-sm font-medium text-slate-300">{{ mod.label }}</span>
        <span :class="['text-sm font-bold tabular-nums', scoreColor(mod.score).text]">
          {{ mod.score }}
        </span>
      </div>

      <!-- Score bar -->
      <div class="mb-2 h-1.5 w-full overflow-hidden rounded-full bg-white/5">
        <div
          :class="['h-full rounded-full transition-all duration-700', scoreColor(mod.score).bar]"
          :style="{ width: `${mod.score}%` }"
        />
      </div>

      <!-- Checks and findings -->
      <div class="flex items-center justify-between text-xs text-slate-500">
        <span>{{ mod.passed_checks }}/{{ mod.total_checks }} checks</span>
        <span v-if="mod.findings_count > 0" class="text-rose-400">
          {{ mod.findings_count }} finding{{ mod.findings_count !== 1 ? 's' : '' }}
        </span>
      </div>
    </div>
  </div>
</template>

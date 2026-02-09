<script setup lang="ts">
import { computed } from 'vue'
import type { ShieldFinding } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

// Filter to findings that have both CVSS and EPSS
const cvePoints = computed(() =>
  props.findings.filter(f => f.cvss_score != null && f.epss_score != null)
    .map(f => ({
      id: f.id,
      cveId: f.cve_id ?? f.title,
      cvss: f.cvss_score!,
      epss: f.epss_score! * 100, // Convert to percentage
      severity: f.severity,
      kev: f.cisa_kev,
    }))
)

// Position calculation: X = CVSS (0-10) → 0-100%, Y = EPSS (0-100) → inverted (100-0%)
function dotStyle(point: { cvss: number; epss: number }) {
  return {
    left: `${(point.cvss / 10) * 100}%`,
    bottom: `${point.epss}%`,
  }
}

function dotColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500'
    case 'high': return 'bg-rose-500'
    case 'medium': return 'bg-amber-500'
    case 'low': return 'bg-slate-400'
    default: return 'bg-slate-500'
  }
}

const quadrantCounts = computed(() => {
  const q = { urgent: 0, monitor: 0, plan: 0, low: 0 }
  for (const p of cvePoints.value) {
    if (p.cvss >= 5 && p.epss >= 50) q.urgent++
    else if (p.cvss < 5 && p.epss >= 50) q.monitor++
    else if (p.cvss >= 5 && p.epss < 50) q.plan++
    else q.low++
  }
  return q
})
</script>

<template>
  <div class="glass-card rounded-xl p-4">
    <h3 class="mb-3 text-sm font-medium text-white">Priority Matrix</h3>

    <div v-if="cvePoints.length === 0" class="flex flex-col items-center justify-center py-12 text-slate-500">
      <p class="text-sm">No CVE data for priority matrix</p>
    </div>

    <div v-else>
      <!-- Quadrant summary -->
      <div class="mb-4 grid grid-cols-4 gap-2 text-center text-xs">
        <div class="rounded bg-red-500/10 px-2 py-1">
          <span class="font-bold text-red-400">{{ quadrantCounts.urgent }}</span>
          <span class="text-slate-500"> Urgent</span>
        </div>
        <div class="rounded bg-amber-500/10 px-2 py-1">
          <span class="font-bold text-amber-400">{{ quadrantCounts.monitor }}</span>
          <span class="text-slate-500"> Monitor</span>
        </div>
        <div class="rounded bg-rose-500/10 px-2 py-1">
          <span class="font-bold text-rose-400">{{ quadrantCounts.plan }}</span>
          <span class="text-slate-500"> Plan</span>
        </div>
        <div class="rounded bg-slate-500/10 px-2 py-1">
          <span class="font-bold text-slate-400">{{ quadrantCounts.low }}</span>
          <span class="text-slate-500"> Low</span>
        </div>
      </div>

      <!-- Scatter plot -->
      <div class="relative">
        <!-- Y-axis label -->
        <div class="absolute -left-6 top-1/2 -translate-y-1/2 -rotate-90 text-[10px] text-slate-500 whitespace-nowrap">
          EPSS Score (%)
        </div>

        <!-- Plot area -->
        <div class="relative ml-4 aspect-square w-full overflow-hidden rounded-lg border border-white/5 bg-white/[0.02]">
          <!-- Quadrant backgrounds -->
          <div class="absolute right-0 top-0 h-1/2 w-1/2 bg-red-500/5" />
          <div class="absolute left-0 top-0 h-1/2 w-1/2 bg-amber-500/5" />
          <div class="absolute bottom-0 right-0 h-1/2 w-1/2 bg-rose-500/5" />
          <div class="absolute bottom-0 left-0 h-1/2 w-1/2 bg-slate-500/5" />

          <!-- Grid lines -->
          <div class="absolute left-1/2 top-0 h-full w-px bg-white/10" />
          <div class="absolute left-0 top-1/2 h-px w-full bg-white/10" />

          <!-- Quadrant labels -->
          <span class="absolute right-2 top-2 text-[9px] font-medium text-red-400/60">URGENT</span>
          <span class="absolute left-2 top-2 text-[9px] font-medium text-amber-400/60">MONITOR</span>
          <span class="absolute bottom-2 right-2 text-[9px] font-medium text-rose-400/60">PLAN</span>
          <span class="absolute bottom-2 left-2 text-[9px] font-medium text-slate-400/60">LOW</span>

          <!-- Data points -->
          <div
            v-for="point in cvePoints"
            :key="point.id"
            class="group absolute -ml-1.5 -mb-1.5 h-3 w-3 rounded-full transition-transform hover:scale-150"
            :class="[dotColor(point.severity), point.kev ? 'ring-2 ring-red-400 animate-pulse' : '']"
            :style="dotStyle(point)"
          >
            <!-- Tooltip -->
            <div class="invisible absolute bottom-full left-1/2 mb-2 -translate-x-1/2 whitespace-nowrap rounded bg-slate-800 px-2 py-1 text-[10px] text-white shadow-lg group-hover:visible z-10">
              <div class="font-mono font-bold">{{ point.cveId }}</div>
              <div>CVSS: {{ point.cvss }} | EPSS: {{ point.epss.toFixed(0) }}%</div>
              <div v-if="point.kev" class="text-red-400">CISA KEV</div>
            </div>
          </div>
        </div>

        <!-- X-axis label -->
        <div class="mt-1 text-center text-[10px] text-slate-500">CVSS Score (0-10)</div>

        <!-- X-axis ticks -->
        <div class="ml-4 flex justify-between text-[9px] text-slate-600">
          <span>0</span>
          <span>5</span>
          <span>10</span>
        </div>
      </div>
    </div>
  </div>
</template>

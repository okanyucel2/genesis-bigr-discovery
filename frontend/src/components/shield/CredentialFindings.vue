<script setup lang="ts">
import { computed } from 'vue'
import { KeyRound, ShieldCheck } from 'lucide-vue-next'
import type { ShieldFinding, FindingSeverity } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

const criticalCount = computed(
  () => props.findings.filter((f) => f.severity === 'critical').length,
)
const highCount = computed(
  () => props.findings.filter((f) => f.severity === 'high').length,
)

function severityClass(s: FindingSeverity) {
  const map: Record<string, string> = {
    critical: 'bg-rose-500/20 text-rose-400',
    high: 'bg-amber-500/20 text-amber-400',
    medium: 'bg-yellow-500/20 text-yellow-400',
    low: 'bg-blue-500/20 text-blue-400',
    info: 'bg-slate-500/20 text-slate-400',
  }
  return map[s] || map.info
}

function severityBorder(s: FindingSeverity) {
  const map: Record<string, string> = {
    critical: 'border-rose-500/50',
    high: 'border-amber-500/50',
    medium: 'border-yellow-500/50',
    low: 'border-blue-500/50',
    info: 'border-slate-500/50',
  }
  return map[s] || map.info
}
</script>

<template>
  <div class="space-y-4">
    <!-- Summary Bar -->
    <div class="glass-card rounded-lg px-4 py-3 flex items-center justify-between">
      <div class="flex items-center gap-2">
        <KeyRound class="h-4 w-4 text-amber-400" />
        <span class="text-sm text-slate-300">
          {{ findings.length }} credential {{ findings.length === 1 ? 'issue' : 'issues' }} found
        </span>
      </div>
      <div class="flex items-center gap-3 text-xs">
        <span v-if="criticalCount > 0" class="text-rose-400">{{ criticalCount }} critical</span>
        <span v-if="highCount > 0" class="text-amber-400">{{ highCount }} high</span>
      </div>
    </div>

    <!-- Empty State -->
    <div v-if="findings.length === 0" class="glass-card rounded-xl p-8 text-center">
      <ShieldCheck class="mx-auto h-10 w-10 text-emerald-400" />
      <h3 class="mt-3 text-sm font-medium text-white">No Default Credentials Found</h3>
      <p class="mt-1 text-xs text-slate-500">All tested services require proper authentication</p>
    </div>

    <!-- Findings Grid -->
    <div v-else class="grid gap-3 sm:grid-cols-2">
      <div
        v-for="finding in findings"
        :key="finding.id"
        class="glass-card rounded-lg p-4 border-l-2"
        :class="severityBorder(finding.severity)"
      >
        <div class="flex items-start justify-between">
          <div>
            <h4 class="text-sm font-medium text-white">{{ finding.title }}</h4>
            <p class="mt-1 text-xs text-slate-400">{{ finding.description }}</p>
          </div>
          <span
            class="ml-2 inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
            :class="severityClass(finding.severity)"
          >
            {{ finding.severity }}
          </span>
        </div>
        <div
          v-if="finding.evidence && Object.keys(finding.evidence).length > 0"
          class="mt-3 rounded bg-black/30 p-2 font-mono text-xs text-slate-400"
        >
          <div v-if="(finding.evidence as Record<string, unknown>).service">
            Service: {{ (finding.evidence as Record<string, unknown>).service }}
          </div>
          <div v-if="(finding.evidence as Record<string, unknown>).port">
            Port: {{ (finding.evidence as Record<string, unknown>).port }}
          </div>
          <div v-if="(finding.evidence as Record<string, unknown>).path">
            Path: {{ (finding.evidence as Record<string, unknown>).path }}
          </div>
        </div>
        <p v-if="finding.remediation" class="mt-2 text-xs text-cyan-400/80">
          {{ finding.remediation }}
        </p>
      </div>
    </div>
  </div>
</template>

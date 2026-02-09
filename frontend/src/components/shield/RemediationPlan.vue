<script setup lang="ts">
import { computed } from 'vue'
import { Wrench } from 'lucide-vue-next'
import type { ShieldFinding, FindingSeverity } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

interface PlanItem {
  finding: ShieldFinding
  effort: string
  impact: string
  label: string
}

function computePriority(finding: ShieldFinding): { effort: string; impact: string; label: string } {
  const impact = (['critical', 'high'] as FindingSeverity[]).includes(finding.severity) ? 'high' : 'low'

  const lowEffortModules = ['headers', 'dns', 'tls']
  const highEffortModules = ['cve', 'owasp']
  let effort: string
  if (lowEffortModules.includes(finding.module)) {
    effort = 'low'
  } else if (highEffortModules.includes(finding.module)) {
    effort = 'high'
  } else {
    effort = 'medium'
  }

  if (impact === 'high' && effort === 'low') return { effort, impact, label: 'Quick Win' }
  if (impact === 'high' && effort !== 'low') return { effort, impact, label: 'Important' }
  if (impact === 'low' && effort !== 'high') return { effort, impact, label: 'Nice to Have' }
  return { effort, impact, label: 'Deprioritize' }
}

const labelOrder: Record<string, number> = {
  'Quick Win': 0,
  'Important': 1,
  'Nice to Have': 2,
  'Deprioritize': 3,
}

const planItems = computed<PlanItem[]>(() => {
  return props.findings
    .filter((f) => f.remediation)
    .map((f) => ({
      finding: f,
      ...computePriority(f),
    }))
    .sort((a, b) => (labelOrder[a.label] ?? 4) - (labelOrder[b.label] ?? 4))
})

interface Quadrant {
  label: string
  count: number
  color: string
}

const quadrants = computed<Quadrant[]>(() => {
  const counts: Record<string, number> = {
    'Quick Win': 0,
    'Important': 0,
    'Nice to Have': 0,
    'Deprioritize': 0,
  }
  for (const item of planItems.value) {
    counts[item.label] = (counts[item.label] ?? 0) + 1
  }
  return [
    { label: 'Quick Win', count: counts['Quick Win'] ?? 0, color: 'text-emerald-400' },
    { label: 'Important', count: counts['Important'] ?? 0, color: 'text-amber-400' },
    { label: 'Nice to Have', count: counts['Nice to Have'] ?? 0, color: 'text-cyan-400' },
    { label: 'Deprioritize', count: counts['Deprioritize'] ?? 0, color: 'text-slate-400' },
  ]
})

function priorityBadgeClass(label: string): string {
  switch (label) {
    case 'Quick Win':
      return 'bg-emerald-500/20 text-emerald-400'
    case 'Important':
      return 'bg-amber-500/20 text-amber-400'
    case 'Nice to Have':
      return 'bg-cyan-500/20 text-cyan-400'
    case 'Deprioritize':
      return 'bg-slate-500/20 text-slate-400'
    default:
      return 'bg-slate-500/20 text-slate-400'
  }
}
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="glass-card rounded-lg px-4 py-3 flex items-center gap-2">
      <Wrench class="h-4 w-4 text-cyan-400" />
      <span class="text-sm font-medium text-white">Remediation Plan</span>
      <span class="text-xs text-slate-500">({{ planItems.length }} actions)</span>
    </div>

    <!-- Empty state -->
    <div
      v-if="planItems.length === 0"
      class="glass-card rounded-xl p-8 text-center"
    >
      <Wrench class="mx-auto h-10 w-10 text-slate-500" />
      <h3 class="mt-3 text-sm font-medium text-white">No Remediation Actions</h3>
      <p class="mt-1 text-xs text-slate-500">No findings with remediation steps available.</p>
    </div>

    <template v-else>
      <!-- Quadrant Summary -->
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div
          v-for="q in quadrants"
          :key="q.label"
          class="glass-card rounded-lg p-3 text-center"
        >
          <div class="text-lg font-bold" :class="q.color">{{ q.count }}</div>
          <div class="text-xs text-slate-500">{{ q.label }}</div>
        </div>
      </div>

      <!-- Plan Items -->
      <div class="space-y-2">
        <div
          v-for="(item, idx) in planItems"
          :key="item.finding.id"
          class="glass-card flex items-start gap-3 rounded-lg px-4 py-3"
        >
          <span class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-white/10 text-xs font-bold text-slate-400">
            {{ idx + 1 }}
          </span>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span
                class="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase"
                :class="priorityBadgeClass(item.label)"
              >
                {{ item.label }}
              </span>
              <span class="text-sm text-white">{{ item.finding.title }}</span>
            </div>
            <p class="mt-1 text-xs text-slate-400">{{ item.finding.remediation }}</p>
            <div class="mt-2 flex items-center gap-3 text-[10px] text-slate-500">
              <span>Effort: {{ item.effort }}</span>
              <span>Impact: {{ item.impact }}</span>
              <span>Module: {{ item.finding.module }}</span>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

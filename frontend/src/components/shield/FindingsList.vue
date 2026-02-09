<script setup lang="ts">
import { ref, computed } from 'vue'
import { ChevronDown, ChevronRight, CheckCircle, ExternalLink } from 'lucide-vue-next'
import type { ShieldFinding, FindingSeverity } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

const expandedId = ref<string | null>(null)

const severityOrder: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

const sortedFindings = computed(() => {
  return [...props.findings].sort(
    (a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5),
  )
})

function toggleRow(id: string) {
  expandedId.value = expandedId.value === id ? null : id
}

function severityConfig(severity: FindingSeverity) {
  switch (severity) {
    case 'critical':
      return { bg: 'bg-rose-500/20', text: 'text-rose-400', label: 'CRITICAL' }
    case 'high':
      return { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'HIGH' }
    case 'medium':
      return { bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'MEDIUM' }
    case 'low':
      return { bg: 'bg-blue-500/20', text: 'text-blue-400', label: 'LOW' }
    case 'info':
      return { bg: 'bg-slate-500/20', text: 'text-slate-400', label: 'INFO' }
    default:
      return { bg: 'bg-slate-500/20', text: 'text-slate-400', label: severity }
  }
}

function formatTarget(finding: ShieldFinding): string {
  if (finding.target_port) {
    return `${finding.target_ip}:${finding.target_port}`
  }
  return finding.target_ip
}
</script>

<template>
  <!-- Empty state -->
  <div
    v-if="findings.length === 0"
    class="glass-card rounded-xl p-8 text-center"
  >
    <CheckCircle class="mx-auto h-10 w-10 text-emerald-400" />
    <h3 class="mt-3 text-lg font-medium text-white">No findings</h3>
    <p class="mt-1 text-sm text-slate-400">Your target looks secure!</p>
  </div>

  <!-- Findings table -->
  <div v-else class="glass-card overflow-hidden rounded-xl">
    <!-- Header -->
    <div class="border-b border-[var(--border-glass)] px-4 py-3">
      <h3 class="text-sm font-medium text-white">
        Findings
        <span class="ml-1 text-slate-500">({{ findings.length }})</span>
      </h3>
    </div>

    <!-- Table header -->
    <div
      class="grid grid-cols-[100px_1fr_80px_140px_100px] gap-2 border-b border-[var(--border-glass)] px-4 py-2 text-xs font-medium text-slate-500"
    >
      <span>Severity</span>
      <span>Title</span>
      <span>Module</span>
      <span>Target</span>
      <span>CVE</span>
    </div>

    <!-- Rows -->
    <div
      v-for="finding in sortedFindings"
      :key="finding.id"
      class="border-b border-[var(--border-glass)] last:border-0"
    >
      <!-- Main row -->
      <button
        class="grid w-full grid-cols-[100px_1fr_80px_140px_100px] items-center gap-2 px-4 py-3 text-left text-sm transition-colors hover:bg-white/5"
        @click="toggleRow(finding.id)"
      >
        <!-- Severity badge -->
        <span
          :class="[
            'inline-flex w-fit items-center rounded-full px-2 py-0.5 text-xs font-semibold',
            severityConfig(finding.severity).bg,
            severityConfig(finding.severity).text,
          ]"
        >
          {{ severityConfig(finding.severity).label }}
        </span>

        <!-- Title -->
        <span class="flex items-center gap-1.5 truncate text-slate-300">
          <component
            :is="expandedId === finding.id ? ChevronDown : ChevronRight"
            class="h-3.5 w-3.5 shrink-0 text-slate-500"
          />
          {{ finding.title }}
        </span>

        <!-- Module -->
        <span class="text-xs text-slate-500">{{ finding.module }}</span>

        <!-- Target -->
        <span class="truncate font-mono text-xs text-slate-400">
          {{ formatTarget(finding) }}
        </span>

        <!-- CVE -->
        <span v-if="finding.cve_id" class="font-mono text-xs text-cyan-400">
          {{ finding.cve_id }}
        </span>
        <span v-else class="text-xs text-slate-600">--</span>
      </button>

      <!-- Expanded detail -->
      <div
        v-if="expandedId === finding.id"
        class="border-t border-[var(--border-glass)] bg-white/[0.02] px-6 py-4"
      >
        <div class="space-y-3 text-sm">
          <!-- Description -->
          <div>
            <h4 class="mb-1 text-xs font-medium uppercase text-slate-500">Description</h4>
            <p class="text-slate-300">{{ finding.description }}</p>
          </div>

          <!-- Remediation -->
          <div>
            <h4 class="mb-1 text-xs font-medium uppercase text-slate-500">Remediation</h4>
            <p class="text-slate-300">{{ finding.remediation }}</p>
          </div>

          <!-- Metadata row -->
          <div class="flex flex-wrap gap-4 text-xs">
            <div v-if="finding.cvss_score !== null">
              <span class="text-slate-500">CVSS:</span>
              <span class="ml-1 font-mono font-semibold text-white">{{ finding.cvss_score }}</span>
            </div>
            <div v-if="finding.epss_score !== null">
              <span class="text-slate-500">EPSS:</span>
              <span class="ml-1 font-mono text-slate-300">
                {{ (finding.epss_score * 100).toFixed(1) }}%
              </span>
            </div>
            <div v-if="finding.cisa_kev">
              <span class="rounded bg-rose-500/20 px-1.5 py-0.5 font-semibold text-rose-400">
                CISA KEV
              </span>
            </div>
            <div v-if="finding.attack_technique">
              <span class="text-slate-500">Technique:</span>
              <span class="ml-1 text-slate-300">{{ finding.attack_technique }}</span>
            </div>
            <div v-if="finding.attack_tactic">
              <span class="text-slate-500">Tactic:</span>
              <span class="ml-1 text-slate-300">{{ finding.attack_tactic }}</span>
            </div>
            <a
              v-if="finding.cve_id"
              :href="`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
            >
              NVD <ExternalLink class="h-3 w-3" />
            </a>
          </div>

          <!-- Evidence -->
          <div v-if="finding.evidence && Object.keys(finding.evidence).length > 0">
            <h4 class="mb-1 text-xs font-medium uppercase text-slate-500">Evidence</h4>
            <pre class="overflow-x-auto rounded-lg bg-black/30 p-3 font-mono text-xs text-slate-400">{{ JSON.stringify(finding.evidence, null, 2) }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

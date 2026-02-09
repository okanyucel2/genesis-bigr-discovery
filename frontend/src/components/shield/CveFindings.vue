<script setup lang="ts">
import { ref, computed } from 'vue'
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  ExternalLink,
  ArrowUpDown,
  Filter,
  ChevronDown,
  ChevronRight,
} from 'lucide-vue-next'
import type { ShieldFinding, FindingSeverity } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

type SortField = 'severity' | 'cvss' | 'epss'

const sortBy = ref<SortField>('severity')
const expandedId = ref<string | null>(null)
const severityFilter = ref<Set<FindingSeverity>>(
  new Set(['critical', 'high', 'medium', 'low', 'info']),
)

const severityOrder: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

const sortedFindings = computed(() => {
  const filtered = props.findings.filter((f) =>
    severityFilter.value.has(f.severity),
  )
  return [...filtered].sort((a, b) => {
    switch (sortBy.value) {
      case 'cvss':
        return (b.cvss_score ?? 0) - (a.cvss_score ?? 0)
      case 'epss':
        return (b.epss_score ?? 0) - (a.epss_score ?? 0)
      default:
        return (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
    }
  })
})

const criticalCount = computed(
  () => props.findings.filter((f) => f.severity === 'critical').length,
)
const kevCount = computed(
  () => props.findings.filter((f) => f.cisa_kev).length,
)

function toggleRow(id: string) {
  expandedId.value = expandedId.value === id ? null : id
}

function toggleSeverityFilter(severity: FindingSeverity) {
  const next = new Set(severityFilter.value)
  if (next.has(severity)) {
    next.delete(severity)
  } else {
    next.add(severity)
  }
  severityFilter.value = next
}

function cvssConfig(score: number | null) {
  if (score === null) return { bg: 'bg-slate-500/20', text: 'text-slate-400', label: 'N/A' }
  if (score >= 9.0) return { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Critical' }
  if (score >= 7.0) return { bg: 'bg-rose-500/20', text: 'text-rose-400', label: 'High' }
  if (score >= 4.0) return { bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'Medium' }
  return { bg: 'bg-slate-500/20', text: 'text-slate-400', label: 'Low' }
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

function epssPercent(score: number | null): number {
  if (score === null) return 0
  return Math.round(score * 100)
}

function epssBarColor(score: number | null): string {
  if (score === null) return 'bg-slate-500'
  if (score >= 0.7) return 'bg-red-400'
  if (score >= 0.4) return 'bg-amber-400'
  return 'bg-cyan-400'
}

const sortOptions: { value: SortField; label: string }[] = [
  { value: 'severity', label: 'Severity' },
  { value: 'cvss', label: 'CVSS Score' },
  { value: 'epss', label: 'EPSS Score' },
]

const filterSeverities: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
</script>

<template>
  <!-- Empty state -->
  <div
    v-if="findings.length === 0"
    class="glass-card rounded-xl p-8 text-center"
  >
    <CheckCircle class="mx-auto h-10 w-10 text-emerald-400" />
    <h3 class="mt-3 text-lg font-medium text-white">No CVEs Detected</h3>
    <p class="mt-1 text-sm text-slate-400">No known vulnerabilities were found for the target services.</p>
  </div>

  <div v-else class="glass-card overflow-hidden rounded-xl">
    <!-- Summary bar -->
    <div class="border-b border-[var(--border-glass)] px-4 py-3">
      <div class="flex flex-wrap items-center gap-4 text-sm">
        <h3 class="font-semibold text-white flex items-center gap-2">
          <ShieldAlert class="h-4 w-4 text-rose-400" />
          CVE Intelligence
        </h3>
        <span class="text-slate-400">
          <span class="font-mono font-semibold text-white">{{ findings.length }}</span>
          CVE{{ findings.length !== 1 ? 's' : '' }} found
        </span>
        <span v-if="criticalCount > 0" class="text-rose-400">
          <span class="font-mono font-semibold">{{ criticalCount }}</span> critical
        </span>
        <span v-if="kevCount > 0" class="flex items-center gap-1 text-red-400">
          <ShieldAlert class="h-3.5 w-3.5" />
          <span class="font-mono font-semibold">{{ kevCount }}</span> actively exploited (KEV)
        </span>
      </div>
    </div>

    <!-- Controls: Sort + Filter -->
    <div class="flex flex-wrap items-center gap-3 border-b border-[var(--border-glass)] px-4 py-2.5">
      <!-- Sort -->
      <div class="flex items-center gap-1.5 text-xs text-slate-500">
        <ArrowUpDown class="h-3.5 w-3.5" />
        <span>Sort:</span>
        <div class="flex gap-1">
          <button
            v-for="opt in sortOptions"
            :key="opt.value"
            :class="[
              'rounded px-2 py-0.5 transition-colors',
              sortBy === opt.value
                ? 'bg-cyan-500/20 text-cyan-400'
                : 'text-slate-400 hover:bg-white/5 hover:text-slate-300',
            ]"
            @click="sortBy = opt.value"
          >
            {{ opt.label }}
          </button>
        </div>
      </div>

      <span class="text-slate-700">|</span>

      <!-- Filter -->
      <div class="flex items-center gap-1.5 text-xs text-slate-500">
        <Filter class="h-3.5 w-3.5" />
        <span>Filter:</span>
        <div class="flex gap-1">
          <button
            v-for="sev in filterSeverities"
            :key="sev"
            :class="[
              'rounded px-2 py-0.5 transition-colors',
              severityFilter.has(sev)
                ? `${severityConfig(sev).bg} ${severityConfig(sev).text}`
                : 'text-slate-600 hover:text-slate-400',
            ]"
            @click="toggleSeverityFilter(sev)"
          >
            {{ sev }}
          </button>
        </div>
      </div>
    </div>

    <!-- Table header -->
    <div
      class="hidden md:grid grid-cols-[110px_70px_120px_70px_90px_1fr] gap-2 border-b border-[var(--border-glass)] px-4 py-2 text-xs font-medium text-slate-500"
    >
      <span>CVE ID</span>
      <span>CVSS</span>
      <span>EPSS</span>
      <span>KEV</span>
      <span>Severity</span>
      <span>Title</span>
    </div>

    <!-- Rows -->
    <div
      v-for="finding in sortedFindings"
      :key="finding.id"
      class="border-b border-[var(--border-glass)] last:border-0"
    >
      <!-- Main row -->
      <button
        class="w-full px-4 py-3 text-left text-sm transition-colors hover:bg-white/5 md:grid md:grid-cols-[110px_70px_120px_70px_90px_1fr] md:items-center md:gap-2"
        @click="toggleRow(finding.id)"
      >
        <!-- CVE ID -->
        <a
          v-if="finding.cve_id"
          :href="`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`"
          target="_blank"
          rel="noopener noreferrer"
          class="inline-flex items-center gap-1 font-mono text-xs font-semibold text-cyan-400 hover:text-cyan-300"
          @click.stop
        >
          {{ finding.cve_id }}
          <ExternalLink class="h-2.5 w-2.5" />
        </a>
        <span v-else class="text-xs text-slate-600">--</span>

        <!-- CVSS Badge -->
        <span
          :class="[
            'inline-flex w-fit items-center rounded-full px-2 py-0.5 text-xs font-bold tabular-nums',
            cvssConfig(finding.cvss_score).bg,
            cvssConfig(finding.cvss_score).text,
          ]"
        >
          {{ finding.cvss_score !== null ? finding.cvss_score.toFixed(1) : 'N/A' }}
        </span>

        <!-- EPSS bar -->
        <div class="flex items-center gap-1.5">
          <div class="h-1.5 w-16 overflow-hidden rounded-full bg-white/5">
            <div
              :class="['h-full rounded-full transition-all', epssBarColor(finding.epss_score)]"
              :style="{ width: `${epssPercent(finding.epss_score)}%` }"
            />
          </div>
          <span class="font-mono text-xs text-slate-400">
            {{ finding.epss_score !== null ? `${epssPercent(finding.epss_score)}%` : '--' }}
          </span>
        </div>

        <!-- KEV -->
        <span v-if="finding.cisa_kev" class="flex items-center gap-1 text-red-400">
          <ShieldAlert class="h-3.5 w-3.5" />
          <span class="text-[10px] font-semibold uppercase">KEV</span>
        </span>
        <span v-else>
          <ShieldCheck class="h-3.5 w-3.5 text-slate-600" />
        </span>

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
      </button>

      <!-- Expanded detail -->
      <div
        v-if="expandedId === finding.id"
        class="border-t border-[var(--border-glass)] bg-white/[0.02] px-6 py-4"
      >
        <div class="space-y-3 text-sm">
          <div>
            <h4 class="mb-1 text-xs font-medium uppercase text-slate-500">Description</h4>
            <p class="text-slate-300">{{ finding.description }}</p>
          </div>
          <div>
            <h4 class="mb-1 text-xs font-medium uppercase text-slate-500">Remediation</h4>
            <p class="text-slate-300">{{ finding.remediation }}</p>
          </div>
          <div class="flex flex-wrap gap-4 text-xs">
            <div v-if="finding.target_port">
              <span class="text-slate-500">Port:</span>
              <span class="ml-1 font-mono text-slate-300">{{ finding.target_ip }}:{{ finding.target_port }}</span>
            </div>
            <div v-if="finding.attack_technique">
              <span class="text-slate-500">Technique:</span>
              <span class="ml-1 text-slate-300">{{ finding.attack_technique }}</span>
            </div>
            <div v-if="finding.attack_tactic">
              <span class="text-slate-500">Tactic:</span>
              <span class="ml-1 text-slate-300">{{ finding.attack_tactic }}</span>
            </div>
            <div v-if="finding.cisa_kev">
              <span class="rounded bg-red-500/20 px-1.5 py-0.5 font-semibold text-red-400">
                Actively Exploited
              </span>
            </div>
          </div>
          <div v-if="finding.evidence && Object.keys(finding.evidence).length > 0">
            <h4 class="mb-1 text-xs font-medium uppercase text-slate-500">Evidence</h4>
            <pre class="overflow-x-auto rounded-lg bg-black/30 p-3 font-mono text-xs text-slate-400">{{ JSON.stringify(finding.evidence, null, 2) }}</pre>
          </div>
        </div>
      </div>
    </div>

    <!-- No results after filter -->
    <div
      v-if="sortedFindings.length === 0 && findings.length > 0"
      class="px-4 py-6 text-center text-sm text-slate-500"
    >
      No CVEs match the current filter. Adjust filters to see results.
    </div>
  </div>
</template>

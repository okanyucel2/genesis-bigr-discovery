<script setup lang="ts">
import { computed } from 'vue'
import { Bug, CheckCircle, XCircle } from 'lucide-vue-next'
import type { ShieldFinding, FindingSeverity } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

const PROBE_NAMES = [
  'SQL Injection',
  'Cross-Site Scripting (XSS)',
  'Directory Traversal',
  'Information Disclosure',
  'Open Redirect',
]

/** Map probe names to keywords we look for in finding titles/evidence */
const PROBE_KEYWORDS: Record<string, string[]> = {
  'SQL Injection': ['sql injection', 'sqli'],
  'Cross-Site Scripting (XSS)': ['cross-site scripting', 'xss'],
  'Directory Traversal': ['directory traversal', 'path traversal', 'lfi'],
  'Information Disclosure': ['information disclosure', 'info_disclosure', 'exposed', 'git repository'],
  'Open Redirect': ['open redirect', 'redirect'],
}

interface ProbeResult {
  name: string
  passed: boolean
  finding: ShieldFinding | null
}

function matchesProbe(finding: ShieldFinding, keywords: string[]): boolean {
  const titleLower = finding.title.toLowerCase()
  const evidence = finding.evidence as Record<string, unknown> | null
  const probe = evidence?.probe as string | undefined
  return keywords.some(
    (kw) =>
      titleLower.includes(kw) ||
      (probe && probe.toLowerCase().includes(kw)),
  )
}

const probeResults = computed<ProbeResult[]>(() => {
  return PROBE_NAMES.map((name) => {
    const keywords = PROBE_KEYWORDS[name] ?? [name.toLowerCase()]
    const finding = props.findings.find((f) => matchesProbe(f, keywords)) ?? null
    return {
      name,
      passed: finding === null,
      finding,
    }
  })
})

const passCount = computed(
  () => probeResults.value.filter((p) => p.passed).length,
)
const failCount = computed(
  () => probeResults.value.filter((p) => !p.passed).length,
)

const failedFindings = computed(() =>
  props.findings.filter((f) => f.severity !== 'info'),
)

function severityTextClass(s: FindingSeverity) {
  const map: Record<string, string> = {
    critical: 'text-rose-400',
    high: 'text-amber-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
    info: 'text-slate-400',
  }
  return map[s] || map.info
}

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
</script>

<template>
  <div class="space-y-4">
    <!-- Summary -->
    <div class="glass-card rounded-lg px-4 py-3 flex items-center justify-between">
      <div class="flex items-center gap-2">
        <Bug class="h-4 w-4 text-purple-400" />
        <span class="text-sm text-slate-300">OWASP Probe Results</span>
      </div>
      <div class="flex items-center gap-3 text-xs">
        <span class="flex items-center gap-1 text-emerald-400">
          <CheckCircle class="h-3 w-3" /> {{ passCount }} passed
        </span>
        <span v-if="failCount > 0" class="flex items-center gap-1 text-rose-400">
          <XCircle class="h-3 w-3" /> {{ failCount }} failed
        </span>
      </div>
    </div>

    <!-- Probe checklist -->
    <div class="glass-card divide-y divide-white/5 rounded-xl">
      <div
        v-for="probe in probeResults"
        :key="probe.name"
        class="flex items-center gap-3 px-4 py-3"
      >
        <component
          :is="probe.passed ? CheckCircle : XCircle"
          class="h-4 w-4 shrink-0"
          :class="probe.passed ? 'text-emerald-400' : 'text-rose-400'"
        />
        <div class="min-w-0 flex-1">
          <span
            class="text-sm"
            :class="probe.passed ? 'text-slate-400' : 'text-white'"
          >
            {{ probe.name }}
          </span>
          <p
            v-if="!probe.passed && probe.finding"
            class="mt-0.5 text-xs text-slate-500"
          >
            {{ probe.finding.title }}
          </p>
        </div>
        <span
          v-if="!probe.passed && probe.finding"
          class="text-[10px] font-semibold uppercase"
          :class="severityTextClass(probe.finding.severity)"
        >
          {{ probe.finding.severity }}
        </span>
      </div>
    </div>

    <!-- Detailed findings for failed probes -->
    <div v-if="failedFindings.length > 0" class="space-y-3">
      <h3 class="text-xs font-medium uppercase tracking-wider text-slate-500">Details</h3>
      <div
        v-for="finding in failedFindings"
        :key="finding.id"
        class="glass-card rounded-lg p-4"
      >
        <div class="flex items-start justify-between">
          <h4 class="text-sm font-medium text-white">{{ finding.title }}</h4>
          <span
            class="ml-2 inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
            :class="severityClass(finding.severity)"
          >
            {{ finding.severity }}
          </span>
        </div>
        <p class="mt-1 text-xs text-slate-400">{{ finding.description }}</p>
        <div
          v-if="finding.evidence && Object.keys(finding.evidence).length > 0"
          class="mt-2 rounded bg-black/30 p-2 font-mono text-xs text-slate-400"
        >
          <template v-for="(val, key) in (finding.evidence as Record<string, unknown>)" :key="key">
            <div>{{ key }}: {{ val }}</div>
          </template>
        </div>
        <p v-if="finding.remediation" class="mt-2 text-xs text-cyan-400/80">
          {{ finding.remediation }}
        </p>
      </div>
    </div>
  </div>
</template>

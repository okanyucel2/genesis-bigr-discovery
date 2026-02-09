<script setup lang="ts">
import { ref, computed } from 'vue'
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
} from 'lucide-vue-next'
import type { ShieldFinding, FindingSeverity } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

interface HeaderCheck {
  name: string
  key: string
  status: 'present' | 'missing' | 'info_leak'
  severity: FindingSeverity | null
  finding: ShieldFinding | null
}

const EXPECTED_HEADERS = [
  { name: 'Strict-Transport-Security (HSTS)', key: 'strict-transport-security' },
  { name: 'Content-Security-Policy (CSP)', key: 'content-security-policy' },
  { name: 'X-Frame-Options', key: 'x-frame-options' },
  { name: 'X-Content-Type-Options', key: 'x-content-type-options' },
  { name: 'Referrer-Policy', key: 'referrer-policy' },
  { name: 'Permissions-Policy', key: 'permissions-policy' },
  { name: 'Server', key: 'server' },
  { name: 'X-Powered-By', key: 'x-powered-by' },
]

const INFO_LEAK_HEADERS = new Set(['server', 'x-powered-by'])

const expandedKey = ref<string | null>(null)

function toggleExpand(key: string) {
  expandedKey.value = expandedKey.value === key ? null : key
}

const headerChecks = computed<HeaderCheck[]>(() => {
  return EXPECTED_HEADERS.map((header) => {
    // Find matching finding for this header
    const finding = props.findings.find((f) => {
      const titleLower = f.title.toLowerCase()
      const keyLower = header.key.toLowerCase()
      return (
        titleLower.includes(keyLower) ||
        titleLower.includes(header.name.toLowerCase().split(' (')[0] ?? '')
      )
    })

    if (!finding) {
      // No finding means the header is present and correct (good)
      return {
        name: header.name,
        key: header.key,
        status: 'present' as const,
        severity: null,
        finding: null,
      }
    }

    // Determine status based on whether this is an info leak header or a missing header
    const isInfoLeak = INFO_LEAK_HEADERS.has(header.key)
    const titleLower = finding.title.toLowerCase()
    const isLeaking = isInfoLeak && (titleLower.includes('leak') || titleLower.includes('exposed') || titleLower.includes('server header'))

    return {
      name: header.name,
      key: header.key,
      status: isLeaking ? ('info_leak' as const) : ('missing' as const),
      severity: finding.severity,
      finding,
    }
  })
})

const presentCount = computed(() => headerChecks.value.filter((h) => h.status === 'present').length)
const totalHeaders = computed(() => headerChecks.value.length)

function statusConfig(status: 'present' | 'missing' | 'info_leak') {
  switch (status) {
    case 'present':
      return { icon: CheckCircle, text: 'text-emerald-400', label: 'Present' }
    case 'missing':
      return { icon: XCircle, text: 'text-rose-400', label: 'Missing' }
    case 'info_leak':
      return { icon: AlertTriangle, text: 'text-amber-400', label: 'Info Leak' }
  }
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
</script>

<template>
  <!-- Empty state -->
  <div
    v-if="findings.length === 0 && headerChecks.every((h) => h.status === 'present')"
    class="glass-card rounded-xl p-8 text-center"
  >
    <ShieldCheck class="mx-auto h-10 w-10 text-emerald-400" />
    <h3 class="mt-3 text-lg font-medium text-white">All headers present</h3>
    <p class="mt-1 text-sm text-slate-400">All recommended security headers are configured correctly.</p>
  </div>

  <div v-else class="glass-card rounded-xl p-5">
    <h3 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
      <ShieldCheck class="h-4 w-4 text-cyan-400" />
      Security Headers Checklist
    </h3>

    <!-- Summary -->
    <div class="mb-4 text-sm text-slate-400">
      <span class="font-mono font-semibold text-white">{{ presentCount }}</span>
      / {{ totalHeaders }} headers configured
    </div>

    <!-- Checklist -->
    <div class="divide-y divide-[var(--border-glass)]">
      <div
        v-for="header in headerChecks"
        :key="header.key"
      >
        <!-- Row -->
        <button
          class="flex w-full items-center gap-3 px-2 py-3 text-left text-sm transition-colors hover:bg-white/5"
          :class="{ 'cursor-default': !header.finding }"
          @click="header.finding ? toggleExpand(header.key) : undefined"
        >
          <!-- Status icon -->
          <component
            :is="statusConfig(header.status).icon"
            :class="['h-4 w-4 shrink-0', statusConfig(header.status).text]"
          />

          <!-- Header name -->
          <span
            :class="[
              'flex-1 font-mono text-xs',
              header.status === 'present' ? 'text-emerald-400' : header.status === 'info_leak' ? 'text-amber-400' : 'text-rose-400',
            ]"
          >
            {{ header.name }}
          </span>

          <!-- Status label -->
          <span :class="['text-xs', statusConfig(header.status).text]">
            {{ statusConfig(header.status).label }}
          </span>

          <!-- Severity badge (if finding exists) -->
          <span
            v-if="header.severity"
            :class="[
              'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold',
              severityConfig(header.severity).bg,
              severityConfig(header.severity).text,
            ]"
          >
            {{ severityConfig(header.severity).label }}
          </span>

          <!-- Expand icon -->
          <component
            v-if="header.finding"
            :is="expandedKey === header.key ? ChevronDown : ChevronRight"
            class="h-3.5 w-3.5 shrink-0 text-slate-500"
          />
        </button>

        <!-- Expanded remediation -->
        <div
          v-if="header.finding && expandedKey === header.key"
          class="border-t border-[var(--border-glass)] bg-white/[0.02] px-4 py-3"
        >
          <div class="space-y-2 text-sm">
            <div>
              <h4 class="mb-1 text-xs font-medium uppercase text-slate-500">Description</h4>
              <p class="text-slate-300">{{ header.finding.description }}</p>
            </div>
            <div>
              <h4 class="mb-1 text-xs font-medium uppercase text-slate-500">Remediation</h4>
              <p class="text-slate-300">{{ header.finding.remediation }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

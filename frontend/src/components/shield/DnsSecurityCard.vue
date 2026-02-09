<script setup lang="ts">
import { computed } from 'vue'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CheckCircle,
  XCircle,
  Mail,
  Globe,
} from 'lucide-vue-next'
import type { ShieldFinding } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

interface DnsCheckResult {
  name: string
  key: string
  status: 'pass' | 'warn' | 'fail'
  detail: string
  finding: ShieldFinding | null
}

function findByKey(key: string): ShieldFinding | null {
  return (
    props.findings.find((f) => {
      const title = f.title.toLowerCase()
      return title.includes(key.toLowerCase())
    }) ?? null
  )
}

const spfCheck = computed<DnsCheckResult>(() => {
  const finding = findByKey('SPF')
  if (!finding) {
    return { name: 'SPF', key: 'spf', status: 'pass', detail: 'SPF record configured', finding: null }
  }
  return {
    name: 'SPF',
    key: 'spf',
    status: finding.severity === 'info' ? 'pass' : 'fail',
    detail: finding.title,
    finding,
  }
})

const dkimCheck = computed<DnsCheckResult>(() => {
  const finding = findByKey('DKIM')
  if (!finding) {
    return { name: 'DKIM', key: 'dkim', status: 'pass', detail: 'DKIM record configured', finding: null }
  }
  return {
    name: 'DKIM',
    key: 'dkim',
    status: finding.severity === 'info' ? 'pass' : finding.severity === 'low' ? 'warn' : 'fail',
    detail: finding.title,
    finding,
  }
})

const dmarcCheck = computed<DnsCheckResult>(() => {
  const finding = findByKey('DMARC')
  if (!finding) {
    return { name: 'DMARC', key: 'dmarc', status: 'pass', detail: 'DMARC policy active', finding: null }
  }
  // Determine DMARC policy from evidence
  const policy = (finding.evidence?.policy as string) ?? ''
  const status = policy === 'none' ? 'fail' : policy === 'quarantine' ? 'warn' : 'fail'
  return {
    name: 'DMARC',
    key: 'dmarc',
    status,
    detail: finding.title,
    finding,
  }
})

const caaCheck = computed<DnsCheckResult>(() => {
  const finding = findByKey('CAA')
  if (!finding) {
    return { name: 'CAA', key: 'caa', status: 'pass', detail: 'CAA record present', finding: null }
  }
  return {
    name: 'CAA',
    key: 'caa',
    status: finding.severity === 'low' ? 'warn' : 'fail',
    detail: finding.title,
    finding,
  }
})

const allChecks = computed(() => [spfCheck.value, dkimCheck.value, dmarcCheck.value, caaCheck.value])

const dmarcPolicy = computed(() => {
  const f = dmarcCheck.value.finding
  if (!f) return 'reject'
  return (f.evidence?.policy as string) ?? 'none'
})

function dmarcPolicyConfig(policy: string) {
  switch (policy) {
    case 'reject':
      return { icon: ShieldCheck, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', label: 'Reject' }
    case 'quarantine':
      return { icon: ShieldAlert, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', label: 'Quarantine' }
    default:
      return { icon: ShieldX, color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/20', label: 'None' }
  }
}

const emailScore = computed(() => {
  let score = 0
  if (spfCheck.value.status === 'pass') score += 30
  if (dkimCheck.value.status === 'pass') score += 30
  else if (dkimCheck.value.status === 'warn') score += 15
  if (dmarcCheck.value.status === 'pass') score += 30
  else if (dmarcCheck.value.status === 'warn') score += 15
  if (caaCheck.value.status === 'pass') score += 10
  else if (caaCheck.value.status === 'warn') score += 5
  return score
})

function statusIcon(status: 'pass' | 'warn' | 'fail') {
  switch (status) {
    case 'pass':
      return CheckCircle
    case 'warn':
      return ShieldAlert
    case 'fail':
      return XCircle
  }
}

function statusColor(status: 'pass' | 'warn' | 'fail') {
  switch (status) {
    case 'pass':
      return 'text-emerald-400'
    case 'warn':
      return 'text-amber-400'
    case 'fail':
      return 'text-rose-400'
  }
}

function scoreColor(score: number) {
  if (score >= 80) return 'text-emerald-400'
  if (score >= 50) return 'text-amber-400'
  return 'text-rose-400'
}
</script>

<template>
  <!-- Empty state -->
  <div
    v-if="findings.length === 0 && allChecks.every((c) => c.status === 'pass')"
    class="glass-card rounded-xl p-8 text-center"
  >
    <ShieldCheck class="mx-auto h-10 w-10 text-emerald-400" />
    <h3 class="mt-3 text-lg font-medium text-white">DNS security configured</h3>
    <p class="mt-1 text-sm text-slate-400">All DNS security records are properly configured.</p>
  </div>

  <div v-else class="glass-card rounded-xl p-5">
    <h3 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
      <Globe class="h-4 w-4 text-cyan-400" />
      DNS Security
    </h3>

    <div class="grid gap-5 lg:grid-cols-2">
      <!-- Left: Email authentication checks -->
      <div>
        <h4 class="mb-3 flex items-center gap-1.5 text-xs font-medium uppercase text-slate-500">
          <Mail class="h-3.5 w-3.5" />
          Email Authentication
        </h4>

        <div class="space-y-2">
          <!-- SPF, DKIM, DMARC main checks -->
          <div
            v-for="check in [spfCheck, dkimCheck, dmarcCheck]"
            :key="check.key"
            class="flex items-center gap-3 rounded-lg border border-[var(--border-glass)] bg-white/[0.02] px-3 py-2.5"
          >
            <component
              :is="statusIcon(check.status)"
              :class="['h-4 w-4 shrink-0', statusColor(check.status)]"
            />
            <div class="min-w-0 flex-1">
              <span class="text-sm font-medium text-white">{{ check.name }}</span>
              <p class="truncate text-xs text-slate-500">{{ check.detail }}</p>
            </div>
          </div>
        </div>

        <!-- DMARC Policy indicator -->
        <div class="mt-3">
          <h4 class="mb-2 text-xs font-medium uppercase text-slate-500">DMARC Policy</h4>
          <div
            :class="[
              'flex items-center gap-2 rounded-lg border p-3',
              dmarcPolicyConfig(dmarcPolicy).bg,
              dmarcPolicyConfig(dmarcPolicy).border,
            ]"
          >
            <component
              :is="dmarcPolicyConfig(dmarcPolicy).icon"
              :class="['h-5 w-5', dmarcPolicyConfig(dmarcPolicy).color]"
            />
            <div>
              <span :class="['text-sm font-semibold', dmarcPolicyConfig(dmarcPolicy).color]">
                p={{ dmarcPolicy }}
              </span>
              <p class="text-xs text-slate-500">
                {{
                  dmarcPolicy === 'reject'
                    ? 'Unauthorized emails are rejected'
                    : dmarcPolicy === 'quarantine'
                      ? 'Unauthorized emails are quarantined'
                      : 'No enforcement - emails pass through'
                }}
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- Right: CAA + summary -->
      <div>
        <!-- CAA record -->
        <h4 class="mb-3 flex items-center gap-1.5 text-xs font-medium uppercase text-slate-500">
          <Shield class="h-3.5 w-3.5" />
          Certificate Authority
        </h4>

        <div class="flex items-center gap-3 rounded-lg border border-[var(--border-glass)] bg-white/[0.02] px-3 py-2.5">
          <component
            :is="statusIcon(caaCheck.status)"
            :class="['h-4 w-4 shrink-0', statusColor(caaCheck.status)]"
          />
          <div class="min-w-0 flex-1">
            <span class="text-sm font-medium text-white">CAA Record</span>
            <p class="truncate text-xs text-slate-500">{{ caaCheck.detail }}</p>
          </div>
        </div>

        <!-- Email security summary score -->
        <div class="mt-4">
          <h4 class="mb-3 text-xs font-medium uppercase text-slate-500">Email Security Score</h4>
          <div class="rounded-lg border border-[var(--border-glass)] bg-white/[0.02] p-4 text-center">
            <span :class="['text-3xl font-bold tabular-nums', scoreColor(emailScore)]">
              {{ emailScore }}
            </span>
            <span class="text-sm text-slate-500"> / 100</span>
            <div class="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-white/5">
              <div
                :class="[
                  'h-full rounded-full transition-all duration-700',
                  emailScore >= 80 ? 'bg-emerald-400' : emailScore >= 50 ? 'bg-amber-400' : 'bg-rose-400',
                ]"
                :style="{ width: `${emailScore}%` }"
              />
            </div>
          </div>
        </div>

        <!-- Findings detail (if any) -->
        <div v-if="findings.length > 0" class="mt-4">
          <h4 class="mb-2 text-xs font-medium uppercase text-slate-500">Issues Found</h4>
          <div class="space-y-1.5">
            <div
              v-for="finding in findings"
              :key="finding.id"
              class="rounded border border-[var(--border-glass)] bg-white/[0.02] px-3 py-2 text-xs"
            >
              <span class="text-slate-300">{{ finding.title }}</span>
              <p class="mt-0.5 text-slate-500">{{ finding.remediation }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Network, AlertTriangle, CheckCircle, ShieldAlert } from 'lucide-vue-next'
import type { ShieldFinding } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

interface PortEntry {
  port: number
  service: string
  risk: 'safe' | 'common' | 'dangerous'
  finding: ShieldFinding | null
}

const safePortSet = new Set([80, 443])
const dangerousPortSet = new Set([21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8443, 27017])
const commonPortSet = new Set([22, 25, 53, 110, 143, 587, 993, 995, 8080, 8443])

const serviceNames: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  135: 'MSRPC',
  139: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  587: 'Submission',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
  27017: 'MongoDB',
}

function getPortRisk(port: number): 'safe' | 'common' | 'dangerous' {
  if (dangerousPortSet.has(port)) return 'dangerous'
  if (safePortSet.has(port)) return 'safe'
  if (commonPortSet.has(port)) return 'common'
  return 'common'
}

const portEntries = computed<PortEntry[]>(() => {
  const entries: PortEntry[] = []
  const seen = new Set<number>()

  for (const f of props.findings) {
    const port = f.target_port
    if (port !== null && !seen.has(port)) {
      seen.add(port)
      const service = f.evidence?.service as string | undefined
      entries.push({
        port,
        service: service || serviceNames[port] || 'Unknown',
        risk: getPortRisk(port),
        finding: f,
      })
    }
  }

  return entries.sort((a, b) => a.port - b.port)
})

const dangerousPorts = computed(() =>
  portEntries.value.filter((e) => e.risk === 'dangerous'),
)

const totalOpen = computed(() => portEntries.value.length)
const totalDangerous = computed(() => dangerousPorts.value.length)

function riskClasses(risk: 'safe' | 'common' | 'dangerous') {
  switch (risk) {
    case 'safe':
      return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
    case 'common':
      return 'border-amber-500/30 bg-amber-500/10 text-amber-400'
    case 'dangerous':
      return 'border-rose-500/30 bg-rose-500/10 text-rose-400'
  }
}
</script>

<template>
  <!-- Empty state -->
  <div
    v-if="findings.length === 0"
    class="glass-card rounded-xl p-8 text-center"
  >
    <CheckCircle class="mx-auto h-10 w-10 text-emerald-400" />
    <h3 class="mt-3 text-lg font-medium text-white">No port findings</h3>
    <p class="mt-1 text-sm text-slate-400">No open ports detected or port scan was not run.</p>
  </div>

  <div v-else class="glass-card rounded-xl p-5">
    <h3 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
      <Network class="h-4 w-4 text-cyan-400" />
      Port Scan Results
    </h3>

    <!-- Summary -->
    <div class="mb-4 flex items-center gap-4 text-sm">
      <span class="text-slate-400">
        <span class="font-mono font-semibold text-white">{{ totalOpen }}</span>
        port{{ totalOpen !== 1 ? 's' : '' }} open
      </span>
      <span v-if="totalDangerous > 0" class="flex items-center gap-1 text-rose-400">
        <AlertTriangle class="h-3.5 w-3.5" />
        <span class="font-mono font-semibold">{{ totalDangerous }}</span>
        dangerous
      </span>
      <span v-else class="flex items-center gap-1 text-emerald-400">
        <CheckCircle class="h-3.5 w-3.5" />
        No dangerous ports
      </span>
    </div>

    <div class="grid gap-5 lg:grid-cols-2">
      <!-- Left: Open ports grid -->
      <div>
        <h4 class="mb-2 text-xs font-medium uppercase text-slate-500">Open Ports</h4>
        <div class="flex flex-wrap gap-2">
          <div
            v-for="entry in portEntries"
            :key="entry.port"
            :class="[
              'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium',
              riskClasses(entry.risk),
            ]"
          >
            <span class="font-mono font-bold">{{ entry.port }}</span>
            <span class="opacity-75">{{ entry.service }}</span>
          </div>
        </div>
      </div>

      <!-- Right: Dangerous ports detail -->
      <div v-if="dangerousPorts.length > 0">
        <h4 class="mb-2 text-xs font-medium uppercase text-slate-500">Dangerous Ports</h4>
        <div class="space-y-2">
          <div
            v-for="entry in dangerousPorts"
            :key="entry.port"
            class="rounded-lg border border-rose-500/20 bg-rose-500/5 p-3"
          >
            <div class="flex items-start gap-2">
              <ShieldAlert class="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
              <div class="min-w-0">
                <div class="flex items-center gap-2">
                  <span class="font-mono text-sm font-bold text-rose-400">
                    Port {{ entry.port }}
                  </span>
                  <span class="text-xs text-slate-400">{{ entry.service }}</span>
                </div>
                <p v-if="entry.finding" class="mt-1 text-xs text-slate-400">
                  {{ entry.finding.description }}
                </p>
                <p v-if="entry.finding?.remediation" class="mt-1 text-xs text-slate-500">
                  {{ entry.finding.remediation }}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Right: All safe message if no dangerous ports -->
      <div v-else class="flex items-center justify-center rounded-lg border border-emerald-500/10 bg-emerald-500/5 p-6">
        <div class="text-center">
          <CheckCircle class="mx-auto h-8 w-8 text-emerald-400" />
          <p class="mt-2 text-sm text-emerald-400">No dangerous ports detected</p>
        </div>
      </div>
    </div>
  </div>
</template>

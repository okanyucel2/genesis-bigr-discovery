<script setup lang="ts">
import { computed } from 'vue'
import { CheckCircle, XCircle, Loader2, Clock, Play, Flag } from 'lucide-vue-next'
import type { ShieldScan } from '@/types/shield'

const props = defineProps<{
  scan: ShieldScan
}>()

interface TimelineEntry {
  key: string
  label: string
  timestamp: string | null
  status: 'completed' | 'running' | 'pending' | 'failed'
  duration: string | null
  type: 'start' | 'module' | 'end'
}

const moduleLabels: Record<string, string> = {
  tls: 'TLS / SSL Check',
  ports: 'Port Scan',
  headers: 'HTTP Headers',
  dns: 'DNS Security',
  cve: 'CVE Matching',
  creds: 'Credential Testing',
  owasp: 'OWASP Probes',
}

function formatTimestamp(iso: string | null): string {
  if (!iso) return '--'
  const d = new Date(iso)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function estimateModuleDuration(_moduleIndex: number, totalModules: number, totalDuration: number | null): string | null {
  if (!totalDuration || totalDuration <= 0) return null
  // Rough estimate: distribute duration across modules
  const perModule = totalDuration / totalModules
  return `${perModule.toFixed(1)}s`
}

const entries = computed<TimelineEntry[]>(() => {
  const result: TimelineEntry[] = []
  const scan = props.scan

  // Scan created
  result.push({
    key: 'created',
    label: 'Scan created',
    timestamp: scan.created_at,
    status: 'completed',
    duration: null,
    type: 'start',
  })

  // Module entries
  const modules = scan.modules_enabled
  const isComplete = scan.status === 'completed'
  const isFailed = scan.status === 'failed'
  const isRunning = scan.status === 'running'

  modules.forEach((mod, idx) => {
    let status: TimelineEntry['status'] = 'pending'
    if (isComplete) {
      status = 'completed'
    } else if (isFailed) {
      // If failed, mark last module as failed, earlier as completed
      if (idx === modules.length - 1) {
        status = 'failed'
      } else {
        status = 'completed'
      }
    } else if (isRunning) {
      // Assume modules run sequentially - estimate which one is active
      status = idx === 0 ? 'running' : 'pending'
    }

    result.push({
      key: `module-${mod}`,
      label: moduleLabels[mod] ?? mod.toUpperCase(),
      timestamp: isComplete || status === 'completed' ? scan.started_at : null,
      status,
      duration: isComplete ? estimateModuleDuration(idx, modules.length, scan.duration_seconds) : null,
      type: 'module',
    })
  })

  // Scan completed/failed
  if (isComplete) {
    result.push({
      key: 'completed',
      label: 'Scan completed',
      timestamp: scan.completed_at,
      status: 'completed',
      duration: scan.duration_seconds ? `${scan.duration_seconds}s total` : null,
      type: 'end',
    })
  } else if (isFailed) {
    result.push({
      key: 'failed',
      label: 'Scan failed',
      timestamp: scan.completed_at,
      status: 'failed',
      duration: null,
      type: 'end',
    })
  } else {
    result.push({
      key: 'pending',
      label: 'Awaiting completion',
      timestamp: null,
      status: 'pending',
      duration: null,
      type: 'end',
    })
  }

  return result
})

function entryIcon(entry: TimelineEntry) {
  if (entry.type === 'start') return Play
  if (entry.type === 'end') return Flag
  switch (entry.status) {
    case 'completed':
      return CheckCircle
    case 'running':
      return Loader2
    case 'failed':
      return XCircle
    default:
      return Clock
  }
}

function entryIconClass(entry: TimelineEntry) {
  switch (entry.status) {
    case 'completed':
      return 'text-cyan-400'
    case 'running':
      return 'text-cyan-400 animate-spin'
    case 'failed':
      return 'text-rose-400'
    default:
      return 'text-slate-600'
  }
}

function lineClass(entry: TimelineEntry) {
  switch (entry.status) {
    case 'completed':
      return 'bg-cyan-500/40'
    case 'running':
      return 'bg-cyan-500/20'
    case 'failed':
      return 'bg-rose-500/40'
    default:
      return 'bg-slate-700'
  }
}

function dotGlowClass(entry: TimelineEntry) {
  if (entry.status === 'completed') return 'shadow-[0_0_6px_rgba(34,211,238,0.4)]'
  if (entry.status === 'running') return 'shadow-[0_0_8px_rgba(34,211,238,0.6)]'
  return ''
}
</script>

<template>
  <div class="glass-card rounded-xl p-5">
    <h3 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
      <Clock class="h-4 w-4 text-cyan-400" />
      Scan Timeline
    </h3>

    <!-- Vertical timeline -->
    <div class="relative ml-3">
      <div
        v-for="(entry, idx) in entries"
        :key="entry.key"
        class="relative flex gap-4 pb-6 last:pb-0"
      >
        <!-- Timeline line (not on last item) -->
        <div
          v-if="idx < entries.length - 1"
          :class="[
            'absolute left-[7px] top-5 w-0.5',
            lineClass(entries[idx + 1] ?? entry),
          ]"
          :style="{ height: 'calc(100% - 8px)' }"
        />

        <!-- Dot -->
        <div
          :class="[
            'relative z-10 flex h-4 w-4 shrink-0 items-center justify-center rounded-full',
            dotGlowClass(entry),
          ]"
        >
          <component
            :is="entryIcon(entry)"
            :class="['h-4 w-4', entryIconClass(entry)]"
          />
        </div>

        <!-- Content -->
        <div class="min-w-0 flex-1 -mt-0.5">
          <div class="flex items-center gap-2">
            <span
              :class="[
                'text-sm font-medium',
                entry.status === 'completed' ? 'text-white' :
                entry.status === 'running' ? 'text-cyan-400' :
                entry.status === 'failed' ? 'text-rose-400' :
                'text-slate-500',
              ]"
            >
              {{ entry.label }}
            </span>
            <span
              v-if="entry.duration"
              class="rounded bg-white/5 px-1.5 py-0.5 font-mono text-xs text-slate-500"
            >
              {{ entry.duration }}
            </span>
          </div>
          <span v-if="entry.timestamp" class="mt-0.5 block font-mono text-xs text-slate-600">
            {{ formatTimestamp(entry.timestamp) }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

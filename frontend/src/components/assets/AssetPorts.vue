<script setup lang="ts">
import { computed } from 'vue'
import EmptyState from '@/components/shared/EmptyState.vue'

const props = defineProps<{
  ports: number[]
}>()

const PORT_SERVICES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  161: 'SNMP',
  443: 'HTTPS',
  445: 'SMB',
  554: 'RTSP',
  631: 'IPP',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1883: 'MQTT',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
  8883: 'MQTTS',
  9100: 'JetDirect',
  27017: 'MongoDB',
}

function getServiceName(port: number): string | null {
  return PORT_SERVICES[port] ?? null
}

function getPortColor(port: number): string {
  // Security-sensitive ports get warm colors
  if ([22, 23, 3389, 5900].includes(port)) return 'border-amber-500/40 bg-amber-500/10 text-amber-300'
  // Web ports get cyan
  if ([80, 443, 8080, 8443].includes(port)) return 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
  // Database ports get purple
  if ([3306, 5432, 1433, 6379, 27017].includes(port)) return 'border-purple-500/40 bg-purple-500/10 text-purple-300'
  // IoT / device ports get green
  if ([554, 9100, 631, 161, 1883, 8883].includes(port)) return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
  // Mail/messaging
  if ([25, 110, 143, 993, 995].includes(port)) return 'border-blue-500/40 bg-blue-500/10 text-blue-300'
  // Default
  return 'border-slate-500/40 bg-slate-500/10 text-slate-300'
}

const sortedPorts = computed(() => [...props.ports].sort((a, b) => a - b))
</script>

<template>
  <div>
    <EmptyState
      v-if="ports.length === 0"
      title="No Open Ports"
      description="No open ports were detected on this asset."
      icon="inbox"
    />

    <div v-else>
      <p class="mb-3 text-xs text-slate-500">
        {{ ports.length }} open port{{ ports.length !== 1 ? 's' : '' }} detected
      </p>
      <div class="flex flex-wrap gap-2">
        <div
          v-for="port in sortedPorts"
          :key="port"
          class="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 transition-colors hover:brightness-125"
          :class="getPortColor(port)"
        >
          <span class="font-mono text-sm font-semibold">{{ port }}</span>
          <span
            v-if="getServiceName(port)"
            class="text-xs opacity-70"
          >
            {{ getServiceName(port) }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

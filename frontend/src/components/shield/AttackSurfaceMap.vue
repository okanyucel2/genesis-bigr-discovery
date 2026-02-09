<script setup lang="ts">
import { computed } from 'vue'
import { Network, ShieldAlert, CheckCircle, Server, Bug } from 'lucide-vue-next'
import type { ShieldFinding, FindingSeverity } from '@/types/shield'

const props = defineProps<{
  findings: ShieldFinding[]
}>()

interface PortNode {
  port: number
  ip: string
}

interface ServiceNode {
  name: string
  version: string | null
  ports: number[]
}

interface CveNode {
  cveId: string
  severity: FindingSeverity
  service: string
  port: number | null
}

interface AttackChain {
  ports: PortNode[]
  services: ServiceNode[]
  cves: CveNode[]
}

const portFindings = computed(() =>
  props.findings.filter((f) => f.module === 'ports'),
)

const cveFindings = computed(() =>
  props.findings.filter((f) => f.module === 'cve'),
)

const attackChain = computed<AttackChain>(() => {
  const portsMap = new Map<number, PortNode>()
  const servicesMap = new Map<string, ServiceNode>()
  const cves: CveNode[] = []

  // Extract ports and services from port findings
  for (const f of portFindings.value) {
    if (f.target_port !== null) {
      if (!portsMap.has(f.target_port)) {
        portsMap.set(f.target_port, { port: f.target_port, ip: f.target_ip })
      }
      const serviceName = (f.evidence?.service as string | undefined)?.toLowerCase() ?? 'unknown'
      const banner = f.evidence?.banner as string | undefined
      if (!servicesMap.has(serviceName)) {
        servicesMap.set(serviceName, {
          name: serviceName,
          version: banner ?? null,
          ports: [],
        })
      }
      const svc = servicesMap.get(serviceName)
      if (svc && !svc.ports.includes(f.target_port)) {
        svc.ports.push(f.target_port)
      }
    }
  }

  // Extract CVEs and link to services
  for (const f of cveFindings.value) {
    if (f.cve_id) {
      const serviceName = (f.evidence?.service as string | undefined)?.toLowerCase() ?? 'unknown'
      cves.push({
        cveId: f.cve_id,
        severity: f.severity,
        service: serviceName,
        port: f.target_port,
      })

      // Ensure the service exists in the map
      if (!servicesMap.has(serviceName)) {
        servicesMap.set(serviceName, {
          name: serviceName,
          version: null,
          ports: f.target_port !== null ? [f.target_port] : [],
        })
      }
      // Ensure the port exists
      if (f.target_port !== null && !portsMap.has(f.target_port)) {
        portsMap.set(f.target_port, { port: f.target_port, ip: f.target_ip })
      }
    }
  }

  const ports = Array.from(portsMap.values()).sort((a, b) => a.port - b.port)
  const services = Array.from(servicesMap.values()).sort((a, b) =>
    a.name.localeCompare(b.name),
  )

  return { ports, services, cves }
})

const hasCves = computed(() => attackChain.value.cves.length > 0)
const hasData = computed(
  () => attackChain.value.ports.length > 0 || attackChain.value.cves.length > 0,
)

function sevColor(severity: FindingSeverity): string {
  switch (severity) {
    case 'critical':
      return 'border-red-500/40 bg-red-500/10 text-red-400'
    case 'high':
      return 'border-rose-500/40 bg-rose-500/10 text-rose-400'
    case 'medium':
      return 'border-amber-500/40 bg-amber-500/10 text-amber-400'
    case 'low':
      return 'border-blue-500/40 bg-blue-500/10 text-blue-400'
    default:
      return 'border-slate-500/40 bg-slate-500/10 text-slate-400'
  }
}

function sevDot(severity: FindingSeverity): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-400'
    case 'high':
      return 'bg-rose-400'
    case 'medium':
      return 'bg-amber-400'
    case 'low':
      return 'bg-blue-400'
    default:
      return 'bg-slate-400'
  }
}

function getServiceCves(serviceName: string): CveNode[] {
  return attackChain.value.cves.filter((c) => c.service === serviceName)
}

function getServicePorts(serviceName: string): number[] {
  const svc = attackChain.value.services.find((s) => s.name === serviceName)
  return svc?.ports ?? []
}
</script>

<template>
  <!-- Empty state -->
  <div
    v-if="!hasData"
    class="glass-card rounded-xl p-8 text-center"
  >
    <CheckCircle class="mx-auto h-10 w-10 text-emerald-400" />
    <h3 class="mt-3 text-lg font-medium text-white">No Attack Surface Data</h3>
    <p class="mt-1 text-sm text-slate-400">
      No port or CVE findings available to map the attack surface.
    </p>
  </div>

  <div v-else class="glass-card rounded-xl p-5">
    <h3 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
      <Network class="h-4 w-4 text-cyan-400" />
      Attack Surface Map
    </h3>

    <p class="mb-4 text-xs text-slate-500">
      Showing port-to-service-to-CVE chain. Connections indicate potential attack paths.
    </p>

    <!-- 3-Column Flow -->
    <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
      <!-- Column 1: Ports -->
      <div>
        <h4 class="mb-2 flex items-center gap-1.5 text-xs font-medium uppercase text-slate-500">
          <Network class="h-3.5 w-3.5" />
          Open Ports
        </h4>
        <div class="space-y-1.5">
          <div
            v-for="port in attackChain.ports"
            :key="port.port"
            class="flex items-center gap-2 rounded-md border border-cyan-500/20 bg-cyan-500/5 px-3 py-2"
          >
            <span class="font-mono text-sm font-bold text-cyan-400">{{ port.port }}</span>
            <span class="text-xs text-slate-500">{{ port.ip }}</span>
          </div>
          <div
            v-if="attackChain.ports.length === 0"
            class="rounded-md border border-[var(--border-glass)] bg-white/[0.02] px-3 py-2 text-xs text-slate-500"
          >
            No ports detected
          </div>
        </div>
      </div>

      <!-- Column 2: Services (with connection indicators) -->
      <div>
        <h4 class="mb-2 flex items-center gap-1.5 text-xs font-medium uppercase text-slate-500">
          <Server class="h-3.5 w-3.5" />
          Services
        </h4>
        <div class="space-y-1.5">
          <div
            v-for="svc in attackChain.services"
            :key="svc.name"
            class="relative rounded-md border border-slate-500/20 bg-white/[0.03] px-3 py-2"
          >
            <!-- Connection line left -->
            <div class="absolute -left-4 top-1/2 hidden h-px w-4 bg-slate-600 md:block" />
            <!-- Connection line right (only if has CVEs) -->
            <div
              v-if="getServiceCves(svc.name).length > 0"
              class="absolute -right-4 top-1/2 hidden h-px w-4 bg-slate-600 md:block"
            />
            <div class="flex items-center gap-2">
              <span class="text-sm font-medium text-white">{{ svc.name }}</span>
              <span v-if="svc.version" class="truncate text-xs text-slate-500">{{ svc.version }}</span>
            </div>
            <div class="mt-1 flex flex-wrap gap-1">
              <span
                v-for="p in getServicePorts(svc.name)"
                :key="p"
                class="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-slate-400"
              >
                :{{ p }}
              </span>
            </div>
            <div
              v-if="getServiceCves(svc.name).length > 0"
              class="mt-1.5 flex items-center gap-1 text-[10px] text-rose-400"
            >
              <Bug class="h-3 w-3" />
              {{ getServiceCves(svc.name).length }} CVE{{ getServiceCves(svc.name).length !== 1 ? 's' : '' }}
            </div>
          </div>
          <div
            v-if="attackChain.services.length === 0"
            class="rounded-md border border-[var(--border-glass)] bg-white/[0.02] px-3 py-2 text-xs text-slate-500"
          >
            No services detected
          </div>
        </div>
      </div>

      <!-- Column 3: CVEs -->
      <div>
        <h4 class="mb-2 flex items-center gap-1.5 text-xs font-medium uppercase text-slate-500">
          <ShieldAlert class="h-3.5 w-3.5" />
          CVEs
        </h4>
        <div class="space-y-1.5">
          <div
            v-for="cve in attackChain.cves"
            :key="cve.cveId"
            :class="[
              'relative rounded-md border px-3 py-2',
              sevColor(cve.severity),
            ]"
          >
            <!-- Connection line left -->
            <div class="absolute -left-4 top-1/2 hidden h-px w-4 bg-slate-600 md:block" />
            <div class="flex items-center gap-2">
              <span :class="['h-2 w-2 rounded-full', sevDot(cve.severity)]" />
              <a
                :href="`https://nvd.nist.gov/vuln/detail/${cve.cveId}`"
                target="_blank"
                rel="noopener noreferrer"
                class="font-mono text-xs font-semibold hover:underline"
                @click.stop
              >
                {{ cve.cveId }}
              </a>
            </div>
            <div class="mt-1 text-[10px] opacity-75">
              {{ cve.service }}{{ cve.port !== null ? ` :${cve.port}` : '' }}
            </div>
          </div>
          <div
            v-if="!hasCves"
            class="rounded-md border border-emerald-500/20 bg-emerald-500/5 px-3 py-4 text-center"
          >
            <CheckCircle class="mx-auto h-5 w-5 text-emerald-400" />
            <p class="mt-1 text-xs text-emerald-400">No CVE associations found</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Flow arrows label (visible on md+) -->
    <div class="mt-3 hidden items-center justify-center gap-6 text-xs text-slate-600 md:flex">
      <span>Ports</span>
      <span>--&gt;</span>
      <span>Services</span>
      <span>--&gt;</span>
      <span>Vulnerabilities</span>
    </div>
  </div>
</template>

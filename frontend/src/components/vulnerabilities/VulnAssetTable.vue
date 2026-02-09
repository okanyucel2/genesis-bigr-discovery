<script setup lang="ts">
import { computed, ref } from 'vue'
import { ArrowUpDown, ChevronDown, ChevronRight } from 'lucide-vue-next'
import type { AssetVulnSummary } from '@/types/api'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import IpLink from '@/components/shared/IpLink.vue'
import SeverityBadge from '@/components/shared/SeverityBadge.vue'

const props = withDefaults(
  defineProps<{
    summaries: AssetVulnSummary[]
    search?: string
  }>(),
  {
    search: '',
  },
)

const emit = defineEmits<{
  'cve-click': [cveId: string]
}>()

type SortKey = 'ip' | 'total_vulns' | 'max_cvss'
type SortDir = 'asc' | 'desc'

const sortKey = ref<SortKey>('max_cvss')
const sortDir = ref<SortDir>('desc')
const expandedIps = ref<Set<string>>(new Set())

function toggleSort(key: SortKey) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortKey.value = key
    sortDir.value = 'desc'
  }
}

function toggleExpand(ip: string) {
  const next = new Set(expandedIps.value)
  if (next.has(ip)) {
    next.delete(ip)
  } else {
    next.add(ip)
  }
  expandedIps.value = next
}

const filteredSummaries = computed(() => {
  let result = props.summaries
  const term = props.search.toLowerCase().trim()

  if (term) {
    result = result.filter(
      (s) =>
        s.ip.includes(term) ||
        s.matches.some(
          (m) =>
            m.cve.cve_id.toLowerCase().includes(term) ||
            m.cve.description.toLowerCase().includes(term) ||
            (m.asset_vendor ?? '').toLowerCase().includes(term),
        ),
    )
  }

  const dir = sortDir.value === 'asc' ? 1 : -1
  return [...result].sort((a, b) => {
    let cmp = 0
    switch (sortKey.value) {
      case 'ip':
        cmp = a.ip.localeCompare(b.ip)
        break
      case 'total_vulns':
        cmp = a.total_vulns - b.total_vulns
        break
      case 'max_cvss':
        cmp = a.max_cvss - b.max_cvss
        break
    }
    return cmp * dir
  })
})

function cvssColor(score: number): string {
  if (score >= 9.0) return 'text-rose-400'
  if (score >= 7.0) return 'text-amber-400'
  if (score >= 4.0) return 'text-cyan-400'
  return 'text-emerald-400'
}
</script>

<template>
  <div class="glass-panel rounded-xl">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead class="w-8" />
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('ip')"
          >
            <span class="flex items-center gap-1">
              IP
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('total_vulns')"
          >
            <span class="flex items-center gap-1">
              Total
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead>Critical</TableHead>
          <TableHead>High</TableHead>
          <TableHead>Medium</TableHead>
          <TableHead>Low</TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('max_cvss')"
          >
            <span class="flex items-center gap-1">
              Max CVSS
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <template v-for="summary in filteredSummaries" :key="summary.ip">
          <!-- Main Row -->
          <TableRow
            class="cursor-pointer"
            @click="toggleExpand(summary.ip)"
          >
            <TableCell class="w-8 pr-0">
              <component
                :is="expandedIps.has(summary.ip) ? ChevronDown : ChevronRight"
                :size="14"
                class="text-slate-500"
              />
            </TableCell>
            <TableCell>
              <IpLink :ip="summary.ip" />
            </TableCell>
            <TableCell class="font-mono text-sm text-slate-300 tabular-nums">
              {{ summary.total_vulns }}
            </TableCell>
            <TableCell>
              <span
                v-if="summary.critical_count > 0"
                class="inline-flex items-center rounded-full bg-red-500/20 px-2 py-0.5 text-xs font-semibold text-red-400"
              >
                {{ summary.critical_count }}
              </span>
              <span v-else class="text-xs text-slate-600">0</span>
            </TableCell>
            <TableCell>
              <span
                v-if="summary.high_count > 0"
                class="inline-flex items-center rounded-full bg-orange-500/20 px-2 py-0.5 text-xs font-semibold text-orange-400"
              >
                {{ summary.high_count }}
              </span>
              <span v-else class="text-xs text-slate-600">0</span>
            </TableCell>
            <TableCell>
              <span
                v-if="summary.medium_count > 0"
                class="inline-flex items-center rounded-full bg-yellow-500/20 px-2 py-0.5 text-xs font-semibold text-yellow-400"
              >
                {{ summary.medium_count }}
              </span>
              <span v-else class="text-xs text-slate-600">0</span>
            </TableCell>
            <TableCell>
              <span
                v-if="summary.low_count > 0"
                class="inline-flex items-center rounded-full bg-blue-500/20 px-2 py-0.5 text-xs font-semibold text-blue-400"
              >
                {{ summary.low_count }}
              </span>
              <span v-else class="text-xs text-slate-600">0</span>
            </TableCell>
            <TableCell>
              <span class="font-mono text-sm font-semibold tabular-nums" :class="cvssColor(summary.max_cvss)">
                {{ summary.max_cvss.toFixed(1) }}
              </span>
            </TableCell>
          </TableRow>

          <!-- Expanded Matches -->
          <TableRow
            v-if="expandedIps.has(summary.ip)"
            class="bg-white/[0.02]"
          >
            <TableCell colspan="8" class="px-8 py-3">
              <div class="space-y-2">
                <div
                  v-for="match in summary.matches"
                  :key="match.cve.cve_id"
                  class="flex items-center gap-3 rounded-lg bg-white/5 px-3 py-2 text-sm"
                >
                  <button
                    class="font-mono text-xs text-cyan-400 hover:text-cyan-300 hover:underline underline-offset-2 transition-colors"
                    @click.stop="emit('cve-click', match.cve.cve_id)"
                  >
                    {{ match.cve.cve_id }}
                  </button>
                  <SeverityBadge :severity="match.cve.severity" :score="match.cve.cvss_score" />
                  <span class="flex-1 truncate text-xs text-slate-400">
                    {{ match.cve.description }}
                  </span>
                  <span
                    v-if="match.cve.cisa_kev"
                    class="rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] font-semibold text-rose-400"
                  >
                    KEV
                  </span>
                  <span
                    v-if="match.cve.fix_available"
                    class="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-semibold text-emerald-400"
                  >
                    Fix
                  </span>
                </div>
              </div>
            </TableCell>
          </TableRow>
        </template>
      </TableBody>
    </Table>
  </div>
</template>

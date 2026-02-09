<script setup lang="ts">
import { computed, ref } from 'vue'
import { ArrowUpDown } from 'lucide-vue-next'
import type { RiskProfile } from '@/types/api'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import IpLink from '@/components/shared/IpLink.vue'
import BigrBadge from '@/components/shared/BigrBadge.vue'
import RiskBadge from '@/components/shared/RiskBadge.vue'

const props = defineProps<{
  risks: RiskProfile[]
}>()

type SortKey = 'ip' | 'hostname' | 'vendor' | 'risk_score' | 'risk_level'
type SortDir = 'asc' | 'desc'

const sortKey = ref<SortKey>('risk_score')
const sortDir = ref<SortDir>('desc')

function toggleSort(key: SortKey) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortKey.value = key
    sortDir.value = 'desc'
  }
}

const riskLevelOrder: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

const sortedRisks = computed(() => {
  const copy = [...props.risks]
  const dir = sortDir.value === 'asc' ? 1 : -1

  copy.sort((a, b) => {
    let cmp = 0
    switch (sortKey.value) {
      case 'ip':
        cmp = a.ip.localeCompare(b.ip)
        break
      case 'hostname':
        cmp = (a.hostname ?? '').localeCompare(b.hostname ?? '')
        break
      case 'vendor':
        cmp = (a.vendor ?? '').localeCompare(b.vendor ?? '')
        break
      case 'risk_score':
        cmp = a.risk_score - b.risk_score
        break
      case 'risk_level':
        cmp =
          (riskLevelOrder[a.risk_level.toLowerCase()] ?? 0) -
          (riskLevelOrder[b.risk_level.toLowerCase()] ?? 0)
        break
    }
    return cmp * dir
  })

  return copy
})

function scoreColor(score: number): string {
  if (score >= 80) return 'text-rose-400'
  if (score >= 60) return 'text-amber-400'
  if (score >= 40) return 'text-cyan-400'
  return 'text-emerald-400'
}
</script>

<template>
  <div class="glass-panel rounded-xl">
    <Table>
      <TableHeader>
        <TableRow>
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
            @click="toggleSort('hostname')"
          >
            <span class="flex items-center gap-1">
              Hostname
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('vendor')"
          >
            <span class="flex items-center gap-1">
              Vendor
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead>Category</TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('risk_score')"
          >
            <span class="flex items-center gap-1">
              Risk Score
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('risk_level')"
          >
            <span class="flex items-center gap-1">
              Risk Level
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead>Top CVE</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="risk in sortedRisks" :key="risk.ip">
          <TableCell>
            <IpLink :ip="risk.ip" />
          </TableCell>
          <TableCell class="text-sm text-slate-300">
            {{ risk.hostname ?? '-' }}
          </TableCell>
          <TableCell class="text-sm text-slate-300">
            {{ risk.vendor ?? '-' }}
          </TableCell>
          <TableCell>
            <BigrBadge :category="risk.bigr_category" :show-icon="false" />
          </TableCell>
          <TableCell>
            <span class="font-mono text-sm font-semibold tabular-nums" :class="scoreColor(risk.risk_score)">
              {{ risk.risk_score }}
            </span>
          </TableCell>
          <TableCell>
            <RiskBadge :level="risk.risk_level" />
          </TableCell>
          <TableCell class="font-mono text-xs text-slate-400">
            {{ risk.top_cve ?? '-' }}
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </div>
</template>

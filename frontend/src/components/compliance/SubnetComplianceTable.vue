<script setup lang="ts">
import { ref, computed } from 'vue'
import type { SubnetCompliance } from '@/types/api'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'

const props = defineProps<{
  subnets: SubnetCompliance[]
}>()

type SortDir = 'asc' | 'desc'
const sortDir = ref<SortDir>('desc')

function toggleSort() {
  sortDir.value = sortDir.value === 'desc' ? 'asc' : 'desc'
}

const sorted = computed(() => {
  const copy = [...props.subnets]
  copy.sort((a, b) =>
    sortDir.value === 'desc' ? b.score - a.score : a.score - b.score,
  )
  return copy
})

function scoreColorClass(score: number): string {
  if (score >= 90) return 'text-emerald-400'
  if (score >= 70) return 'text-cyan-400'
  if (score >= 50) return 'text-amber-400'
  return 'text-rose-400'
}

function gradeBadgeClass(grade: string): string {
  const base = 'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold'
  switch (grade) {
    case 'A':
      return `${base} bg-emerald-500/20 text-emerald-400`
    case 'B':
      return `${base} bg-cyan-500/20 text-cyan-400`
    case 'C':
      return `${base} bg-amber-500/20 text-amber-400`
    case 'D':
      return `${base} bg-orange-500/20 text-orange-400`
    default:
      return `${base} bg-rose-500/20 text-rose-400`
  }
}
</script>

<template>
  <Table>
    <TableHeader>
      <TableRow>
        <TableHead>CIDR</TableHead>
        <TableHead>Label</TableHead>
        <TableHead class="cursor-pointer select-none" @click="toggleSort">
          Score
          <span class="ml-1 text-xs">{{ sortDir === 'desc' ? '▼' : '▲' }}</span>
        </TableHead>
        <TableHead>Grade</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow v-for="subnet in sorted" :key="subnet.cidr">
        <TableCell class="font-mono text-sm">{{ subnet.cidr }}</TableCell>
        <TableCell>{{ subnet.label || '—' }}</TableCell>
        <TableCell>
          <span :class="['font-semibold tabular-nums', scoreColorClass(subnet.score)]">
            {{ subnet.score }}
          </span>
        </TableCell>
        <TableCell>
          <span :class="gradeBadgeClass(subnet.grade)">{{ subnet.grade }}</span>
        </TableCell>
      </TableRow>
    </TableBody>
  </Table>
</template>

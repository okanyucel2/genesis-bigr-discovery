<script setup lang="ts">
import { computed, ref } from 'vue'
import { ArrowUpDown } from 'lucide-vue-next'
import type { Certificate } from '@/types/api'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'

const props = withDefaults(
  defineProps<{
    certificates: Certificate[]
    search?: string
    filter?: string
  }>(),
  {
    search: '',
    filter: 'all',
  },
)

type SortKey = 'endpoint' | 'cn' | 'issuer' | 'days_until_expiry' | 'key_size'
type SortDir = 'asc' | 'desc'

const sortKey = ref<SortKey>('days_until_expiry')
const sortDir = ref<SortDir>('asc')

function toggleSort(key: SortKey) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortKey.value = key
    sortDir.value = key === 'days_until_expiry' ? 'asc' : 'desc'
  }
}

const filteredCerts = computed(() => {
  let result = props.certificates

  // Apply filter
  switch (props.filter) {
    case 'expiring':
      result = result.filter(
        (c) => c.days_until_expiry !== null && c.days_until_expiry >= 0 && c.days_until_expiry <= 30,
      )
      break
    case 'expired':
      result = result.filter((c) => c.days_until_expiry !== null && c.days_until_expiry < 0)
      break
    case 'self-signed':
      result = result.filter((c) => c.is_self_signed)
      break
  }

  // Apply search
  const term = props.search.toLowerCase().trim()
  if (term) {
    result = result.filter(
      (c) =>
        c.ip.includes(term) ||
        (c.cn ?? '').toLowerCase().includes(term) ||
        (c.issuer ?? '').toLowerCase().includes(term) ||
        String(c.port).includes(term),
    )
  }

  // Sort
  const dir = sortDir.value === 'asc' ? 1 : -1
  return [...result].sort((a, b) => {
    let cmp = 0
    switch (sortKey.value) {
      case 'endpoint':
        cmp = a.ip.localeCompare(b.ip) || a.port - b.port
        break
      case 'cn':
        cmp = (a.cn ?? '').localeCompare(b.cn ?? '')
        break
      case 'issuer':
        cmp = (a.issuer ?? '').localeCompare(b.issuer ?? '')
        break
      case 'days_until_expiry':
        cmp = (a.days_until_expiry ?? 9999) - (b.days_until_expiry ?? 9999)
        break
      case 'key_size':
        cmp = (a.key_size ?? 0) - (b.key_size ?? 0)
        break
    }
    return cmp * dir
  })
})

function expiryColor(days: number | null): string {
  if (days === null) return 'text-slate-500'
  if (days < 0) return 'text-rose-400'
  if (days <= 30) return 'text-amber-400'
  return 'text-emerald-400'
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}
</script>

<template>
  <div class="glass-panel rounded-xl">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('endpoint')"
          >
            <span class="flex items-center gap-1">
              IP:Port
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('cn')"
          >
            <span class="flex items-center gap-1">
              CN
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('issuer')"
          >
            <span class="flex items-center gap-1">
              Issuer
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead>Valid From</TableHead>
          <TableHead>Valid To</TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('days_until_expiry')"
          >
            <span class="flex items-center gap-1">
              Days Left
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
          <TableHead>Self-Signed</TableHead>
          <TableHead
            class="cursor-pointer select-none"
            @click="toggleSort('key_size')"
          >
            <span class="flex items-center gap-1">
              Key Size
              <ArrowUpDown :size="12" class="text-slate-500" />
            </span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="cert in filteredCerts" :key="`${cert.ip}:${cert.port}`">
          <TableCell class="font-mono text-sm text-slate-300">
            {{ cert.ip }}:{{ cert.port }}
          </TableCell>
          <TableCell class="max-w-[200px] truncate text-sm text-slate-300" :title="cert.cn ?? ''">
            {{ cert.cn ?? '-' }}
          </TableCell>
          <TableCell class="max-w-[200px] truncate text-sm text-slate-400" :title="cert.issuer ?? ''">
            {{ cert.issuer ?? '-' }}
          </TableCell>
          <TableCell class="text-xs text-slate-500">
            {{ formatDate(cert.valid_from) }}
          </TableCell>
          <TableCell class="text-xs text-slate-500">
            {{ formatDate(cert.valid_to) }}
          </TableCell>
          <TableCell>
            <span
              class="font-mono text-sm font-semibold tabular-nums"
              :class="expiryColor(cert.days_until_expiry)"
            >
              {{ cert.days_until_expiry !== null ? cert.days_until_expiry : '-' }}
            </span>
          </TableCell>
          <TableCell>
            <span
              v-if="cert.is_self_signed"
              class="inline-flex items-center rounded-full bg-slate-500/20 px-2 py-0.5 text-xs font-medium text-slate-400"
            >
              Yes
            </span>
            <span v-else class="text-xs text-slate-600">No</span>
          </TableCell>
          <TableCell>
            <span
              class="font-mono text-sm tabular-nums"
              :class="cert.key_size !== null && cert.key_size < 2048 ? 'text-rose-400' : 'text-slate-300'"
            >
              {{ cert.key_size ?? '-' }}
            </span>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </div>
</template>

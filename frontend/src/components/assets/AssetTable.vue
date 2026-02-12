<script setup lang="ts">
import { ref, computed } from 'vue'
import type { Asset } from '@/types/api'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import BigrBadge from '@/components/shared/BigrBadge.vue'
import ConfidenceBadge from '@/components/shared/ConfidenceBadge.vue'
import IpLink from '@/components/shared/IpLink.vue'
import EmptyState from '@/components/shared/EmptyState.vue'
import { ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-vue-next'

const props = defineProps<{
  assets: Asset[]
}>()

type SortField =
  | 'ip'
  | 'hostname'
  | 'vendor'
  | 'bigr_category'
  | 'confidence_score'
  | 'last_seen'
type SortDir = 'asc' | 'desc'

const sortField = ref<SortField>('ip')
const sortDir = ref<SortDir>('asc')

function toggleSort(field: SortField) {
  if (sortField.value === field) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortField.value = field
    sortDir.value = 'asc'
  }
}

const sortedAssets = computed(() => {
  return [...props.assets].sort((a, b) => {
    const valA = a[sortField.value] ?? ''
    const valB = b[sortField.value] ?? ''
    const cmp =
      typeof valA === 'number' && typeof valB === 'number'
        ? valA - valB
        : String(valA).localeCompare(String(valB))
    return sortDir.value === 'asc' ? cmp : -cmp
  })
})

function formatTimeAgo(dateStr: string | null): string {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMin = Math.floor(diffMs / 60000)
  if (diffMin < 1) return 'az önce'
  if (diffMin < 60) return `${diffMin}dk önce`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}sa önce`
  const diffDay = Math.floor(diffHr / 24)
  return `${diffDay}g önce`
}

interface ColumnDef {
  field: SortField
  label: string
}

const columns: ColumnDef[] = [
  { field: 'ip', label: 'IP Adresi' },
  { field: 'hostname', label: 'Cihaz Adı' },
  { field: 'vendor', label: 'Üretici' },
  { field: 'bigr_category', label: 'Kategori' },
  { field: 'confidence_score', label: 'Güven' },
  { field: 'last_seen', label: 'Son Görülme' },
]
</script>

<template>
  <div>
    <EmptyState
      v-if="assets.length === 0"
      icon="search"
      title="Cihaz bulunamadı"
      description="Filtrelerinizi ayarlayın veya cihaz keşfi için yeni tarama başlatın."
    />

    <Table v-else>
      <TableHeader>
        <TableRow>
          <TableHead
            v-for="col in columns"
            :key="col.field"
            class="cursor-pointer select-none hover:text-foreground transition-colors"
            @click="toggleSort(col.field)"
          >
            <div class="flex items-center gap-1">
              <span>{{ col.label }}</span>
              <ArrowUp
                v-if="sortField === col.field && sortDir === 'asc'"
                :size="14"
                class="text-primary"
              />
              <ArrowDown
                v-else-if="sortField === col.field && sortDir === 'desc'"
                :size="14"
                class="text-primary"
              />
              <ArrowUpDown v-else :size="14" class="opacity-30" />
            </div>
          </TableHead>
          <TableHead>MAC</TableHead>
          <TableHead>Portlar</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="asset in sortedAssets" :key="asset.ip">
          <TableCell>
            <IpLink :ip="asset.ip" />
          </TableCell>
          <TableCell class="text-sm text-foreground">
            {{ asset.hostname ?? '-' }}
          </TableCell>
          <TableCell class="text-sm text-muted-foreground">
            {{ asset.vendor ?? '-' }}
          </TableCell>
          <TableCell>
            <BigrBadge :category="asset.bigr_category" />
          </TableCell>
          <TableCell>
            <ConfidenceBadge
              :score="asset.confidence_score"
              :level="asset.confidence_level"
            />
          </TableCell>
          <TableCell class="text-sm text-muted-foreground whitespace-nowrap">
            {{ formatTimeAgo(asset.last_seen) }}
          </TableCell>
          <TableCell class="font-mono text-xs text-muted-foreground">
            {{ asset.mac ?? '-' }}
          </TableCell>
          <TableCell>
            <TooltipProvider v-if="asset.open_ports?.length > 0">
              <Tooltip>
                <TooltipTrigger as-child>
                  <Badge variant="secondary" class="cursor-default tabular-nums">
                    {{ asset.open_ports.length }}
                    port
                  </Badge>
                </TooltipTrigger>
                <TooltipContent side="top">
                  <p class="font-mono text-xs">
                    {{ asset.open_ports.join(', ') }}
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <span
              v-else
              class="text-sm text-muted-foreground/50"
            >
              -
            </span>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </div>
</template>

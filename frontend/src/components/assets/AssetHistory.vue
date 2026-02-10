<script setup lang="ts">
import { computed } from 'vue'
import type { AssetHistoryEntry } from '@/types/api'
import BigrBadge from '@/components/shared/BigrBadge.vue'
import ConfidenceBadge from '@/components/shared/ConfidenceBadge.vue'
import EmptyState from '@/components/shared/EmptyState.vue'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'

const props = defineProps<{
  history: AssetHistoryEntry[]
}>()

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  if (isNaN(date.getTime())) return '-'
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function relativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 30) return `${diffDays}d ago`
  return ''
}

const sortedHistory = computed(() =>
  [...props.history].sort(
    (a, b) => new Date(b.seen_at).getTime() - new Date(a.seen_at).getTime(),
  ),
)
</script>

<template>
  <div>
    <EmptyState
      v-if="history.length === 0"
      title="No History"
      description="No scan history found for this asset."
      icon="inbox"
    />

    <div v-else class="glass-panel rounded-xl overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow class="border-white/[0.06] hover:bg-transparent">
            <TableHead class="text-slate-400">Scan Time</TableHead>
            <TableHead class="text-slate-400">Scan ID</TableHead>
            <TableHead class="text-slate-400">Category</TableHead>
            <TableHead class="text-slate-400 text-right">Confidence</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow
            v-for="(entry, idx) in sortedHistory"
            :key="`${entry.scan_id}-${idx}`"
            class="border-white/[0.06] hover:bg-white/[0.03]"
          >
            <TableCell>
              <div class="flex flex-col">
                <span class="text-sm text-slate-200">
                  {{ formatDate(entry.seen_at) }}
                </span>
                <span
                  v-if="relativeTime(entry.seen_at)"
                  class="text-xs text-slate-500"
                >
                  {{ relativeTime(entry.seen_at) }}
                </span>
              </div>
            </TableCell>
            <TableCell>
              <span class="font-mono text-xs text-slate-400">
                {{ entry.scan_id.slice(0, 8) }}
              </span>
            </TableCell>
            <TableCell>
              <BigrBadge :category="entry.bigr_category" />
            </TableCell>
            <TableCell class="text-right">
              <ConfidenceBadge :score="entry.confidence_score" />
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { MostChangedAsset } from '@/types/api'
import IpLink from '@/components/shared/IpLink.vue'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table'

const props = defineProps<{
  assets: MostChangedAsset[]
}>()

const sorted = computed(() => {
  return [...props.assets].sort((a, b) => b.change_count - a.change_count)
})

function timeAgo(dateStr: string): string {
  const now = new Date()
  const date = new Date(dateStr)
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`

  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`

  const diffDays = Math.floor(diffHours / 24)
  if (diffDays < 30) return `${diffDays}d ago`

  const diffMonths = Math.floor(diffDays / 30)
  return `${diffMonths}mo ago`
}
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle class="text-base">Most Changed Assets</CardTitle>
    </CardHeader>
    <CardContent>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>IP Address</TableHead>
            <TableHead>Changes</TableHead>
            <TableHead>Last Change</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="asset in sorted" :key="asset.ip">
            <TableCell>
              <IpLink :ip="asset.ip" />
            </TableCell>
            <TableCell>
              <span class="font-semibold tabular-nums text-amber-400">
                {{ asset.change_count }}
              </span>
            </TableCell>
            <TableCell class="text-muted-foreground text-sm">
              {{ timeAgo(asset.last_change) }}
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </CardContent>
  </Card>
</template>

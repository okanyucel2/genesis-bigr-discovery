<script setup lang="ts">
import { computed } from 'vue'
import type { Asset } from '@/types/api'
import BigrBadge from '@/components/shared/BigrBadge.vue'
import ConfidenceBadge from '@/components/shared/ConfidenceBadge.vue'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Fingerprint } from 'lucide-vue-next'

const props = defineProps<{
  asset: Asset
}>()

function formatDate(dateStr: string | null): string {
  if (!dateStr) return 'N/A'
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function relativeTime(dateStr: string | null): string {
  if (!dateStr) return ''
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
  return formatDate(dateStr)
}

const fields = computed(() => [
  { label: 'MAC Address', value: props.asset.mac, mono: true },
  { label: 'Hostname', value: props.asset.hostname ?? 'N/A', mono: false },
  { label: 'Vendor', value: props.asset.vendor ?? 'Unknown', mono: false },
  { label: 'OS Hint', value: props.asset.os_hint ?? 'N/A', mono: false },
  { label: 'Scan Method', value: props.asset.scan_method, mono: false },
  {
    label: 'Open Ports',
    value: props.asset.open_ports.length > 0
      ? `${props.asset.open_ports.length} port${props.asset.open_ports.length !== 1 ? 's' : ''}`
      : 'None detected',
    mono: false,
  },
  { label: 'First Seen', value: formatDate(props.asset.first_seen), mono: false, sub: relativeTime(props.asset.first_seen) },
  { label: 'Last Seen', value: formatDate(props.asset.last_seen), mono: false, sub: relativeTime(props.asset.last_seen) },
])
</script>

<template>
  <div class="glass-card rounded-xl p-6">
    <!-- Header: IP + Category + Override -->
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div class="flex flex-col gap-2">
        <div class="flex items-center gap-3">
          <h2 class="font-mono text-2xl font-bold text-cyan-400">
            {{ asset.ip }}
          </h2>
          <BigrBadge :category="asset.bigr_category" />
          <Badge
            v-if="asset.manual_override"
            variant="outline"
            class="border-amber-500/50 text-amber-400"
          >
            <Fingerprint :size="12" class="mr-1" />
            Manual Override
          </Badge>
        </div>
        <p v-if="asset.hostname" class="text-sm text-slate-400">
          {{ asset.hostname }}
        </p>
      </div>
      <div class="flex items-center gap-2">
        <ConfidenceBadge
          :score="asset.confidence_score"
          :level="asset.confidence_level"
        />
      </div>
    </div>

    <Separator class="my-5 bg-white/[0.06]" />

    <!-- Detail Fields Grid -->
    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div
        v-for="field in fields"
        :key="field.label"
        class="space-y-1"
      >
        <dt class="text-xs font-medium uppercase tracking-wider text-slate-500">
          {{ field.label }}
        </dt>
        <dd
          class="text-sm text-slate-200"
          :class="{ 'font-mono': field.mono }"
        >
          {{ field.value }}
          <span
            v-if="field.sub"
            class="ml-1 text-xs text-slate-500"
          >
            ({{ field.sub }})
          </span>
        </dd>
      </div>
    </div>
  </div>
</template>

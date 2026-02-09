<script setup lang="ts">
import { computed } from 'vue'
import {
  Plus,
  Minus,
  RefreshCw,
  ArrowRight,
} from 'lucide-vue-next'
import type { AssetChange } from '@/types/api'

const props = defineProps<{
  changes: AssetChange[]
}>()

const displayChanges = computed(() => props.changes.slice(0, 10))

interface ChangeConfig {
  icon: typeof Plus
  color: string
  label: string
}

const defaultConfig: ChangeConfig = { icon: RefreshCw, color: 'text-amber-400', label: 'Changed' }

const changeTypeConfig: Record<string, ChangeConfig> = {
  new_asset: { icon: Plus, color: 'text-emerald-400', label: 'New' },
  removed: { icon: Minus, color: 'text-rose-400', label: 'Removed' },
  changed: defaultConfig,
}

function getChangeConfig(type: string): ChangeConfig {
  return changeTypeConfig[type] ?? defaultConfig
}

function formatTimeAgo(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)

  if (diffSec < 60) return `${diffSec}s ago`
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  const diffDay = Math.floor(diffHr / 24)
  if (diffDay < 30) return `${diffDay}d ago`
  return date.toLocaleDateString()
}
</script>

<template>
  <div class="space-y-1">
    <div
      v-if="displayChanges.length === 0"
      class="flex items-center justify-center py-8 text-sm text-slate-500"
    >
      No recent changes detected
    </div>

    <div
      v-for="change in displayChanges"
      :key="change.id"
      class="flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-white/5"
    >
      <!-- Change type icon -->
      <div
        class="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-white/5"
      >
        <component
          :is="getChangeConfig(change.change_type).icon"
          class="h-3.5 w-3.5"
          :class="getChangeConfig(change.change_type).color"
        />
      </div>

      <!-- Content -->
      <div class="min-w-0 flex-1">
        <div class="flex items-center gap-2">
          <RouterLink
            :to="`/assets/${change.ip}`"
            class="text-sm font-mono text-cyan-400 hover:text-cyan-300 hover:underline transition-colors"
          >
            {{ change.ip }}
          </RouterLink>
          <span
            v-if="change.field_name"
            class="text-[10px] font-medium uppercase tracking-wider text-slate-500"
          >
            {{ change.field_name }}
          </span>
        </div>

        <!-- Old -> New value for changed type -->
        <div
          v-if="change.change_type === 'changed' && change.old_value"
          class="mt-0.5 flex items-center gap-1.5 text-xs"
        >
          <span class="text-slate-500 truncate max-w-[120px]">
            {{ change.old_value }}
          </span>
          <ArrowRight class="h-3 w-3 shrink-0 text-slate-600" />
          <span class="text-slate-300 truncate max-w-[120px]">
            {{ change.new_value }}
          </span>
        </div>
        <div
          v-else-if="change.change_type === 'new_asset'"
          class="mt-0.5 text-xs text-emerald-400/70"
        >
          New asset discovered
        </div>
        <div
          v-else-if="change.change_type === 'removed'"
          class="mt-0.5 text-xs text-rose-400/70"
        >
          Asset no longer detected
        </div>
      </div>

      <!-- Time -->
      <span class="shrink-0 text-[10px] text-slate-500 tabular-nums">
        {{ formatTimeAgo(change.detected_at) }}
      </span>
    </div>
  </div>
</template>

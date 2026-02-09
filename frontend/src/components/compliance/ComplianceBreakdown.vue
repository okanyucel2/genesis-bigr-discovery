<script setup lang="ts">
import { computed } from 'vue'
import type { ComplianceResponse } from '@/types/api'

const props = defineProps<{
  breakdown: ComplianceResponse['breakdown']
}>()

const segments = computed(() => {
  const total = props.breakdown.total_assets
  if (total === 0) return []

  return [
    {
      label: 'Fully Classified',
      value: props.breakdown.fully_classified,
      pct: (props.breakdown.fully_classified / total) * 100,
      color: 'bg-emerald-400',
      textColor: 'text-emerald-400',
    },
    {
      label: 'Partially Classified',
      value: props.breakdown.partially_classified,
      pct: (props.breakdown.partially_classified / total) * 100,
      color: 'bg-amber-400',
      textColor: 'text-amber-400',
    },
    {
      label: 'Unclassified',
      value: props.breakdown.unclassified,
      pct: (props.breakdown.unclassified / total) * 100,
      color: 'bg-rose-400',
      textColor: 'text-rose-400',
    },
    {
      label: 'Manual Overrides',
      value: props.breakdown.manual_overrides,
      pct: (props.breakdown.manual_overrides / total) * 100,
      color: 'bg-cyan-400',
      textColor: 'text-cyan-400',
    },
  ]
})
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between text-sm">
      <span class="text-muted-foreground">Total Assets</span>
      <span class="font-semibold text-white tabular-nums">{{ breakdown.total_assets }}</span>
    </div>

    <!-- Stacked bar -->
    <div class="h-4 w-full flex rounded-full overflow-hidden bg-white/5">
      <div
        v-for="seg in segments"
        :key="seg.label"
        :class="[seg.color, 'transition-all duration-500']"
        :style="{ width: `${seg.pct}%` }"
      />
    </div>

    <!-- Legend -->
    <div class="grid grid-cols-2 gap-3">
      <div
        v-for="seg in segments"
        :key="seg.label"
        class="flex items-center gap-2"
      >
        <span :class="[seg.color, 'h-2.5 w-2.5 rounded-full shrink-0']" />
        <div class="flex flex-col">
          <span class="text-xs text-muted-foreground">{{ seg.label }}</span>
          <span :class="['text-sm font-medium tabular-nums', seg.textColor]">
            {{ seg.value }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

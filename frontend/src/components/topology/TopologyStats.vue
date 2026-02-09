<script setup lang="ts">
import { computed } from 'vue'
import { GitFork, Circle, Router, Monitor, Cpu } from 'lucide-vue-next'
import type { TopologyResponse } from '@/types/api'

const props = defineProps<{
  stats: TopologyResponse['stats']
}>()

const nodeTypeEntries = computed(() => {
  const iconMap: Record<string, typeof Router> = {
    gateway: Router,
    switch: GitFork,
    device: Monitor,
    subnet: Cpu,
  }

  const colorMap: Record<string, string> = {
    gateway: '#22d3ee',
    switch: '#94a3b8',
    device: '#8b5cf6',
    subnet: '#10b981',
  }

  return Object.entries(props.stats.node_types).map(([type, count]) => ({
    type,
    count,
    icon: iconMap[type] ?? Circle,
    color: colorMap[type] ?? '#64748b',
  }))
})
</script>

<template>
  <div class="flex flex-wrap gap-3">
    <!-- Total Nodes -->
    <div class="glass-card flex min-w-[120px] items-center gap-3 rounded-xl px-4 py-3">
      <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10">
        <Circle :size="16" class="text-cyan-400" />
      </div>
      <div>
        <p class="text-lg font-bold tabular-nums text-white">{{ stats.total_nodes }}</p>
        <p class="text-[10px] font-medium uppercase tracking-wider text-slate-500">Nodes</p>
      </div>
    </div>

    <!-- Total Edges -->
    <div class="glass-card flex min-w-[120px] items-center gap-3 rounded-xl px-4 py-3">
      <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10">
        <GitFork :size="16" class="text-emerald-400" />
      </div>
      <div>
        <p class="text-lg font-bold tabular-nums text-white">{{ stats.total_edges }}</p>
        <p class="text-[10px] font-medium uppercase tracking-wider text-slate-500">Edges</p>
      </div>
    </div>

    <!-- Node Type Breakdown -->
    <div
      v-for="entry in nodeTypeEntries"
      :key="entry.type"
      class="glass-card flex min-w-[120px] items-center gap-3 rounded-xl px-4 py-3"
    >
      <div
        class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg"
        :style="{ background: entry.color + '1a' }"
      >
        <component
          :is="entry.icon"
          :size="16"
          :style="{ color: entry.color }"
        />
      </div>
      <div>
        <p class="text-lg font-bold tabular-nums text-white">{{ entry.count }}</p>
        <p class="text-[10px] font-medium uppercase tracking-wider text-slate-500">
          {{ entry.type }}
        </p>
      </div>
    </div>
  </div>
</template>

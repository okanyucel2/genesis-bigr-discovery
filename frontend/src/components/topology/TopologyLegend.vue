<script setup lang="ts">
import { BIGR_CATEGORIES, BIGR_CATEGORY_LIST } from '@/types/bigr'

const nodeTypes = [
  { type: 'Gateway', shape: 'diamond', color: '#22d3ee' },
  { type: 'Switch', shape: 'square', color: '#94a3b8' },
  { type: 'Device', shape: 'circle', color: '#64748b' },
]
</script>

<template>
  <div class="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-xl border border-white/5 bg-white/[0.02] px-4 py-3">
    <!-- Node Types -->
    <div class="flex items-center gap-4">
      <span class="text-[10px] font-medium uppercase tracking-wider text-slate-500">
        Node Types
      </span>
      <div
        v-for="item in nodeTypes"
        :key="item.type"
        class="flex items-center gap-1.5"
      >
        <svg width="14" height="14" viewBox="0 0 14 14" class="shrink-0">
          <!-- Diamond -->
          <polygon
            v-if="item.shape === 'diamond'"
            points="7,1 13,7 7,13 1,7"
            :fill="item.color"
            fill-opacity="0.3"
            :stroke="item.color"
            stroke-width="1.5"
          />
          <!-- Square -->
          <rect
            v-else-if="item.shape === 'square'"
            x="1.5"
            y="1.5"
            width="11"
            height="11"
            rx="2"
            :fill="item.color"
            fill-opacity="0.3"
            :stroke="item.color"
            stroke-width="1.5"
          />
          <!-- Circle -->
          <circle
            v-else
            cx="7"
            cy="7"
            r="5.5"
            :fill="item.color"
            fill-opacity="0.3"
            :stroke="item.color"
            stroke-width="1.5"
          />
        </svg>
        <span class="text-xs text-slate-400">{{ item.type }}</span>
      </div>
    </div>

    <!-- Separator -->
    <div class="h-4 w-px bg-white/10" />

    <!-- BİGR Categories -->
    <div class="flex items-center gap-4">
      <span class="text-[10px] font-medium uppercase tracking-wider text-slate-500">
        Categories
      </span>
      <div
        v-for="cat in BIGR_CATEGORY_LIST"
        :key="cat"
        class="flex items-center gap-1.5"
      >
        <div
          class="h-2.5 w-2.5 rounded-full"
          :style="{ backgroundColor: BIGR_CATEGORIES[cat].color }"
        />
        <span class="text-xs text-slate-400">{{ BIGR_CATEGORIES[cat].label }}</span>
      </div>
    </div>
  </div>
</template>

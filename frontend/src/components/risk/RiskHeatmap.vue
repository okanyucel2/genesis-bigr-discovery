<script setup lang="ts">
import { computed, ref } from 'vue'
import type { RiskProfile } from '@/types/api'

const props = defineProps<{
  profiles: RiskProfile[]
}>()

const emit = defineEmits<{
  'asset-click': [ip: string]
}>()

const sortedProfiles = computed(() =>
  [...props.profiles].sort((a, b) => b.risk_score - a.risk_score),
)

const hoveredIndex = ref<number | null>(null)
const tooltipX = ref(0)
const tooltipY = ref(0)

function riskColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'critical':
      return 'bg-rose-500'
    case 'high':
      return 'bg-amber-500'
    case 'medium':
      return 'bg-cyan-500'
    case 'low':
      return 'bg-emerald-500'
    default:
      return 'bg-slate-500'
  }
}

function riskBorderColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'critical':
      return 'ring-rose-400/50'
    case 'high':
      return 'ring-amber-400/50'
    case 'medium':
      return 'ring-cyan-400/50'
    case 'low':
      return 'ring-emerald-400/50'
    default:
      return 'ring-slate-400/50'
  }
}

function handleMouseEnter(index: number, event: MouseEvent) {
  hoveredIndex.value = index
  const rect = (event.target as HTMLElement).getBoundingClientRect()
  tooltipX.value = rect.left + rect.width / 2
  tooltipY.value = rect.top
}

function handleMouseLeave() {
  hoveredIndex.value = null
}

function handleClick(ip: string) {
  emit('asset-click', ip)
}
</script>

<template>
  <div class="glass-panel rounded-xl p-5">
    <h3 class="mb-4 text-sm font-medium text-slate-300">Risk Heatmap</h3>

    <div v-if="sortedProfiles.length === 0" class="py-8 text-center text-sm text-slate-500">
      No risk profiles available
    </div>

    <div v-else class="flex flex-wrap gap-1.5">
      <div
        v-for="(profile, index) in sortedProfiles"
        :key="profile.ip"
        class="relative h-8 w-8 cursor-pointer rounded-sm transition-all duration-150 hover:scale-125 hover:ring-2"
        :class="[riskColor(profile.risk_level), riskBorderColor(profile.risk_level)]"
        :title="`${profile.ip} - Score: ${profile.risk_score}`"
        @mouseenter="handleMouseEnter(index, $event)"
        @mouseleave="handleMouseLeave"
        @click="handleClick(profile.ip)"
      />
    </div>

    <!-- Tooltip -->
    <Teleport to="body">
      <div
        v-if="hoveredIndex !== null && sortedProfiles[hoveredIndex]"
        class="pointer-events-none fixed z-50 -translate-x-1/2 -translate-y-full rounded-lg border border-white/10 bg-slate-900/95 px-3 py-2 text-xs shadow-xl backdrop-blur-sm"
        :style="{
          left: `${tooltipX}px`,
          top: `${tooltipY - 8}px`,
        }"
      >
        <p class="font-mono font-medium text-white">
          {{ sortedProfiles[hoveredIndex]!.ip }}
        </p>
        <p v-if="sortedProfiles[hoveredIndex]!.hostname" class="text-slate-400">
          {{ sortedProfiles[hoveredIndex]!.hostname }}
        </p>
        <p class="mt-1 text-slate-300">
          Score: <span class="font-semibold">{{ sortedProfiles[hoveredIndex]!.risk_score }}</span>
        </p>
      </div>
    </Teleport>

    <!-- Legend -->
    <div class="mt-4 flex items-center gap-4 text-xs text-slate-400">
      <div class="flex items-center gap-1.5">
        <div class="h-3 w-3 rounded-sm bg-rose-500" />
        <span>Critical</span>
      </div>
      <div class="flex items-center gap-1.5">
        <div class="h-3 w-3 rounded-sm bg-amber-500" />
        <span>High</span>
      </div>
      <div class="flex items-center gap-1.5">
        <div class="h-3 w-3 rounded-sm bg-cyan-500" />
        <span>Medium</span>
      </div>
      <div class="flex items-center gap-1.5">
        <div class="h-3 w-3 rounded-sm bg-emerald-500" />
        <span>Low</span>
      </div>
    </div>
  </div>
</template>

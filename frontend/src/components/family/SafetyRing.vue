<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    score: number // 0.0 - 1.0
    size?: number // px
    strokeWidth?: number
  }>(),
  {
    size: 96,
    strokeWidth: 6,
  },
)

const radius = computed(() => (props.size - props.strokeWidth) / 2)
const circumference = computed(() => 2 * Math.PI * radius.value)
const dashOffset = computed(() => circumference.value * (1 - props.score))
const percentage = computed(() => Math.round(props.score * 100))

const ringColor = computed(() => {
  if (props.score >= 0.8) return '#10b981' // emerald
  if (props.score >= 0.5) return '#f59e0b' // amber
  return '#ef4444' // red
})

const ringBgColor = computed(() => {
  if (props.score >= 0.8) return 'rgba(16, 185, 129, 0.15)'
  if (props.score >= 0.5) return 'rgba(245, 158, 11, 0.15)'
  return 'rgba(239, 68, 68, 0.15)'
})
</script>

<template>
  <div class="relative inline-flex items-center justify-center" :style="{ width: size + 'px', height: size + 'px' }">
    <svg :width="size" :height="size" class="transform -rotate-90">
      <!-- Background circle -->
      <circle
        :cx="size / 2"
        :cy="size / 2"
        :r="radius"
        fill="none"
        :stroke="ringBgColor"
        :stroke-width="strokeWidth"
      />
      <!-- Progress circle -->
      <circle
        :cx="size / 2"
        :cy="size / 2"
        :r="radius"
        fill="none"
        :stroke="ringColor"
        :stroke-width="strokeWidth"
        stroke-linecap="round"
        :stroke-dasharray="circumference"
        :stroke-dashoffset="dashOffset"
        class="transition-all duration-1000 ease-out"
      />
    </svg>
    <!-- Center text -->
    <div class="absolute inset-0 flex flex-col items-center justify-center">
      <span
        class="text-lg font-bold tabular-nums"
        :style="{ color: ringColor, fontSize: size > 80 ? '1.25rem' : '0.875rem' }"
      >
        {{ percentage }}
      </span>
      <span
        class="text-slate-500"
        :style="{ fontSize: size > 80 ? '0.625rem' : '0.5rem' }"
      >
        puan
      </span>
    </div>
  </div>
</template>

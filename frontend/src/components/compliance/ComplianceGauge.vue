<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'

const props = defineProps<{
  score: number
  grade: string
}>()

const animated = ref(false)

onMounted(() => {
  requestAnimationFrame(() => {
    animated.value = true
  })
})

const scoreColor = computed(() => {
  if (props.score >= 90) return { stroke: '#34d399', text: 'text-emerald-400' }
  if (props.score >= 70) return { stroke: '#22d3ee', text: 'text-cyan-400' }
  if (props.score >= 50) return { stroke: '#fbbf24', text: 'text-amber-400' }
  return { stroke: '#fb7185', text: 'text-rose-400' }
})

const circumference = 2 * Math.PI * 70
const dashOffset = computed(() => {
  const progress = animated.value ? props.score / 100 : 0
  return circumference * (1 - progress)
})
</script>

<template>
  <div class="flex flex-col items-center justify-center">
    <div class="relative w-48 h-48">
      <svg viewBox="0 0 160 160" class="w-full h-full -rotate-90">
        <!-- Background circle -->
        <circle
          cx="80"
          cy="80"
          r="70"
          fill="none"
          stroke="rgba(255, 255, 255, 0.05)"
          stroke-width="10"
        />
        <!-- Progress circle -->
        <circle
          cx="80"
          cy="80"
          r="70"
          fill="none"
          :stroke="scoreColor.stroke"
          stroke-width="10"
          stroke-linecap="round"
          :stroke-dasharray="circumference"
          :stroke-dashoffset="dashOffset"
          class="transition-[stroke-dashoffset] duration-1000 ease-out"
        />
      </svg>
      <!-- Center text -->
      <div class="absolute inset-0 flex flex-col items-center justify-center">
        <span :class="['text-4xl font-bold tabular-nums', scoreColor.text]">
          {{ score }}
        </span>
        <span class="text-lg font-semibold text-muted-foreground">
          {{ grade }}
        </span>
      </div>
    </div>
    <p class="mt-2 text-sm text-muted-foreground">Compliance Score</p>
  </div>
</template>

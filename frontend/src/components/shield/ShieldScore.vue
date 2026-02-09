<script setup lang="ts">
import { computed, ref, watch, onMounted } from 'vue'
import type { ShieldGrade } from '@/types/shield'

const props = defineProps<{
  score: number | null
  grade: ShieldGrade | null
  loading?: boolean
}>()

const animated = ref(false)
const displayScore = ref(0)
let animFrame: number | null = null

onMounted(() => {
  requestAnimationFrame(() => {
    animated.value = true
    animateScore(props.score ?? 0)
  })
})

watch(
  () => props.score,
  (newVal) => {
    if (newVal !== null) {
      animateScore(newVal)
    }
  },
)

function animateScore(target: number) {
  if (animFrame) cancelAnimationFrame(animFrame)
  const start = displayScore.value
  const diff = target - start
  const duration = 1000
  const startTime = performance.now()

  function step(now: number) {
    const elapsed = now - startTime
    const progress = Math.min(elapsed / duration, 1)
    // Ease out cubic
    const eased = 1 - Math.pow(1 - progress, 3)
    displayScore.value = Math.round(start + diff * eased)
    if (progress < 1) {
      animFrame = requestAnimationFrame(step)
    }
  }

  animFrame = requestAnimationFrame(step)
}

const circumference = 2 * Math.PI * 70

const dashOffset = computed(() => {
  const progress = animated.value ? (props.score ?? 0) / 100 : 0
  return circumference * (1 - progress)
})

const scoreColor = computed(() => {
  const s = props.score ?? 0
  if (s >= 90) return { stroke: '#34d399', text: 'text-emerald-400' }
  if (s >= 70) return { stroke: '#22d3ee', text: 'text-cyan-400' }
  if (s >= 50) return { stroke: '#fbbf24', text: 'text-amber-400' }
  return { stroke: '#fb7185', text: 'text-rose-400' }
})

const gradeConfig = computed(() => {
  const g = props.grade
  if (!g) return null
  switch (g) {
    case 'A+':
      return { bg: 'bg-emerald-500/20', text: 'text-emerald-400', border: 'border-emerald-500/30' }
    case 'A':
    case 'B+':
      return { bg: 'bg-cyan-500/20', text: 'text-cyan-400', border: 'border-cyan-500/30' }
    case 'B':
    case 'C+':
      return { bg: 'bg-amber-500/20', text: 'text-amber-400', border: 'border-amber-500/30' }
    case 'C':
    case 'D':
    case 'F':
      return { bg: 'bg-rose-500/20', text: 'text-rose-400', border: 'border-rose-500/30' }
    default:
      return { bg: 'bg-slate-500/20', text: 'text-slate-400', border: 'border-slate-500/30' }
  }
})
</script>

<template>
  <div class="flex flex-col items-center justify-center">
    <!-- Loading skeleton -->
    <template v-if="loading">
      <div class="relative h-48 w-48">
        <div class="absolute inset-0 animate-pulse rounded-full bg-white/5" />
      </div>
      <div class="mt-3 h-6 w-16 animate-pulse rounded bg-white/5" />
    </template>

    <!-- No scan state -->
    <template v-else-if="score === null">
      <div class="relative h-48 w-48">
        <svg viewBox="0 0 160 160" class="h-full w-full -rotate-90">
          <circle
            cx="80"
            cy="80"
            r="70"
            fill="none"
            stroke="rgba(255, 255, 255, 0.05)"
            stroke-width="10"
          />
        </svg>
        <div class="absolute inset-0 flex flex-col items-center justify-center">
          <span class="text-sm text-slate-500">No scan yet</span>
        </div>
      </div>
    </template>

    <!-- Score display -->
    <template v-else>
      <div class="relative h-48 w-48">
        <svg viewBox="0 0 160 160" class="h-full w-full -rotate-90">
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
            {{ displayScore }}
          </span>
          <span class="text-xs text-slate-500">/ 100</span>
        </div>
      </div>

      <!-- Grade badge -->
      <div
        v-if="gradeConfig"
        :class="[
          'mt-3 rounded-lg border px-4 py-1 text-lg font-bold',
          gradeConfig.bg,
          gradeConfig.text,
          gradeConfig.border,
        ]"
      >
        {{ grade }}
      </div>

      <p class="mt-2 text-sm text-slate-500">Shield Score</p>
    </template>
  </div>
</template>

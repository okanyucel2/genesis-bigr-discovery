<script setup lang="ts">
import { computed } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  score: number
  level?: string
  class?: string
}>()

// Normalize: backend may send 0-1 or 0-100
const normalizedScore = computed(() => {
  const s = props.score
  return s > 0 && s <= 1 ? Math.round(s * 10000) / 100 : Math.round(s * 100) / 100
})

const confidenceConfig = computed(() => {
  const pct = normalizedScore.value
  if (pct >= 90)
    return { bg: 'bg-emerald-500/20', text: 'text-emerald-400', label: 'Yüksek' }
  if (pct >= 70)
    return { bg: 'bg-cyan-500/20', text: 'text-cyan-400', label: 'İyi' }
  if (pct >= 50)
    return { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Orta' }
  return { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Düşük' }
})

const displayLabel = computed(() => props.level ?? confidenceConfig.value.label)
</script>

<template>
  <span
    :class="
      cn(
        'inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold',
        confidenceConfig.bg,
        confidenceConfig.text,
        props.class,
      )
    "
  >
    <span>{{ displayLabel }}</span>
    <span class="opacity-75">{{ normalizedScore }}%</span>
  </span>
</template>

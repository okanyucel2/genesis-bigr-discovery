<script setup lang="ts">
import { computed } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  level: string
  score?: number
  class?: string
}>()

const riskConfig = computed(() => {
  const lvl = props.level.toLowerCase()
  switch (lvl) {
    case 'critical':
      return { bg: 'bg-red-500/20', text: 'text-red-400', label: 'Critical' }
    case 'high':
      return {
        bg: 'bg-orange-500/20',
        text: 'text-orange-400',
        label: 'High',
      }
    case 'medium':
      return {
        bg: 'bg-yellow-500/20',
        text: 'text-yellow-400',
        label: 'Medium',
      }
    case 'low':
      return {
        bg: 'bg-emerald-500/20',
        text: 'text-emerald-400',
        label: 'Low',
      }
    default:
      return {
        bg: 'bg-gray-500/20',
        text: 'text-gray-400',
        label: 'Unknown',
      }
  }
})
</script>

<template>
  <span
    :class="
      cn(
        'inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold',
        riskConfig.bg,
        riskConfig.text,
        props.class,
      )
    "
  >
    <span>{{ riskConfig.label }}</span>
    <span v-if="score !== undefined" class="opacity-75">{{ score }}</span>
  </span>
</template>

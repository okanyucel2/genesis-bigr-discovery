<script setup lang="ts">
import { computed } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  severity: string
  score?: number
  class?: string
}>()

const severityConfig = computed(() => {
  const level = props.severity.toLowerCase()
  switch (level) {
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
      return { bg: 'bg-blue-500/20', text: 'text-blue-400', label: 'Low' }
    default:
      return { bg: 'bg-gray-500/20', text: 'text-gray-400', label: 'None' }
  }
})
</script>

<template>
  <span
    :class="
      cn(
        'inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold',
        severityConfig.bg,
        severityConfig.text,
        props.class,
      )
    "
  >
    <span>{{ severityConfig.label }}</span>
    <span v-if="score !== undefined" class="opacity-75">{{ score.toFixed(1) }}</span>
  </span>
</template>

<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { cn } from '@/lib/utils'

const props = defineProps<{
  ip: string
  class?: string
}>()
</script>

<template>
  <RouterLink
    :to="`/assets/${ip}`"
    :class="
      cn(
        'font-mono text-sm text-primary hover:text-primary/80 hover:underline underline-offset-4 transition-colors',
        props.class,
      )
    "
  >
    {{ ip }}
  </RouterLink>
</template>

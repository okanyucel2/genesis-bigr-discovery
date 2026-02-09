<script setup lang="ts">
import { Loader2 } from 'lucide-vue-next'
import { cn } from '@/lib/utils'

const props = defineProps<{
  message?: string
  class?: string
}>()
</script>

<template>
  <div
    :class="
      cn(
        'flex flex-col items-center justify-center py-12 text-center',
        props.class,
      )
    "
  >
    <Loader2 :size="32" class="mb-4 animate-spin text-primary" />
    <p v-if="message" class="text-sm text-muted-foreground">{{ message }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  title: string
  icon: string
  status?: 'ok' | 'warning' | 'danger'
}>()

const borderClass = computed(() => {
  switch (props.status) {
    case 'warning':
      return 'border-amber-500/30'
    case 'danger':
      return 'border-rose-500/30'
    default:
      return 'border-[var(--border-glass)]'
  }
})

const dotClass = computed(() => {
  switch (props.status) {
    case 'warning':
      return 'bg-amber-400'
    case 'danger':
      return 'bg-rose-400 animate-pulse'
    default:
      return 'bg-emerald-400'
  }
})
</script>

<template>
  <div
    class="glass-card rounded-xl border p-5 transition-all duration-300"
    :class="borderClass"
  >
    <!-- Header -->
    <div class="mb-3 flex items-center justify-between">
      <div class="flex items-center gap-2">
        <span class="text-xl leading-none">{{ icon }}</span>
        <h3 class="text-sm font-semibold text-slate-200">{{ title }}</h3>
      </div>
      <span class="h-2 w-2 rounded-full" :class="dotClass" />
    </div>

    <!-- Content slot -->
    <slot />
  </div>
</template>

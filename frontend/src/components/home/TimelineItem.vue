<script setup lang="ts">
import { computed } from 'vue'
import { relativeTime } from '@/lib/time-utils'
import type { TimelineItem } from '@/types/home-dashboard'

const props = defineProps<{
  item: TimelineItem
  expanded: boolean
}>()

defineEmits<{
  toggle: []
}>()

const severityClass = computed(() => {
  switch (props.item.severity) {
    case 'critical':
      return 'border-l-rose-500 bg-rose-500/5'
    case 'high':
      return 'border-l-amber-500 bg-amber-500/5'
    case 'medium':
      return 'border-l-yellow-500 bg-yellow-500/5'
    case 'low':
      return 'border-l-blue-500 bg-blue-500/5'
    default:
      return 'border-l-slate-600 bg-white/[0.02]'
  }
})

const timeText = computed(() => relativeTime(props.item.timestamp))
</script>

<template>
  <div
    class="timeline-item cursor-pointer rounded-lg border-l-2 px-4 py-3 transition-all duration-200 hover:bg-white/5"
    :class="severityClass"
    @click="$emit('toggle')"
  >
    <div class="flex items-start gap-3">
      <span class="mt-0.5 text-base leading-none">{{ item.icon }}</span>
      <div class="min-w-0 flex-1">
        <p class="text-sm text-slate-200">{{ item.message }}</p>
        <p class="mt-1 text-[10px] text-slate-500">{{ timeText }}</p>
      </div>
      <button
        v-if="item.detail"
        class="shrink-0 text-[10px] text-cyan-400 transition-colors hover:text-cyan-300"
        @click.stop="$emit('toggle')"
      >
        {{ expanded ? 'Gizle' : 'Detay' }}
      </button>
    </div>

    <!-- Expanded detail -->
    <Transition name="expand">
      <div v-if="expanded && item.detail" class="mt-2 rounded-md bg-black/20 px-3 py-2">
        <p class="text-xs text-slate-400 font-mono">{{ item.detail }}</p>
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.expand-enter-active,
.expand-leave-active {
  transition: all 0.2s ease;
  overflow: hidden;
}
.expand-enter-from,
.expand-leave-to {
  opacity: 0;
  max-height: 0;
}
.expand-enter-to,
.expand-leave-from {
  opacity: 1;
  max-height: 100px;
}
</style>

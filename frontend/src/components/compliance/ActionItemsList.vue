<script setup lang="ts">
import { ref, computed } from 'vue'
import type { ActionItem } from '@/types/api'
import IpLink from '@/components/shared/IpLink.vue'
import { Button } from '@/components/ui/button'

const props = defineProps<{
  items: ActionItem[]
}>()

const expanded = ref(false)
const maxItems = 10

const visibleItems = computed(() => {
  if (expanded.value) return props.items
  return props.items.slice(0, maxItems)
})

const hasMore = computed(() => props.items.length > maxItems)

function priorityBadgeClass(priority: string): string {
  const base = 'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold'
  switch (priority) {
    case 'critical':
      return `${base} bg-rose-500/20 text-rose-400`
    case 'high':
      return `${base} bg-amber-500/20 text-amber-400`
    case 'medium':
      return `${base} bg-cyan-500/20 text-cyan-400`
    default:
      return `${base} bg-slate-500/20 text-slate-400`
  }
}
</script>

<template>
  <div class="space-y-2">
    <div
      v-for="(item, idx) in visibleItems"
      :key="`${item.ip}-${item.type}-${idx}`"
      class="flex items-center gap-3 rounded-lg border border-border bg-white/5 px-4 py-3"
    >
      <span :class="priorityBadgeClass(item.priority)">
        {{ item.priority }}
      </span>
      <IpLink :ip="item.ip" />
      <span class="text-xs text-muted-foreground">{{ item.type }}</span>
      <span class="ml-auto text-sm text-muted-foreground truncate max-w-[40%]">
        {{ item.reason }}
      </span>
    </div>

    <div v-if="items.length === 0" class="py-4 text-center text-sm text-muted-foreground">
      No action items
    </div>

    <div v-if="hasMore" class="flex justify-center pt-2">
      <Button
        variant="ghost"
        size="sm"
        class="text-xs text-muted-foreground hover:text-white"
        @click="expanded = !expanded"
      >
        {{ expanded ? 'Show less' : `Show all (${items.length})` }}
      </Button>
    </div>
  </div>
</template>

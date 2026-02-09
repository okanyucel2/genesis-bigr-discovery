<script setup lang="ts">
import { computed } from 'vue'
import { InboxIcon, SearchX, FileQuestion } from 'lucide-vue-next'
import { cn } from '@/lib/utils'

const props = withDefaults(
  defineProps<{
    icon?: string
    title: string
    description?: string
    class?: string
  }>(),
  {
    icon: 'inbox',
  },
)

const iconComponents: Record<string, typeof InboxIcon> = {
  inbox: InboxIcon,
  search: SearchX,
  file: FileQuestion,
}

const iconComponent = computed(
  () => iconComponents[props.icon ?? 'inbox'] ?? InboxIcon,
)
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
    <component
      :is="iconComponent"
      :size="48"
      class="mb-4 text-muted-foreground/50"
    />
    <h3 class="text-lg font-medium text-foreground">{{ title }}</h3>
    <p v-if="description" class="mt-1 text-sm text-muted-foreground">
      {{ description }}
    </p>
    <div v-if="$slots.action" class="mt-4">
      <slot name="action" />
    </div>
  </div>
</template>

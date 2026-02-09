<script setup lang="ts">
import { type HTMLAttributes, computed } from 'vue'
import { Separator as SeparatorPrimitive } from 'radix-vue'
import { cn } from '@/lib/utils'

const props = withDefaults(
  defineProps<{
    orientation?: 'horizontal' | 'vertical'
    decorative?: boolean
    class?: HTMLAttributes['class']
  }>(),
  {
    orientation: 'horizontal',
    decorative: true,
  },
)

const delegatedProps = computed(() => {
  const { class: _, ...delegated } = props
  return delegated
})
</script>

<template>
  <SeparatorPrimitive
    v-bind="delegatedProps"
    :class="
      cn(
        'shrink-0 bg-border',
        props.orientation === 'horizontal' ? 'h-px w-full' : 'h-full w-px',
        props.class,
      )
    "
  />
</template>

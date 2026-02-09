<script setup lang="ts">
import { computed } from 'vue'
import { Network, Globe, Cpu, Laptop, HelpCircle } from 'lucide-vue-next'
import { type BigrCategory, BIGR_CATEGORIES } from '@/types/bigr'
import { cn } from '@/lib/utils'

const props = withDefaults(
  defineProps<{
    category: BigrCategory
    showIcon?: boolean
    class?: string
  }>(),
  {
    showIcon: true,
  },
)

const categoryInfo = computed(() => BIGR_CATEGORIES[props.category])

const iconComponents: Record<string, typeof Network> = {
  Network,
  Globe,
  Cpu,
  Laptop,
  HelpCircle,
}

const iconComponent = computed(() => iconComponents[categoryInfo.value.icon])
</script>

<template>
  <span
    :class="
      cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium',
        categoryInfo.bgClass,
        categoryInfo.textClass,
        props.class,
      )
    "
  >
    <component
      :is="iconComponent"
      v-if="showIcon && iconComponent"
      :size="12"
    />
    <span>{{ categoryInfo.label }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import {
  Network,
  Globe,
  Cpu,
  Laptop,
  HelpCircle,
} from 'lucide-vue-next'
import { BIGR_CATEGORIES } from '@/types/bigr'
import type { BigrCategory } from '@/types/bigr'

const props = defineProps<{
  category: BigrCategory
  count: number
}>()

const router = useRouter()

const categoryInfo = computed(() => BIGR_CATEGORIES[props.category])

const iconMap: Record<string, typeof Network> = {
  Network,
  Globe,
  Cpu,
  Laptop,
  HelpCircle,
}

const iconComponent = computed(() => iconMap[categoryInfo.value.icon] ?? HelpCircle)

function navigateToAssets() {
  router.push({ path: '/assets', query: { category: props.category } })
}
</script>

<template>
  <button
    class="glass-card w-full rounded-xl p-4 text-left transition-all duration-200 cursor-pointer"
    @click="navigateToAssets"
  >
    <div class="flex items-center gap-3">
      <div
        class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg"
        :class="categoryInfo.bgClass"
      >
        <component
          :is="iconComponent"
          class="h-4.5 w-4.5"
          :class="categoryInfo.textClass"
        />
      </div>
      <div class="min-w-0 flex-1">
        <p class="text-xs text-slate-400 truncate">
          {{ categoryInfo.label }}
        </p>
        <p class="text-lg font-bold text-white tabular-nums">
          {{ count }}
        </p>
      </div>
    </div>
  </button>
</template>

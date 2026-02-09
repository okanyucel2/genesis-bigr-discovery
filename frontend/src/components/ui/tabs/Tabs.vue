<script setup lang="ts">
import { TabsRoot, type TabsRootProps } from 'radix-vue'

const props = defineProps<TabsRootProps>()
const emits = defineEmits<{
  'update:modelValue': [value: string]
}>()
</script>

<template>
  <TabsRoot
    v-bind="props"
    @update:model-value="(val) => emits('update:modelValue', val as string)"
  >
    <slot />
  </TabsRoot>
</template>

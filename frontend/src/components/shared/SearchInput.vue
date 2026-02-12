<script setup lang="ts">
import { ref, watch } from 'vue'
import { Search } from 'lucide-vue-next'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { useDebounceFn } from '@vueuse/core'

const props = withDefaults(
  defineProps<{
    modelValue: string
    placeholder?: string
    debounceMs?: number
    class?: string
  }>(),
  {
    placeholder: 'Ara...',
    debounceMs: 300,
  },
)

const emits = defineEmits<{
  'update:modelValue': [value: string]
}>()

const localValue = ref(props.modelValue)

const debouncedEmit = useDebounceFn((val: string) => {
  emits('update:modelValue', val)
}, props.debounceMs)

watch(localValue, (val) => {
  debouncedEmit(val)
})

watch(
  () => props.modelValue,
  (val) => {
    if (val !== localValue.value) {
      localValue.value = val
    }
  },
)
</script>

<template>
  <div :class="cn('relative', props.class)">
    <Search
      :size="16"
      class="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
    />
    <Input
      v-model="localValue"
      :placeholder="placeholder"
      class="pl-9"
    />
  </div>
</template>

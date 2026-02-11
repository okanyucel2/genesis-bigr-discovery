<script setup lang="ts">
import { computed } from 'vue'
import { getDeviceIcon } from '@/lib/device-icons'

const props = defineProps<{
  deviceType: string
  size?: 'sm' | 'md' | 'lg'
}>()

const icon = computed(() => getDeviceIcon(props.deviceType))

const sizeClass = computed(() => {
  switch (props.size) {
    case 'lg':
      return 'text-3xl'
    case 'sm':
      return 'text-base'
    default:
      return 'text-xl'
  }
})
</script>

<template>
  <span :class="sizeClass" class="leading-none">{{ icon }}</span>
</template>

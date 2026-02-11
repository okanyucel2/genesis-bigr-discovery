<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import DeviceIcon from './DeviceIcon.vue'

const props = defineProps<{
  devices: { type: string; name: string }[]
}>()

const visibleDevices = ref<number>(0)
let interval: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  interval = setInterval(() => {
    if (visibleDevices.value < props.devices.length) {
      visibleDevices.value++
    } else if (interval) {
      clearInterval(interval)
    }
  }, 800)
})

onUnmounted(() => {
  if (interval) clearInterval(interval)
})
</script>

<template>
  <div class="discovery-animation relative flex flex-col items-center py-6">
    <!-- Radar pulse -->
    <div class="radar-container relative mb-6">
      <div class="radar-ring radar-ring-1" />
      <div class="radar-ring radar-ring-2" />
      <div class="radar-center">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="h-6 w-6 text-cyan-400">
          <path stroke-linecap="round" stroke-linejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" />
        </svg>
      </div>
    </div>

    <!-- Discovered devices (appear one by one) -->
    <div class="flex flex-wrap justify-center gap-3">
      <TransitionGroup name="device-pop">
        <div
          v-for="(device, idx) in devices.slice(0, visibleDevices)"
          :key="idx"
          class="flex items-center gap-2 rounded-full bg-white/5 px-3 py-1.5"
        >
          <DeviceIcon :device-type="device.type" size="sm" />
          <span class="text-xs text-slate-300">{{ device.name }}</span>
        </div>
      </TransitionGroup>
    </div>
  </div>
</template>

<style scoped>
.radar-container {
  width: 80px;
  height: 80px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.radar-center {
  position: relative;
  z-index: 2;
}

.radar-ring {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 40px;
  height: 40px;
  border-radius: 50%;
  border: 1px solid rgba(6, 182, 212, 0.3);
  animation: radar-expand 2s ease-out infinite;
}

.radar-ring-2 {
  animation-delay: 1s;
}

@keyframes radar-expand {
  0% {
    width: 30px;
    height: 30px;
    opacity: 0.6;
  }
  100% {
    width: 80px;
    height: 80px;
    opacity: 0;
  }
}

.device-pop-enter-active {
  transition: all 0.4s ease-out;
}

.device-pop-enter-from {
  opacity: 0;
  transform: scale(0.5);
}
</style>

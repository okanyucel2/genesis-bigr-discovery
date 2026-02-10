<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'

const emit = defineEmits<{
  advance: []
}>()

const showGreeting = ref(false)
const showSubtext = ref(false)
const progressWidth = ref(0)

let advanceTimer: ReturnType<typeof setTimeout> | null = null
let progressInterval: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  // Animate greeting text
  setTimeout(() => {
    showGreeting.value = true
  }, 400)

  setTimeout(() => {
    showSubtext.value = true
  }, 1200)

  // Progress bar fills over 2.5 seconds
  const duration = 2500
  const startTime = Date.now()
  progressInterval = setInterval(() => {
    const elapsed = Date.now() - startTime
    progressWidth.value = Math.min((elapsed / duration) * 100, 100)
    if (elapsed >= duration) {
      if (progressInterval) clearInterval(progressInterval)
    }
  }, 16)

  // Auto-advance after 2.5 seconds
  advanceTimer = setTimeout(() => {
    emit('advance')
  }, 2800)
})

onUnmounted(() => {
  if (advanceTimer) clearTimeout(advanceTimer)
  if (progressInterval) clearInterval(progressInterval)
})
</script>

<template>
  <div class="flex flex-col items-center justify-center min-h-[60vh] px-6">
    <!-- Animated Shield Icon -->
    <div class="shield-container mb-8">
      <div class="shield-pulse" />
      <div class="shield-icon">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          class="h-16 w-16 text-cyan-400"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
          />
        </svg>
      </div>
    </div>

    <!-- Greeting Text -->
    <Transition name="fade-up">
      <h1
        v-if="showGreeting"
        class="text-2xl font-bold text-white text-center mb-3 sm:text-3xl"
      >
        Merhaba! Ben BIGR Shield, dijital koruyucun.
      </h1>
    </Transition>

    <!-- Subtext -->
    <Transition name="fade-up">
      <p
        v-if="showSubtext"
        class="text-slate-400 text-center text-sm sm:text-base max-w-md"
      >
        Simdi agini tanimama izin ver...
      </p>
    </Transition>

    <!-- Progress Indicator -->
    <div class="mt-10 w-48">
      <div class="h-1 rounded-full bg-white/10 overflow-hidden">
        <div
          class="h-full rounded-full bg-cyan-400 transition-none"
          :style="{ width: `${progressWidth}%` }"
        />
      </div>
    </div>
  </div>
</template>

<style scoped>
.shield-container {
  position: relative;
  width: 96px;
  height: 96px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.shield-icon {
  position: relative;
  z-index: 2;
  animation: shield-float 3s ease-in-out infinite;
}

.shield-pulse {
  position: absolute;
  inset: -8px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(6, 182, 212, 0.15) 0%, transparent 70%);
  animation: shield-pulse-anim 2s ease-in-out infinite;
}

@keyframes shield-float {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-6px); }
}

@keyframes shield-pulse-anim {
  0%, 100% {
    transform: scale(1);
    opacity: 0.6;
  }
  50% {
    transform: scale(1.3);
    opacity: 0.2;
  }
}

.fade-up-enter-active {
  transition: all 0.6s ease;
}

.fade-up-enter-from {
  opacity: 0;
  transform: translateY(12px);
}
</style>

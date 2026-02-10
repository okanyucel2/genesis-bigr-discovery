<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useOnboardingStore } from '@/stores/onboarding'

const emit = defineEmits<{
  advance: []
}>()

const store = useOnboardingStore()

const scanPhase = ref(0) // 0=detecting, 1=scanning, 2=checking, 3=done
const scanMessages = [
  'Ag tespit ediliyor...',
  'Guvenlik kontrolleri yapiliyor...',
  'Tehdit istihbarati kontrol ediliyor...',
  'Tamamlandi!',
]

const currentMessage = computed(() => scanMessages[scanPhase.value] ?? '')

const scoreColor = computed(() => {
  if (store.safetyLevel === 'safe') return '#10b981'
  if (store.safetyLevel === 'warning') return '#f59e0b'
  return '#ef4444'
})

const scorePercent = computed(() => Math.round(store.safetyScore * 100))

onMounted(async () => {
  // Animate through scan phases while the actual scan runs
  const phaseInterval = setInterval(() => {
    if (scanPhase.value < 2) {
      scanPhase.value++
    }
  }, 800)

  await store.startScan()

  clearInterval(phaseInterval)
  scanPhase.value = 3
})

function handleContinue() {
  emit('advance')
}
</script>

<template>
  <div class="flex flex-col items-center justify-center min-h-[60vh] px-6">
    <!-- Scanning Animation -->
    <div
      v-if="scanPhase < 3"
      class="scan-container mb-8"
    >
      <div class="scan-ring scan-ring-1" />
      <div class="scan-ring scan-ring-2" />
      <div class="scan-ring scan-ring-3" />
      <div class="scan-center">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          class="h-8 w-8 text-cyan-400"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
          />
        </svg>
      </div>
    </div>

    <!-- Phase Message -->
    <p
      v-if="scanPhase < 3"
      class="text-slate-400 text-sm mb-2 animate-pulse"
    >
      {{ currentMessage }}
    </p>

    <!-- Result Card (shown after scan completes) -->
    <Transition name="fade-up">
      <div
        v-if="scanPhase === 3 && store.networkInfo"
        class="w-full max-w-md space-y-6"
      >
        <!-- Network Detected -->
        <div class="glass-card rounded-xl p-6 text-center">
          <!-- Safety Score Circle -->
          <div class="mx-auto mb-4 relative w-28 h-28">
            <svg class="w-28 h-28 -rotate-90" viewBox="0 0 120 120">
              <circle
                cx="60" cy="60" r="52"
                fill="none"
                stroke="rgba(255,255,255,0.08)"
                stroke-width="8"
              />
              <circle
                cx="60" cy="60" r="52"
                fill="none"
                :stroke="scoreColor"
                stroke-width="8"
                stroke-linecap="round"
                :stroke-dasharray="`${scorePercent * 3.27} 327`"
                class="score-circle"
              />
            </svg>
            <div class="absolute inset-0 flex flex-col items-center justify-center">
              <span
                class="text-2xl font-bold"
                :style="{ color: scoreColor }"
              >
                {{ scorePercent }}
              </span>
              <span class="text-[10px] text-slate-500 uppercase tracking-wider">
                Guvenlik
              </span>
            </div>
          </div>

          <!-- Network Name -->
          <div class="mb-3">
            <p class="text-xs text-slate-500 uppercase tracking-wider mb-1">
              Tespit Edilen Ag
            </p>
            <p class="text-lg font-semibold text-white">
              {{ store.networkInfo.ssid || 'Bilinmeyen Ag' }}
            </p>
            <p
              v-if="store.networkInfo.gateway_ip"
              class="text-xs text-slate-500 mt-0.5"
            >
              Gateway: {{ store.networkInfo.gateway_ip }}
            </p>
          </div>

          <!-- Safety Message -->
          <div class="mt-4 rounded-lg bg-white/5 p-3">
            <p class="text-sm text-slate-200 font-medium">
              {{ store.safetyMessage }}
            </p>
            <p class="text-xs text-slate-400 mt-1">
              {{ store.safetyDetail }}
            </p>
          </div>

          <!-- Risk Factors (if any) -->
          <div
            v-if="store.networkInfo.risk_factors.length > 0"
            class="mt-3 space-y-1"
          >
            <p
              v-for="(factor, idx) in store.networkInfo.risk_factors.slice(0, 3)"
              :key="idx"
              class="text-xs text-amber-400/80 flex items-center gap-1.5"
            >
              <span class="inline-block w-1 h-1 rounded-full bg-amber-400 shrink-0" />
              {{ factor }}
            </p>
          </div>
        </div>

        <!-- Continue Button -->
        <button
          class="w-full rounded-xl bg-cyan-500/20 border border-cyan-500/30 py-3 text-sm font-medium text-cyan-400 transition-all hover:bg-cyan-500/30 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]"
          @click="handleContinue"
        >
          Devam Et
        </button>
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.scan-container {
  position: relative;
  width: 120px;
  height: 120px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.scan-center {
  position: relative;
  z-index: 2;
}

.scan-ring {
  position: absolute;
  border-radius: 50%;
  border: 1px solid rgba(6, 182, 212, 0.3);
  animation: scan-expand 2.4s ease-out infinite;
}

.scan-ring-1 {
  width: 60px;
  height: 60px;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  animation-delay: 0s;
}

.scan-ring-2 {
  width: 60px;
  height: 60px;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  animation-delay: 0.8s;
}

.scan-ring-3 {
  width: 60px;
  height: 60px;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  animation-delay: 1.6s;
}

@keyframes scan-expand {
  0% {
    width: 40px;
    height: 40px;
    opacity: 0.8;
    border-color: rgba(6, 182, 212, 0.5);
  }
  100% {
    width: 120px;
    height: 120px;
    opacity: 0;
    border-color: rgba(6, 182, 212, 0);
  }
}

.score-circle {
  transition: stroke-dasharray 1s ease-out;
}

.fade-up-enter-active {
  transition: all 0.5s ease;
}

.fade-up-enter-from {
  opacity: 0;
  transform: translateY(16px);
}
</style>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useOnboardingStore } from '@/stores/onboarding'

const router = useRouter()
const store = useOnboardingStore()

const showCheckmark = ref(false)
const showContent = ref(false)

const scoreColor = computed(() => {
  if (store.safetyLevel === 'safe') return '#10b981'
  if (store.safetyLevel === 'warning') return '#f59e0b'
  return '#ef4444'
})

const scorePercent = computed(() => Math.round(store.safetyScore * 100))

const riskCount = computed(() => store.networkInfo?.risk_factors.length ?? 0)

onMounted(() => {
  setTimeout(() => {
    showCheckmark.value = true
  }, 300)

  setTimeout(() => {
    showContent.value = true
  }, 800)
})

async function goToDashboard() {
  await store.completeOnboarding()
  router.push('/')
}
</script>

<template>
  <div class="flex flex-col items-center justify-center min-h-[60vh] px-6">
    <!-- Checkmark Animation -->
    <div class="mb-8 relative">
      <div class="ready-glow" />
      <Transition name="scale-up">
        <div
          v-if="showCheckmark"
          class="relative z-10 flex h-20 w-20 items-center justify-center rounded-full bg-emerald-500/20 border border-emerald-500/30"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            class="h-10 w-10 text-emerald-400 checkmark-draw"
          >
            <path
              d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
              class="checkmark-path"
            />
          </svg>
        </div>
      </Transition>
    </div>

    <Transition name="fade-up">
      <div
        v-if="showContent"
        class="w-full max-w-md space-y-6"
      >
        <!-- Title -->
        <div class="text-center">
          <h2 class="text-2xl font-bold text-white sm:text-3xl">
            Hazirim! Arkani kolluyorum.
          </h2>
          <p class="mt-2 text-sm text-slate-400">
            Sen kahveni yudumla, arkani biz kollariz.
          </p>
        </div>

        <!-- Summary Card -->
        <div class="glass-card rounded-xl p-5 space-y-4">
          <!-- Network Name & Score -->
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs text-slate-500 uppercase tracking-wider">
                Agin
              </p>
              <p class="text-lg font-semibold text-white">
                {{ store.networkName || store.networkInfo?.ssid || 'Ag' }}
              </p>
            </div>
            <div class="text-right">
              <p class="text-xs text-slate-500 uppercase tracking-wider">
                Guvenlik
              </p>
              <p
                class="text-lg font-bold tabular-nums"
                :style="{ color: scoreColor }"
              >
                {{ scorePercent }}%
              </p>
            </div>
          </div>

          <!-- Divider -->
          <div class="border-t border-white/5" />

          <!-- Stats Row -->
          <div class="grid grid-cols-3 gap-3 text-center">
            <div>
              <p class="text-lg font-bold text-white tabular-nums">
                {{ store.networkInfo?.device_count ?? 0 }}
              </p>
              <p class="text-[10px] text-slate-500 uppercase tracking-wider">
                Cihaz
              </p>
            </div>
            <div>
              <p
                class="text-lg font-bold tabular-nums"
                :class="riskCount === 0 ? 'text-emerald-400' : 'text-amber-400'"
              >
                {{ riskCount }}
              </p>
              <p class="text-[10px] text-slate-500 uppercase tracking-wider">
                Risk
              </p>
            </div>
            <div>
              <p class="text-lg font-bold text-cyan-400 tabular-nums">
                {{ store.networkInfo?.open_ports.length ?? 0 }}
              </p>
              <p class="text-[10px] text-slate-500 uppercase tracking-wider">
                Acik Port
              </p>
            </div>
          </div>
        </div>

        <!-- CTA Button -->
        <button
          class="w-full rounded-xl bg-cyan-500 py-3.5 text-sm font-semibold text-slate-900 transition-all hover:bg-cyan-400 hover:shadow-[0_0_30px_rgba(6,182,212,0.3)]"
          @click="goToDashboard"
        >
          Dashboard'a Git
        </button>
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.ready-glow {
  position: absolute;
  inset: -20px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(16, 185, 129, 0.15) 0%, transparent 70%);
  animation: glow-pulse 2s ease-in-out infinite;
}

@keyframes glow-pulse {
  0%, 100% { opacity: 0.6; transform: scale(1); }
  50% { opacity: 0.3; transform: scale(1.2); }
}

.checkmark-path {
  stroke-dasharray: 100;
  stroke-dashoffset: 100;
  animation: draw-check 0.8s ease forwards 0.3s;
}

@keyframes draw-check {
  to { stroke-dashoffset: 0; }
}

.scale-up-enter-active {
  transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.scale-up-enter-from {
  opacity: 0;
  transform: scale(0.5);
}

.fade-up-enter-active {
  transition: all 0.6s ease;
}

.fade-up-enter-from {
  opacity: 0;
  transform: translateY(16px);
}
</style>

<script setup lang="ts">
import { computed } from 'vue'
import { useOnboardingStore } from '@/stores/onboarding'
import WelcomeStep from '@/components/onboarding/WelcomeStep.vue'
import NetworkScanStep from '@/components/onboarding/NetworkScanStep.vue'
import NameNetworkStep from '@/components/onboarding/NameNetworkStep.vue'
import ReadyStep from '@/components/onboarding/ReadyStep.vue'

const store = useOnboardingStore()

const steps = ['Hosgeldin', 'Ag Taramasi', 'Isimlendirme', 'Hazir']

const stepIndicators = computed(() =>
  steps.map((label, idx) => ({
    label,
    active: idx === store.currentStep,
    completed: idx < store.currentStep,
  })),
)

function advanceToScan() {
  store.goToStep(1)
}

function advanceToName() {
  store.goToStep(2)
}

function advanceToReady() {
  store.goToStep(3)
}
</script>

<template>
  <div class="onboarding-page min-h-screen bg-[var(--bg-space-deep)] relative overflow-hidden">
    <!-- Background subtle grid pattern -->
    <div class="bg-grid" />

    <!-- Step Indicator -->
    <div class="relative z-10 flex items-center justify-center gap-2 pt-8 pb-4 px-6">
      <template v-for="(step, idx) in stepIndicators" :key="idx">
        <div class="flex items-center gap-2">
          <!-- Step dot -->
          <div
            class="flex h-7 w-7 items-center justify-center rounded-full text-[10px] font-bold transition-all duration-300"
            :class="[
              step.completed
                ? 'bg-cyan-500/30 text-cyan-400 border border-cyan-500/40'
                : step.active
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                  : 'bg-white/5 text-slate-600 border border-white/10',
            ]"
          >
            <!-- Checkmark for completed -->
            <svg
              v-if="step.completed"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="3"
              class="h-3 w-3"
            >
              <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
            </svg>
            <span v-else>{{ idx + 1 }}</span>
          </div>

          <!-- Step label (hidden on small screens) -->
          <span
            class="hidden text-[10px] uppercase tracking-wider sm:inline"
            :class="
              step.active || step.completed
                ? 'text-slate-300'
                : 'text-slate-600'
            "
          >
            {{ step.label }}
          </span>
        </div>

        <!-- Connector line (not after last) -->
        <div
          v-if="idx < steps.length - 1"
          class="h-px w-8 sm:w-12 transition-colors duration-300"
          :class="
            stepIndicators[idx + 1]?.completed || stepIndicators[idx + 1]?.active
              ? 'bg-cyan-500/30'
              : 'bg-white/10'
          "
        />
      </template>
    </div>

    <!-- Step Content -->
    <div class="relative z-10">
      <Transition name="step-slide" mode="out-in">
        <WelcomeStep
          v-if="store.currentStep === 0"
          key="welcome"
          @advance="advanceToScan"
        />
        <NetworkScanStep
          v-else-if="store.currentStep === 1"
          key="scan"
          @advance="advanceToName"
        />
        <NameNetworkStep
          v-else-if="store.currentStep === 2"
          key="name"
          @advance="advanceToReady"
        />
        <ReadyStep
          v-else-if="store.currentStep === 3"
          key="ready"
        />
      </Transition>
    </div>
  </div>
</template>

<style scoped>
.bg-grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(6, 182, 212, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(6, 182, 212, 0.03) 1px, transparent 1px);
  background-size: 60px 60px;
  mask-image: radial-gradient(ellipse 80% 80% at 50% 30%, black 30%, transparent 80%);
  -webkit-mask-image: radial-gradient(ellipse 80% 80% at 50% 30%, black 30%, transparent 80%);
}

/* Step transition animation */
.step-slide-enter-active {
  transition: all 0.4s ease;
}

.step-slide-leave-active {
  transition: all 0.25s ease;
}

.step-slide-enter-from {
  opacity: 0;
  transform: translateX(30px);
}

.step-slide-leave-to {
  opacity: 0;
  transform: translateX(-30px);
}
</style>

<script setup lang="ts">
import ChatOnboarding from '@/components/onboarding/ChatOnboarding.vue'
</script>

<template>
  <div class="onboarding-page min-h-screen bg-[var(--bg-space-deep)] relative overflow-hidden">
    <!-- Background subtle grid pattern -->
    <div class="bg-grid" />

    <!-- BIGR Logo + Title -->
    <div class="relative z-10 flex items-center justify-center gap-3 pt-8 pb-2">
      <div class="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/20">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="h-5 w-5 text-cyan-400">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
      </div>
      <div>
        <h1 class="text-sm font-bold tracking-wide text-neon-cyan">BIGR Shield</h1>
        <p class="text-[10px] text-slate-500">Dijital koruyucunuz</p>
      </div>
    </div>

    <!-- Chat-based onboarding -->
    <div class="relative z-10">
      <ChatOnboarding />
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

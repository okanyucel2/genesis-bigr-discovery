<script setup lang="ts">
import { computed } from 'vue'
import type { KalkanData } from '@/types/home-dashboard'

const props = defineProps<{
  data: KalkanData
}>()

const stateClass = computed(() => {
  switch (props.data.state) {
    case 'green':
      return 'kalkan-green'
    case 'yellow':
      return 'kalkan-yellow'
    case 'red':
      return 'kalkan-red'
  }
})

const stateGlow = computed(() => {
  switch (props.data.state) {
    case 'green':
      return 'rgba(16, 185, 129, 0.3)'
    case 'yellow':
      return 'rgba(245, 158, 11, 0.3)'
    case 'red':
      return 'rgba(244, 63, 94, 0.3)'
  }
})

const stateColor = computed(() => {
  switch (props.data.state) {
    case 'green':
      return '#10b981'
    case 'yellow':
      return '#f59e0b'
    case 'red':
      return '#f43f5e'
  }
})
</script>

<template>
  <div class="kalkan-container relative flex flex-col items-center justify-center px-6 py-10 md:py-16">
    <!-- Shield SVG -->
    <div class="kalkan-shield relative" :class="stateClass">
      <svg
        viewBox="0 0 120 140"
        class="h-32 w-28 md:h-44 md:w-36"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M60 8L12 32V68C12 98 33 124 60 132C87 124 108 98 108 68V32L60 8Z"
          :fill="stateGlow"
          :stroke="stateColor"
          stroke-width="2"
        />
        <text
          x="60"
          y="78"
          text-anchor="middle"
          :fill="stateColor"
          font-size="32"
          font-weight="bold"
          class="tabular-nums"
        >
          {{ data.score }}
        </text>
      </svg>
      <!-- Animated ring -->
      <div class="kalkan-ring absolute inset-0" :class="stateClass" />
    </div>

    <!-- Status message -->
    <p class="mt-6 max-w-md text-center text-base font-medium text-slate-200 md:text-lg">
      {{ data.message }}
    </p>

    <!-- Micro data row -->
    <div class="mt-4 flex items-center gap-6 text-xs text-slate-400">
      <span>
        Skor: <strong class="text-slate-200">{{ data.score }}</strong>
      </span>
      <span class="h-3 w-px bg-slate-700" />
      <span>
        Cihaz: <strong class="text-slate-200">{{ data.deviceCount }}</strong>
      </span>
      <span class="h-3 w-px bg-slate-700" />
      <span>
        Engellenen: <strong class="text-slate-200">{{ data.blockedThisMonth }}</strong>
      </span>
    </div>
  </div>
</template>

<style scoped>
.kalkan-container {
  min-height: 200px;
}

.kalkan-shield {
  filter: drop-shadow(0 0 20px var(--glow-color, rgba(16, 185, 129, 0.2)));
}

.kalkan-ring {
  border-radius: 50%;
  pointer-events: none;
}

/* Green: slow breathe */
.kalkan-green {
  --glow-color: rgba(16, 185, 129, 0.3);
  animation: breathe 4s ease-in-out infinite;
}

/* Yellow: gentle vibrate */
.kalkan-yellow {
  --glow-color: rgba(245, 158, 11, 0.3);
  animation: vibrate 2s ease-in-out infinite;
}

/* Red: alarm pulse */
.kalkan-red {
  --glow-color: rgba(244, 63, 94, 0.4);
  animation: alarm 1s ease-in-out infinite;
}

@keyframes breathe {
  0%,
  100% {
    transform: scale(1);
    opacity: 0.8;
  }
  50% {
    transform: scale(1.03);
    opacity: 1;
  }
}

@keyframes vibrate {
  0%,
  100% {
    transform: translateX(0);
  }
  25% {
    transform: translateX(-1px);
  }
  75% {
    transform: translateX(1px);
  }
}

@keyframes alarm {
  0%,
  100% {
    transform: scale(1);
    filter: drop-shadow(0 0 15px rgba(244, 63, 94, 0.3));
  }
  50% {
    transform: scale(1.02);
    filter: drop-shadow(0 0 30px rgba(244, 63, 94, 0.6));
  }
}
</style>

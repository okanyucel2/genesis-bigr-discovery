<script setup lang="ts">
import { computed } from 'vue'
import { Sparkles, Shield } from 'lucide-vue-next'
import type { ShieldPrediction, FindingSeverity } from '@/types/shield'

const props = defineProps<{
  prediction: ShieldPrediction | null
}>()

const emit = defineEmits<{
  verify: []
}>()

const confidenceConfig = computed(() => {
  if (!props.prediction) return null
  const c = props.prediction.confidence
  if (c > 0.8) return { label: 'Very High', color: 'text-emerald-400', bg: 'bg-emerald-500/20' }
  if (c > 0.6) return { label: 'High Confidence', color: 'text-cyan-400', bg: 'bg-cyan-500/20' }
  if (c >= 0.3) return { label: 'Preliminary', color: 'text-amber-400', bg: 'bg-amber-500/20' }
  return null // Hidden below 0.3
})

function severityColor(severity: FindingSeverity): string {
  switch (severity) {
    case 'critical':
      return 'bg-rose-500/20 text-rose-400'
    case 'high':
      return 'bg-orange-500/20 text-orange-400'
    case 'medium':
      return 'bg-amber-500/20 text-amber-400'
    case 'low':
      return 'bg-blue-500/20 text-blue-400'
    case 'info':
      return 'bg-slate-500/20 text-slate-400'
    default:
      return 'bg-slate-500/20 text-slate-400'
  }
}
</script>

<template>
  <div v-if="prediction" class="glass-card rounded-xl p-5">
    <!-- Header -->
    <div class="mb-4 flex items-center gap-2">
      <Sparkles class="h-4 w-4 text-cyan-400" />
      <h3 class="text-sm font-medium text-white">AI Prediction</h3>
      <span
        v-if="confidenceConfig"
        :class="[
          'ml-auto rounded-full px-2 py-0.5 text-xs font-medium',
          confidenceConfig.bg,
          confidenceConfig.color,
        ]"
      >
        {{ confidenceConfig.label }}
      </span>
    </div>

    <!-- Predicted score -->
    <div class="mb-4 flex items-baseline gap-3">
      <span class="text-3xl font-bold tabular-nums text-white">
        {{ prediction.predicted_score }}
      </span>
      <span class="text-sm text-slate-500">predicted score</span>
    </div>

    <!-- Stats -->
    <div class="mb-4 grid grid-cols-2 gap-3">
      <div class="rounded-lg bg-white/5 p-3">
        <div class="text-xs text-slate-500">Confidence</div>
        <div class="mt-0.5 font-mono text-sm font-semibold text-white">
          {{ (prediction.confidence * 100).toFixed(0) }}%
        </div>
      </div>
      <div class="rounded-lg bg-white/5 p-3">
        <div class="text-xs text-slate-500">Similar Targets</div>
        <div class="mt-0.5 font-mono text-sm font-semibold text-white">
          {{ prediction.similar_targets_count }}
        </div>
      </div>
    </div>

    <!-- Likely findings -->
    <div v-if="prediction.likely_findings.length > 0" class="mb-4">
      <h4 class="mb-2 text-xs font-medium text-slate-500">Likely Findings</h4>
      <div class="flex flex-wrap gap-1.5">
        <span
          v-for="(f, i) in prediction.likely_findings"
          :key="i"
          :class="[
            'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium',
            severityColor(f.severity),
          ]"
        >
          {{ f.cve_id }}
          <span class="opacity-60">{{ (f.probability * 100).toFixed(0) }}%</span>
        </span>
      </div>
    </div>

    <!-- Verify button -->
    <button
      class="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-500/20 px-3 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/30"
      @click="emit('verify')"
    >
      <Shield class="h-4 w-4" />
      Verify with Full Scan
    </button>

    <!-- Accuracy indicator -->
    <div
      v-if="prediction.prediction_accuracy !== null"
      class="mt-3 text-center text-xs text-slate-500"
    >
      Previous accuracy: {{ (prediction.prediction_accuracy! * 100).toFixed(1) }}%
    </div>
  </div>
</template>

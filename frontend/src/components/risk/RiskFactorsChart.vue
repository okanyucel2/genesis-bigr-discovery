<script setup lang="ts">
import { computed } from 'vue'
import type { RiskFactors } from '@/types/api'

const props = defineProps<{
  factors: RiskFactors
}>()

interface FactorDisplay {
  key: keyof RiskFactors
  label: string
  color: string
  bgColor: string
}

const factorMeta: FactorDisplay[] = [
  { key: 'cve_score', label: 'CVE Score', color: 'bg-rose-400', bgColor: 'bg-rose-400/20' },
  { key: 'exposure_score', label: 'Exposure', color: 'bg-amber-400', bgColor: 'bg-amber-400/20' },
  { key: 'classification_score', label: 'Classification', color: 'bg-cyan-400', bgColor: 'bg-cyan-400/20' },
  { key: 'age_score', label: 'Age', color: 'bg-purple-400', bgColor: 'bg-purple-400/20' },
  { key: 'change_score', label: 'Change Frequency', color: 'bg-emerald-400', bgColor: 'bg-emerald-400/20' },
]

const factorValues = computed(() =>
  factorMeta.map((meta) => ({
    ...meta,
    value: props.factors[meta.key],
    percent: Math.round(props.factors[meta.key] * 100),
  })),
)
</script>

<template>
  <div class="space-y-3">
    <h4 class="text-xs font-medium uppercase tracking-wider text-slate-400">
      Risk Factors
    </h4>
    <div class="space-y-2.5">
      <div
        v-for="factor in factorValues"
        :key="factor.key"
        class="space-y-1"
      >
        <div class="flex items-center justify-between text-xs">
          <span class="text-slate-300">{{ factor.label }}</span>
          <span class="font-mono tabular-nums text-slate-400">{{ factor.percent }}%</span>
        </div>
        <div class="h-2 w-full rounded-full bg-white/5">
          <div
            class="h-full rounded-full transition-all duration-500"
            :class="factor.color"
            :style="{ width: `${factor.percent}%` }"
          />
        </div>
      </div>
    </div>
  </div>
</template>

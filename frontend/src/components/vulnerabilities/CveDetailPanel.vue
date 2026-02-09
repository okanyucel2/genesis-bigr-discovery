<script setup lang="ts">
import { computed } from 'vue'
import { X, ExternalLink, ShieldAlert, CheckCircle } from 'lucide-vue-next'
import type { CveEntry } from '@/types/api'
import SeverityBadge from '@/components/shared/SeverityBadge.vue'

const props = defineProps<{
  cve: CveEntry
}>()

const emit = defineEmits<{
  close: []
}>()

const cvssColor = computed(() => {
  const score = props.cve.cvss_score
  if (score >= 9.0) return 'text-rose-400'
  if (score >= 7.0) return 'text-amber-400'
  if (score >= 4.0) return 'text-cyan-400'
  return 'text-emerald-400'
})

const cvssBarColor = computed(() => {
  const score = props.cve.cvss_score
  if (score >= 9.0) return 'bg-rose-400'
  if (score >= 7.0) return 'bg-amber-400'
  if (score >= 4.0) return 'bg-cyan-400'
  return 'bg-emerald-400'
})

const publishedFormatted = computed(() => {
  if (!props.cve.published) return null
  return new Date(props.cve.published).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
})
</script>

<template>
  <div class="glass-panel rounded-xl p-5">
    <!-- Header -->
    <div class="mb-4 flex items-start justify-between">
      <div>
        <h3 class="font-mono text-sm font-semibold text-white">
          {{ cve.cve_id }}
        </h3>
        <div class="mt-1 flex items-center gap-2">
          <SeverityBadge :severity="cve.severity" />
        </div>
      </div>
      <button
        class="rounded-md p-1 text-slate-400 transition-colors hover:bg-white/10 hover:text-slate-200"
        @click="emit('close')"
      >
        <X :size="16" />
      </button>
    </div>

    <!-- CVSS Score -->
    <div class="mb-4">
      <div class="flex items-baseline gap-2">
        <span class="text-3xl font-bold tabular-nums" :class="cvssColor">
          {{ cve.cvss_score.toFixed(1) }}
        </span>
        <span class="text-xs text-slate-500">/ 10.0</span>
      </div>
      <div class="mt-2 h-2 w-full rounded-full bg-white/5">
        <div
          class="h-full rounded-full transition-all duration-500"
          :class="cvssBarColor"
          :style="{ width: `${(cve.cvss_score / 10) * 100}%` }"
        />
      </div>
    </div>

    <!-- Description -->
    <div class="mb-4">
      <h4 class="mb-1 text-xs font-medium uppercase tracking-wider text-slate-500">Description</h4>
      <p class="text-sm leading-relaxed text-slate-300">
        {{ cve.description }}
      </p>
    </div>

    <!-- Details Grid -->
    <div class="mb-4 space-y-2.5 text-sm">
      <div class="flex items-start justify-between">
        <span class="text-slate-500">Vendor</span>
        <span class="text-right text-slate-300">{{ cve.affected_vendor }}</span>
      </div>
      <div class="flex items-start justify-between">
        <span class="text-slate-500">Product</span>
        <span class="text-right text-slate-300">{{ cve.affected_product }}</span>
      </div>
      <div v-if="cve.cpe" class="flex items-start justify-between">
        <span class="text-slate-500">CPE</span>
        <span class="text-right font-mono text-xs text-slate-400 max-w-[200px] break-all">{{ cve.cpe }}</span>
      </div>
      <div v-if="publishedFormatted" class="flex items-start justify-between">
        <span class="text-slate-500">Published</span>
        <span class="text-right text-slate-300">{{ publishedFormatted }}</span>
      </div>
    </div>

    <!-- Flags -->
    <div class="flex flex-wrap gap-2">
      <div
        v-if="cve.fix_available"
        class="flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-400"
      >
        <CheckCircle :size="12" />
        Fix Available
      </div>
      <div
        v-else
        class="flex items-center gap-1.5 rounded-full bg-slate-500/10 px-3 py-1.5 text-xs font-medium text-slate-400"
      >
        No Fix Available
      </div>

      <div
        v-if="cve.cisa_kev"
        class="flex items-center gap-1.5 rounded-full bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-400"
      >
        <ShieldAlert :size="12" />
        CISA KEV
      </div>
    </div>

    <!-- NVD Link -->
    <a
      :href="`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`"
      target="_blank"
      rel="noopener noreferrer"
      class="mt-4 flex items-center gap-1.5 text-xs text-cyan-400 transition-colors hover:text-cyan-300"
    >
      View on NVD
      <ExternalLink :size="10" />
    </a>
  </div>
</template>

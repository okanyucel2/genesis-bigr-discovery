<script setup lang="ts">
import type { VerilerimCard } from '@/types/home-dashboard'

defineProps<{
  data: VerilerimCard
}>()

const categoryLabels: Record<string, string> = {
  advertising: 'reklam sunucusu',
  analytics: 'analitik takipci',
  social: 'sosyal medya pikseli',
  fingerprinting: 'parmak izi okuyucu',
}
</script>

<template>
  <div class="space-y-3">
    <div class="flex items-baseline justify-between">
      <span class="text-xs text-slate-400">HTTPS Sertifika</span>
      <span class="text-lg font-bold tabular-nums text-emerald-400">{{ data.httpsCount }}</span>
    </div>
    <div class="flex items-baseline justify-between">
      <span class="text-xs text-slate-400">Uyumluluk</span>
      <span class="text-sm font-semibold text-slate-200">{{ data.complianceGrade }}</span>
    </div>
    <div v-if="data.expiringCerts > 0" class="rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
      {{ data.expiringCerts }} sertifika suresi dolmak uzere
    </div>
    <div v-if="data.selfSignedCerts > 0" class="text-xs text-slate-500">
      {{ data.selfSignedCerts }} self-signed sertifika
    </div>

    <!-- Tracker blocking stats -->
    <div v-if="data.trackersBlocked > 0" class="mt-1 space-y-1.5">
      <div class="flex items-baseline justify-between">
        <span class="text-xs text-slate-400">Bu hafta engellenen takipci</span>
        <span class="text-lg font-bold tabular-nums text-rose-400">{{ data.trackersBlocked }}</span>
      </div>
      <div class="space-y-0.5 pl-1">
        <div
          v-for="(count, cat) in data.trackerCategories"
          :key="cat"
          class="flex items-center justify-between text-[10px] text-slate-500"
        >
          <span>{{ count }} {{ categoryLabels[cat] || cat }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

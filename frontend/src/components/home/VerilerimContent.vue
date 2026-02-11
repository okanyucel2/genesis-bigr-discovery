<script setup lang="ts">
import type { VerilerimCard } from '@/types/home-dashboard'

defineProps<{
  data: VerilerimCard
}>()
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
  </div>
</template>

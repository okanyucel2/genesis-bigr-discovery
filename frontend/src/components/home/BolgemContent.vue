<script setup lang="ts">
import type { BolgemCard } from '@/types/home-dashboard'

defineProps<{
  data: BolgemCard
}>()
</script>

<template>
  <div class="space-y-3">
    <div class="flex items-baseline justify-between">
      <span class="text-xs text-slate-400">Topluluk Skoru</span>
      <span class="text-lg font-bold tabular-nums text-purple-400">{{ data.communityScore }}</span>
    </div>
    <div class="flex items-baseline justify-between">
      <span class="text-xs text-slate-400">Aktif Ajan</span>
      <span class="text-sm font-semibold tabular-nums text-slate-200">{{ data.activeAgents }}</span>
    </div>
    <div v-if="data.verifiedThreats > 0" class="flex items-baseline justify-between">
      <span class="text-xs text-slate-400">Dogrulanmis Tehdit</span>
      <span class="text-sm font-semibold tabular-nums text-rose-400">{{ data.verifiedThreats }}</span>
    </div>
    <div class="mt-1 flex items-center gap-1.5 text-xs">
      <span
        class="h-2 w-2 rounded-full"
        :class="data.isContributing ? 'bg-emerald-400' : 'bg-slate-600'"
      />
      <span class="text-slate-400">
        {{ data.isContributing ? 'Katilim aktif' : 'Katilim pasif' }}
      </span>
    </div>
    <div v-if="data.isContributing" class="flex gap-4 text-[10px] text-slate-500">
      <span>Gonderdim: {{ data.signalsContributed }}</span>
      <span>Aldim: {{ data.signalsReceived }}</span>
    </div>
  </div>
</template>

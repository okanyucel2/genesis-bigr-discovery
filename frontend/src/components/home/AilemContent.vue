<script setup lang="ts">
import type { AilemCard } from '@/types/home-dashboard'

defineProps<{
  data: AilemCard
}>()
</script>

<template>
  <div class="space-y-2">
    <div v-if="data.devices.length === 0" class="text-xs text-slate-500">
      Aile cihazlari henuz eklenmedi
    </div>
    <div
      v-for="device in data.devices"
      :key="device.id"
      class="flex items-center gap-2 rounded-lg px-2 py-1.5 transition-colors hover:bg-white/5"
    >
      <span class="text-base leading-none">{{ device.icon }}</span>
      <div class="min-w-0 flex-1">
        <p class="truncate text-xs font-medium text-slate-200">{{ device.name }}</p>
        <p v-if="device.ownerName" class="text-[10px] text-slate-500">{{ device.ownerName }}</p>
      </div>
      <span
        class="h-2 w-2 shrink-0 rounded-full"
        :class="device.isOnline ? 'bg-emerald-400' : 'bg-slate-600'"
      />
    </div>
    <div v-if="data.totalThreats > 0" class="mt-1 rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
      {{ data.totalThreats }} aktif tehdit
    </div>
  </div>
</template>

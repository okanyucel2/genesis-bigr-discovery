<script setup lang="ts">
import type { EvimCard } from '@/types/home-dashboard'
import { resolveDeviceName } from '@/lib/device-icons'

defineProps<{
  data: EvimCard
}>()

defineEmits<{
  identify: [ip: string]
  block: [ip: string]
}>()
</script>

<template>
  <div class="space-y-3">
    <div class="flex items-baseline justify-between">
      <span class="text-xs text-slate-400">Toplam Cihaz</span>
      <span class="text-lg font-bold tabular-nums text-cyan-400">{{ data.totalDevices }}</span>
    </div>

    <!-- Device type summary -->
    <div class="flex flex-wrap gap-1.5">
      <span
        v-for="(count, type) in data.deviceTypes"
        :key="type"
        class="rounded-full bg-white/5 px-2 py-0.5 text-[10px] text-slate-400"
      >
        {{ type }}: {{ count }}
      </span>
    </div>

    <!-- New device alerts -->
    <div
      v-for="device in data.newDevices"
      :key="device.ip"
      class="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3"
    >
      <p class="text-xs font-medium text-amber-300">Yeni cihaz algilandi</p>
      <p class="mt-0.5 text-[10px] text-slate-400">
        {{ resolveDeviceName(device.ip, device.hostname, device.vendor) }}
      </p>
      <div class="mt-2 flex gap-2">
        <button
          class="rounded bg-emerald-500/20 px-2.5 py-1 text-[10px] font-medium text-emerald-300 transition-colors hover:bg-emerald-500/30"
          @click="$emit('identify', device.ip)"
        >
          Taniyorum
        </button>
        <button
          class="rounded bg-rose-500/20 px-2.5 py-1 text-[10px] font-medium text-rose-300 transition-colors hover:bg-rose-500/30"
          @click="$emit('block', device.ip)"
        >
          Engelle
        </button>
      </div>
    </div>
  </div>
</template>

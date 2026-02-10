<script setup lang="ts">
import { computed } from 'vue'
import { Trash2, Edit3, AlertTriangle } from 'lucide-vue-next'
import type { FamilyDevice } from '@/types/api'
import SafetyRing from './SafetyRing.vue'

const props = defineProps<{
  device: FamilyDevice
}>()

defineEmits<{
  remove: [deviceId: string]
  edit: [deviceId: string]
  click: [deviceId: string]
}>()

const lastSeenFormatted = computed(() => {
  if (!props.device.last_seen) return 'Bilinmiyor'
  const date = props.device.last_seen.slice(0, 19).replace('T', ' ')
  return date
})

const safetyLevelLabel = computed(() => {
  const level = props.device.safety_level
  if (level === 'safe') return 'Guvenli'
  if (level === 'warning') return 'Dikkat'
  return 'Tehlike'
})

const safetyLevelColor = computed(() => {
  const level = props.device.safety_level
  if (level === 'safe') return 'text-emerald-400'
  if (level === 'warning') return 'text-amber-400'
  return 'text-red-400'
})

const borderAccent = computed(() => {
  const level = props.device.safety_level
  if (level === 'safe') return 'border-emerald-500/20'
  if (level === 'warning') return 'border-amber-500/20'
  return 'border-red-500/20'
})
</script>

<template>
  <div
    class="group glass-card relative cursor-pointer rounded-xl border p-5 transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:shadow-emerald-500/5"
    :class="borderAccent"
    @click="$emit('click', device.id)"
  >
    <!-- Online indicator dot -->
    <div class="absolute right-4 top-4 flex items-center gap-1.5">
      <span
        class="h-2.5 w-2.5 rounded-full"
        :class="device.is_online ? 'bg-emerald-400 shadow-[0_0_6px_rgba(16,185,129,0.6)]' : 'bg-slate-600'"
      />
      <span class="text-[10px]" :class="device.is_online ? 'text-emerald-400' : 'text-slate-500'">
        {{ device.is_online ? 'Cevrimici' : 'Cevrimdisi' }}
      </span>
    </div>

    <!-- Device icon + name -->
    <div class="flex items-start gap-3">
      <div class="text-2xl leading-none">{{ device.icon }}</div>
      <div class="min-w-0 flex-1">
        <h3 class="truncate text-sm font-semibold text-white">{{ device.name }}</h3>
        <p v-if="device.owner_name" class="mt-0.5 text-xs text-slate-400">
          {{ device.owner_name }}
        </p>
        <p v-if="device.network_name" class="mt-0.5 text-[10px] text-slate-500">
          {{ device.network_name }}
        </p>
      </div>
    </div>

    <!-- Safety ring + stats -->
    <div class="mt-4 flex items-center justify-between">
      <SafetyRing :score="device.safety_score" :size="64" :stroke-width="5" />

      <div class="flex flex-col items-end gap-1">
        <span class="text-xs font-medium" :class="safetyLevelColor">
          {{ safetyLevelLabel }}
        </span>
        <div v-if="device.open_threats > 0" class="flex items-center gap-1 text-amber-400">
          <AlertTriangle class="h-3 w-3" />
          <span class="text-xs font-medium">{{ device.open_threats }} tehdit</span>
        </div>
        <span class="text-[10px] text-slate-500">{{ lastSeenFormatted }}</span>
      </div>
    </div>

    <!-- Action buttons (on hover) -->
    <div class="absolute bottom-3 right-3 flex gap-1 opacity-0 transition-opacity group-hover:opacity-100">
      <button
        class="rounded-md p-1.5 text-slate-500 transition-colors hover:bg-white/5 hover:text-slate-300"
        title="Duzenle"
        @click.stop="$emit('edit', device.id)"
      >
        <Edit3 class="h-3.5 w-3.5" />
      </button>
      <button
        class="rounded-md p-1.5 text-slate-500 transition-colors hover:bg-red-500/10 hover:text-red-400"
        title="Kaldir"
        @click.stop="$emit('remove', device.id)"
      >
        <Trash2 class="h-3.5 w-3.5" />
      </button>
    </div>
  </div>
</template>

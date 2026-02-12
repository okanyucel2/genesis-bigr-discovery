<script setup lang="ts">
import type { Asset, DeviceStatus } from '@/types/api'
import { guessDeviceFromVendor, resolveDeviceName } from '@/lib/device-icons'
import { BIGR_CATEGORIES } from '@/types/bigr'
import { CheckCircle, Ban, AlertTriangle, HelpCircle, ChevronDown, ChevronUp } from 'lucide-vue-next'
import { ref } from 'vue'

const props = defineProps<{
  asset: Asset
  status: DeviceStatus
}>()

defineEmits<{
  acknowledge: [ip: string]
  block: [ip: string]
}>()

const expanded = ref(false)

const device = guessDeviceFromVendor(props.asset.vendor)
const name = resolveDeviceName(props.asset.ip, props.asset.hostname, props.asset.vendor)
const categoryInfo = BIGR_CATEGORIES[props.asset.bigr_category] ?? BIGR_CATEGORIES.unclassified

const statusConfig: Record<DeviceStatus, { label: string; class: string; icon: typeof CheckCircle }> = {
  acknowledged: { label: 'Taninmis', class: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', icon: CheckCircle },
  ignored: { label: 'Engellendi', class: 'bg-rose-500/15 text-rose-400 border-rose-500/30', icon: Ban },
  new: { label: 'Yeni', class: 'bg-amber-500/15 text-amber-400 border-amber-500/30', icon: AlertTriangle },
  unknown: { label: 'Bilinmeyen', class: 'bg-slate-500/15 text-slate-400 border-slate-500/30', icon: HelpCircle },
}

const sConf = statusConfig[props.status]

function formatTimeAgo(dateStr: string | null): string {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMin = Math.floor(diffMs / 60000)
  if (diffMin < 1) return 'az once'
  if (diffMin < 60) return `${diffMin}dk once`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}sa once`
  const diffDay = Math.floor(diffHr / 24)
  return `${diffDay}g once`
}
</script>

<template>
  <div class="rounded-xl border border-border/50 bg-white/[0.02] transition-all hover:bg-white/[0.04]">
    <!-- Main row -->
    <div class="flex items-center gap-3 px-4 py-3">
      <!-- Device icon -->
      <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-xl"
        :class="categoryInfo.bgClass">
        {{ device.icon }}
      </div>

      <!-- Name + subtitle -->
      <div class="min-w-0 flex-1">
        <div class="flex items-center gap-2">
          <p class="truncate text-sm font-medium text-white">{{ name }}</p>
          <span
            class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium"
            :class="sConf.class"
          >
            <component :is="sConf.icon" class="h-3 w-3" />
            {{ sConf.label }}
          </span>
        </div>
        <p class="mt-0.5 truncate text-xs text-slate-500">
          {{ asset.vendor ?? 'Bilinmeyen uretici' }}
          <span class="text-slate-600">·</span>
          {{ asset.ip }}
          <span class="text-slate-600">·</span>
          {{ formatTimeAgo(asset.last_seen) }}
        </p>
      </div>

      <!-- Actions -->
      <div class="flex shrink-0 items-center gap-2">
        <template v-if="status === 'new' || status === 'unknown'">
          <button
            class="rounded-lg bg-emerald-500/15 px-3 py-1.5 text-xs font-medium text-emerald-400 transition-colors hover:bg-emerald-500/25"
            @click="$emit('acknowledge', asset.ip)"
          >
            Taniyorum
          </button>
          <button
            class="rounded-lg bg-rose-500/15 px-3 py-1.5 text-xs font-medium text-rose-400 transition-colors hover:bg-rose-500/25"
            @click="$emit('block', asset.ip)"
          >
            Engelle
          </button>
        </template>
        <button
          class="rounded p-1 text-slate-500 transition-colors hover:text-slate-300"
          @click="expanded = !expanded"
        >
          <ChevronUp v-if="expanded" class="h-4 w-4" />
          <ChevronDown v-else class="h-4 w-4" />
        </button>
      </div>
    </div>

    <!-- Expanded details -->
    <Transition
      enter-active-class="transition duration-200 ease-out"
      enter-from-class="opacity-0 -translate-y-1"
      enter-to-class="opacity-100 translate-y-0"
      leave-active-class="transition duration-150 ease-in"
      leave-from-class="opacity-100 translate-y-0"
      leave-to-class="opacity-0 -translate-y-1"
    >
      <div v-if="expanded" class="border-t border-border/30 px-4 py-3">
        <div class="grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-4">
          <div>
            <span class="text-slate-500">MAC</span>
            <p class="font-mono text-slate-300">{{ asset.mac || '-' }}</p>
          </div>
          <div>
            <span class="text-slate-500">Kategori</span>
            <p :class="categoryInfo.textClass">{{ categoryInfo.labelTr }}</p>
          </div>
          <div>
            <span class="text-slate-500">Guven</span>
            <p class="text-slate-300">{{ Math.round(asset.confidence_score) }}%</p>
          </div>
          <div>
            <span class="text-slate-500">Acik Portlar</span>
            <p class="text-slate-300">
              {{ asset.open_ports?.length ? asset.open_ports.join(', ') : 'Yok' }}
            </p>
          </div>
          <div>
            <span class="text-slate-500">Ilk Gorulme</span>
            <p class="text-slate-300">{{ formatTimeAgo(asset.first_seen) }}</p>
          </div>
          <div>
            <span class="text-slate-500">Hostname</span>
            <p class="text-slate-300">{{ asset.hostname || '-' }}</p>
          </div>
          <div v-if="asset.sensitivity_level">
            <span class="text-slate-500">Hassasiyet</span>
            <p class="text-slate-300">{{ asset.sensitivity_level }}</p>
          </div>
        </div>
      </div>
    </Transition>
  </div>
</template>

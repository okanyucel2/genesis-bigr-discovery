<script setup lang="ts">
import { onMounted, watch, ref } from 'vue'
import { useAssetsStore } from '@/stores/assets'
import { useUiStore } from '@/stores/ui'
import type { DeviceStatus } from '@/types/api'
import AssetFilters from '@/components/assets/AssetFilters.vue'
import AssetTable from '@/components/assets/AssetTable.vue'
import DeviceCard from '@/components/assets/DeviceCard.vue'
import LoadingState from '@/components/shared/LoadingState.vue'
import { Search, Laptop, CheckCircle, Ban, AlertTriangle, HelpCircle } from 'lucide-vue-next'

const store = useAssetsStore()
const ui = useUiStore()
const advancedMode = ref(false)
const localSearch = ref('')

watch(() => ui.selectedNetwork, () => {
  store.fetchAssets(undefined, undefined, ui.selectedNetwork ?? undefined)
})

watch(localSearch, (q) => store.setSearchQuery(q))

function setStatus(status: DeviceStatus | null) {
  store.setStatus(store.selectedStatus === status ? null : status)
}

onMounted(() => {
  if (store.assets.length === 0) {
    store.fetchAssets(undefined, undefined, ui.selectedNetwork ?? undefined)
  }
})

const statusTabs: { key: DeviceStatus | null; label: string; icon: typeof Laptop }[] = [
  { key: null, label: 'Tumu', icon: Laptop },
  { key: 'acknowledged', label: 'Taninmis', icon: CheckCircle },
  { key: 'ignored', label: 'Engelli', icon: Ban },
  { key: 'new', label: 'Yeni', icon: AlertTriangle },
  { key: 'unknown', label: 'Bilinmeyen', icon: HelpCircle },
]
</script>

<template>
  <div class="space-y-5">
    <!-- Header -->
    <div class="flex items-end justify-between">
      <div>
        <h1 class="text-2xl font-bold text-white">Cihazlarim</h1>
        <p class="mt-1 text-sm text-slate-500">
          Aginizda bulunan {{ store.totalAssets }} cihaz
        </p>
      </div>
      <label class="flex items-center gap-2 text-xs text-slate-500 cursor-pointer select-none">
        <input
          v-model="advancedMode"
          type="checkbox"
          class="rounded border-slate-600 bg-slate-800 text-cyan-500 focus:ring-cyan-500/30"
        />
        Gelismis Gorunum
      </label>
    </div>

    <!-- Advanced mode: existing table -->
    <template v-if="advancedMode">
      <AssetFilters />
      <div class="glass-card rounded-lg border border-border/50 p-1">
        <LoadingState v-if="store.loading" message="Cihazlar kesfediliyor..." />
        <div v-else-if="store.error" class="flex flex-col items-center justify-center py-12 text-center">
          <p class="text-sm text-destructive">{{ store.error }}</p>
          <button class="mt-3 text-sm text-primary hover:underline" @click="store.fetchAssets()">Tekrar Dene</button>
        </div>
        <template v-else>
          <div class="flex items-center justify-between px-4 py-3">
            <p class="text-sm text-muted-foreground">
              Gosteriliyor
              <span class="font-medium text-foreground">{{ store.filteredAssets.length }}</span>
              / <span class="font-medium text-foreground">{{ store.totalAssets }}</span> cihaz
            </p>
          </div>
          <AssetTable :assets="store.filteredAssets" />
        </template>
      </div>
    </template>

    <!-- Basic mode: card view -->
    <template v-else>
      <!-- Status tabs -->
      <div class="flex gap-2 overflow-x-auto pb-1">
        <button
          v-for="tab in statusTabs"
          :key="tab.key ?? 'all'"
          class="flex items-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap"
          :class="store.selectedStatus === tab.key
            ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400'
            : 'border-border/40 bg-white/[0.02] text-slate-400 hover:bg-white/[0.05]'"
          @click="setStatus(tab.key)"
        >
          <component :is="tab.icon" class="h-3.5 w-3.5" />
          {{ tab.label }}
          <span class="ml-0.5 rounded-full bg-white/10 px-1.5 py-0.5 text-[10px] tabular-nums">
            {{ tab.key === null ? store.totalAssets : store.statusCounts[tab.key] }}
          </span>
        </button>
      </div>

      <!-- Search -->
      <div class="relative">
        <Search class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
        <input
          v-model="localSearch"
          type="text"
          placeholder="Cihaz ara (isim, IP, uretici)..."
          class="w-full rounded-lg border border-border/40 bg-white/[0.02] py-2.5 pl-10 pr-4 text-sm text-white placeholder:text-slate-600 focus:border-cyan-500/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/20"
        />
      </div>

      <!-- Loading / Error -->
      <LoadingState v-if="store.loading" message="Cihazlar kesfediliyor..." />
      <div v-else-if="store.error" class="flex flex-col items-center justify-center py-12 text-center">
        <p class="text-sm text-rose-400">{{ store.error }}</p>
        <button
          class="mt-3 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm text-cyan-300 transition-colors hover:bg-cyan-500/30"
          @click="store.fetchAssets()"
        >
          Tekrar Dene
        </button>
      </div>

      <!-- Device cards -->
      <div v-else-if="store.filteredAssets.length === 0" class="py-16 text-center">
        <p class="text-sm text-slate-500">Bu filtrede cihaz bulunamadi.</p>
      </div>
      <div v-else class="space-y-2">
        <DeviceCard
          v-for="asset in store.filteredAssets"
          :key="asset.ip + asset.mac"
          :asset="asset"
          :status="store.getDeviceStatus(asset)"
          @acknowledge="store.acknowledgeDevice"
          @block="store.blockDevice"
        />
      </div>
    </template>
  </div>
</template>

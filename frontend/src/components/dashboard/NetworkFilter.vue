<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Wifi } from 'lucide-vue-next'
import type { NetworkSummary } from '@/types/api'
import { bigrApi } from '@/lib/api'
import { useUiStore } from '@/stores/ui'

const ui = useUiStore()
const networks = ref<NetworkSummary[]>([])
const loading = ref(false)

async function fetchNetworks() {
  loading.value = true
  try {
    const { data } = await bigrApi.getNetworks()
    networks.value = data.networks
  } catch {
    networks.value = []
  } finally {
    loading.value = false
  }
}

function selectNetwork(networkId: string | null) {
  ui.setSelectedNetwork(networkId)
}

onMounted(fetchNetworks)
</script>

<template>
  <div class="flex items-center gap-2">
    <Wifi class="h-4 w-4 text-slate-400" />
    <select
      :value="ui.selectedNetwork ?? ''"
      class="rounded-md border border-slate-600 bg-slate-800 px-3 py-1.5 text-sm text-white focus:border-cyan-500 focus:outline-none"
      @change="selectNetwork(($event.target as HTMLSelectElement).value || null)"
    >
      <option value="">Tüm Ağlar</option>
      <option
        v-for="net in networks"
        :key="net.id"
        :value="net.id"
      >
        {{ net.friendly_name || net.fingerprint_hash.slice(0, 8) }} ({{ net.asset_count }})
      </option>
    </select>
  </div>
</template>

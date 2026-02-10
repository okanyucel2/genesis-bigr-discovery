<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { Globe } from 'lucide-vue-next'
import type { SiteSummary } from '@/types/api'
import { bigrApi } from '@/lib/api'
import { useUiStore } from '@/stores/ui'

const ui = useUiStore()
const sites = ref<SiteSummary[]>([])
const loading = ref(false)

async function fetchSites() {
  loading.value = true
  try {
    const { data } = await bigrApi.getSites()
    sites.value = data.sites
  } catch {
    sites.value = []
  } finally {
    loading.value = false
  }
}

function selectSite(site: string | null) {
  ui.setSelectedSite(site)
}

onMounted(fetchSites)
</script>

<template>
  <div class="flex items-center gap-2">
    <Globe class="h-4 w-4 text-slate-400" />
    <select
      :value="ui.selectedSite ?? ''"
      class="rounded-md border border-slate-600 bg-slate-800 px-3 py-1.5 text-sm text-white focus:border-cyan-500 focus:outline-none"
      @change="selectSite(($event.target as HTMLSelectElement).value || null)"
    >
      <option value="">All Sites</option>
      <option
        v-for="site in sites"
        :key="site.site_name"
        :value="site.site_name"
      >
        {{ site.site_name }} ({{ site.asset_count }})
      </option>
    </select>
  </div>
</template>

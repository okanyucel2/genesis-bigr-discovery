import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUiStore = defineStore('ui', () => {
  const sidebarCollapsed = ref(false)
  const selectedSite = ref<string | null>(null)
  const selectedNetwork = ref<string | null>(null)

  function toggleSidebar() {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  function setSidebarCollapsed(collapsed: boolean) {
    sidebarCollapsed.value = collapsed
  }

  function setSelectedSite(site: string | null) {
    selectedSite.value = site
  }

  function setSelectedNetwork(networkId: string | null) {
    selectedNetwork.value = networkId
  }

  return {
    sidebarCollapsed,
    selectedSite,
    selectedNetwork,
    toggleSidebar,
    setSidebarCollapsed,
    setSelectedSite,
    setSelectedNetwork,
  }
})

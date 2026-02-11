import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUiStore = defineStore('ui', () => {
  const sidebarCollapsed = ref(false)
  const selectedSite = ref<string | null>(null)
  const selectedNetwork = ref<string | null>(null)
  const advancedMode = ref(false)

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

  function toggleAdvancedMode() {
    advancedMode.value = !advancedMode.value
  }

  return {
    sidebarCollapsed,
    selectedSite,
    selectedNetwork,
    advancedMode,
    toggleSidebar,
    setSidebarCollapsed,
    setSelectedSite,
    setSelectedNetwork,
    toggleAdvancedMode,
  }
})

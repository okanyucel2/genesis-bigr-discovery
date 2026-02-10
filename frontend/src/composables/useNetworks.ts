import { ref, onMounted } from 'vue'
import type { NetworkSummary } from '@/types/api'
import { bigrApi } from '@/lib/api'

export function useNetworks() {
  const networks = ref<NetworkSummary[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchNetworks() {
    loading.value = true
    error.value = null
    try {
      const { data } = await bigrApi.getNetworks()
      networks.value = data.networks
    } catch {
      networks.value = []
    } finally {
      loading.value = false
    }
  }

  async function renameNetwork(networkId: string, friendlyName: string) {
    try {
      await bigrApi.renameNetwork(networkId, friendlyName)
      // Refresh list after rename
      await fetchNetworks()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Failed to rename network'
    }
  }

  onMounted(fetchNetworks)

  return {
    networks,
    loading,
    error,
    fetchNetworks,
    renameNetwork,
  }
}

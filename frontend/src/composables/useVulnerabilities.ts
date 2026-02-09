import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { VulnerabilitiesResponse } from '@/types/api'

export function useVulnerabilities() {
  const data = ref<VulnerabilitiesResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchVulnerabilities() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getVulnerabilities()
      data.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load vulnerability data'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    data,
    loading,
    error,
    fetchVulnerabilities,
  }
}

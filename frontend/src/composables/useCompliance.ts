import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { ComplianceResponse } from '@/types/api'

export function useCompliance() {
  const data = ref<ComplianceResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchCompliance() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getCompliance()
      data.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load compliance data'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    data,
    loading,
    error,
    fetchCompliance,
  }
}

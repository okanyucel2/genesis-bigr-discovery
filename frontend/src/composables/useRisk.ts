import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { RiskResponse } from '@/types/api'

export function useRisk() {
  const data = ref<RiskResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchRisk() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getRisk()
      data.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load risk data'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    data,
    loading,
    error,
    fetchRisk,
  }
}

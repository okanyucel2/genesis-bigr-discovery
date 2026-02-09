import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { AnalyticsResponse } from '@/types/api'

export function useAnalytics() {
  const data = ref<AnalyticsResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchAnalytics(days = 30) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getAnalytics(days)
      data.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load analytics data'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    data,
    loading,
    error,
    fetchAnalytics,
  }
}

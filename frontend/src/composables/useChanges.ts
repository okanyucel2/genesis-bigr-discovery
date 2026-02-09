import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { AssetChange } from '@/types/api'

export function useChanges() {
  const changes = ref<AssetChange[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchChanges(limit = 50) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getChanges(limit)
      changes.value = res.data.changes
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load changes'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    changes,
    loading,
    error,
    fetchChanges,
  }
}

import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { Subnet } from '@/types/api'

export function useSubnets() {
  const subnets = ref<Subnet[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchSubnets() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getSubnets()
      subnets.value = res.data.subnets
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Failed to load subnets'
    } finally {
      loading.value = false
    }
  }

  return { subnets, loading, error, fetchSubnets }
}

import { ref } from 'vue'
import type { Agent } from '@/types/api'
import { bigrApi } from '@/lib/api'

export function useAgents() {
  const agents = ref<Agent[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchAgents() {
    loading.value = true
    error.value = null
    try {
      const { data } = await bigrApi.getAgents()
      agents.value = data.agents
    } catch (err: any) {
      error.value = err.message || 'Failed to fetch agents'
    } finally {
      loading.value = false
    }
  }

  return { agents, loading, error, fetchAgents }
}

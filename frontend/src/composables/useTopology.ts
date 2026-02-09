import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { TopologyNode, TopologyEdge, TopologyResponse } from '@/types/api'

export function useTopology() {
  const nodes = ref<TopologyNode[]>([])
  const edges = ref<TopologyEdge[]>([])
  const stats = ref<TopologyResponse['stats']>({
    total_nodes: 0,
    total_edges: 0,
    node_types: {},
  })
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchTopology(cidr?: string) {
    loading.value = true
    error.value = null
    try {
      const res = cidr
        ? await bigrApi.getTopologySubnet(cidr)
        : await bigrApi.getTopology()
      nodes.value = res.data.nodes
      edges.value = res.data.edges
      stats.value = res.data.stats
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load topology'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    nodes,
    edges,
    stats,
    loading,
    error,
    fetchTopology,
  }
}

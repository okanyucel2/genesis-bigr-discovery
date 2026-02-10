import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type {
  CollectiveThreatsResponse,
  CollectiveStats,
  ContributionStatus,
  CollectiveFeedResponse,
} from '@/types/api'

export function useCollective() {
  const threats = ref<CollectiveThreatsResponse | null>(null)
  const stats = ref<CollectiveStats | null>(null)
  const contribution = ref<ContributionStatus | null>(null)
  const feed = ref<CollectiveFeedResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchThreats(minConfidence = 0.5) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getCollectiveThreats(minConfidence)
      threats.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load collective threats'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  async function fetchStats() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getCollectiveStats()
      stats.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load collective stats'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  async function fetchContribution(agentHash = '') {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getContributionStatus(agentHash)
      contribution.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load contribution status'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  async function fetchFeed(limit = 20) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getCollectiveFeed(limit)
      feed.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load collective feed'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  async function fetchAll() {
    loading.value = true
    error.value = null
    try {
      const [statsRes, feedRes, contributionRes] = await Promise.all([
        bigrApi.getCollectiveStats(),
        bigrApi.getCollectiveFeed(),
        bigrApi.getContributionStatus(),
      ])
      stats.value = statsRes.data
      feed.value = feedRes.data
      contribution.value = contributionRes.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load collective data'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    threats,
    stats,
    contribution,
    feed,
    loading,
    error,
    fetchThreats,
    fetchStats,
    fetchContribution,
    fetchFeed,
    fetchAll,
  }
}

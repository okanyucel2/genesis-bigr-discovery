import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type {
  GuardianStatusResponse,
  GuardianStatsResponse,
  GuardianRule,
  GuardianBlocklist,
  GuardianHealthResponse,
} from '@/types/api'

export function useGuardian() {
  const status = ref<GuardianStatusResponse | null>(null)
  const stats = ref<GuardianStatsResponse | null>(null)
  const rules = ref<GuardianRule[]>([])
  const blocklists = ref<GuardianBlocklist[]>([])
  const health = ref<GuardianHealthResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  const blockRules = computed(() => rules.value.filter((r) => r.action === 'block'))
  const allowRules = computed(() => rules.value.filter((r) => r.action === 'allow'))
  const activeBlocklists = computed(() => blocklists.value.filter((b) => b.is_enabled))

  async function fetchStatus() {
    try {
      const res = await bigrApi.getGuardianStatus()
      status.value = res.data
    } catch {
      // Silently fail
    }
  }

  async function fetchStats() {
    try {
      const res = await bigrApi.getGuardianStats()
      stats.value = res.data
    } catch {
      // Silently fail
    }
  }

  async function fetchRules() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getGuardianRules()
      rules.value = res.data.rules
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Kurallar yuklenemedi'
    } finally {
      loading.value = false
    }
  }

  async function fetchBlocklists() {
    try {
      const res = await bigrApi.getGuardianBlocklists()
      blocklists.value = res.data.blocklists
    } catch {
      // Silently fail
    }
  }

  async function fetchHealth() {
    try {
      const res = await bigrApi.getGuardianHealth()
      health.value = res.data
    } catch {
      // Silently fail
    }
  }

  async function addRule(action: string, domain: string, category = 'custom', reason = '') {
    error.value = null
    try {
      await bigrApi.addGuardianRule(action, domain, category, reason)
      await fetchRules()
      await fetchStatus()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Kural eklenemedi'
    }
  }

  async function deleteRule(ruleId: string) {
    error.value = null
    try {
      await bigrApi.deleteGuardianRule(ruleId)
      await fetchRules()
      await fetchStatus()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Kural silinemedi'
    }
  }

  async function updateBlocklists() {
    error.value = null
    try {
      await bigrApi.updateGuardianBlocklists()
      await fetchBlocklists()
      await fetchStatus()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Listeler guncellenemedi'
    }
  }

  async function refreshAll() {
    loading.value = true
    await Promise.all([
      fetchStatus(),
      fetchStats(),
      fetchRules(),
      fetchBlocklists(),
      fetchHealth(),
    ])
    loading.value = false
  }

  return {
    status,
    stats,
    rules,
    blocklists,
    health,
    loading,
    error,
    blockRules,
    allowRules,
    activeBlocklists,
    fetchStatus,
    fetchStats,
    fetchRules,
    fetchBlocklists,
    fetchHealth,
    addRule,
    deleteRule,
    updateBlocklists,
    refreshAll,
  }
}

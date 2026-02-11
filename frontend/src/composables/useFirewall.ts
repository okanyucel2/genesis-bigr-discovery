import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type {
  FirewallStatus,
  FirewallRule,
  FirewallEvent,
  FirewallConfig,
  FirewallDailyStats,
} from '@/types/api'

export function useFirewall() {
  const status = ref<FirewallStatus | null>(null)
  const rules = ref<FirewallRule[]>([])
  const events = ref<FirewallEvent[]>([])
  const config = ref<FirewallConfig | null>(null)
  const dailyStats = ref<FirewallDailyStats | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  const activeRules = computed(() => rules.value.filter((r) => r.is_active))
  const blockRules = computed(() =>
    rules.value.filter((r) => r.rule_type.startsWith('block_')),
  )
  const allowRules = computed(() =>
    rules.value.filter((r) => r.rule_type.startsWith('allow_')),
  )
  const blockedEvents = computed(() =>
    events.value.filter((e) => e.action === 'blocked'),
  )

  async function fetchStatus() {
    try {
      const res = await bigrApi.getFirewallStatus()
      status.value = res.data
    } catch {
      // Silently fail
    }
  }

  async function fetchRules(ruleType?: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getFirewallRules(ruleType, false)
      rules.value = res.data.rules
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Kurallar yuklenemedi'
    } finally {
      loading.value = false
    }
  }

  async function addRule(rule: Partial<FirewallRule>) {
    error.value = null
    try {
      await bigrApi.addFirewallRule(rule)
      await fetchRules()
      await fetchStatus()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Kural eklenemedi'
    }
  }

  async function removeRule(ruleId: string) {
    error.value = null
    try {
      await bigrApi.removeFirewallRule(ruleId)
      await fetchRules()
      await fetchStatus()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Kural silinemedi'
    }
  }

  async function toggleRule(ruleId: string) {
    error.value = null
    try {
      await bigrApi.toggleFirewallRule(ruleId)
      await fetchRules()
      await fetchStatus()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Kural degistirilemedi'
    }
  }

  async function syncThreats() {
    error.value = null
    try {
      const res = await bigrApi.syncFirewallThreats()
      await fetchRules()
      await fetchStatus()
      return res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Tehdit senkronizasyonu basarisiz'
      return null
    }
  }

  async function syncPorts() {
    error.value = null
    try {
      const res = await bigrApi.syncFirewallPorts()
      await fetchRules()
      await fetchStatus()
      return res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Port senkronizasyonu basarisiz'
      return null
    }
  }

  async function syncShield() {
    error.value = null
    try {
      const res = await bigrApi.syncFirewallShield()
      await fetchRules()
      await fetchStatus()
      return res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Shield senkronizasyonu basarisiz'
      return null
    }
  }

  async function fetchEvents(limit = 100, action?: string) {
    try {
      const res = await bigrApi.getFirewallEvents(limit, action)
      events.value = res.data.events
    } catch {
      // Silently fail
    }
  }

  async function fetchConfig() {
    try {
      const res = await bigrApi.getFirewallConfig()
      config.value = res.data
    } catch {
      // Silently fail
    }
  }

  async function updateConfig(newConfig: FirewallConfig) {
    error.value = null
    try {
      const res = await bigrApi.updateFirewallConfig(newConfig)
      config.value = res.data.config
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Yapilandirma guncellenemedi'
    }
  }

  async function fetchDailyStats() {
    try {
      const res = await bigrApi.getFirewallDailyStats()
      dailyStats.value = res.data
    } catch {
      // Silently fail
    }
  }

  async function installAdapter() {
    error.value = null
    try {
      const res = await bigrApi.installFirewallAdapter()
      return res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Adapter yuklenemedi'
      return null
    }
  }

  async function refreshAll() {
    loading.value = true
    await Promise.all([
      fetchStatus(),
      fetchRules(),
      fetchEvents(),
      fetchConfig(),
      fetchDailyStats(),
    ])
    loading.value = false
  }

  return {
    status,
    rules,
    events,
    config,
    dailyStats,
    loading,
    error,
    activeRules,
    blockRules,
    allowRules,
    blockedEvents,
    fetchStatus,
    fetchRules,
    addRule,
    removeRule,
    toggleRule,
    syncThreats,
    syncPorts,
    syncShield,
    fetchEvents,
    fetchConfig,
    updateConfig,
    fetchDailyStats,
    installAdapter,
    refreshAll,
  }
}

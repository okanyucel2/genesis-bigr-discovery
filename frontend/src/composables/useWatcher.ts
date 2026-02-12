import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type { WatcherStatus, WatcherScan, WatcherAlert } from '@/types/api'

export function useWatcher() {
  const status = ref<WatcherStatus | null>(null)
  const history = ref<WatcherScan[]>([])
  const alerts = ref<WatcherAlert[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  const isRunning = computed(() => status.value?.is_running ?? false)
  const totalAlerts = computed(() => alerts.value.length)
  const criticalAlerts = computed(() =>
    alerts.value.filter((a) => a.severity === 'critical'),
  )

  async function fetchStatus() {
    try {
      const res = await bigrApi.getWatcherStatus()
      status.value = res.data
    } catch {
      // Silently fail
    }
  }

  async function fetchHistory(limit = 20) {
    try {
      const res = await bigrApi.getWatcherHistory(limit)
      history.value = res.data.scans
    } catch {
      // Silently fail
    }
  }

  async function fetchAlerts(limit = 50) {
    try {
      const res = await bigrApi.getWatcherAlerts(limit)
      alerts.value = res.data.alerts
    } catch {
      // Silently fail
    }
  }

  async function triggerScan(subnet?: string) {
    error.value = null
    try {
      await bigrApi.triggerWatcherScan(subnet)
      await fetchStatus()
      await fetchHistory()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Tarama tetiklenemedi'
    }
  }

  async function refreshAll() {
    loading.value = true
    await Promise.all([fetchStatus(), fetchHistory(), fetchAlerts()])
    loading.value = false
  }

  return {
    status,
    history,
    alerts,
    loading,
    error,
    isRunning,
    totalAlerts,
    criticalAlerts,
    fetchStatus,
    fetchHistory,
    fetchAlerts,
    triggerScan,
    refreshAll,
  }
}

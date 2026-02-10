import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type { HumanNotification, HumanizeRequest } from '@/types/api'

export function useNotifications() {
  const notifications = ref<HumanNotification[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)
  const readIds = ref<Set<string>>(new Set())
  const activeSeverityFilter = ref<string | null>(null)

  const unreadCount = computed(() =>
    notifications.value.filter((n) => !readIds.value.has(n.id)).length,
  )

  const filteredNotifications = computed(() => {
    if (!activeSeverityFilter.value) return notifications.value
    return notifications.value.filter(
      (n) => n.severity === activeSeverityFilter.value,
    )
  })

  const criticalNotifications = computed(() =>
    notifications.value.filter((n) => n.severity === 'critical'),
  )

  const warningNotifications = computed(() =>
    notifications.value.filter((n) => n.severity === 'warning'),
  )

  const infoNotifications = computed(() =>
    notifications.value.filter((n) => n.severity === 'info'),
  )

  async function fetchSampleNotifications() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getSampleNotifications()
      notifications.value = res.data.samples
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Bildirimler yuklenemedi'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  async function humanizeAlert(request: HumanizeRequest) {
    error.value = null
    try {
      const res = await bigrApi.humanizeAlert(request)
      const notification = res.data.notification
      notifications.value.unshift(notification)
      return notification
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Bildirim olusturulamadi'
      error.value = message
      return null
    }
  }

  async function humanizeBatch(requests: HumanizeRequest[]) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.humanizeBatch(requests)
      const newNotifications = res.data.notifications
      notifications.value.unshift(...newNotifications)
      return newNotifications
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Toplu bildirim olusturulamadi'
      error.value = message
      return []
    } finally {
      loading.value = false
    }
  }

  function markAsRead(id: string) {
    readIds.value.add(id)
  }

  function markAllAsRead() {
    for (const n of notifications.value) {
      readIds.value.add(n.id)
    }
  }

  function setSeverityFilter(severity: string | null) {
    activeSeverityFilter.value = severity
  }

  function clearNotifications() {
    notifications.value = []
    readIds.value.clear()
  }

  return {
    notifications,
    filteredNotifications,
    criticalNotifications,
    warningNotifications,
    infoNotifications,
    loading,
    error,
    unreadCount,
    activeSeverityFilter,
    fetchSampleNotifications,
    humanizeAlert,
    humanizeBatch,
    markAsRead,
    markAllAsRead,
    setSeverityFilter,
    clearNotifications,
  }
}

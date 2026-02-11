import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type {
  FamilyOverview,
  FamilyAlert,
  FamilyTimelineEntry,
  AddDeviceRequest,
  UpdateDeviceRequest,
} from '@/types/api'

export const useFamilyStore = defineStore('family', () => {
  const overview = ref<FamilyOverview | null>(null)
  const alerts = ref<FamilyAlert[]>([])
  const timeline = ref<FamilyTimelineEntry[]>([])
  const isLoading = ref(false)
  const isAddingDevice = ref(false)
  const error = ref<string | null>(null)
  const subscriptionId = ref<string | null>(null)

  // Computed
  const devices = computed(() => overview.value?.devices ?? [])
  const deviceCount = computed(() => devices.value.length)
  const maxDevices = computed(() => overview.value?.max_devices ?? 5)
  const canAddDevice = computed(() => deviceCount.value < maxDevices.value)
  const avgSafetyScore = computed(() => overview.value?.avg_safety_score ?? 0)
  const safetyLevel = computed(() => overview.value?.safety_level ?? 'warning')
  const totalThreats = computed(() => overview.value?.total_threats ?? 0)
  const devicesOnline = computed(() => overview.value?.devices_online ?? 0)

  const safetyMessage = computed(() => {
    const level = safetyLevel.value
    if (level === 'safe') return 'Ailen guvende'
    if (level === 'warning') return 'Dikkat gereken cihazlar var'
    return 'Acil dikkat gerektiren tehditler var!'
  })

  const safetyMessageDetail = computed(() => {
    const level = safetyLevel.value
    if (level === 'safe') return 'Tum cihazlar guvenli durumda. Endiselenme.'
    if (level === 'warning') return 'Bazi cihazlarda dikkat edilmesi gereken durumlar var.'
    return 'Ailenin guvenligini tehdit eden durumlar tespit edildi.'
  })

  const unreadAlerts = computed(() => alerts.value.filter((a) => !a.is_read))

  async function setSubscriptionId(id: string) {
    subscriptionId.value = id
  }

  async function fetchOverview() {
    if (!subscriptionId.value) return
    isLoading.value = true
    error.value = null
    try {
      const res = await bigrApi.getFamilyOverview(subscriptionId.value)
      overview.value = res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Aile paneli yuklenemedi'
    } finally {
      isLoading.value = false
    }
  }

  async function fetchAlerts() {
    if (!subscriptionId.value) return
    error.value = null
    try {
      const res = await bigrApi.getFamilyAlerts(subscriptionId.value)
      alerts.value = res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Uyarilar yuklenemedi'
    }
  }

  async function fetchTimeline() {
    if (!subscriptionId.value) return
    error.value = null
    try {
      const res = await bigrApi.getFamilyTimeline(subscriptionId.value)
      timeline.value = res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Zaman cizelgesi yuklenemedi'
    }
  }

  async function addDevice(request: AddDeviceRequest) {
    if (!subscriptionId.value) return null
    isAddingDevice.value = true
    error.value = null
    try {
      const res = await bigrApi.addFamilyDevice(subscriptionId.value, request)
      // Refresh overview to get updated device list
      await fetchOverview()
      return res.data
    } catch (e: unknown) {
      if (e && typeof e === 'object' && 'response' in e) {
        const axiosErr = e as { response?: { data?: { detail?: string } } }
        error.value = axiosErr.response?.data?.detail ?? 'Cihaz eklenemedi'
      } else {
        error.value = e instanceof Error ? e.message : 'Cihaz eklenemedi'
      }
      return null
    } finally {
      isAddingDevice.value = false
    }
  }

  async function removeDevice(deviceId: string) {
    error.value = null
    try {
      await bigrApi.removeFamilyDevice(deviceId)
      await fetchOverview()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Cihaz kaldirilamadi'
    }
  }

  async function updateDevice(deviceId: string, request: UpdateDeviceRequest) {
    error.value = null
    try {
      await bigrApi.updateFamilyDevice(deviceId, request)
      await fetchOverview()
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Cihaz guncellenemedi'
    }
  }

  async function loadAll() {
    await Promise.all([fetchOverview(), fetchAlerts(), fetchTimeline()])
  }

  function $reset() {
    overview.value = null
    alerts.value = []
    timeline.value = []
    isLoading.value = false
    isAddingDevice.value = false
    error.value = null
    subscriptionId.value = null
  }

  return {
    // State
    overview,
    alerts,
    timeline,
    isLoading,
    isAddingDevice,
    error,
    subscriptionId,
    // Computed
    devices,
    deviceCount,
    maxDevices,
    canAddDevice,
    avgSafetyScore,
    safetyLevel,
    totalThreats,
    devicesOnline,
    safetyMessage,
    safetyMessageDetail,
    unreadAlerts,
    // Actions
    setSubscriptionId,
    fetchOverview,
    fetchAlerts,
    fetchTimeline,
    addDevice,
    removeDevice,
    updateDevice,
    loadAll,
    $reset,
  }
})

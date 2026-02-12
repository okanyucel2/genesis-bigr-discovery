import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { Asset, DeviceStatus } from '@/types/api'
import type { BigrCategory } from '@/types/bigr'
import { bigrApi } from '@/lib/api'
import { useToast } from '@/composables/useToast'

function getDeviceStatus(asset: Asset): DeviceStatus {
  if (asset.is_ignored) return 'ignored'
  if (asset.manual_category === 'acknowledged') return 'acknowledged'
  // New = first seen in last 7 days
  if (asset.first_seen) {
    const weekAgo = new Date()
    weekAgo.setDate(weekAgo.getDate() - 7)
    if (new Date(asset.first_seen) > weekAgo) return 'new'
  }
  return 'unknown'
}

export const useAssetsStore = defineStore('assets', () => {
  const assets = ref<Asset[]>([])
  const categorySummary = ref<Record<string, number>>({})
  const loading = ref(false)
  const error = ref<string | null>(null)
  const selectedSubnet = ref<string | null>(null)
  const searchQuery = ref('')
  const selectedCategory = ref<BigrCategory | null>(null)
  const selectedStatus = ref<DeviceStatus | null>(null)

  const toast = useToast()

  async function fetchAssets(subnet?: string, site?: string, network?: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getAssets(subnet, site, network)
      assets.value = res.data.assets ?? []
      categorySummary.value = res.data.category_summary ?? {}
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load assets'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  const filteredAssets = computed(() => {
    let result = assets.value
    if (selectedCategory.value) {
      result = result.filter((a) => a.bigr_category === selectedCategory.value)
    }
    if (selectedStatus.value) {
      result = result.filter((a) => getDeviceStatus(a) === selectedStatus.value)
    }
    if (searchQuery.value) {
      const q = searchQuery.value.toLowerCase()
      result = result.filter(
        (a) =>
          a.ip.includes(q) ||
          a.hostname?.toLowerCase().includes(q) ||
          a.vendor?.toLowerCase().includes(q) ||
          a.mac?.toLowerCase().includes(q),
      )
    }
    return result
  })

  const statusCounts = computed(() => {
    const counts: Record<DeviceStatus, number> = {
      acknowledged: 0,
      ignored: 0,
      new: 0,
      unknown: 0,
    }
    for (const a of assets.value) {
      counts[getDeviceStatus(a)]++
    }
    return counts
  })

  const totalAssets = computed(() => assets.value.length)

  async function acknowledgeDevice(ip: string) {
    try {
      await bigrApi.acknowledgeDevice(ip)
      // Update local state
      const asset = assets.value.find((a) => a.ip === ip)
      if (asset) {
        asset.manual_category = 'acknowledged'
      }
      toast.success(`Cihaz tanindi.`)
    } catch {
      toast.error(`Cihaz tanınamadi.`)
    }
  }

  async function blockDevice(ip: string) {
    try {
      await bigrApi.blockDevice(ip)
      const asset = assets.value.find((a) => a.ip === ip)
      if (asset) {
        asset.is_ignored = 1
      }
      toast.success(`Cihaz engellendi.`)
    } catch {
      toast.error(`Cihaz engellenemedi.`)
    }
  }

  function setCategory(category: BigrCategory | null) {
    selectedCategory.value = category
  }

  function setSearchQuery(query: string) {
    searchQuery.value = query
  }

  function setSubnet(subnet: string | null) {
    selectedSubnet.value = subnet
  }

  function setStatus(status: DeviceStatus | null) {
    selectedStatus.value = status
  }

  function $reset() {
    assets.value = []
    categorySummary.value = {}
    loading.value = false
    error.value = null
    selectedSubnet.value = null
    searchQuery.value = ''
    selectedCategory.value = null
    selectedStatus.value = null
  }

  return {
    assets,
    categorySummary,
    loading,
    error,
    selectedSubnet,
    searchQuery,
    selectedCategory,
    selectedStatus,
    fetchAssets,
    filteredAssets,
    statusCounts,
    totalAssets,
    acknowledgeDevice,
    blockDevice,
    getDeviceStatus,
    setCategory,
    setSearchQuery,
    setSubnet,
    setStatus,
    $reset,
  }
})

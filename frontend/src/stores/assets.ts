import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { Asset } from '@/types/api'
import type { BigrCategory } from '@/types/bigr'
import { bigrApi } from '@/lib/api'

export const useAssetsStore = defineStore('assets', () => {
  const assets = ref<Asset[]>([])
  const categorySummary = ref<Record<string, number>>({})
  const loading = ref(false)
  const error = ref<string | null>(null)
  const selectedSubnet = ref<string | null>(null)
  const searchQuery = ref('')
  const selectedCategory = ref<BigrCategory | null>(null)

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

  const totalAssets = computed(() => assets.value.length)

  function setCategory(category: BigrCategory | null) {
    selectedCategory.value = category
  }

  function setSearchQuery(query: string) {
    searchQuery.value = query
  }

  function setSubnet(subnet: string | null) {
    selectedSubnet.value = subnet
  }

  function $reset() {
    assets.value = []
    categorySummary.value = {}
    loading.value = false
    error.value = null
    selectedSubnet.value = null
    searchQuery.value = ''
    selectedCategory.value = null
  }

  return {
    assets,
    categorySummary,
    loading,
    error,
    selectedSubnet,
    searchQuery,
    selectedCategory,
    fetchAssets,
    filteredAssets,
    totalAssets,
    setCategory,
    setSearchQuery,
    setSubnet,
    $reset,
  }
})

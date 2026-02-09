import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import type { Asset } from '@/types/api'
import type { BigrCategory } from '@/types/bigr'

export function useAssets() {
  const assets = ref<Asset[]>([])
  const categorySummary = ref<Record<string, number>>({})
  const totalAssets = ref(0)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchAssets(subnet?: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getAssets(subnet)
      assets.value = res.data.assets
      categorySummary.value = res.data.category_summary
      totalAssets.value = res.data.total_assets
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load assets'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  const assetsByCategory = computed(() => {
    const groups: Record<BigrCategory, Asset[]> = {
      ag_ve_sistemler: [],
      uygulamalar: [],
      iot: [],
      tasinabilir: [],
      unclassified: [],
    }
    for (const asset of assets.value) {
      const cat = asset.bigr_category as BigrCategory
      if (groups[cat]) {
        groups[cat].push(asset)
      } else {
        groups.unclassified.push(asset)
      }
    }
    return groups
  })

  return {
    assets,
    categorySummary,
    totalAssets,
    loading,
    error,
    fetchAssets,
    assetsByCategory,
  }
}

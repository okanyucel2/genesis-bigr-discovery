import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { Asset, AssetHistoryEntry } from '@/types/api'

export function useAssetDetail() {
  const asset = ref<Asset | null>(null)
  const history = ref<AssetHistoryEntry[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchDetail(ip: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getAssetDetail(ip)
      asset.value = res.data.asset
      history.value = res.data.history
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Failed to load asset detail'
    } finally {
      loading.value = false
    }
  }

  return { asset, history, loading, error, fetchDetail }
}

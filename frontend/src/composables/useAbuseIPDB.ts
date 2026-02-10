import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { AbuseIPDBCheck, AbuseIPDBStatus, AbuseIPDBEnrichment } from '@/types/api'

export function useAbuseIPDB() {
  const checkResult = ref<AbuseIPDBCheck | null>(null)
  const status = ref<AbuseIPDBStatus | null>(null)
  const enrichment = ref<AbuseIPDBEnrichment | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function checkIP(ip: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.checkAbuseIPDB(ip)
      checkResult.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'AbuseIPDB sorgusu basarisiz oldu'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  async function fetchStatus() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getAbuseIPDBStatus()
      status.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'AbuseIPDB durumu alinamadi'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  async function enrichAsset(ip: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.enrichAsset(ip)
      enrichment.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Varlik zenginlestirme basarisiz oldu'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    checkResult,
    status,
    enrichment,
    loading,
    error,
    checkIP,
    fetchStatus,
    enrichAsset,
  }
}

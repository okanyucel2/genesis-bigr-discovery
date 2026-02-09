import { ref } from 'vue'
import { bigrApi } from '@/lib/api'
import type { CertificatesResponse } from '@/types/api'

export function useCertificates() {
  const data = ref<CertificatesResponse | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchCertificates() {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getCertificates()
      data.value = res.data
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to load certificate data'
      error.value = message
    } finally {
      loading.value = false
    }
  }

  return {
    data,
    loading,
    error,
    fetchCertificates,
  }
}

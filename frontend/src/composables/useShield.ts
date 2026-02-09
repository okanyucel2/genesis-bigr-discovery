import { ref, onUnmounted } from 'vue'
import { bigrApi } from '@/lib/api'
import type {
  ShieldScan,
  ShieldFinding,
  ScanDepth,
  ShieldScanResponse,
  ShieldFindingsResponse,
} from '@/types/shield'
import { useShieldStore } from '@/stores/shield'

export function useShield() {
  const currentScan = ref<ShieldScan | null>(null)
  const findings = ref<ShieldFinding[]>([])
  const loading = ref(false)
  const scanning = ref(false)
  const error = ref<string | null>(null)

  let pollTimer: ReturnType<typeof setInterval> | null = null
  const store = useShieldStore()

  function stopPolling() {
    if (pollTimer !== null) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  async function startScan(target: string, depth: ScanDepth, modules?: string[]) {
    loading.value = true
    scanning.value = true
    error.value = null
    try {
      const res = await bigrApi.startShieldScan(target, depth, modules)
      const scan = (res.data as ShieldScanResponse).scan
      currentScan.value = scan
      store.addScan(scan)
      pollScan(scan.id)
      return scan
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to start scan'
      error.value = message
      scanning.value = false
      return null
    } finally {
      loading.value = false
    }
  }

  async function fetchScan(scanId: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getShieldScan(scanId)
      const scan = (res.data as ShieldScanResponse).scan
      currentScan.value = scan
      store.updateScan(scan)
      return scan
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to fetch scan'
      error.value = message
      return null
    } finally {
      loading.value = false
    }
  }

  async function fetchFindings(scanId: string) {
    loading.value = true
    error.value = null
    try {
      const res = await bigrApi.getShieldFindings(scanId)
      const data = res.data as ShieldFindingsResponse
      findings.value = data.findings
      return data.findings
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Failed to fetch findings'
      error.value = message
      return []
    } finally {
      loading.value = false
    }
  }

  function pollScan(scanId: string) {
    stopPolling()
    pollTimer = setInterval(async () => {
      try {
        const res = await bigrApi.getShieldScan(scanId)
        const scan = (res.data as ShieldScanResponse).scan
        currentScan.value = scan
        store.updateScan(scan)

        if (scan.status === 'completed' || scan.status === 'failed') {
          stopPolling()
          scanning.value = false

          if (scan.status === 'completed') {
            // Auto-fetch findings when scan completes
            findings.value = scan.findings ?? []
            if (findings.value.length === 0) {
              await fetchFindings(scanId)
            }
          }
        }
      } catch {
        // Silently retry on poll errors
      }
    }, 2000)
  }

  onUnmounted(() => {
    stopPolling()
  })

  return {
    currentScan,
    findings,
    loading,
    scanning,
    error,
    startScan,
    fetchScan,
    fetchFindings,
    pollScan,
    stopPolling,
  }
}

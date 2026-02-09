import { ref, onMounted, onUnmounted } from 'vue'
import { bigrApi } from '@/lib/api'

export type HealthStatus = 'ok' | 'error' | 'loading'

const POLL_INTERVAL_MS = 30_000

export function useHealth() {
  const status = ref<HealthStatus>('loading')
  const dataFile = ref<string | null>(null)
  const dataExists = ref(false)
  let pollTimer: ReturnType<typeof setInterval> | null = null

  async function checkHealth() {
    try {
      const res = await bigrApi.getHealth()
      status.value = res.data.status === 'ok' ? 'ok' : 'error'
      dataFile.value = res.data.data_file
      dataExists.value = res.data.exists
    } catch {
      status.value = 'error'
      dataFile.value = null
      dataExists.value = false
    }
  }

  function startPolling() {
    stopPolling()
    pollTimer = setInterval(checkHealth, POLL_INTERVAL_MS)
  }

  function stopPolling() {
    if (pollTimer !== null) {
      clearInterval(pollTimer)
      pollTimer = null
    }
  }

  onMounted(() => {
    checkHealth()
    startPolling()
  })

  onUnmounted(() => {
    stopPolling()
  })

  return {
    status,
    dataFile,
    dataExists,
    checkHealth,
  }
}

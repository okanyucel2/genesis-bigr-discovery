import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getWatcherStatus: vi.fn(),
    getWatcherHistory: vi.fn(),
    getWatcherAlerts: vi.fn(),
    triggerWatcherScan: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'
import { useWatcher } from '@/composables/useWatcher'

function mockAxios<T>(data: T) {
  return Promise.resolve({ data, status: 200, statusText: 'OK', headers: {}, config: { headers: {} } } as any)
}

describe('useWatcher', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { status, history, alerts, loading, error, isRunning } = useWatcher()
    expect(status.value).toBeNull()
    expect(history.value).toEqual([])
    expect(alerts.value).toEqual([])
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
    expect(isRunning.value).toBe(false)
  })

  it('fetchStatus populates status', async () => {
    const mockStatus = {
      is_running: true,
      pid: 1234,
      uptime_seconds: 600,
      targets: [{ subnet: '10.0.0.0/24', interval_seconds: 300 }],
      last_scan_at: '2026-01-01T00:00:00Z',
      scan_count: 10,
    }
    vi.mocked(bigrApi.getWatcherStatus).mockReturnValue(mockAxios(mockStatus))

    const { status, isRunning, fetchStatus } = useWatcher()
    await fetchStatus()

    expect(status.value).toEqual(mockStatus)
    expect(isRunning.value).toBe(true)
  })

  it('fetchHistory populates history', async () => {
    const scans = [
      { subnet: '10.0.0.0/24', started_at: '', completed_at: '', asset_count: 5, changes_count: 1, status: 'completed' },
    ]
    vi.mocked(bigrApi.getWatcherHistory).mockReturnValue(mockAxios({ scans, total: 1 }))

    const { history, fetchHistory } = useWatcher()
    await fetchHistory()

    expect(history.value).toEqual(scans)
  })

  it('fetchAlerts populates alerts', async () => {
    const alertList = [
      { alert_type: 'NEW_DEVICE', severity: 'warning', ip: '10.0.0.5', message: 'New device', timestamp: '' },
    ]
    vi.mocked(bigrApi.getWatcherAlerts).mockReturnValue(mockAxios({ alerts: alertList, total: 1 }))

    const { alerts, totalAlerts, fetchAlerts } = useWatcher()
    await fetchAlerts()

    expect(alerts.value).toEqual(alertList)
    expect(totalAlerts.value).toBe(1)
  })

  it('criticalAlerts filters by severity', async () => {
    const alertList = [
      { alert_type: 'ROGUE_DEVICE', severity: 'critical', ip: '10.0.0.5', message: 'Rogue', timestamp: '' },
      { alert_type: 'PORT_CHANGE', severity: 'warning', ip: '10.0.0.6', message: 'Port', timestamp: '' },
    ]
    vi.mocked(bigrApi.getWatcherAlerts).mockReturnValue(mockAxios({ alerts: alertList, total: 2 }))

    const { criticalAlerts, fetchAlerts } = useWatcher()
    await fetchAlerts()

    expect(criticalAlerts.value).toHaveLength(1)
    expect(criticalAlerts.value[0]!.ip).toBe('10.0.0.5')
  })

  it('triggerScan calls API and refreshes', async () => {
    vi.mocked(bigrApi.triggerWatcherScan).mockReturnValue(mockAxios({ status: 'triggered', subnet: '10.0.0.0/24' }))
    vi.mocked(bigrApi.getWatcherStatus).mockReturnValue(mockAxios({
      is_running: true, pid: 1, uptime_seconds: 0, targets: [], last_scan_at: null, scan_count: 1,
    }))
    vi.mocked(bigrApi.getWatcherHistory).mockReturnValue(mockAxios({ scans: [], total: 0 }))

    const { triggerScan } = useWatcher()
    await triggerScan('10.0.0.0/24')

    expect(bigrApi.triggerWatcherScan).toHaveBeenCalledWith('10.0.0.0/24')
    expect(bigrApi.getWatcherStatus).toHaveBeenCalled()
    expect(bigrApi.getWatcherHistory).toHaveBeenCalled()
  })

  it('refreshAll fetches all data', async () => {
    vi.mocked(bigrApi.getWatcherStatus).mockReturnValue(mockAxios({
      is_running: false, pid: null, uptime_seconds: 0, targets: [], last_scan_at: null, scan_count: 0,
    }))
    vi.mocked(bigrApi.getWatcherHistory).mockReturnValue(mockAxios({ scans: [], total: 0 }))
    vi.mocked(bigrApi.getWatcherAlerts).mockReturnValue(mockAxios({ alerts: [], total: 0 }))

    const { refreshAll } = useWatcher()
    await refreshAll()

    expect(bigrApi.getWatcherStatus).toHaveBeenCalled()
    expect(bigrApi.getWatcherHistory).toHaveBeenCalled()
    expect(bigrApi.getWatcherAlerts).toHaveBeenCalled()
  })

  it('handles fetchStatus error silently', async () => {
    vi.mocked(bigrApi.getWatcherStatus).mockRejectedValue(new Error('Network error'))

    const { status, fetchStatus } = useWatcher()
    await fetchStatus()

    expect(status.value).toBeNull()
  })
})

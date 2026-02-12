import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import WatcherView from '@/views/WatcherView.vue'

vi.mock('@/composables/useWatcher', () => ({
  useWatcher: vi.fn(() => ({
    status: { value: null },
    history: { value: [] },
    alerts: { value: [] },
    loading: { value: false },
    error: { value: null },
    isRunning: { value: false },
    totalAlerts: { value: 0 },
    criticalAlerts: { value: [] },
    fetchStatus: vi.fn(),
    fetchHistory: vi.fn(),
    fetchAlerts: vi.fn(),
    triggerScan: vi.fn(),
    refreshAll: vi.fn(),
  })),
}))

import { useWatcher } from '@/composables/useWatcher'
import { ref, computed } from 'vue'

describe('WatcherView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows loading state when loading with no status', () => {
    vi.mocked(useWatcher).mockReturnValue({
      status: ref(null),
      history: ref([]),
      alerts: ref([]),
      loading: ref(true),
      error: ref(null),
      isRunning: computed(() => false),
      totalAlerts: computed(() => 0),
      criticalAlerts: computed(() => []),
      fetchStatus: vi.fn(),
      fetchHistory: vi.fn(),
      fetchAlerts: vi.fn(),
      triggerScan: vi.fn(),
      refreshAll: vi.fn(),
    })

    const wrapper = mount(WatcherView)
    expect(wrapper.text()).toContain('Izleme durumu yukleniyor')
  })

  it('shows active status banner when watcher is running', () => {
    vi.mocked(useWatcher).mockReturnValue({
      status: ref({
        is_running: true,
        pid: 42567,
        uptime_seconds: 7245,
        targets: [{ subnet: '192.168.1.0/24', interval_seconds: 300 }],
        last_scan_at: '2026-01-01T00:00:00Z',
        scan_count: 47,
      }),
      history: ref([]),
      alerts: ref([]),
      loading: ref(false),
      error: ref(null),
      isRunning: computed(() => true),
      totalAlerts: computed(() => 0),
      criticalAlerts: computed(() => []),
      fetchStatus: vi.fn(),
      fetchHistory: vi.fn(),
      fetchAlerts: vi.fn(),
      triggerScan: vi.fn(),
      refreshAll: vi.fn(),
    })

    const wrapper = mount(WatcherView)
    expect(wrapper.text()).toContain('Izleme Aktif')
    expect(wrapper.text()).toContain('42567')
    expect(wrapper.text()).toContain('47')
  })

  it('shows inactive status banner when watcher is stopped', () => {
    vi.mocked(useWatcher).mockReturnValue({
      status: ref({
        is_running: false,
        pid: null,
        uptime_seconds: 0,
        targets: [],
        last_scan_at: null,
        scan_count: 0,
      }),
      history: ref([]),
      alerts: ref([]),
      loading: ref(false),
      error: ref(null),
      isRunning: computed(() => false),
      totalAlerts: computed(() => 0),
      criticalAlerts: computed(() => []),
      fetchStatus: vi.fn(),
      fetchHistory: vi.fn(),
      fetchAlerts: vi.fn(),
      triggerScan: vi.fn(),
      refreshAll: vi.fn(),
    })

    const wrapper = mount(WatcherView)
    expect(wrapper.text()).toContain('Izleme Durdurulmus')
  })

  it('renders stats cards with correct values', () => {
    vi.mocked(useWatcher).mockReturnValue({
      status: ref({
        is_running: true,
        pid: 100,
        uptime_seconds: 3661,
        targets: [],
        last_scan_at: '2026-02-01T12:00:00Z',
        scan_count: 23,
      }),
      history: ref([]),
      alerts: ref([{ alert_type: 'NEW_DEVICE', severity: 'warning', ip: '1.2.3.4', message: 'x', timestamp: '' }]),
      loading: ref(false),
      error: ref(null),
      isRunning: computed(() => true),
      totalAlerts: computed(() => 1),
      criticalAlerts: computed(() => []),
      fetchStatus: vi.fn(),
      fetchHistory: vi.fn(),
      fetchAlerts: vi.fn(),
      triggerScan: vi.fn(),
      refreshAll: vi.fn(),
    })

    const wrapper = mount(WatcherView)
    expect(wrapper.text()).toContain('1sa 1dk')
    expect(wrapper.text()).toContain('23')
  })

  it('calls refreshAll on mount', () => {
    const refreshAllFn = vi.fn()
    vi.mocked(useWatcher).mockReturnValue({
      status: ref(null),
      history: ref([]),
      alerts: ref([]),
      loading: ref(false),
      error: ref(null),
      isRunning: computed(() => false),
      totalAlerts: computed(() => 0),
      criticalAlerts: computed(() => []),
      fetchStatus: vi.fn(),
      fetchHistory: vi.fn(),
      fetchAlerts: vi.fn(),
      triggerScan: vi.fn(),
      refreshAll: refreshAllFn,
    })

    mount(WatcherView)
    expect(refreshAllFn).toHaveBeenCalled()
  })
})

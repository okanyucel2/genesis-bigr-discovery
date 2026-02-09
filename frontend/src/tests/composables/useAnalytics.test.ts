import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useAnalytics } from '@/composables/useAnalytics'
import type { AnalyticsResponse } from '@/types/api'

const mockAnalyticsResponse: AnalyticsResponse = {
  asset_count_trend: {
    name: 'Total Assets',
    points: [
      { date: '2026-01-10', value: 40, label: null },
      { date: '2026-01-17', value: 42, label: null },
      { date: '2026-01-24', value: 45, label: null },
    ],
  },
  category_trends: [
    {
      name: 'Network & Systems',
      points: [
        { date: '2026-01-10', value: 15, label: null },
        { date: '2026-01-17', value: 16, label: null },
      ],
    },
    {
      name: 'IoT',
      points: [
        { date: '2026-01-10', value: 8, label: null },
        { date: '2026-01-17', value: 9, label: null },
      ],
    },
  ],
  new_vs_removed: {
    name: 'New vs Removed',
    points: [
      { date: '2026-01-10', value: 3, label: 'new' },
      { date: '2026-01-17', value: -1, label: 'removed' },
    ],
  },
  most_changed_assets: [
    { ip: '192.168.1.50', change_count: 12, last_change: '2026-02-09T10:00:00Z' },
    { ip: '192.168.1.10', change_count: 5, last_change: '2026-02-08T14:30:00Z' },
  ],
  scan_frequency: [
    { date: '2026-02-07', scan_count: 3, total_assets: 45 },
    { date: '2026-02-08', scan_count: 2, total_assets: 46 },
    { date: '2026-02-09', scan_count: 4, total_assets: 48 },
  ],
}

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getAnalytics: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockedGetAnalytics = vi.mocked(bigrApi.getAnalytics)

describe('useAnalytics', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { data, loading, error } = useAnalytics()

    expect(data.value).toBeNull()
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
  })

  it('sets loading state correctly during fetch', async () => {
    let resolvePromise: (value: unknown) => void
    const pendingPromise = new Promise((resolve) => {
      resolvePromise = resolve
    })

    mockedGetAnalytics.mockReturnValue(pendingPromise as ReturnType<typeof bigrApi.getAnalytics>)

    const { loading, fetchAnalytics } = useAnalytics()
    expect(loading.value).toBe(false)

    const fetchPromise = fetchAnalytics()
    expect(loading.value).toBe(true)

    resolvePromise!({ data: mockAnalyticsResponse })
    await fetchPromise

    expect(loading.value).toBe(false)
  })

  it('populates data on successful fetch', async () => {
    mockedGetAnalytics.mockResolvedValue({
      data: mockAnalyticsResponse,
    } as Awaited<ReturnType<typeof bigrApi.getAnalytics>>)

    const { data, fetchAnalytics } = useAnalytics()

    await fetchAnalytics()

    expect(data.value).not.toBeNull()
    expect(data.value!.asset_count_trend).not.toBeNull()
    expect(data.value!.asset_count_trend!.points).toHaveLength(3)
    expect(data.value!.category_trends).toHaveLength(2)
    expect(data.value!.most_changed_assets).toHaveLength(2)
    expect(data.value!.most_changed_assets[0]!.ip).toBe('192.168.1.50')
    expect(data.value!.scan_frequency).toHaveLength(3)
  })

  it('passes days parameter to API call', async () => {
    mockedGetAnalytics.mockResolvedValue({
      data: mockAnalyticsResponse,
    } as Awaited<ReturnType<typeof bigrApi.getAnalytics>>)

    const { fetchAnalytics } = useAnalytics()

    await fetchAnalytics(7)

    expect(mockedGetAnalytics).toHaveBeenCalledWith(7)
  })

  it('uses default 30 days when no parameter provided', async () => {
    mockedGetAnalytics.mockResolvedValue({
      data: mockAnalyticsResponse,
    } as Awaited<ReturnType<typeof bigrApi.getAnalytics>>)

    const { fetchAnalytics } = useAnalytics()

    await fetchAnalytics()

    expect(mockedGetAnalytics).toHaveBeenCalledWith(30)
  })

  it('sets error on failed fetch', async () => {
    mockedGetAnalytics.mockRejectedValue(new Error('Network error'))

    const { error, loading, fetchAnalytics } = useAnalytics()

    await fetchAnalytics()

    expect(error.value).toBe('Network error')
    expect(loading.value).toBe(false)
  })

  it('clears error on new fetch attempt', async () => {
    mockedGetAnalytics.mockRejectedValueOnce(new Error('First error'))

    const { error, fetchAnalytics } = useAnalytics()

    await fetchAnalytics()
    expect(error.value).toBe('First error')

    mockedGetAnalytics.mockResolvedValueOnce({
      data: mockAnalyticsResponse,
    } as Awaited<ReturnType<typeof bigrApi.getAnalytics>>)

    await fetchAnalytics()
    expect(error.value).toBeNull()
  })

  it('handles non-Error exceptions gracefully', async () => {
    mockedGetAnalytics.mockRejectedValue('string error')

    const { error, fetchAnalytics } = useAnalytics()

    await fetchAnalytics()

    expect(error.value).toBe('Failed to load analytics data')
  })
})

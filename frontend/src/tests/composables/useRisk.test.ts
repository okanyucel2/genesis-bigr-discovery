import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useRisk } from '@/composables/useRisk'
import type { RiskResponse, RiskProfile } from '@/types/api'

const mockRiskProfile: RiskProfile = {
  ip: '192.168.1.1',
  mac: 'AA:BB:CC:DD:EE:01',
  hostname: 'gateway',
  vendor: 'Cisco',
  bigr_category: 'ag_ve_sistemler',
  risk_score: 85,
  risk_level: 'critical',
  factors: {
    cve_score: 0.9,
    exposure_score: 0.8,
    classification_score: 0.5,
    age_score: 0.3,
    change_score: 0.6,
  },
  top_cve: 'CVE-2024-1234',
}

const mockRiskResponse: RiskResponse = {
  profiles: [mockRiskProfile],
  average_risk: 65.2,
  max_risk: 85,
  critical_count: 1,
  high_count: 2,
  medium_count: 5,
  low_count: 10,
  top_risks: [mockRiskProfile],
}

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getRisk: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockedGetRisk = vi.mocked(bigrApi.getRisk)

describe('useRisk', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { data, loading, error } = useRisk()

    expect(data.value).toBeNull()
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
  })

  it('sets loading state correctly during fetch', async () => {
    let resolvePromise: (value: unknown) => void
    const pendingPromise = new Promise((resolve) => {
      resolvePromise = resolve
    })

    mockedGetRisk.mockReturnValue(pendingPromise as ReturnType<typeof bigrApi.getRisk>)

    const { loading, fetchRisk } = useRisk()
    expect(loading.value).toBe(false)

    const fetchPromise = fetchRisk()
    expect(loading.value).toBe(true)

    resolvePromise!({ data: mockRiskResponse })
    await fetchPromise

    expect(loading.value).toBe(false)
  })

  it('populates data on successful fetch', async () => {
    mockedGetRisk.mockResolvedValue({
      data: mockRiskResponse,
    } as Awaited<ReturnType<typeof bigrApi.getRisk>>)

    const { data, fetchRisk } = useRisk()

    await fetchRisk()

    expect(data.value).not.toBeNull()
    expect(data.value!.profiles).toHaveLength(1)
    expect(data.value!.profiles[0]!.ip).toBe('192.168.1.1')
    expect(data.value!.average_risk).toBe(65.2)
    expect(data.value!.critical_count).toBe(1)
    expect(data.value!.high_count).toBe(2)
    expect(data.value!.medium_count).toBe(5)
    expect(data.value!.low_count).toBe(10)
  })

  it('sets error on failed fetch', async () => {
    mockedGetRisk.mockRejectedValue(new Error('Network error'))

    const { error, loading, fetchRisk } = useRisk()

    await fetchRisk()

    expect(error.value).toBe('Network error')
    expect(loading.value).toBe(false)
  })

  it('uses fallback error message for non-Error objects', async () => {
    mockedGetRisk.mockRejectedValue('unknown failure')

    const { error, fetchRisk } = useRisk()

    await fetchRisk()

    expect(error.value).toBe('Failed to load risk data')
  })

  it('clears error on new fetch attempt', async () => {
    mockedGetRisk.mockRejectedValueOnce(new Error('First error'))

    const { error, fetchRisk } = useRisk()

    await fetchRisk()
    expect(error.value).toBe('First error')

    mockedGetRisk.mockResolvedValueOnce({
      data: mockRiskResponse,
    } as Awaited<ReturnType<typeof bigrApi.getRisk>>)

    await fetchRisk()
    expect(error.value).toBeNull()
  })
})

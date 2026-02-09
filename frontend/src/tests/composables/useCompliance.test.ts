import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useCompliance } from '@/composables/useCompliance'
import type { ComplianceResponse } from '@/types/api'

const mockComplianceResponse: ComplianceResponse = {
  breakdown: {
    compliance_score: 78,
    grade: 'B',
    total_assets: 50,
    fully_classified: 30,
    partially_classified: 12,
    unclassified: 5,
    manual_overrides: 3,
  },
  distribution: {
    ag_ve_sistemler: 15,
    uygulamalar: 10,
    iot: 8,
    tasinabilir: 7,
    unclassified: 5,
    total: 45,
  },
  subnet_compliance: [
    { cidr: '192.168.1.0/24', label: 'Office LAN', score: 85, grade: 'A' },
    { cidr: '10.0.0.0/24', label: 'Server VLAN', score: 92, grade: 'A' },
  ],
  action_items: [
    { priority: 'critical', type: 'unclassified', ip: '192.168.1.100', reason: 'No classification' },
    { priority: 'high', type: 'low_confidence', ip: '192.168.1.50', reason: 'Low confidence score' },
  ],
}

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getCompliance: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockedGetCompliance = vi.mocked(bigrApi.getCompliance)

describe('useCompliance', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { data, loading, error } = useCompliance()

    expect(data.value).toBeNull()
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
  })

  it('sets loading state correctly during fetch', async () => {
    let resolvePromise: (value: unknown) => void
    const pendingPromise = new Promise((resolve) => {
      resolvePromise = resolve
    })

    mockedGetCompliance.mockReturnValue(pendingPromise as ReturnType<typeof bigrApi.getCompliance>)

    const { loading, fetchCompliance } = useCompliance()
    expect(loading.value).toBe(false)

    const fetchPromise = fetchCompliance()
    expect(loading.value).toBe(true)

    resolvePromise!({ data: mockComplianceResponse })
    await fetchPromise

    expect(loading.value).toBe(false)
  })

  it('populates data on successful fetch', async () => {
    mockedGetCompliance.mockResolvedValue({
      data: mockComplianceResponse,
    } as Awaited<ReturnType<typeof bigrApi.getCompliance>>)

    const { data, fetchCompliance } = useCompliance()

    await fetchCompliance()

    expect(data.value).not.toBeNull()
    expect(data.value!.breakdown.compliance_score).toBe(78)
    expect(data.value!.breakdown.grade).toBe('B')
    expect(data.value!.subnet_compliance).toHaveLength(2)
    expect(data.value!.subnet_compliance[0]!.cidr).toBe('192.168.1.0/24')
    expect(data.value!.action_items).toHaveLength(2)
    expect(data.value!.action_items[0]!.priority).toBe('critical')
  })

  it('sets error on failed fetch', async () => {
    mockedGetCompliance.mockRejectedValue(new Error('Network error'))

    const { error, loading, fetchCompliance } = useCompliance()

    await fetchCompliance()

    expect(error.value).toBe('Network error')
    expect(loading.value).toBe(false)
  })

  it('clears error on new fetch attempt', async () => {
    mockedGetCompliance.mockRejectedValueOnce(new Error('First error'))

    const { error, fetchCompliance } = useCompliance()

    await fetchCompliance()
    expect(error.value).toBe('First error')

    mockedGetCompliance.mockResolvedValueOnce({
      data: mockComplianceResponse,
    } as Awaited<ReturnType<typeof bigrApi.getCompliance>>)

    await fetchCompliance()
    expect(error.value).toBeNull()
  })

  it('handles non-Error exceptions gracefully', async () => {
    mockedGetCompliance.mockRejectedValue('string error')

    const { error, fetchCompliance } = useCompliance()

    await fetchCompliance()

    expect(error.value).toBe('Failed to load compliance data')
  })
})

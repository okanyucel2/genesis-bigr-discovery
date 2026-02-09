import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useVulnerabilities } from '@/composables/useVulnerabilities'
import type { VulnerabilitiesResponse, AssetVulnSummary, CveEntry, VulnMatch } from '@/types/api'

const mockCve: CveEntry = {
  cve_id: 'CVE-2024-5678',
  cvss_score: 9.8,
  severity: 'critical',
  description: 'Remote code execution vulnerability',
  affected_vendor: 'ExampleVendor',
  affected_product: 'ExampleProduct',
  cpe: 'cpe:2.3:a:example:product:1.0',
  published: '2024-03-15T00:00:00Z',
  fix_available: true,
  cisa_kev: true,
}

const mockMatch: VulnMatch = {
  asset_ip: '192.168.1.10',
  asset_mac: 'AA:BB:CC:DD:EE:02',
  asset_vendor: 'Dell',
  cve: mockCve,
  match_type: 'vendor',
  match_confidence: 0.85,
}

const mockSummary: AssetVulnSummary = {
  ip: '192.168.1.10',
  total_vulns: 3,
  critical_count: 1,
  high_count: 1,
  medium_count: 1,
  low_count: 0,
  max_cvss: 9.8,
  matches: [mockMatch],
}

const mockVulnResponse: VulnerabilitiesResponse = {
  summaries: [mockSummary],
}

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getVulnerabilities: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockedGetVulnerabilities = vi.mocked(bigrApi.getVulnerabilities)

describe('useVulnerabilities', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { data, loading, error } = useVulnerabilities()

    expect(data.value).toBeNull()
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
  })

  it('sets loading state correctly during fetch', async () => {
    let resolvePromise: (value: unknown) => void
    const pendingPromise = new Promise((resolve) => {
      resolvePromise = resolve
    })

    mockedGetVulnerabilities.mockReturnValue(
      pendingPromise as ReturnType<typeof bigrApi.getVulnerabilities>,
    )

    const { loading, fetchVulnerabilities } = useVulnerabilities()
    expect(loading.value).toBe(false)

    const fetchPromise = fetchVulnerabilities()
    expect(loading.value).toBe(true)

    resolvePromise!({ data: mockVulnResponse })
    await fetchPromise

    expect(loading.value).toBe(false)
  })

  it('populates data on successful fetch', async () => {
    mockedGetVulnerabilities.mockResolvedValue({
      data: mockVulnResponse,
    } as Awaited<ReturnType<typeof bigrApi.getVulnerabilities>>)

    const { data, fetchVulnerabilities } = useVulnerabilities()

    await fetchVulnerabilities()

    expect(data.value).not.toBeNull()
    expect(data.value!.summaries).toHaveLength(1)
    expect(data.value!.summaries[0]!.ip).toBe('192.168.1.10')
    expect(data.value!.summaries[0]!.total_vulns).toBe(3)
    expect(data.value!.summaries[0]!.max_cvss).toBe(9.8)
    expect(data.value!.summaries[0]!.matches[0]!.cve.cve_id).toBe('CVE-2024-5678')
  })

  it('sets error on failed fetch', async () => {
    mockedGetVulnerabilities.mockRejectedValue(new Error('Network error'))

    const { error, loading, fetchVulnerabilities } = useVulnerabilities()

    await fetchVulnerabilities()

    expect(error.value).toBe('Network error')
    expect(loading.value).toBe(false)
  })

  it('uses fallback error message for non-Error objects', async () => {
    mockedGetVulnerabilities.mockRejectedValue('unknown failure')

    const { error, fetchVulnerabilities } = useVulnerabilities()

    await fetchVulnerabilities()

    expect(error.value).toBe('Failed to load vulnerability data')
  })

  it('clears error on new fetch attempt', async () => {
    mockedGetVulnerabilities.mockRejectedValueOnce(new Error('First error'))

    const { error, fetchVulnerabilities } = useVulnerabilities()

    await fetchVulnerabilities()
    expect(error.value).toBe('First error')

    mockedGetVulnerabilities.mockResolvedValueOnce({
      data: mockVulnResponse,
    } as Awaited<ReturnType<typeof bigrApi.getVulnerabilities>>)

    await fetchVulnerabilities()
    expect(error.value).toBeNull()
  })
})

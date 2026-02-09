import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useAssets } from '@/composables/useAssets'
import type { Asset, AssetsResponse } from '@/types/api'

const mockAssetsResponse: AssetsResponse = {
  assets: [
    {
      ip: '192.168.1.1',
      mac: 'AA:BB:CC:DD:EE:01',
      hostname: 'gateway',
      vendor: 'Cisco',
      open_ports: [22, 80, 443],
      os_hint: 'IOS',
      bigr_category: 'ag_ve_sistemler',
      bigr_category_tr: 'Ağ ve Sistemler',
      confidence_score: 0.95,
      confidence_level: 'high',
      scan_method: 'nmap',
      first_seen: '2026-01-01T00:00:00Z',
      last_seen: '2026-02-09T00:00:00Z',
      manual_override: false,
    },
    {
      ip: '192.168.1.10',
      mac: 'AA:BB:CC:DD:EE:02',
      hostname: 'web-server',
      vendor: 'Dell',
      open_ports: [80, 443, 8080],
      os_hint: 'Linux',
      bigr_category: 'uygulamalar',
      bigr_category_tr: 'Uygulamalar',
      confidence_score: 0.88,
      confidence_level: 'high',
      scan_method: 'nmap',
      first_seen: '2026-01-15T00:00:00Z',
      last_seen: '2026-02-09T00:00:00Z',
      manual_override: false,
    },
    {
      ip: '192.168.1.50',
      mac: 'AA:BB:CC:DD:EE:03',
      hostname: 'camera-01',
      vendor: 'Hikvision',
      open_ports: [80, 554],
      os_hint: null,
      bigr_category: 'iot',
      bigr_category_tr: 'IoT Cihazlar',
      confidence_score: 0.72,
      confidence_level: 'medium',
      scan_method: 'nmap',
      first_seen: '2026-02-01T00:00:00Z',
      last_seen: '2026-02-09T00:00:00Z',
      manual_override: false,
    },
    {
      ip: '192.168.1.100',
      mac: 'AA:BB:CC:DD:EE:04',
      hostname: null,
      vendor: null,
      open_ports: [],
      os_hint: null,
      bigr_category: 'unclassified',
      bigr_category_tr: 'Sınıflandırılmamış',
      confidence_score: 0.1,
      confidence_level: 'low',
      scan_method: 'nmap',
      first_seen: '2026-02-08T00:00:00Z',
      last_seen: '2026-02-09T00:00:00Z',
      manual_override: false,
    },
  ] satisfies Asset[],
  category_summary: {
    ag_ve_sistemler: 1,
    uygulamalar: 1,
    iot: 1,
    tasinabilir: 0,
    unclassified: 1,
  },
  total_assets: 4,
  target: '192.168.1.0/24',
  scan_method: 'nmap',
  duration_seconds: 12.5,
}

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getAssets: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockedGetAssets = vi.mocked(bigrApi.getAssets)

describe('useAssets', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { assets, categorySummary, totalAssets, loading, error } = useAssets()

    expect(assets.value).toEqual([])
    expect(categorySummary.value).toEqual({})
    expect(totalAssets.value).toBe(0)
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
  })

  it('sets loading state correctly during fetch', async () => {
    let resolvePromise: (value: unknown) => void
    const pendingPromise = new Promise((resolve) => {
      resolvePromise = resolve
    })

    mockedGetAssets.mockReturnValue(pendingPromise as ReturnType<typeof bigrApi.getAssets>)

    const { loading, fetchAssets } = useAssets()
    expect(loading.value).toBe(false)

    const fetchPromise = fetchAssets()
    expect(loading.value).toBe(true)

    resolvePromise!({ data: mockAssetsResponse })
    await fetchPromise

    expect(loading.value).toBe(false)
  })

  it('populates assets and categorySummary on successful fetch', async () => {
    mockedGetAssets.mockResolvedValue({
      data: mockAssetsResponse,
    } as Awaited<ReturnType<typeof bigrApi.getAssets>>)

    const { assets, categorySummary, totalAssets, fetchAssets } = useAssets()

    await fetchAssets()

    expect(assets.value).toHaveLength(4)
    expect(assets.value[0]!.ip).toBe('192.168.1.1')
    expect(categorySummary.value).toEqual(mockAssetsResponse.category_summary)
    expect(totalAssets.value).toBe(4)
  })

  it('passes subnet parameter to API call', async () => {
    mockedGetAssets.mockResolvedValue({
      data: mockAssetsResponse,
    } as Awaited<ReturnType<typeof bigrApi.getAssets>>)

    const { fetchAssets } = useAssets()

    await fetchAssets('10.0.0.0/24')

    expect(mockedGetAssets).toHaveBeenCalledWith('10.0.0.0/24')
  })

  it('sets error on failed fetch', async () => {
    mockedGetAssets.mockRejectedValue(new Error('Network error'))

    const { error, loading, fetchAssets } = useAssets()

    await fetchAssets()

    expect(error.value).toBe('Network error')
    expect(loading.value).toBe(false)
  })

  it('clears error on new fetch attempt', async () => {
    mockedGetAssets.mockRejectedValueOnce(new Error('First error'))

    const { error, fetchAssets } = useAssets()

    await fetchAssets()
    expect(error.value).toBe('First error')

    mockedGetAssets.mockResolvedValueOnce({
      data: mockAssetsResponse,
    } as Awaited<ReturnType<typeof bigrApi.getAssets>>)

    await fetchAssets()
    expect(error.value).toBeNull()
  })

  it('groups assets by category correctly', async () => {
    mockedGetAssets.mockResolvedValue({
      data: mockAssetsResponse,
    } as Awaited<ReturnType<typeof bigrApi.getAssets>>)

    const { assetsByCategory, fetchAssets } = useAssets()

    await fetchAssets()

    expect(assetsByCategory.value.ag_ve_sistemler).toHaveLength(1)
    expect(assetsByCategory.value.ag_ve_sistemler[0]!.ip).toBe('192.168.1.1')
    expect(assetsByCategory.value.uygulamalar).toHaveLength(1)
    expect(assetsByCategory.value.uygulamalar[0]!.ip).toBe('192.168.1.10')
    expect(assetsByCategory.value.iot).toHaveLength(1)
    expect(assetsByCategory.value.iot[0]!.ip).toBe('192.168.1.50')
    expect(assetsByCategory.value.tasinabilir).toHaveLength(0)
    expect(assetsByCategory.value.unclassified).toHaveLength(1)
    expect(assetsByCategory.value.unclassified[0]!.ip).toBe('192.168.1.100')
  })

  it('puts assets with unknown categories into unclassified', async () => {
    const responseWithUnknown: AssetsResponse = {
      ...mockAssetsResponse,
      assets: [
        {
          ...mockAssetsResponse.assets[0]!,
          bigr_category: 'unknown_category' as 'unclassified',
        },
      ],
    }

    mockedGetAssets.mockResolvedValue({
      data: responseWithUnknown,
    } as Awaited<ReturnType<typeof bigrApi.getAssets>>)

    const { assetsByCategory, fetchAssets } = useAssets()

    await fetchAssets()

    expect(assetsByCategory.value.unclassified).toHaveLength(1)
    expect(assetsByCategory.value.ag_ve_sistemler).toHaveLength(0)
  })
})

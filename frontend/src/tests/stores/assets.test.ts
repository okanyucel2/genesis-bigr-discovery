import { describe, it, expect, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAssetsStore } from '@/stores/assets'
import type { Asset, AssetsResponse } from '@/types/api'

const mockAssets: Asset[] = [
  {
    ip: '192.168.1.1',
    mac: 'AA:BB:CC:DD:EE:01',
    hostname: 'core-switch',
    vendor: 'Cisco',
    open_ports: [22, 80],
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
    ip: '192.168.1.2',
    mac: 'AA:BB:CC:DD:EE:02',
    hostname: 'firewall-01',
    vendor: 'Fortinet',
    open_ports: [443],
    os_hint: 'FortiOS',
    bigr_category: 'ag_ve_sistemler',
    bigr_category_tr: 'Ağ ve Sistemler',
    confidence_score: 0.90,
    confidence_level: 'high',
    scan_method: 'nmap',
    first_seen: '2026-01-02T00:00:00Z',
    last_seen: '2026-02-09T00:00:00Z',
    manual_override: false,
  },
  {
    ip: '192.168.1.10',
    mac: 'AA:BB:CC:DD:EE:03',
    hostname: 'app-server',
    vendor: 'Dell',
    open_ports: [80, 443, 8080],
    os_hint: 'Linux',
    bigr_category: 'uygulamalar',
    bigr_category_tr: 'Uygulamalar',
    confidence_score: 0.85,
    confidence_level: 'high',
    scan_method: 'nmap',
    first_seen: '2026-01-10T00:00:00Z',
    last_seen: '2026-02-09T00:00:00Z',
    manual_override: false,
  },
  {
    ip: '192.168.1.50',
    mac: 'AA:BB:CC:DD:EE:04',
    hostname: 'printer-floor2',
    vendor: 'HP',
    open_ports: [9100, 631],
    os_hint: null,
    bigr_category: 'iot',
    bigr_category_tr: 'IoT Cihazlar',
    confidence_score: 0.70,
    confidence_level: 'medium',
    scan_method: 'nmap',
    first_seen: '2026-02-01T00:00:00Z',
    last_seen: '2026-02-09T00:00:00Z',
    manual_override: false,
  },
  {
    ip: '192.168.1.200',
    mac: 'AA:BB:CC:DD:EE:05',
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
]

const mockAssetsResponse: AssetsResponse = {
  assets: mockAssets,
  category_summary: {
    ag_ve_sistemler: 2,
    uygulamalar: 1,
    iot: 1,
    tasinabilir: 0,
    unclassified: 1,
  },
  total_assets: 5,
  target: '192.168.1.0/24',
  scan_method: 'nmap',
  duration_seconds: 15.2,
}

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getAssets: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockedGetAssets = vi.mocked(bigrApi.getAssets)

describe('useAssetsStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('initializes with default state', () => {
    const store = useAssetsStore()

    expect(store.assets).toEqual([])
    expect(store.categorySummary).toEqual({})
    expect(store.loading).toBe(false)
    expect(store.error).toBeNull()
    expect(store.selectedSubnet).toBeNull()
    expect(store.searchQuery).toBe('')
    expect(store.selectedCategory).toBeNull()
    expect(store.totalAssets).toBe(0)
  })

  describe('fetchAssets', () => {
    it('populates store with fetched data', async () => {
      mockedGetAssets.mockResolvedValue({
        data: mockAssetsResponse,
      } as Awaited<ReturnType<typeof bigrApi.getAssets>>)

      const store = useAssetsStore()
      await store.fetchAssets()

      expect(store.assets).toHaveLength(5)
      expect(store.categorySummary).toEqual(mockAssetsResponse.category_summary)
      expect(store.totalAssets).toBe(5)
      expect(store.loading).toBe(false)
      expect(store.error).toBeNull()
    })

    it('sets loading during fetch', async () => {
      let resolvePromise: (value: unknown) => void
      const pendingPromise = new Promise((resolve) => {
        resolvePromise = resolve
      })

      mockedGetAssets.mockReturnValue(pendingPromise as ReturnType<typeof bigrApi.getAssets>)

      const store = useAssetsStore()
      const fetchPromise = store.fetchAssets()

      expect(store.loading).toBe(true)

      resolvePromise!({ data: mockAssetsResponse })
      await fetchPromise

      expect(store.loading).toBe(false)
    })

    it('sets error on failure', async () => {
      mockedGetAssets.mockRejectedValue(new Error('Connection refused'))

      const store = useAssetsStore()
      await store.fetchAssets()

      expect(store.error).toBe('Connection refused')
      expect(store.loading).toBe(false)
    })

    it('passes subnet parameter', async () => {
      mockedGetAssets.mockResolvedValue({
        data: mockAssetsResponse,
      } as Awaited<ReturnType<typeof bigrApi.getAssets>>)

      const store = useAssetsStore()
      await store.fetchAssets('10.0.0.0/24')

      expect(mockedGetAssets).toHaveBeenCalledWith('10.0.0.0/24', undefined, undefined)
    })
  })

  describe('filteredAssets', () => {
    beforeEach(async () => {
      mockedGetAssets.mockResolvedValue({
        data: mockAssetsResponse,
      } as Awaited<ReturnType<typeof bigrApi.getAssets>>)
    })

    it('returns all assets when no filters active', async () => {
      const store = useAssetsStore()
      await store.fetchAssets()

      expect(store.filteredAssets).toHaveLength(5)
    })

    it('filters by category', async () => {
      const store = useAssetsStore()
      await store.fetchAssets()

      store.setCategory('ag_ve_sistemler')

      expect(store.filteredAssets).toHaveLength(2)
      expect(store.filteredAssets.every((a) => a.bigr_category === 'ag_ve_sistemler')).toBe(true)
    })

    it('filters by search query on IP', async () => {
      const store = useAssetsStore()
      await store.fetchAssets()

      store.setSearchQuery('192.168.1.1')

      // Matches 192.168.1.1, 192.168.1.10, 192.168.1.100 (but 100 is now 200)
      // Actually: 192.168.1.1 and 192.168.1.10 (IP contains "192.168.1.1")
      expect(store.filteredAssets).toHaveLength(2)
    })

    it('filters by search query on hostname', async () => {
      const store = useAssetsStore()
      await store.fetchAssets()

      store.setSearchQuery('switch')

      expect(store.filteredAssets).toHaveLength(1)
      expect(store.filteredAssets[0]!.hostname).toBe('core-switch')
    })

    it('filters by search query on vendor', async () => {
      const store = useAssetsStore()
      await store.fetchAssets()

      store.setSearchQuery('cisco')

      expect(store.filteredAssets).toHaveLength(1)
      expect(store.filteredAssets[0]!.vendor).toBe('Cisco')
    })

    it('filters by search query on mac', async () => {
      const store = useAssetsStore()
      await store.fetchAssets()

      store.setSearchQuery('ee:05')

      expect(store.filteredAssets).toHaveLength(1)
      expect(store.filteredAssets[0]!.ip).toBe('192.168.1.200')
    })

    it('applies category and search filters together', async () => {
      const store = useAssetsStore()
      await store.fetchAssets()

      store.setCategory('ag_ve_sistemler')
      store.setSearchQuery('cisco')

      expect(store.filteredAssets).toHaveLength(1)
      expect(store.filteredAssets[0]!.ip).toBe('192.168.1.1')
    })

    it('returns empty when combined filters match nothing', async () => {
      const store = useAssetsStore()
      await store.fetchAssets()

      store.setCategory('iot')
      store.setSearchQuery('cisco')

      expect(store.filteredAssets).toHaveLength(0)
    })
  })

  describe('actions', () => {
    it('setCategory updates selectedCategory', () => {
      const store = useAssetsStore()
      store.setCategory('iot')
      expect(store.selectedCategory).toBe('iot')
    })

    it('setCategory accepts null to clear filter', () => {
      const store = useAssetsStore()
      store.setCategory('iot')
      store.setCategory(null)
      expect(store.selectedCategory).toBeNull()
    })

    it('setSearchQuery updates searchQuery', () => {
      const store = useAssetsStore()
      store.setSearchQuery('test')
      expect(store.searchQuery).toBe('test')
    })

    it('setSubnet updates selectedSubnet', () => {
      const store = useAssetsStore()
      store.setSubnet('10.0.0.0/24')
      expect(store.selectedSubnet).toBe('10.0.0.0/24')
    })

    it('$reset clears all state', async () => {
      mockedGetAssets.mockResolvedValue({
        data: mockAssetsResponse,
      } as Awaited<ReturnType<typeof bigrApi.getAssets>>)

      const store = useAssetsStore()
      await store.fetchAssets()
      store.setCategory('iot')
      store.setSearchQuery('test')
      store.setSubnet('10.0.0.0/24')

      store.$reset()

      expect(store.assets).toEqual([])
      expect(store.categorySummary).toEqual({})
      expect(store.loading).toBe(false)
      expect(store.error).toBeNull()
      expect(store.selectedSubnet).toBeNull()
      expect(store.searchQuery).toBe('')
      expect(store.selectedCategory).toBeNull()
    })
  })
})

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useTopology } from '@/composables/useTopology'
import type { TopologyResponse } from '@/types/api'

const mockTopologyResponse: TopologyResponse = {
  nodes: [
    {
      id: 'gw-192.168.1.1',
      label: '192.168.1.1',
      ip: '192.168.1.1',
      mac: 'AA:BB:CC:DD:EE:01',
      hostname: 'gateway',
      vendor: 'Cisco',
      type: 'gateway',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.95,
      open_ports: [22, 80, 443],
      size: 24,
      color: '#06b6d4',
      subnet: '192.168.1.0/24',
      switch_port: null,
    },
    {
      id: 'sw-192.168.1.2',
      label: 'core-switch',
      ip: '192.168.1.2',
      mac: 'AA:BB:CC:DD:EE:02',
      hostname: 'core-switch',
      vendor: 'HP',
      type: 'switch',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.90,
      open_ports: [22, 161],
      size: 20,
      color: '#3b82f6',
      subnet: '192.168.1.0/24',
      switch_port: null,
    },
    {
      id: 'dev-192.168.1.50',
      label: 'camera-01',
      ip: '192.168.1.50',
      mac: 'AA:BB:CC:DD:EE:03',
      hostname: 'camera-01',
      vendor: 'Hikvision',
      type: 'device',
      bigr_category: 'iot',
      confidence: 0.72,
      open_ports: [80, 554],
      size: 12,
      color: '#10b981',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/1',
    },
  ],
  edges: [
    {
      source: 'gw-192.168.1.1',
      target: 'sw-192.168.1.2',
      type: 'gateway',
      label: 'uplink',
    },
    {
      source: 'sw-192.168.1.2',
      target: 'dev-192.168.1.50',
      type: 'switch',
      label: 'Gi0/1',
    },
  ],
  stats: {
    total_nodes: 3,
    total_edges: 2,
    node_types: {
      gateway: 1,
      switch: 1,
      device: 1,
    },
  },
}

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getTopology: vi.fn(),
    getTopologySubnet: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockedGetTopology = vi.mocked(bigrApi.getTopology)
const mockedGetTopologySubnet = vi.mocked(bigrApi.getTopologySubnet)

describe('useTopology', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { nodes, edges, stats, loading, error } = useTopology()

    expect(nodes.value).toEqual([])
    expect(edges.value).toEqual([])
    expect(stats.value).toEqual({
      total_nodes: 0,
      total_edges: 0,
      node_types: {},
    })
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
  })

  it('populates nodes, edges, and stats on successful fetch', async () => {
    mockedGetTopology.mockResolvedValue({
      data: mockTopologyResponse,
    } as Awaited<ReturnType<typeof bigrApi.getTopology>>)

    const { nodes, edges, stats, fetchTopology } = useTopology()

    await fetchTopology()

    expect(nodes.value).toHaveLength(3)
    expect(nodes.value[0]!.id).toBe('gw-192.168.1.1')
    expect(nodes.value[0]!.type).toBe('gateway')
    expect(nodes.value[1]!.id).toBe('sw-192.168.1.2')
    expect(nodes.value[2]!.id).toBe('dev-192.168.1.50')

    expect(edges.value).toHaveLength(2)
    expect(edges.value[0]!.source).toBe('gw-192.168.1.1')
    expect(edges.value[0]!.target).toBe('sw-192.168.1.2')

    expect(stats.value.total_nodes).toBe(3)
    expect(stats.value.total_edges).toBe(2)
    expect(stats.value.node_types).toEqual({
      gateway: 1,
      switch: 1,
      device: 1,
    })
  })

  it('sets loading state correctly during fetch', async () => {
    let resolvePromise: (value: unknown) => void
    const pendingPromise = new Promise((resolve) => {
      resolvePromise = resolve
    })

    mockedGetTopology.mockReturnValue(pendingPromise as ReturnType<typeof bigrApi.getTopology>)

    const { loading, fetchTopology } = useTopology()
    expect(loading.value).toBe(false)

    const fetchPromise = fetchTopology()
    expect(loading.value).toBe(true)

    resolvePromise!({ data: mockTopologyResponse })
    await fetchPromise

    expect(loading.value).toBe(false)
  })

  it('sets error on failed fetch', async () => {
    mockedGetTopology.mockRejectedValue(new Error('Network error'))

    const { error, loading, fetchTopology } = useTopology()

    await fetchTopology()

    expect(error.value).toBe('Network error')
    expect(loading.value).toBe(false)
  })

  it('sets generic error message for non-Error throws', async () => {
    mockedGetTopology.mockRejectedValue('string error')

    const { error, fetchTopology } = useTopology()

    await fetchTopology()

    expect(error.value).toBe('Failed to load topology')
  })

  it('clears error on new fetch attempt', async () => {
    mockedGetTopology.mockRejectedValueOnce(new Error('First error'))

    const { error, fetchTopology } = useTopology()

    await fetchTopology()
    expect(error.value).toBe('First error')

    mockedGetTopology.mockResolvedValueOnce({
      data: mockTopologyResponse,
    } as Awaited<ReturnType<typeof bigrApi.getTopology>>)

    await fetchTopology()
    expect(error.value).toBeNull()
  })

  it('calls getTopologySubnet when cidr parameter is provided', async () => {
    mockedGetTopologySubnet.mockResolvedValue({
      data: mockTopologyResponse,
    } as Awaited<ReturnType<typeof bigrApi.getTopologySubnet>>)

    const { fetchTopology } = useTopology()

    await fetchTopology('10.0.0.0/24')

    expect(mockedGetTopologySubnet).toHaveBeenCalledWith('10.0.0.0/24')
    expect(mockedGetTopology).not.toHaveBeenCalled()
  })

  it('calls getTopology when no cidr parameter is provided', async () => {
    mockedGetTopology.mockResolvedValue({
      data: mockTopologyResponse,
    } as Awaited<ReturnType<typeof bigrApi.getTopology>>)

    const { fetchTopology } = useTopology()

    await fetchTopology()

    expect(mockedGetTopology).toHaveBeenCalled()
    expect(mockedGetTopologySubnet).not.toHaveBeenCalled()
  })

  it('populates data correctly from subnet-filtered fetch', async () => {
    mockedGetTopologySubnet.mockResolvedValue({
      data: mockTopologyResponse,
    } as Awaited<ReturnType<typeof bigrApi.getTopologySubnet>>)

    const { nodes, edges, stats, fetchTopology } = useTopology()

    await fetchTopology('192.168.1.0/24')

    expect(nodes.value).toHaveLength(3)
    expect(edges.value).toHaveLength(2)
    expect(stats.value.total_nodes).toBe(3)
  })
})

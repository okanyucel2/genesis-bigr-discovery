import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useGuardian } from '@/composables/useGuardian'

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getGuardianStatus: vi.fn(),
    getGuardianStats: vi.fn(),
    getGuardianRules: vi.fn(),
    getGuardianBlocklists: vi.fn(),
    getGuardianHealth: vi.fn(),
    addGuardianRule: vi.fn(),
    deleteGuardianRule: vi.fn(),
    updateGuardianBlocklists: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

describe('useGuardian', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { status, stats, rules, blocklists, health, loading, error } = useGuardian()

    expect(status.value).toBeNull()
    expect(stats.value).toBeNull()
    expect(rules.value).toEqual([])
    expect(blocklists.value).toEqual([])
    expect(health.value).toBeNull()
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
  })

  it('fetchStatus populates status on success', async () => {
    const mockData = {
      guardian_active: true,
      dns_filtering: true,
      blocked_domains_count: 45000,
      stats: { total_queries: 1000, blocked_queries: 100, allowed_queries: 900, cache_hit_rate: 0.4 },
      lifetime_stats: { total_queries: 5000, blocked_queries: 500, allowed_queries: 4500 },
    }
    vi.mocked(bigrApi.getGuardianStatus).mockResolvedValue({ data: mockData } as never)

    const { status, fetchStatus } = useGuardian()
    await fetchStatus()

    expect(status.value).not.toBeNull()
    expect(status.value!.guardian_active).toBe(true)
    expect(status.value!.blocked_domains_count).toBe(45000)
  })

  it('fetchStatus silently fails on error', async () => {
    vi.mocked(bigrApi.getGuardianStatus).mockRejectedValue(new Error('Network error'))

    const { status, error, fetchStatus } = useGuardian()
    await fetchStatus()

    expect(status.value).toBeNull()
    expect(error.value).toBeNull()
  })

  it('fetchRules populates rules and sets loading', async () => {
    const mockRules = [
      { id: 'r1', action: 'block', domain: 'bad.com', category: 'malware', reason: '', hit_count: 5, created_at: '' },
      { id: 'r2', action: 'allow', domain: 'good.com', category: 'custom', reason: '', hit_count: 2, created_at: '' },
    ]
    vi.mocked(bigrApi.getGuardianRules).mockResolvedValue({
      data: { rules: mockRules, total: 2 },
    } as never)

    const { rules, blockRules, allowRules, fetchRules } = useGuardian()
    await fetchRules()

    expect(rules.value).toHaveLength(2)
    expect(blockRules.value).toHaveLength(1)
    expect(allowRules.value).toHaveLength(1)
  })

  it('fetchRules sets error on failure', async () => {
    vi.mocked(bigrApi.getGuardianRules).mockRejectedValue(new Error('Failed'))

    const { error, fetchRules } = useGuardian()
    await fetchRules()

    expect(error.value).toBe('Failed')
  })

  it('addRule calls API and re-fetches', async () => {
    vi.mocked(bigrApi.addGuardianRule).mockResolvedValue({} as never)
    vi.mocked(bigrApi.getGuardianRules).mockResolvedValue({ data: { rules: [], total: 0 } } as never)
    vi.mocked(bigrApi.getGuardianStatus).mockResolvedValue({ data: {} } as never)

    const { addRule } = useGuardian()
    await addRule('block', 'evil.com', 'malware', 'test')

    expect(bigrApi.addGuardianRule).toHaveBeenCalledWith('block', 'evil.com', 'malware', 'test')
    expect(bigrApi.getGuardianRules).toHaveBeenCalled()
    expect(bigrApi.getGuardianStatus).toHaveBeenCalled()
  })

  it('deleteRule calls API and re-fetches', async () => {
    vi.mocked(bigrApi.deleteGuardianRule).mockResolvedValue({} as never)
    vi.mocked(bigrApi.getGuardianRules).mockResolvedValue({ data: { rules: [], total: 0 } } as never)
    vi.mocked(bigrApi.getGuardianStatus).mockResolvedValue({ data: {} } as never)

    const { deleteRule } = useGuardian()
    await deleteRule('r1')

    expect(bigrApi.deleteGuardianRule).toHaveBeenCalledWith('r1')
    expect(bigrApi.getGuardianRules).toHaveBeenCalled()
    expect(bigrApi.getGuardianStatus).toHaveBeenCalled()
  })

  it('refreshAll calls all fetch methods', async () => {
    vi.mocked(bigrApi.getGuardianStatus).mockResolvedValue({ data: {} } as never)
    vi.mocked(bigrApi.getGuardianStats).mockResolvedValue({ data: {} } as never)
    vi.mocked(bigrApi.getGuardianRules).mockResolvedValue({ data: { rules: [], total: 0 } } as never)
    vi.mocked(bigrApi.getGuardianBlocklists).mockResolvedValue({ data: { blocklists: [] } } as never)
    vi.mocked(bigrApi.getGuardianHealth).mockResolvedValue({ data: {} } as never)

    const { refreshAll } = useGuardian()
    await refreshAll()

    expect(bigrApi.getGuardianStatus).toHaveBeenCalled()
    expect(bigrApi.getGuardianStats).toHaveBeenCalled()
    expect(bigrApi.getGuardianRules).toHaveBeenCalled()
    expect(bigrApi.getGuardianBlocklists).toHaveBeenCalled()
    expect(bigrApi.getGuardianHealth).toHaveBeenCalled()
  })
})

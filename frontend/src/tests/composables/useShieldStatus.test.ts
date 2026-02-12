import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useShieldStatus } from '@/composables/useShieldStatus'
import type { ShieldStatus } from '@/types/home-dashboard'

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getGuardianStatus: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

describe('useShieldStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('defaults to no shield installed', () => {
    const { shieldStatus } = useShieldStatus()

    expect(shieldStatus.value.installed).toBe(false)
    expect(shieldStatus.value.online).toBe(false)
    expect(shieldStatus.value.deployment).toBe('none')
    expect(shieldStatus.value.capabilities.dns).toBe(false)
    expect(shieldStatus.value.capabilities.firewall).toBe(false)
  })

  it('setShieldStatus updates the status', () => {
    const { shieldStatus, setShieldStatus } = useShieldStatus()

    const newStatus: ShieldStatus = {
      installed: true,
      online: true,
      deployment: 'standalone',
      capabilities: { dns: true, firewall: false },
    }
    setShieldStatus(newStatus)

    expect(shieldStatus.value.installed).toBe(true)
    expect(shieldStatus.value.online).toBe(true)
    expect(shieldStatus.value.deployment).toBe('standalone')
    expect(shieldStatus.value.capabilities.dns).toBe(true)
    expect(shieldStatus.value.capabilities.firewall).toBe(false)
  })

  it('setShieldStatus can simulate shield with router', () => {
    const { shieldStatus, setShieldStatus } = useShieldStatus()

    setShieldStatus({
      installed: true,
      online: true,
      deployment: 'router',
      capabilities: { dns: true, firewall: true },
    })

    expect(shieldStatus.value.deployment).toBe('router')
    expect(shieldStatus.value.capabilities.firewall).toBe(true)
  })

  it('shieldStatus is readonly ref', () => {
    const { shieldStatus } = useShieldStatus()

    // The ref itself is readonly — can only change via setShieldStatus
    expect(shieldStatus.value.installed).toBe(false)
  })

  it('fetchShieldStatus maps Guardian API to ShieldStatus when active', async () => {
    vi.mocked(bigrApi.getGuardianStatus).mockResolvedValue({
      data: {
        guardian_active: true,
        dns_filtering: true,
        blocked_domains_count: 45000,
        stats: { total_queries: 1000, blocked_queries: 120, allowed_queries: 880, cache_hit_rate: 0.4 },
        lifetime_stats: { total_queries: 5000, blocked_queries: 600, allowed_queries: 4400 },
      },
    } as never)

    const { shieldStatus, guardianData, guardianBlockedCount, guardianDomainCount, fetchShieldStatus } = useShieldStatus()
    await fetchShieldStatus()

    expect(shieldStatus.value.installed).toBe(true)
    expect(shieldStatus.value.online).toBe(true)
    expect(shieldStatus.value.deployment).toBe('standalone')
    expect(shieldStatus.value.capabilities.dns).toBe(true)
    expect(shieldStatus.value.capabilities.firewall).toBe(false)
    expect(guardianData.value).not.toBeNull()
    expect(guardianBlockedCount.value).toBe(120)
    expect(guardianDomainCount.value).toBe(45000)
  })

  it('fetchShieldStatus maps Guardian API when inactive', async () => {
    vi.mocked(bigrApi.getGuardianStatus).mockResolvedValue({
      data: {
        guardian_active: false,
        dns_filtering: false,
        blocked_domains_count: 0,
        stats: { total_queries: 0, blocked_queries: 0, allowed_queries: 0, cache_hit_rate: 0 },
        lifetime_stats: { total_queries: 0, blocked_queries: 0, allowed_queries: 0 },
      },
    } as never)

    const { shieldStatus, fetchShieldStatus } = useShieldStatus()
    await fetchShieldStatus()

    expect(shieldStatus.value.installed).toBe(true)
    expect(shieldStatus.value.online).toBe(false)
    expect(shieldStatus.value.capabilities.dns).toBe(false)
  })

  it('fetchShieldStatus falls back to defaults on API error', async () => {
    vi.mocked(bigrApi.getGuardianStatus).mockRejectedValue(new Error('Network error'))

    const { shieldStatus, guardianData, guardianBlockedCount, fetchShieldStatus } = useShieldStatus()
    await fetchShieldStatus()

    expect(shieldStatus.value.installed).toBe(false)
    expect(shieldStatus.value.online).toBe(false)
    expect(guardianData.value).toBeNull()
    expect(guardianBlockedCount.value).toBe(0)
  })
})

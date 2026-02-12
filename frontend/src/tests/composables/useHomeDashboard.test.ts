import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useHomeDashboard } from '@/composables/useHomeDashboard'
import type { ComplianceResponse, RiskResponse, CertificatesResponse, FamilyOverview } from '@/types/api'

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getCompliance: vi.fn(),
    getRisk: vi.fn(),
    getCertificates: vi.fn(),
    getFamilyOverview: vi.fn(),
    getFamilyAlerts: vi.fn(),
    getFamilyTimeline: vi.fn(),
    getCollectiveStats: vi.fn(),
    getContributionStatus: vi.fn(),
    getFirewallDailyStats: vi.fn(),
    getFirewallEvents: vi.fn(),
    getChanges: vi.fn(),
    getAssets: vi.fn(),
    getGuardianStatus: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockCompliance: ComplianceResponse = {
  compliance_score: 85,
  grade: 'A',
  breakdown: { total_assets: 12, fully_classified: 10, partially_classified: 1, unclassified: 1, manual_overrides: 0 },
  distribution: { counts: {}, percentages: {}, total: 12 },
  subnet_compliance: [],
  action_items: [],
}

const mockRisk: RiskResponse = {
  profiles: [],
  average_risk: 25,
  max_risk: 60,
  critical_count: 0,
  high_count: 1,
  medium_count: 3,
  low_count: 8,
  top_risks: [],
}

const mockCerts: CertificatesResponse = {
  certificates: [
    { ip: '192.168.1.1', port: 443, cn: 'test.local', issuer: 'Let\'s Encrypt', valid_from: '2025-01-01', valid_to: '2026-06-01', days_until_expiry: 100, is_self_signed: false, key_size: 2048, serial_number: '123' },
    { ip: '192.168.1.2', port: 443, cn: 'old.local', issuer: 'Self', valid_from: '2024-01-01', valid_to: '2026-02-20', days_until_expiry: 10, is_self_signed: true, key_size: 2048, serial_number: '456' },
  ],
}

const mockFamily: FamilyOverview = {
  family_name: 'Test Ailesi',
  plan_id: 'family_plus',
  devices: [
    { id: 'd1', name: 'Phone', device_type: 'phone', icon: '📱', owner_name: 'Ali', is_online: true, last_seen: '2026-02-09', safety_score: 90, safety_level: 'safe', open_threats: 0, ip: '192.168.1.10', network_name: 'Ev' },
    { id: 'd2', name: 'TV', device_type: 'tv', icon: '📺', owner_name: null, is_online: false, last_seen: '2026-02-08', safety_score: 70, safety_level: 'warning', open_threats: 1, ip: '192.168.1.11', network_name: 'Ev' },
  ],
  max_devices: 10,
  total_threats: 1,
  avg_safety_score: 80,
  safety_level: 'safe',
  devices_online: 1,
  last_scan: '2026-02-09',
}

function mockSettled() {
  vi.mocked(bigrApi.getCompliance).mockResolvedValue({ data: mockCompliance } as never)
  vi.mocked(bigrApi.getRisk).mockResolvedValue({ data: mockRisk } as never)
  vi.mocked(bigrApi.getCertificates).mockResolvedValue({ data: mockCerts } as never)
  vi.mocked(bigrApi.getFamilyOverview).mockResolvedValue({ data: mockFamily } as never)
  vi.mocked(bigrApi.getFamilyAlerts).mockResolvedValue({ data: [] } as never)
  vi.mocked(bigrApi.getFamilyTimeline).mockResolvedValue({ data: [] } as never)
  vi.mocked(bigrApi.getCollectiveStats).mockResolvedValue({ data: { total_signals: 100, active_agents: 50, verified_threats: 5, subnets_monitored: 200, community_protection_score: 78, last_updated: '' } } as never)
  vi.mocked(bigrApi.getContributionStatus).mockResolvedValue({ data: { signals_contributed: 10, signals_received: 50, is_contributing: true, opt_in: true, privacy_level: 'anonymous' } } as never)
  vi.mocked(bigrApi.getFirewallDailyStats).mockResolvedValue({ data: { date: '2026-02-09', blocked: 47, allowed: 1283, total: 1330, block_rate: 3.5 } } as never)
  vi.mocked(bigrApi.getFirewallEvents).mockResolvedValue({ data: { events: [], total: 0 } } as never)
  vi.mocked(bigrApi.getChanges).mockResolvedValue({ data: { changes: [] } } as never)
  vi.mocked(bigrApi.getAssets).mockResolvedValue({ data: { assets: [], total_assets: 12, target: '', scan_method: '', duration_seconds: 0, category_summary: {} } } as never)
  vi.mocked(bigrApi.getGuardianStatus).mockResolvedValue({ data: { guardian_active: false, dns_filtering: false, blocked_domains_count: 0, stats: { total_queries: 0, blocked_queries: 0, allowed_queries: 0, cache_hit_rate: 0 }, lifetime_stats: { total_queries: 0, blocked_queries: 0, allowed_queries: 0 } } } as never)
}

describe('useHomeDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { loading, error, dashboardData } = useHomeDashboard()
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
    expect(dashboardData.value.kalkan.score).toBeGreaterThan(0)
  })

  it('sets loading state during fetch', async () => {
    mockSettled()
    const { loading, fetchDashboard } = useHomeDashboard()
    expect(loading.value).toBe(false)
    const p = fetchDashboard()
    expect(loading.value).toBe(true)
    await p
    expect(loading.value).toBe(false)
  })

  it('calculates kalkan score correctly', async () => {
    mockSettled()
    const { kalkan, fetchDashboard } = useHomeDashboard()
    await fetchDashboard()

    // score = 85 * 0.4 + (100 - 25) * 0.3 + 100 * 0.3 = 34 + 22.5 + 30 = 86.5 → 87
    expect(kalkan.value.score).toBe(87)
    expect(kalkan.value.state).toBe('green')
    expect(kalkan.value.message).toContain('guvende')
  })

  it('calculates yellow kalkan state', async () => {
    mockSettled()
    vi.mocked(bigrApi.getCompliance).mockResolvedValue({
      data: { ...mockCompliance, compliance_score: 40 },
    } as never)
    vi.mocked(bigrApi.getRisk).mockResolvedValue({
      data: { ...mockRisk, average_risk: 60 },
    } as never)

    const { kalkan, fetchDashboard } = useHomeDashboard()
    await fetchDashboard()

    // score = 40 * 0.4 + (100 - 60) * 0.3 + 100 * 0.3 = 16 + 12 + 30 = 58
    expect(kalkan.value.score).toBe(58)
    expect(kalkan.value.state).toBe('yellow')
    expect(kalkan.value.message).toContain('Dikkat')
  })

  it('calculates red kalkan state', async () => {
    mockSettled()
    vi.mocked(bigrApi.getCompliance).mockResolvedValue({
      data: { ...mockCompliance, compliance_score: 20 },
    } as never)
    vi.mocked(bigrApi.getRisk).mockResolvedValue({
      data: { ...mockRisk, average_risk: 85 },
    } as never)
    vi.mocked(bigrApi.getFirewallDailyStats).mockResolvedValue({
      data: { date: '2026-02-09', blocked: 200, allowed: 100, total: 300, block_rate: 66 },
    } as never)

    const { kalkan, fetchDashboard } = useHomeDashboard()
    await fetchDashboard()

    // score = 20 * 0.4 + (100 - 85) * 0.3 + 70 * 0.3 = 8 + 4.5 + 21 = 33.5 → 34
    expect(kalkan.value.score).toBeLessThan(50)
    expect(kalkan.value.state).toBe('red')
    expect(kalkan.value.message).toContain('Acil')
  })

  it('handles partial API failure gracefully', async () => {
    mockSettled()
    // Family fails but others succeed
    vi.mocked(bigrApi.getFamilyOverview).mockRejectedValue(new Error('Family unavailable'))

    const { ailem, kalkan, error, fetchDashboard } = useHomeDashboard()
    await fetchDashboard()

    // Ailem should degrade to empty
    expect(ailem.value.familyName).toBe('')
    expect(ailem.value.devices).toHaveLength(0)
    // Kalkan should still work
    expect(kalkan.value.score).toBeGreaterThan(0)
    // No global error since not all failed
    expect(error.value).toBeNull()
  })

  it('sets error when all APIs fail', async () => {
    const rejection = () => Promise.reject(new Error('Network down'))
    vi.mocked(bigrApi.getCompliance).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getRisk).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getCertificates).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getFamilyOverview).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getFamilyAlerts).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getFamilyTimeline).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getCollectiveStats).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getContributionStatus).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getFirewallDailyStats).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getFirewallEvents).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getChanges).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getAssets).mockReturnValue(rejection() as never)
    vi.mocked(bigrApi.getGuardianStatus).mockReturnValue(rejection() as never)

    const { error, fetchDashboard } = useHomeDashboard()
    await fetchDashboard()

    expect(error.value).toBe('Veriler yuklenemedi. Lutfen tekrar deneyin.')
  })

  it('populates verilerim card correctly', async () => {
    mockSettled()
    const { verilerim, fetchDashboard } = useHomeDashboard()
    await fetchDashboard()

    expect(verilerim.value.httpsCount).toBe(2)
    expect(verilerim.value.totalCertificates).toBe(2)
    expect(verilerim.value.expiringCerts).toBe(1) // 10 days < 30
    expect(verilerim.value.selfSignedCerts).toBe(1)
    expect(verilerim.value.complianceGrade).toBe('A')
  })

  it('populates ailem card correctly', async () => {
    mockSettled()
    const { ailem, fetchDashboard } = useHomeDashboard()
    await fetchDashboard()

    expect(ailem.value.familyName).toBe('Test Ailesi')
    expect(ailem.value.devices).toHaveLength(2)
    expect(ailem.value.devicesOnline).toBe(1)
    expect(ailem.value.totalThreats).toBe(1)
  })

  it('populates bolgem card correctly', async () => {
    mockSettled()
    const { bolgem, fetchDashboard } = useHomeDashboard()
    await fetchDashboard()

    expect(bolgem.value.communityScore).toBe(78)
    expect(bolgem.value.activeAgents).toBe(50)
    expect(bolgem.value.isContributing).toBe(true)
  })
})

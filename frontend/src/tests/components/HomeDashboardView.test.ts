import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import HomeDashboardView from '@/views/HomeDashboardView.vue'

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
    getStreak: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

function mockAllApis() {
  vi.mocked(bigrApi.getCompliance).mockResolvedValue({ data: { compliance_score: 85, grade: 'A', breakdown: { total_assets: 12, fully_classified: 10, partially_classified: 1, unclassified: 1, manual_overrides: 0 }, distribution: { counts: {}, percentages: {}, total: 12 }, subnet_compliance: [], action_items: [] } } as never)
  vi.mocked(bigrApi.getRisk).mockResolvedValue({ data: { profiles: [], average_risk: 25, max_risk: 60, critical_count: 0, high_count: 1, medium_count: 3, low_count: 8, top_risks: [] } } as never)
  vi.mocked(bigrApi.getCertificates).mockResolvedValue({ data: { certificates: [] } } as never)
  vi.mocked(bigrApi.getFamilyOverview).mockResolvedValue({ data: { family_name: 'Test', plan_id: 'plus', devices: [], max_devices: 10, total_threats: 0, avg_safety_score: 90, safety_level: 'safe', devices_online: 0, last_scan: null } } as never)
  vi.mocked(bigrApi.getFamilyAlerts).mockResolvedValue({ data: [] } as never)
  vi.mocked(bigrApi.getFamilyTimeline).mockResolvedValue({ data: [] } as never)
  vi.mocked(bigrApi.getCollectiveStats).mockResolvedValue({ data: { total_signals: 100, active_agents: 50, verified_threats: 5, subnets_monitored: 200, community_protection_score: 78, last_updated: '' } } as never)
  vi.mocked(bigrApi.getContributionStatus).mockResolvedValue({ data: { signals_contributed: 10, signals_received: 50, is_contributing: true, opt_in: true, privacy_level: 'anonymous' } } as never)
  vi.mocked(bigrApi.getFirewallDailyStats).mockResolvedValue({ data: { date: '2026-02-09', blocked: 47, allowed: 1283, total: 1330, block_rate: 3.5 } } as never)
  vi.mocked(bigrApi.getFirewallEvents).mockResolvedValue({ data: { events: [], total: 0 } } as never)
  vi.mocked(bigrApi.getChanges).mockResolvedValue({ data: { changes: [] } } as never)
  vi.mocked(bigrApi.getAssets).mockResolvedValue({ data: { assets: [], total_assets: 12, target: '', scan_method: '', duration_seconds: 0, category_summary: {} } } as never)
  vi.mocked(bigrApi.getGuardianStatus).mockResolvedValue({ data: { guardian_active: true, dns_filtering: true, blocked_domains_count: 45000, stats: { total_queries: 1000, blocked_queries: 120, allowed_queries: 880, cache_hit_rate: 0.4 }, lifetime_stats: { total_queries: 5000, blocked_queries: 600, allowed_queries: 4400 } } } as never)
  vi.mocked(bigrApi.getStreak).mockResolvedValue({ data: { current_streak_days: 42, longest_streak_days: 67, total_safe_days: 128, streak_broken_count: 3, milestone: { badge: 'fire', title_tr: 'Aylik Koruyucu', days_required: 30 }, next_milestone: { badge: 'star', title_tr: 'Ceyrek Sampiyonu', days_remaining: 48 } } } as never)
}

describe('HomeDashboardView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setActivePinia(createPinia())
  })

  it('shows loading state when fetch is pending', async () => {
    // Use a never-resolving promise to keep loading state
    vi.mocked(bigrApi.getCompliance).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getRisk).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getCertificates).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getFamilyOverview).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getFamilyAlerts).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getFamilyTimeline).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getCollectiveStats).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getContributionStatus).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getFirewallDailyStats).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getFirewallEvents).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getChanges).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getAssets).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getGuardianStatus).mockReturnValue(new Promise(() => {}) as never)
    vi.mocked(bigrApi.getStreak).mockReturnValue(new Promise(() => {}) as never)

    const wrapper = mount(HomeDashboardView)
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Veriler yukleniyor')
  })

  it('renders dashboard after loading', async () => {
    mockAllApis()
    const wrapper = mount(HomeDashboardView)
    await flushPromises()

    expect(wrapper.text()).toContain('guvende')
    expect(wrapper.text()).toContain('Verilerim')
    expect(wrapper.text()).toContain('Ailem')
    expect(wrapper.text()).toContain('Evim')
    expect(wrapper.text()).toContain('Bolgem')
  })

  it('shows error state and retry button when all fail', async () => {
    const rejection = () => Promise.reject(new Error('fail'))
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
    vi.mocked(bigrApi.getStreak).mockReturnValue(rejection() as never)

    const wrapper = mount(HomeDashboardView)
    await flushPromises()

    expect(wrapper.text()).toContain('Veriler yuklenemedi')
    expect(wrapper.find('button').text()).toContain('Tekrar Dene')
  })
})

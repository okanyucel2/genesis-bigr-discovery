import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ShieldFindingsView from '@/views/ShieldFindingsView.vue'
import type { AgentShieldFinding, ShieldFindingsListResponse } from '@/types/api'

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getAgentShieldFindings: vi.fn(),
  },
}))

vi.mock('@/stores/ui', () => ({
  useUiStore: vi.fn(() => ({
    selectedSite: null,
  })),
}))

import { bigrApi } from '@/lib/api'
import { useUiStore } from '@/stores/ui'

const stubs = {
  ShieldAlert: { template: '<span>ShieldAlert</span>' },
  Loader2: { template: '<span>Loader2</span>' },
  AlertTriangle: { template: '<span>AlertTriangle</span>' },
  RefreshCw: { template: '<span>RefreshCw</span>' },
  SiteFilter: { template: '<div data-testid="site-filter">SiteFilter</div>' },
}

function makeFinding(overrides: Partial<AgentShieldFinding> = {}): AgentShieldFinding {
  return {
    id: 1,
    scan_id: 'sh_001',
    module: 'tls',
    severity: 'high',
    title: 'Weak Cipher',
    detail: 'TLS 1.0 detected',
    target_ip: '10.0.0.1',
    remediation: 'Upgrade TLS',
    target: 'example.com',
    site_name: 'Test Site',
    agent_id: 'agent_1',
    scanned_at: '2026-02-12T00:00:00Z',
    ...overrides,
  }
}

const mockResponse: ShieldFindingsListResponse = {
  findings: [
    makeFinding({ id: 1, severity: 'critical', title: 'SSL Expired' }),
    makeFinding({ id: 2, severity: 'medium', title: 'Weak Cipher' }),
    makeFinding({ id: 3, severity: 'info', title: 'Open Port' }),
  ],
  total: 3,
  severity_counts: { critical: 1, high: 0, medium: 1, low: 0, info: 1 },
}

function mountView() {
  return mount(ShieldFindingsView, {
    global: { stubs },
  })
}

describe('ShieldFindingsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useUiStore).mockReturnValue({ selectedSite: null } as ReturnType<typeof useUiStore>)
  })

  it('shows "Loading findings..." initially before API resolves', async () => {
    // Create a promise that we control so the API stays pending
    let resolve!: (value: { data: ShieldFindingsListResponse }) => void
    vi.mocked(bigrApi.getAgentShieldFindings).mockReturnValue(
      new Promise((r) => {
        resolve = r
      }),
    )

    const wrapper = mountView()

    // While the API is pending, loading text should be visible
    expect(wrapper.text()).toContain('Loading findings...')

    // Now resolve so the component finishes its lifecycle
    resolve({ data: mockResponse })
    await flushPromises()

    // Loading text should disappear after resolve
    expect(wrapper.text()).not.toContain('Loading findings...')
  })

  it('shows findings after successful load', async () => {
    vi.mocked(bigrApi.getAgentShieldFindings).mockResolvedValue({
      data: mockResponse,
    })

    const wrapper = mountView()
    await flushPromises()

    // Finding titles should be visible
    expect(wrapper.text()).toContain('SSL Expired')
    expect(wrapper.text()).toContain('Weak Cipher')
    expect(wrapper.text()).toContain('Open Port')

    // Detail text visible
    expect(wrapper.text()).toContain('TLS 1.0 detected')

    // Target IP visible
    expect(wrapper.text()).toContain('10.0.0.1')

    // Module visible
    expect(wrapper.text()).toContain('tls')

    // Remediation visible
    expect(wrapper.text()).toContain('Upgrade TLS')
  })

  it('shows severity filter chips with counts', async () => {
    vi.mocked(bigrApi.getAgentShieldFindings).mockResolvedValue({
      data: mockResponse,
    })

    const wrapper = mountView()
    await flushPromises()

    // "All" chip with total count
    expect(wrapper.text()).toContain('All (3)')

    // Individual severity chips with their counts
    expect(wrapper.text()).toContain('critical (1)')
    expect(wrapper.text()).toContain('high (0)')
    expect(wrapper.text()).toContain('medium (1)')
    expect(wrapper.text()).toContain('low (0)')
    expect(wrapper.text()).toContain('info (1)')
  })

  it('shows "No Findings" when findings array is empty', async () => {
    vi.mocked(bigrApi.getAgentShieldFindings).mockResolvedValue({
      data: {
        findings: [],
        total: 0,
        severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      },
    })

    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('No Findings')
    expect(wrapper.text()).toContain('No security findings from agent scans yet')
  })

  it('shows error state and "Try Again" button on API failure', async () => {
    vi.mocked(bigrApi.getAgentShieldFindings).mockRejectedValue(
      new Error('Network error'),
    )

    const wrapper = mountView()
    await flushPromises()

    // Error heading
    expect(wrapper.text()).toContain('Unable to Load')

    // Error message
    expect(wrapper.text()).toContain('Network error')

    // Try Again button
    const tryAgainBtn = wrapper.findAll('button').find((btn) => btn.text().includes('Try Again'))
    expect(tryAgainBtn).toBeTruthy()
  })

  it('sorts findings by severity order (critical before medium before info)', async () => {
    // Provide findings in reverse order to verify sorting
    vi.mocked(bigrApi.getAgentShieldFindings).mockResolvedValue({
      data: {
        findings: [
          makeFinding({ id: 10, severity: 'info', title: 'Info Finding' }),
          makeFinding({ id: 11, severity: 'critical', title: 'Critical Finding' }),
          makeFinding({ id: 12, severity: 'medium', title: 'Medium Finding' }),
        ],
        total: 3,
        severity_counts: { critical: 1, high: 0, medium: 1, low: 0, info: 1 },
      },
    })

    const wrapper = mountView()
    await flushPromises()

    // Get all finding title elements (h4 tags inside the findings list)
    const titles = wrapper.findAll('h4').map((el) => el.text())

    const criticalIdx = titles.indexOf('Critical Finding')
    const mediumIdx = titles.indexOf('Medium Finding')
    const infoIdx = titles.indexOf('Info Finding')

    // All three should be present
    expect(criticalIdx).toBeGreaterThanOrEqual(0)
    expect(mediumIdx).toBeGreaterThanOrEqual(0)
    expect(infoIdx).toBeGreaterThanOrEqual(0)

    // critical should come before medium, which should come before info
    expect(criticalIdx).toBeLessThan(mediumIdx)
    expect(mediumIdx).toBeLessThan(infoIdx)
  })
})

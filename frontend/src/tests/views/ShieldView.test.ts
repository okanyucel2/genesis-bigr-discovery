import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { ref } from 'vue'
import ShieldView from '@/views/ShieldView.vue'

vi.mock('@/composables/useShield', () => ({
  useShield: vi.fn(() => ({
    currentScan: ref(null),
    findings: ref([]),
    loading: ref(false),
    scanning: ref(false),
    error: ref(null),
    startScan: vi.fn(),
    fetchScan: vi.fn(),
  })),
}))

import { useShield } from '@/composables/useShield'

const childStubs = {
  ScanForm: { template: '<div data-testid="scan-form">ScanForm</div>' },
  ShieldScore: { template: '<div data-testid="shield-score">ShieldScore</div>' },
  ModuleScoreCards: { template: '<div data-testid="module-score-cards">ModuleScoreCards</div>' },
  FindingsList: { template: '<div data-testid="findings-list">FindingsList</div>' },
  PortScanResults: { template: '<div>PortScanResults</div>' },
  HeadersChecklist: { template: '<div>HeadersChecklist</div>' },
  DnsSecurityCard: { template: '<div>DnsSecurityCard</div>' },
  ShieldTimeline: { template: '<div data-testid="shield-timeline">ShieldTimeline</div>' },
  CveFindings: { template: '<div>CveFindings</div>' },
  CredentialFindings: { template: '<div>CredentialFindings</div>' },
  OwaspResults: { template: '<div>OwaspResults</div>' },
  RemediationPlan: { template: '<div>RemediationPlan</div>' },
  AttackSurfaceMap: { template: '<div>AttackSurfaceMap</div>' },
  PriorityMatrix: { template: '<div>PriorityMatrix</div>' },
  Tabs: { template: '<div data-testid="tabs"><slot /></div>' },
  TabsList: { template: '<div><slot /></div>' },
  TabsTrigger: { template: '<div><slot /></div>' },
  TabsContent: { template: '<div><slot /></div>' },
  Shield: { template: '<span>ShieldIcon</span>' },
  Loader2: { template: '<span data-testid="loader">Loader2</span>' },
  AlertTriangle: { template: '<span>AlertTriangle</span>' },
  RefreshCw: { template: '<span>RefreshCw</span>' },
  CheckCircle: { template: '<span>CheckCircle</span>' },
  XCircle: { template: '<span>XCircle</span>' },
}

function mountShield() {
  return mount(ShieldView, {
    global: {
      stubs: childStubs,
    },
  })
}

const mockCompletedScan = {
  id: 'sh_001',
  target: 'example.com',
  status: 'completed' as const,
  shield_score: 72,
  grade: 'B',
  scan_depth: 'standard',
  modules_enabled: ['tls', 'ports'],
  total_checks: 20,
  passed_checks: 14,
  failed_checks: 6,
  warning_checks: 0,
  findings: [],
  module_scores: {
    tls: { module: 'tls', score: 80, total_checks: 8, passed_checks: 6, findings_count: 2 },
  },
  duration_seconds: 12,
  created_at: '2026-02-12T00:00:00Z',
  started_at: '2026-02-12T00:00:00Z',
  completed_at: '2026-02-12T00:00:02Z',
  target_type: 'domain',
}

describe('ShieldView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders ScanForm component', () => {
    vi.mocked(useShield).mockReturnValue({
      currentScan: ref(null),
      findings: ref([]),
      loading: ref(false),
      scanning: ref(false),
      error: ref(null),
      startScan: vi.fn(),
      fetchScan: vi.fn(),
    })

    const wrapper = mountShield()
    expect(wrapper.find('[data-testid="scan-form"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('ScanForm')
  })

  it('shows empty state when no scan exists', () => {
    vi.mocked(useShield).mockReturnValue({
      currentScan: ref(null),
      findings: ref([]),
      loading: ref(false),
      scanning: ref(false),
      error: ref(null),
      startScan: vi.fn(),
      fetchScan: vi.fn(),
    })

    const wrapper = mountShield()
    expect(wrapper.text()).toContain('Başlamak için bir hedef girin')
    expect(wrapper.find('[data-testid="shield-score"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="tabs"]').exists()).toBe(false)
  })

  it('shows scanning state with loader when scan is running', () => {
    vi.mocked(useShield).mockReturnValue({
      currentScan: ref({
        ...mockCompletedScan,
        status: 'running',
        completed_at: null,
        duration_seconds: null,
      }),
      findings: ref([]),
      loading: ref(false),
      scanning: ref(true),
      error: ref(null),
      startScan: vi.fn(),
      fetchScan: vi.fn(),
    })

    const wrapper = mountShield()
    // Scanning state shows status text with target
    expect(wrapper.text()).toContain('taranıyor...')
    // Progress bar indicator is visible
    expect(wrapper.find('.animate-pulse').exists()).toBe(true)
    // Should NOT show empty state
    expect(wrapper.text()).not.toContain('Başlamak için bir hedef girin')
    // Should NOT show completed results
    expect(wrapper.find('[data-testid="shield-score"]').exists()).toBe(false)
  })

  it('shows completed results when scan is done', () => {
    vi.mocked(useShield).mockReturnValue({
      currentScan: ref({ ...mockCompletedScan }),
      findings: ref([]),
      loading: ref(false),
      scanning: ref(false),
      error: ref(null),
      startScan: vi.fn(),
      fetchScan: vi.fn(),
    })

    const wrapper = mountShield()
    // ShieldScore rendered
    expect(wrapper.find('[data-testid="shield-score"]').exists()).toBe(true)
    // ModuleScoreCards rendered (module_scores has entries)
    expect(wrapper.find('[data-testid="module-score-cards"]').exists()).toBe(true)
    // FindingsList rendered inside tabs
    expect(wrapper.find('[data-testid="findings-list"]').exists()).toBe(true)
    // Tabs rendered
    expect(wrapper.find('[data-testid="tabs"]').exists()).toBe(true)
    // ShieldTimeline rendered
    expect(wrapper.find('[data-testid="shield-timeline"]').exists()).toBe(true)
    // Should NOT show empty state
    expect(wrapper.text()).not.toContain('Başlamak için bir hedef girin')
    // Should NOT show scanning loader
    expect(wrapper.find('[data-testid="loader"]').exists()).toBe(false)
  })
})

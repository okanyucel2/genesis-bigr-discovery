import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type { ShieldScan, ShieldFinding } from '@/types/shield'

// Mock onUnmounted since the composable registers a cleanup callback
vi.mock('vue', async () => {
  const actual = await vi.importActual<typeof import('vue')>('vue')
  return {
    ...actual,
    onUnmounted: vi.fn(),
  }
})

vi.mock('@/lib/api', () => ({
  bigrApi: {
    startShieldScan: vi.fn(),
    getShieldScan: vi.fn(),
    getShieldFindings: vi.fn(),
  },
}))

const mockStore = {
  addScan: vi.fn(),
  updateScan: vi.fn(),
  $reset: vi.fn(),
  recentScans: [],
  currentScanId: null,
  currentScan: null,
}

vi.mock('@/stores/shield', () => ({
  useShieldStore: () => mockStore,
}))

import { bigrApi } from '@/lib/api'
import { useShield } from '@/composables/useShield'

function createMockScan(overrides: Partial<ShieldScan> = {}): ShieldScan {
  return {
    id: 'scan-001',
    target: '192.168.1.0/24',
    target_type: 'network',
    status: 'queued',
    created_at: '2026-02-12T10:00:00Z',
    started_at: null,
    completed_at: null,
    shield_score: null,
    grade: null,
    scan_depth: 'standard',
    modules_enabled: ['port_scan', 'vuln_check'],
    total_checks: 0,
    passed_checks: 0,
    failed_checks: 0,
    warning_checks: 0,
    findings: [],
    module_scores: {},
    duration_seconds: null,
    ...overrides,
  }
}

function createMockFinding(overrides: Partial<ShieldFinding> = {}): ShieldFinding {
  return {
    id: 'finding-001',
    scan_id: 'scan-001',
    module: 'vuln_check',
    severity: 'high',
    title: 'Open SSH Port',
    description: 'Port 22 is open with weak key exchange',
    remediation: 'Disable weak ciphers',
    target_ip: '192.168.1.10',
    target_port: 22,
    evidence: {},
    attack_technique: null,
    attack_tactic: null,
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
    ...overrides,
  }
}

describe('useShield', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('startScan', () => {
    it('calls API and adds scan to store', async () => {
      const mockScan = createMockScan({ status: 'running' })
      vi.mocked(bigrApi.startShieldScan).mockResolvedValue({
        data: { scan: mockScan },
      } as never)
      // Mock getShieldScan for the poll that startScan triggers
      vi.mocked(bigrApi.getShieldScan).mockResolvedValue({
        data: { scan: mockScan },
      } as never)

      const { startScan, currentScan } = useShield()
      const result = await startScan('192.168.1.0/24', 'standard', ['port_scan'], 'medium')

      expect(bigrApi.startShieldScan).toHaveBeenCalledWith(
        '192.168.1.0/24',
        'standard',
        ['port_scan'],
        'medium',
      )
      expect(result).toEqual(mockScan)
      expect(currentScan.value).toEqual(mockScan)
      expect(mockStore.addScan).toHaveBeenCalledWith(mockScan)
    })

    it('sets loading state during call', async () => {
      const mockScan = createMockScan()
      let resolveApi: (value: unknown) => void
      const apiPromise = new Promise((resolve) => {
        resolveApi = resolve
      })
      vi.mocked(bigrApi.startShieldScan).mockReturnValue(apiPromise as never)
      vi.mocked(bigrApi.getShieldScan).mockResolvedValue({
        data: { scan: mockScan },
      } as never)

      const { startScan, loading, scanning } = useShield()

      // Start the call but don't await yet
      const scanPromise = startScan('10.0.0.1', 'quick')

      // loading and scanning should be true while the call is in flight
      expect(loading.value).toBe(true)
      expect(scanning.value).toBe(true)

      // Resolve the API call
      resolveApi!({ data: { scan: mockScan } })
      await scanPromise

      // loading should be false after resolution; scanning remains true (polling active)
      expect(loading.value).toBe(false)
      expect(scanning.value).toBe(true)
    })

    it('sets error on API failure and clears scanning', async () => {
      vi.mocked(bigrApi.startShieldScan).mockRejectedValue(new Error('Network timeout'))

      const { startScan, error, scanning, loading } = useShield()
      const result = await startScan('10.0.0.1', 'deep')

      expect(result).toBeNull()
      expect(error.value).toBe('Network timeout')
      expect(scanning.value).toBe(false)
      expect(loading.value).toBe(false)
    })
  })

  describe('fetchScan', () => {
    it('updates store with scan result', async () => {
      const mockScan = createMockScan({ id: 'scan-abc', status: 'completed', shield_score: 85 })
      vi.mocked(bigrApi.getShieldScan).mockResolvedValue({
        data: { scan: mockScan },
      } as never)

      const { fetchScan, currentScan } = useShield()
      const result = await fetchScan('scan-abc')

      expect(bigrApi.getShieldScan).toHaveBeenCalledWith('scan-abc')
      expect(result).toEqual(mockScan)
      expect(currentScan.value).toEqual(mockScan)
      expect(mockStore.updateScan).toHaveBeenCalledWith(mockScan)
    })
  })

  describe('fetchFindings', () => {
    it('returns findings array', async () => {
      const mockFindings = [
        createMockFinding({ id: 'f-1', severity: 'critical' }),
        createMockFinding({ id: 'f-2', severity: 'medium' }),
      ]
      vi.mocked(bigrApi.getShieldFindings).mockResolvedValue({
        data: { findings: mockFindings, total: 2 },
      } as never)

      const { fetchFindings, findings } = useShield()
      const result = await fetchFindings('scan-001')

      expect(bigrApi.getShieldFindings).toHaveBeenCalledWith('scan-001')
      expect(result).toEqual(mockFindings)
      expect(findings.value).toEqual(mockFindings)
    })

    it('sets error state on failure', async () => {
      vi.mocked(bigrApi.getShieldFindings).mockRejectedValue(new Error('Server error'))

      const { fetchFindings, error, findings, loading } = useShield()
      const result = await fetchFindings('scan-bad')

      expect(result).toEqual([])
      expect(findings.value).toEqual([])
      expect(error.value).toBe('Server error')
      expect(loading.value).toBe(false)
    })
  })
})

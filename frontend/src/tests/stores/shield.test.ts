import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useShieldStore } from '@/stores/shield'
import type { ShieldScan } from '@/types/shield'

function makeScan(id: string, overrides: Partial<ShieldScan> = {}): ShieldScan {
  return {
    id,
    target: 'example.com',
    target_type: 'domain',
    status: 'completed',
    created_at: '2026-02-12T00:00:00Z',
    started_at: '2026-02-12T00:00:00Z',
    completed_at: '2026-02-12T00:00:02Z',
    shield_score: 72,
    grade: 'B',
    scan_depth: 'standard',
    modules_enabled: ['tls', 'ports'],
    total_checks: 20,
    passed_checks: 14,
    failed_checks: 6,
    warning_checks: 0,
    findings: [],
    module_scores: {},
    duration_seconds: 12,
    ...overrides,
  }
}

describe('useShieldStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  describe('initial state', () => {
    it('has empty recentScans', () => {
      const store = useShieldStore()
      expect(store.recentScans).toEqual([])
    })

    it('has null currentScanId', () => {
      const store = useShieldStore()
      expect(store.currentScanId).toBeNull()
    })

    it('has null currentScan', () => {
      const store = useShieldStore()
      expect(store.currentScan).toBeNull()
    })
  })

  describe('addScan', () => {
    it('adds a scan to recentScans and sets currentScanId', () => {
      const store = useShieldStore()
      const scan = makeScan('scan-1')

      store.addScan(scan)

      expect(store.recentScans).toHaveLength(1)
      expect(store.recentScans[0]).toEqual(scan)
      expect(store.currentScanId).toBe('scan-1')
    })

    it('adds new scans to the front (most recent first)', () => {
      const store = useShieldStore()
      const scan1 = makeScan('scan-1')
      const scan2 = makeScan('scan-2')
      const scan3 = makeScan('scan-3')

      store.addScan(scan1)
      store.addScan(scan2)
      store.addScan(scan3)

      expect(store.recentScans).toHaveLength(3)
      expect(store.recentScans[0].id).toBe('scan-3')
      expect(store.recentScans[1].id).toBe('scan-2')
      expect(store.recentScans[2].id).toBe('scan-1')
    })

    it('deduplicates by id, moving updated scan to front', () => {
      const store = useShieldStore()
      const scan1 = makeScan('scan-1', { shield_score: 50 })
      const scan2 = makeScan('scan-2')

      store.addScan(scan1)
      store.addScan(scan2)
      expect(store.recentScans).toHaveLength(2)

      const scan1Updated = makeScan('scan-1', { shield_score: 90 })
      store.addScan(scan1Updated)

      expect(store.recentScans).toHaveLength(2)
      expect(store.recentScans[0].id).toBe('scan-1')
      expect(store.recentScans[0].shield_score).toBe(90)
      expect(store.recentScans[1].id).toBe('scan-2')
    })

    it('keeps a maximum of 50 scans', () => {
      const store = useShieldStore()

      for (let i = 0; i < 51; i++) {
        store.addScan(makeScan(`scan-${i}`))
      }

      expect(store.recentScans).toHaveLength(50)
      // Most recent scan should be first
      expect(store.recentScans[0].id).toBe('scan-50')
      // Oldest scan (scan-0) should have been evicted
      expect(store.recentScans.find((s) => s.id === 'scan-0')).toBeUndefined()
    })
  })

  describe('updateScan', () => {
    it('updates an existing scan in place', () => {
      const store = useShieldStore()
      const scan1 = makeScan('scan-1', { shield_score: 50 })
      const scan2 = makeScan('scan-2')

      store.addScan(scan1)
      store.addScan(scan2)

      const scan1Updated = makeScan('scan-1', { shield_score: 95, grade: 'A' })
      store.updateScan(scan1Updated)

      expect(store.recentScans).toHaveLength(2)
      // Order preserved: scan-2 first, scan-1 second (updateScan does not reorder)
      expect(store.recentScans[0].id).toBe('scan-2')
      expect(store.recentScans[1].id).toBe('scan-1')
      expect(store.recentScans[1].shield_score).toBe(95)
      expect(store.recentScans[1].grade).toBe('A')
    })

    it('adds scan via addScan if not found in recentScans', () => {
      const store = useShieldStore()
      const scan1 = makeScan('scan-1')

      store.addScan(scan1)

      const scan2 = makeScan('scan-2', { target: 'new-target.com' })
      store.updateScan(scan2)

      expect(store.recentScans).toHaveLength(2)
      // Delegated to addScan, so scan-2 is at front
      expect(store.recentScans[0].id).toBe('scan-2')
      expect(store.recentScans[0].target).toBe('new-target.com')
      expect(store.currentScanId).toBe('scan-2')
    })
  })

  describe('currentScan', () => {
    it('returns the scan matching currentScanId', () => {
      const store = useShieldStore()
      const scan1 = makeScan('scan-1', { target: 'alpha.com' })
      const scan2 = makeScan('scan-2', { target: 'beta.com' })

      store.addScan(scan1)
      store.addScan(scan2)

      // currentScanId should be scan-2 (last added)
      expect(store.currentScan).not.toBeNull()
      expect(store.currentScan!.id).toBe('scan-2')
      expect(store.currentScan!.target).toBe('beta.com')

      // Manually change currentScanId
      store.currentScanId = 'scan-1'
      expect(store.currentScan!.id).toBe('scan-1')
      expect(store.currentScan!.target).toBe('alpha.com')
    })

    it('returns null when currentScanId does not match any scan', () => {
      const store = useShieldStore()
      const scan = makeScan('scan-1')

      store.addScan(scan)
      store.currentScanId = 'nonexistent-id'

      expect(store.currentScan).toBeNull()
    })
  })

  describe('$reset', () => {
    it('clears all state back to initial values', () => {
      const store = useShieldStore()

      store.addScan(makeScan('scan-1'))
      store.addScan(makeScan('scan-2'))
      store.addScan(makeScan('scan-3'))

      expect(store.recentScans).toHaveLength(3)
      expect(store.currentScanId).toBe('scan-3')
      expect(store.currentScan).not.toBeNull()

      store.$reset()

      expect(store.recentScans).toEqual([])
      expect(store.currentScanId).toBeNull()
      expect(store.currentScan).toBeNull()
    })
  })
})

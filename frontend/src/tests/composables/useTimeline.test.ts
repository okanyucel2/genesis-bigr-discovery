import { describe, it, expect } from 'vitest'
import { useTimeline } from '@/composables/useTimeline'
import type { FirewallEvent, FamilyTimelineEntry, AssetChange } from '@/types/api'

const mockFirewallEvents: FirewallEvent[] = [
  { id: 'fe1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.1', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
  { id: 'fe2', timestamp: '2026-02-09T09:00:00Z', action: 'allow', rule_id: null, source_ip: '192.168.1.2', dest_ip: '8.8.8.8', dest_port: 53, protocol: 'udp', process_name: 'chrome', direction: 'outbound' },
]

const mockFamilyEntries: FamilyTimelineEntry[] = [
  { id: 'ft1', device_id: 'd1', device_name: 'Phone', device_icon: '📱', event_type: 'threat_blocked', message: 'Tehdit engellendi', timestamp: '2026-02-09T11:00:00Z' },
]

const mockChanges: AssetChange[] = [
  { id: 1, ip: '192.168.1.50', mac: null, change_type: 'new', field_name: null, old_value: null, new_value: null, detected_at: '2026-02-09T08:00:00Z' },
]

describe('useTimeline', () => {
  it('merges and sorts events by timestamp', () => {
    const { buildTimeline } = useTimeline()
    const items = buildTimeline(mockFirewallEvents, mockFamilyEntries, mockChanges, [])

    expect(items).toHaveLength(4)
    // Newest first: family (11:00) > fw block (10:00) > fw allow (09:00) > change (08:00)
    expect(items[0]!.id).toBe('fam_ft1')
    expect(items[1]!.id).toBe('fw_fe1')
    expect(items[3]!.id).toBe('chg_1')
  })

  it('assigns correct severity to firewall events', () => {
    const { buildTimeline } = useTimeline()
    const items = buildTimeline(mockFirewallEvents, [], [], [])

    const blockItem = items.find((i) => i.id === 'fw_fe1')
    const allowItem = items.find((i) => i.id === 'fw_fe2')
    expect(blockItem!.severity).toBe('medium')
    expect(allowItem!.severity).toBe('info')
  })

  it('assigns high severity to threat_blocked family events', () => {
    const { buildTimeline } = useTimeline()
    const items = buildTimeline([], mockFamilyEntries, [], [])

    expect(items[0]!.severity).toBe('high')
  })

  it('toggle expand works', () => {
    const { toggleExpand, isExpanded } = useTimeline()

    expect(isExpanded('test_id')).toBe(false)
    toggleExpand('test_id')
    expect(isExpanded('test_id')).toBe(true)
    toggleExpand('test_id')
    expect(isExpanded('test_id')).toBe(false)
  })

  it('showMore increments visible count', () => {
    const { visibleCount, showMore } = useTimeline()

    expect(visibleCount.value).toBe(5)
    showMore()
    expect(visibleCount.value).toBe(10)
    showMore()
    expect(visibleCount.value).toBe(15)
  })

  it('humanizes firewall messages in Turkish', () => {
    const { buildTimeline } = useTimeline()
    const items = buildTimeline(mockFirewallEvents, [], [], [])

    expect(items[0]!.message).toContain('engellendi')
    expect(items[1]!.message).toContain('izin verildi')
  })

  it('generates detail for firewall events', () => {
    const { buildTimeline } = useTimeline()
    const items = buildTimeline(mockFirewallEvents, [], [], [])

    expect(items[0]!.detail).toContain('TCP')
    expect(items[0]!.detail).toContain('Gelen')
  })
})

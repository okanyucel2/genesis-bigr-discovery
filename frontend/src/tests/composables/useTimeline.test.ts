import { describe, it, expect } from 'vitest'
import { useTimeline } from '@/composables/useTimeline'
import type { FirewallEvent, FamilyTimelineEntry, AssetChange } from '@/types/api'
import { isRichDetail } from '@/types/home-dashboard'
import type { TimelineRichDetail, ShieldStatus } from '@/types/home-dashboard'

const noShield: ShieldStatus = { installed: false, online: false, deployment: 'none', capabilities: { dns: false, firewall: false } }
const shieldDns: ShieldStatus = { installed: true, online: true, deployment: 'standalone', capabilities: { dns: true, firewall: false } }
const shieldFull: ShieldStatus = { installed: true, online: true, deployment: 'router', capabilities: { dns: true, firewall: true } }
const shieldOffline: ShieldStatus = { installed: true, online: false, deployment: 'standalone', capabilities: { dns: true, firewall: false } }

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
    // Pass localIp matching dest of block event (192.168.1.1) for local "engellendi"
    const items = buildTimeline(mockFirewallEvents, [], [], [], {}, '192.168.1.1')

    expect(items[0]!.message).toContain('engellendi')
    expect(items[1]!.message).toContain('izin verildi')
  })

  it('generates rich detail for firewall events', () => {
    const { buildTimeline } = useTimeline()
    // Pass localIp matching dest so summary says "engellendi" (local perspective)
    const items = buildTimeline(mockFirewallEvents, [], [], [], {}, '192.168.1.1')

    const detail = items[0]!.detail
    expect(isRichDetail(detail)).toBe(true)
    const rich = detail as TimelineRichDetail
    expect(rich.summary).toContain('TCP')
    expect(rich.summary).toContain('engellendi')
    expect(rich.fields.some((f) => f.label === 'Protokol' && f.value === 'TCP')).toBe(true)
    expect(rich.fields.some((f) => f.label === 'Yon' && f.value === 'Gelen')).toBe(true)
  })

  it('uses "tespit edildi" in summary for remote device events', () => {
    const { buildTimeline } = useTimeline()
    const events: FirewallEvent[] = [
      { id: 'rem1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.50', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(events, [], [], [], {}, '192.168.1.103')
    const rich = items[0]!.detail as TimelineRichDetail

    expect(rich.summary).toContain('tespit edildi')
    expect(rich.summary).toContain('kalici koruma onerilir')
  })

  it('differentiates message for local vs remote device blocks', () => {
    const { buildTimeline } = useTimeline()
    const events: FirewallEvent[] = [
      { id: 'loc1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.103', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
      { id: 'rem1', timestamp: '2026-02-09T09:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.50', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(events, [], [], [], {}, '192.168.1.103')

    // Local: simple "engellendi"
    expect(items[0]!.message).toBe('1.2.3.4 → 192.168.1.103:443 engellendi')
    // Remote: "ag izleme ile tespit edildi"
    expect(items[1]!.message).toBe('1.2.3.4 → 192.168.1.50:443 — ag izleme ile tespit edildi')
  })

  it('includes threatContext for malicious IP', () => {
    const { buildTimeline } = useTimeline()
    const maliciousEvent: FirewallEvent[] = [
      { id: 'mal1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'rule_threat_001', source_ip: '45.33.32.156', dest_ip: '192.168.1.1', dest_port: 8443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(maliciousEvent, [], [], [])
    const rich = items[0]!.detail as TimelineRichDetail

    expect(rich.threatContext).toBeDefined()
    expect(rich.threatContext!.isKnownMalicious).toBe(true)
    expect(rich.threatContext!.reputation).toBe('malicious')
  })

  it('does not include "Kalici Engelle" for allow events', () => {
    const { buildTimeline } = useTimeline()
    const allowEvents: FirewallEvent[] = [
      { id: 'a1', timestamp: '2026-02-09T09:00:00Z', action: 'allow', rule_id: null, source_ip: '192.168.1.2', dest_ip: '8.8.8.8', dest_port: 53, protocol: 'udp', process_name: null, direction: 'outbound' },
    ]
    const items = buildTimeline(allowEvents, [], [], [])
    const rich = items[0]!.detail as TimelineRichDetail

    expect(rich.actions).toHaveLength(0)
  })

  it('includes direct block + rule actions for LOCAL device block events', () => {
    const { buildTimeline } = useTimeline()
    const blockEvents: FirewallEvent[] = [
      { id: 'b1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.1', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    // Pass localIp matching the dest (affected device for inbound)
    const items = buildTimeline(blockEvents, [], [], [], {}, '192.168.1.1')
    const rich = items[0]!.detail as TimelineRichDetail

    expect(rich.actions).toHaveLength(2)
    expect(rich.actions[0]!.handler).toBe('block-permanent')
    expect(rich.actions[0]!.suggested).toBeFalsy()
    expect(rich.actions[1]!.handler).toBe('view-rule')
  })

  it('includes suggested actions for REMOTE device block events (no shield)', () => {
    const { buildTimeline } = useTimeline()
    const blockEvents: FirewallEvent[] = [
      { id: 'b1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.50', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    // No shield installed → Shield Kur + DNS + Router (all suggested) + view-rule (direct)
    const items = buildTimeline(blockEvents, [], [], [], {}, '192.168.1.103', noShield)
    const rich = items[0]!.detail as TimelineRichDetail

    const suggested = rich.actions.filter((a) => a.suggested)
    const direct = rich.actions.filter((a) => !a.suggested)

    expect(suggested).toHaveLength(3)
    expect(suggested[0]!.handler).toBe('setup-shield')
    expect(suggested[1]!.handler).toBe('suggest-dns')
    expect(suggested[2]!.handler).toBe('suggest-router')
    expect(direct).toHaveLength(1)
    expect(direct[0]!.handler).toBe('view-rule')
  })

  it('includes direct shield-block for REMOTE when shield has firewall', () => {
    const { buildTimeline } = useTimeline()
    const blockEvents: FirewallEvent[] = [
      { id: 'b1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.50', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(blockEvents, [], [], [], {}, '192.168.1.103', shieldFull)
    const rich = items[0]!.detail as TimelineRichDetail

    const direct = rich.actions.filter((a) => !a.suggested)
    expect(direct).toHaveLength(3) // shield-block (firewall) + shield-block (dns) + view-rule
    expect(direct[0]!.handler).toBe('shield-block')
    expect(direct[0]!.label).toContain('Shield ile Engelle')
    expect(direct[1]!.handler).toBe('shield-block')
    expect(direct[1]!.label).toContain('DNS ile Engelle')
    expect(direct[2]!.handler).toBe('view-rule')
  })

  it('includes direct DNS block for REMOTE when shield has DNS only', () => {
    const { buildTimeline } = useTimeline()
    const blockEvents: FirewallEvent[] = [
      { id: 'b1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.50', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(blockEvents, [], [], [], {}, '192.168.1.103', shieldDns)
    const rich = items[0]!.detail as TimelineRichDetail

    const direct = rich.actions.filter((a) => !a.suggested)
    expect(direct).toHaveLength(2) // shield-block (dns) + view-rule
    expect(direct[0]!.handler).toBe('shield-block')
    expect(direct[0]!.label).toContain('DNS ile Engelle')
    expect(direct[1]!.handler).toBe('view-rule')
  })

  it('includes suggested actions when shield is offline', () => {
    const { buildTimeline } = useTimeline()
    const blockEvents: FirewallEvent[] = [
      { id: 'b1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.50', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(blockEvents, [], [], [], {}, '192.168.1.103', shieldOffline)
    const rich = items[0]!.detail as TimelineRichDetail

    const suggested = rich.actions.filter((a) => a.suggested)
    expect(suggested).toHaveLength(2) // DNS + Router (both suggested with offline note)
    expect(suggested[0]!.handler).toBe('suggest-dns')
    expect(suggested[0]!.suggestReason).toContain('cevrimdisi')
    expect(suggested[1]!.handler).toBe('suggest-router')
  })

  it('uses "Shield tarafindan engellendi" for remote events when shield active', () => {
    const { buildTimeline } = useTimeline()
    const events: FirewallEvent[] = [
      { id: 'rem1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'r1', source_ip: '1.2.3.4', dest_ip: '192.168.1.50', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(events, [], [], [], {}, '192.168.1.103', shieldFull)
    const rich = items[0]!.detail as TimelineRichDetail

    expect(rich.summary).toContain('Shield tarafindan engellendi')
    expect(rich.summary).not.toContain('kalici koruma onerilir')
  })

  it('includes process_name field when present', () => {
    const { buildTimeline } = useTimeline()
    const items = buildTimeline(mockFirewallEvents, [], [], [])

    // Second event (allow) has process_name: 'chrome'
    const allowDetail = items[1]!.detail as TimelineRichDetail
    expect(allowDetail.fields.some((f) => f.label === 'Islem' && f.value === 'chrome')).toBe(true)
  })

  it('includes ruleContext for ad-blocking rules', () => {
    const { buildTimeline } = useTimeline()
    const adEvent: FirewallEvent[] = [
      { id: 'ad1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'rule_ad_001', source_ip: '192.168.1.102', dest_ip: '104.21.67.89', dest_port: 443, protocol: 'tcp', process_name: 'smarttv-app', direction: 'outbound' },
    ]
    const items = buildTimeline(adEvent, [], [], [])
    const rich = items[0]!.detail as TimelineRichDetail

    expect(rich.ruleContext).toBeDefined()
    expect(rich.ruleContext!.category).toBe('ad')
    expect(rich.ruleContext!.label).toBe('Reklam Engellendi')
    expect(rich.ruleContext!.reason).toContain('smarttv-app')
    expect(rich.ruleContext!.bannerVariant).toBe('purple')
  })

  it('does not include ruleContext for unknown rule prefix', () => {
    const { buildTimeline } = useTimeline()
    const events: FirewallEvent[] = [
      { id: 'u1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: 'custom_rule', source_ip: '1.2.3.4', dest_ip: '192.168.1.1', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(events, [], [], [])
    const rich = items[0]!.detail as TimelineRichDetail

    expect(rich.ruleContext).toBeUndefined()
  })

  it('resolves device names in rich detail summary', () => {
    const { buildTimeline } = useTimeline()
    const lookup = { '192.168.1.1': 'Intel Corporate Cihaz' }
    const events: FirewallEvent[] = [
      { id: 'dl1', timestamp: '2026-02-09T10:00:00Z', action: 'block', rule_id: null, source_ip: '1.2.3.4', dest_ip: '192.168.1.1', dest_port: 443, protocol: 'tcp', process_name: null, direction: 'inbound' },
    ]
    const items = buildTimeline(events, [], [], [], lookup)
    const rich = items[0]!.detail as TimelineRichDetail

    expect(rich.summary).toContain('Intel Corporate Cihaz')
  })
})

import { ref } from 'vue'
import type {
  FirewallEvent,
  FamilyTimelineEntry,
  AssetChange,
  CollectiveSignalReport,
} from '@/types/api'
import type { TimelineItem, TimelineSeverity } from '@/types/home-dashboard'

type DeviceLookup = Record<string, string>

function resolveIp(ip: string, lookup: DeviceLookup): string {
  return lookup[ip] ?? ip
}

function firewallToTimeline(events: FirewallEvent[], lookup: DeviceLookup): TimelineItem[] {
  return events.map((e) => ({
    id: `fw_${e.id}`,
    source: 'firewall' as const,
    severity: e.action === 'block' ? 'medium' as TimelineSeverity : 'info' as TimelineSeverity,
    message: e.action === 'block'
      ? `${resolveIp(e.source_ip, lookup)} → ${resolveIp(e.dest_ip, lookup)}:${e.dest_port} engellendi`
      : `${resolveIp(e.source_ip, lookup)} → ${resolveIp(e.dest_ip, lookup)}:${e.dest_port} izin verildi`,
    detail: [
      `Protokol: ${e.protocol.toUpperCase()}`,
      `Yon: ${e.direction === 'inbound' ? 'Gelen' : 'Giden'}`,
      e.process_name ? `Islem: ${e.process_name}` : null,
      e.rule_id ? `Kural: ${e.rule_id}` : null,
    ].filter(Boolean).join(' | '),
    timestamp: e.timestamp,
    icon: e.action === 'block' ? '🛡️' : '✅',
  }))
}

function familyToTimeline(entries: FamilyTimelineEntry[]): TimelineItem[] {
  return entries.map((e) => {
    let severity: TimelineSeverity = 'info'
    if (e.event_type === 'threat_blocked') severity = 'high'
    if (e.event_type === 'device_offline') severity = 'low'

    return {
      id: `fam_${e.id}`,
      source: 'family' as const,
      severity,
      message: `${e.device_icon} ${e.device_name}: ${e.message}`,
      detail: null,
      timestamp: e.timestamp,
      icon: e.device_icon,
    }
  })
}

function changesToTimeline(changes: AssetChange[], lookup: DeviceLookup): TimelineItem[] {
  return changes.map((c) => ({
    id: `chg_${c.id}`,
    source: 'change' as const,
    severity: c.change_type === 'new' ? 'medium' as TimelineSeverity : 'info' as TimelineSeverity,
    message: c.change_type === 'new'
      ? `Yeni cihaz: ${resolveIp(c.ip, lookup)}`
      : `${resolveIp(c.ip, lookup)} - ${c.field_name ?? 'alan'} degisti`,
    detail: c.old_value || c.new_value
      ? `${c.old_value ?? '(yok)'} → ${c.new_value ?? '(yok)'}`
      : null,
    timestamp: c.detected_at,
    icon: c.change_type === 'new' ? '📡' : '🔄',
  }))
}

function collectiveToTimeline(threats: CollectiveSignalReport[]): TimelineItem[] {
  return threats.map((t, i) => ({
    id: `col_${i}`,
    source: 'collective' as const,
    severity: t.avg_severity > 7 ? 'critical' as TimelineSeverity : t.avg_severity > 4 ? 'high' as TimelineSeverity : 'medium' as TimelineSeverity,
    message: `Topluluk uyarisi: ${t.signal_type} (${t.reporter_count} raportör)`,
    detail: `Guven: %${Math.round(t.confidence * 100)} | Dogrulanmis: ${t.is_verified ? 'Evet' : 'Hayir'}`,
    timestamp: t.last_seen,
    icon: '🌐',
  }))
}

export function useTimeline() {
  const visibleCount = ref(5)
  const expandedIds = ref<Set<string>>(new Set())

  function buildTimeline(
    firewallEvents: FirewallEvent[],
    familyEntries: FamilyTimelineEntry[],
    changesList: AssetChange[],
    collectiveThreats: CollectiveSignalReport[],
    deviceLookup: DeviceLookup = {},
  ): TimelineItem[] {
    const all = [
      ...firewallToTimeline(firewallEvents, deviceLookup),
      ...familyToTimeline(familyEntries),
      ...changesToTimeline(changesList, deviceLookup),
      ...collectiveToTimeline(collectiveThreats),
    ]

    // Sort by timestamp descending (newest first)
    all.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    return all
  }

  function toggleExpand(id: string) {
    if (expandedIds.value.has(id)) {
      expandedIds.value.delete(id)
    } else {
      expandedIds.value.add(id)
    }
  }

  function isExpanded(id: string): boolean {
    return expandedIds.value.has(id)
  }

  function showMore() {
    visibleCount.value += 5
  }

  return {
    visibleCount,
    expandedIds,
    buildTimeline,
    toggleExpand,
    isExpanded,
    showMore,
  }
}

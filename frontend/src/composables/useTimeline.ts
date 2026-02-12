import { ref } from 'vue'
import type {
  FirewallEvent,
  FamilyTimelineEntry,
  AssetChange,
  CollectiveSignalReport,
  TrackerEvent,
} from '@/types/api'
import type {
  TimelineItem,
  TimelineSeverity,
  TimelineRichDetail,
  TimelineDetailField,
  TimelineDetailAction,
  ShieldStatus,
} from '@/types/home-dashboard'
import { getThreatContext } from '@/lib/threat-intel'
import { getRuleCategory, buildBlockReason } from '@/lib/rule-descriptions'

type DeviceLookup = Record<string, string>

const defaultShield: ShieldStatus = {
  installed: false,
  online: false,
  deployment: 'none',
  capabilities: { dns: false, firewall: false },
}

function resolveIp(ip: string, lookup: DeviceLookup): string {
  return lookup[ip] ?? ip
}

function isLocalDevice(ip: string, localIp: string | null): boolean {
  if (!localIp) return false
  return ip === localIp
}

function buildRemoteActions(blockTargetIp: string, shield: ShieldStatus): TimelineDetailAction[] {
  const actions: TimelineDetailAction[] = []

  if (shield.installed && shield.online) {
    // Shield active — direct actions based on capabilities
    if (shield.capabilities.firewall) {
      actions.push({
        label: 'Shield ile Engelle',
        variant: 'danger',
        icon: '🛡️',
        handler: 'shield-block',
        metadata: { ip: blockTargetIp },
      })
    }
    if (shield.capabilities.dns) {
      actions.push({
        label: 'DNS ile Engelle',
        variant: 'primary',
        icon: '🌐',
        handler: 'shield-block',
        metadata: { ip: blockTargetIp, method: 'dns' },
      })
    }
  } else if (shield.installed && !shield.online) {
    // Shield installed but offline — suggested actions with warning
    actions.push({
      label: 'DNS ile Kalici Engelle',
      variant: 'primary',
      icon: '🌐',
      handler: 'suggest-dns',
      metadata: { ip: blockTargetIp },
      suggested: true,
      suggestReason: 'Shield cevrimdisi — yeniden baslatildiginda uygulanacak',
    })
    actions.push({
      label: "Router'da Kalici Engelle",
      variant: 'secondary',
      icon: '📡',
      handler: 'suggest-router',
      metadata: { ip: blockTargetIp },
      suggested: true,
      suggestReason: "Router'a kalici kural ekleyerek bu IP'nin tekrar erisimini engelleyin",
    })
  } else {
    // No shield — suggest setup + manual actions
    actions.push({
      label: 'Shield Kur',
      variant: 'primary',
      icon: '🛡️',
      handler: 'setup-shield',
      metadata: { ip: blockTargetIp },
      suggested: true,
      suggestReason: 'Shield kurarak tum ag cihazlarinizi kalici olarak koruyun',
    })
    actions.push({
      label: 'DNS ile Kalici Engelle',
      variant: 'secondary',
      icon: '🌐',
      handler: 'suggest-dns',
      metadata: { ip: blockTargetIp },
      suggested: true,
      suggestReason: 'Mevcut engelleme gecici — DNS filtreleme tum agi kalici olarak korur',
    })
    actions.push({
      label: "Router'da Kalici Engelle",
      variant: 'secondary',
      icon: '📡',
      handler: 'suggest-router',
      metadata: { ip: blockTargetIp },
      suggested: true,
      suggestReason: "Router'a kalici kural ekleyerek bu IP'nin tekrar erisimini engelleyin",
    })
  }

  return actions
}

function buildFirewallRichDetail(e: FirewallEvent, lookup: DeviceLookup, localIp: string | null, shield: ShieldStatus): TimelineRichDetail {
  const srcName = resolveIp(e.source_ip, lookup)
  const dstName = resolveIp(e.dest_ip, lookup)
  const dirLabel = e.direction === 'inbound' ? 'Gelen' : 'Giden'
  const proto = e.protocol.toUpperCase()

  // Determine locality early — needed for summary wording
  const affectedDeviceIp = e.direction === 'inbound' ? e.dest_ip : e.source_ip
  const isLocal = isLocalDevice(affectedDeviceIp, localIp)

  let summary: string
  if (e.action === 'block') {
    if (isLocal) {
      summary = e.direction === 'inbound'
        ? `${srcName} adresindan gelen ${proto} baglantisi engellendi.`
        : `${dstName}:${e.dest_port} adresine giden ${proto} baglantisi engellendi.`
    } else if (shield.installed && shield.online) {
      const deviceName = e.direction === 'inbound' ? dstName : srcName
      summary = e.direction === 'inbound'
        ? `${srcName} adresindan ${deviceName} cihazina yonelik ${proto} baglantisi Shield tarafindan engellendi.`
        : `${deviceName} cihazindan ${dstName}:${e.dest_port} adresine giden ${proto} baglantisi Shield tarafindan engellendi.`
    } else {
      const deviceName = e.direction === 'inbound' ? dstName : srcName
      summary = e.direction === 'inbound'
        ? `${srcName} adresindan ${deviceName} cihazina yonelik ${proto} baglantisi tespit edildi. Mevcut kural ile engellendi ancak kalici koruma onerilir.`
        : `${deviceName} cihazindan ${dstName}:${e.dest_port} adresine giden ${proto} baglantisi tespit edildi. Mevcut kural ile engellendi ancak kalici koruma onerilir.`
    }
  } else {
    summary = e.direction === 'inbound'
      ? `${srcName} adresindan ${dstName}:${e.dest_port} portuna gelen ${proto} baglantisina izin verildi.`
      : `${srcName} adresindan ${dstName}:${e.dest_port} portuna giden ${proto} baglantisina izin verildi.`
  }

  const fields: TimelineDetailField[] = [
    { icon: '🔌', label: 'Protokol', value: proto },
    { icon: e.direction === 'inbound' ? '↙️' : '↗️', label: 'Yon', value: dirLabel },
  ]
  if (e.process_name) {
    fields.push({ icon: '⚙️', label: 'Islem', value: e.process_name })
  }
  if (e.rule_id) {
    fields.push({ icon: '📋', label: 'Kural', value: e.rule_id })
  }

  const actions: TimelineDetailAction[] = []
  if (e.action === 'block') {
    const blockTargetIp = e.direction === 'inbound' ? e.source_ip : e.dest_ip

    if (isLocal) {
      // Local device: direct action — agent can apply iptables/pf rules
      actions.push({
        label: 'Kalici Engelle',
        variant: 'danger',
        icon: '🚫',
        handler: 'block-permanent',
        metadata: { ip: blockTargetIp },
      })
    } else {
      // Remote device: actions depend on Shield status
      actions.push(...buildRemoteActions(blockTargetIp, shield))
    }
    if (e.rule_id) {
      actions.push({
        label: 'Kural Detayi',
        variant: 'secondary',
        icon: '📋',
        handler: 'view-rule',
        metadata: { ruleId: e.rule_id },
      })
    }
  }

  const threatContext = getThreatContext(e.source_ip, e.dest_ip, e.direction)

  const ruleCat = getRuleCategory(e.rule_id)
  const reason = buildBlockReason(e.rule_id, e.process_name)
  const ruleContext = ruleCat && reason
    ? { category: ruleCat.category, label: ruleCat.label, reason, bannerVariant: ruleCat.bannerVariant }
    : undefined

  return { summary, fields, actions, threatContext, ruleContext }
}

function buildFirewallMessage(e: FirewallEvent, lookup: DeviceLookup, localIp: string | null): string {
  const src = resolveIp(e.source_ip, lookup)
  const dst = resolveIp(e.dest_ip, lookup)
  const affectedIp = e.direction === 'inbound' ? e.dest_ip : e.source_ip
  const isLocal = isLocalDevice(affectedIp, localIp)

  if (e.action !== 'block') {
    return `${src} → ${dst}:${e.dest_port} izin verildi`
  }

  if (isLocal) {
    return `${src} → ${dst}:${e.dest_port} engellendi`
  }

  // Remote device — clarify this is observed, not directly blocked by agent
  return `${src} → ${dst}:${e.dest_port} — ag izleme ile tespit edildi`
}

function firewallToTimeline(events: FirewallEvent[], lookup: DeviceLookup, localIp: string | null, shield: ShieldStatus): TimelineItem[] {
  return events.map((e) => ({
    id: `fw_${e.id}`,
    source: 'firewall' as const,
    severity: e.action === 'block' ? 'medium' as TimelineSeverity : 'info' as TimelineSeverity,
    message: buildFirewallMessage(e, lookup, localIp),
    detail: buildFirewallRichDetail(e, lookup, localIp, shield),
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

const _trackerCategoryLabels: Record<string, string> = {
  advertising: 'reklam sunucusu',
  analytics: 'analitik takipci',
  social: 'sosyal medya pikseli',
  fingerprinting: 'parmak izi okuyucu',
}

function trackerToTimeline(events: TrackerEvent[]): TimelineItem[] {
  return events.map((e, i) => ({
    id: `trk_${i}`,
    source: 'tracker' as const,
    severity: 'medium' as TimelineSeverity,
    message: `${e.domain} engellendi — ${_trackerCategoryLabels[e.category] || e.category}`,
    detail: `${e.block_count} kez engellendi`,
    timestamp: e.last_blocked || new Date().toISOString(),
    icon: '🚫',
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
    localIp: string | null = null,
    shield: ShieldStatus = defaultShield,
    trackerEventsList: TrackerEvent[] = [],
  ): TimelineItem[] {
    const all = [
      ...firewallToTimeline(firewallEvents, deviceLookup, localIp, shield),
      ...familyToTimeline(familyEntries),
      ...changesToTimeline(changesList, deviceLookup),
      ...collectiveToTimeline(collectiveThreats),
      ...trackerToTimeline(trackerEventsList),
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

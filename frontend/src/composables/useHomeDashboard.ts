import { ref, computed } from 'vue'
import { bigrApi } from '@/lib/api'
import { buildDeviceLookup } from '@/lib/device-icons'
import type {
  ComplianceResponse,
  RiskResponse,
  CertificatesResponse,
  FamilyOverview,
  FamilyAlert,
  FamilyTimelineEntry,
  CollectiveStats,
  ContributionStatus,
  FirewallDailyStats,
  FirewallEvent,
  AssetChange,
  HumanNotification,
} from '@/types/api'
import type {
  KalkanData,
  KalkanState,
  VerilerimCard,
  AilemCard,
  EvimCard,
  BolgemCard,
  HomeDashboardData,
} from '@/types/home-dashboard'

export function useHomeDashboard() {
  const loading = ref(false)
  const error = ref<string | null>(null)

  // Raw API data
  const compliance = ref<ComplianceResponse | null>(null)
  const risk = ref<RiskResponse | null>(null)
  const certificates = ref<CertificatesResponse | null>(null)
  const family = ref<FamilyOverview | null>(null)
  const familyAlerts = ref<FamilyAlert[]>([])
  const familyTimeline = ref<FamilyTimelineEntry[]>([])
  const collectiveStats = ref<CollectiveStats | null>(null)
  const contribution = ref<ContributionStatus | null>(null)
  const firewallDailyStats = ref<FirewallDailyStats | null>(null)
  const firewallEvents = ref<FirewallEvent[]>([])
  const changes = ref<AssetChange[]>([])
  const notifications = ref<HumanNotification[]>([])
  const assets = ref<{ total_assets: number; assets: { ip: string; mac: string; hostname: string | null; vendor: string | null; first_seen: string | null }[] } | null>(null)

  function calcKalkanState(score: number): KalkanState {
    if (score >= 80) return 'green'
    if (score >= 50) return 'yellow'
    return 'red'
  }

  function calcKalkanMessage(state: KalkanState, deviceCount: number): string {
    switch (state) {
      case 'green':
        return `Aileniz guvende. ${deviceCount} cihaz koruma altinda.`
      case 'yellow':
        return `Dikkat gerektiren durumlar var. ${deviceCount} cihaz izleniyor.`
      case 'red':
        return `Acil mudahale gerekiyor! ${deviceCount} cihaz risk altinda.`
    }
  }

  const kalkan = computed<KalkanData>(() => {
    const compScore = compliance.value?.compliance_score ?? 75
    const riskAvg = risk.value?.average_risk ?? 30
    const fwStats = firewallDailyStats.value
    const fwScore = fwStats ? Math.min(100, 100 - (fwStats.block_rate > 10 ? 30 : fwStats.block_rate > 5 ? 15 : 0)) : 80

    const score = Math.round(compScore * 0.4 + (100 - riskAvg) * 0.3 + fwScore * 0.3)
    const state = calcKalkanState(score)
    const deviceCount = family.value?.devices.length ?? assets.value?.total_assets ?? 0
    const blockedThisMonth = fwStats?.blocked ?? 0

    return {
      score,
      state,
      message: calcKalkanMessage(state, deviceCount),
      deviceCount,
      blockedThisMonth,
      complianceScore: compScore,
      riskScore: riskAvg,
      firewallScore: fwScore,
    }
  })

  const verilerim = computed<VerilerimCard>(() => {
    const certs = certificates.value?.certificates ?? []
    const httpsCount = certs.filter((c) => c.port === 443).length
    const expiringCerts = certs.filter((c) => c.days_until_expiry !== null && c.days_until_expiry <= 30).length
    const selfSignedCerts = certs.filter((c) => c.is_self_signed).length

    return {
      httpsCount,
      totalCertificates: certs.length,
      expiringCerts,
      selfSignedCerts,
      complianceGrade: compliance.value?.grade ?? '-',
    }
  })

  const ailem = computed<AilemCard>(() => {
    const fam = family.value
    if (!fam) {
      return {
        familyName: '',
        devices: [],
        totalThreats: 0,
        avgSafetyScore: 0,
        devicesOnline: 0,
      }
    }
    return {
      familyName: fam.family_name,
      devices: fam.devices.map((d) => ({
        id: d.id,
        name: d.name,
        icon: d.icon,
        ownerName: d.owner_name,
        isOnline: d.is_online,
        safetyLevel: d.safety_level,
      })),
      totalThreats: fam.total_threats,
      avgSafetyScore: fam.avg_safety_score,
      devicesOnline: fam.devices_online,
    }
  })

  const evim = computed<EvimCard>(() => {
    const assetList = assets.value?.assets ?? []
    const deviceTypes: Record<string, number> = {}
    for (const a of assetList) {
      const vendor = a.vendor ?? 'Bilinmeyen'
      deviceTypes[vendor] = (deviceTypes[vendor] ?? 0) + 1
    }

    // New devices = first seen in last 7 days
    const weekAgo = new Date()
    weekAgo.setDate(weekAgo.getDate() - 7)
    const newDevices = assetList
      .filter((a) => a.first_seen && new Date(a.first_seen) > weekAgo)
      .map((a) => ({
        ip: a.ip,
        mac: a.mac,
        hostname: a.hostname,
        vendor: a.vendor,
        firstSeen: a.first_seen,
      }))

    return {
      totalDevices: assets.value?.total_assets ?? 0,
      deviceTypes,
      newDevices,
      lastScan: family.value?.last_scan ?? null,
    }
  })

  const bolgem = computed<BolgemCard>(() => {
    const stats = collectiveStats.value
    const contrib = contribution.value
    return {
      communityScore: stats?.community_protection_score ?? 0,
      activeAgents: stats?.active_agents ?? 0,
      verifiedThreats: stats?.verified_threats ?? 0,
      isContributing: contrib?.is_contributing ?? false,
      signalsContributed: contrib?.signals_contributed ?? 0,
      signalsReceived: contrib?.signals_received ?? 0,
    }
  })

  const deviceLookup = computed<Record<string, string>>(() =>
    buildDeviceLookup(assets.value?.assets ?? []),
  )

  // The IP of the machine running the BİGR agent.
  // In production this would come from /api/agent/info.
  // In demo mode we use 192.168.1.103 (the unclassified device running chrome).
  const localIp = ref<string | null>('192.168.1.103')

  const dashboardData = computed<HomeDashboardData>(() => ({
    kalkan: kalkan.value,
    verilerim: verilerim.value,
    ailem: ailem.value,
    evim: evim.value,
    bolgem: bolgem.value,
  }))

  async function fetchDashboard() {
    loading.value = true
    error.value = null

    const results = await Promise.allSettled([
      bigrApi.getCompliance(),                          // 0
      bigrApi.getRisk(),                                // 1
      bigrApi.getCertificates(),                        // 2
      bigrApi.getFamilyOverview('default'),             // 3
      bigrApi.getFamilyAlerts('default', 20),           // 4
      bigrApi.getFamilyTimeline('default', 30),         // 5
      bigrApi.getCollectiveStats(),                     // 6
      bigrApi.getContributionStatus(),                  // 7
      bigrApi.getFirewallDailyStats(),                  // 8
      bigrApi.getFirewallEvents(50),                    // 9
      bigrApi.getChanges(20),                           // 10
      bigrApi.getAssets(),                              // 11
    ])

    // Extract data from settled results — each card degrades independently
    if (results[0]!.status === 'fulfilled') compliance.value = results[0]!.value.data
    if (results[1]!.status === 'fulfilled') risk.value = results[1]!.value.data
    if (results[2]!.status === 'fulfilled') certificates.value = results[2]!.value.data
    if (results[3]!.status === 'fulfilled') family.value = results[3]!.value.data
    if (results[4]!.status === 'fulfilled') familyAlerts.value = results[4]!.value.data
    if (results[5]!.status === 'fulfilled') familyTimeline.value = results[5]!.value.data
    if (results[6]!.status === 'fulfilled') collectiveStats.value = results[6]!.value.data
    if (results[7]!.status === 'fulfilled') contribution.value = results[7]!.value.data
    if (results[8]!.status === 'fulfilled') firewallDailyStats.value = results[8]!.value.data
    if (results[9]!.status === 'fulfilled') firewallEvents.value = results[9]!.value.data.events
    if (results[10]!.status === 'fulfilled') changes.value = results[10]!.value.data.changes
    if (results[11]!.status === 'fulfilled') {
      const d = results[11]!.value.data
      assets.value = { total_assets: d.total_assets, assets: d.assets.map((a) => ({ ip: a.ip, mac: a.mac, hostname: a.hostname, vendor: a.vendor, first_seen: a.first_seen })) }
    }

    // If ALL failed, set error
    const allFailed = results.every((r) => r.status === 'rejected')
    if (allFailed) {
      error.value = 'Veriler yuklenemedi. Lutfen tekrar deneyin.'
    }

    loading.value = false
  }

  return {
    loading,
    error,
    dashboardData,
    kalkan,
    verilerim,
    ailem,
    evim,
    bolgem,
    deviceLookup,
    localIp,
    firewallEvents,
    familyTimeline,
    familyAlerts,
    changes,
    notifications,
    fetchDashboard,
  }
}

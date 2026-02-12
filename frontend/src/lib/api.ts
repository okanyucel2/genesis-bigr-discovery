import axios from 'axios'
import type { AxiosResponse } from 'axios'
import type {
  FirewallStatus,
  FirewallRulesResponse,
  FirewallRule,
  FirewallEventsResponse,
  FirewallConfig,
  FirewallDailyStats,
  AssetsResponse,
  AssetDetailResponse,
  ScansResponse,
  ChangesResponse,
  SubnetsResponse,
  SwitchesResponse,
  TopologyResponse,
  ComplianceResponse,
  AnalyticsResponse,
  RiskResponse,
  VulnerabilitiesResponse,
  CertificatesResponse,
  HealthResponse,
  AgentsResponse,
  AgentCommandsResponse,
  CreateCommandResponse,
  SitesResponse,
  NetworksResponse,
  ShieldFindingsListResponse,
  OnboardingStartResponse,
  OnboardingStatusResponse,
  OnboardingNameResponse,
  OnboardingCompleteResponse,
  PlansResponse,
  SubscriptionInfo,
  ActivatePlanResponse,
  UsageInfo,
  TierAccessInfo,
  RemediationPlan,
  RemediationHistoryResponse,
  RemediationExecuteResponse,
  DeadManStatusResponse,
  DeadManStatus,
  DeadManSwitchConfig,
  AbuseIPDBCheck,
  AbuseIPDBStatus,
  AbuseIPDBBlacklistResponse,
  AbuseIPDBEnrichment,
  AbuseIPDBSettings,
  AbuseIPDBSettingsUpdate,
  AbuseIPDBTestResult,
  HumanizeRequest,
  HumanizeResponse,
  HumanizeBatchResponse,
  SampleNotificationsResponse,
  CollectiveThreatsResponse,
  CollectiveStats,
  ContributionStatus,
  CollectiveFeedResponse,
  FamilyOverview,
  FamilyDevice,
  FamilyAlert,
  FamilyTimelineEntry,
  AddDeviceRequest,
  UpdateDeviceRequest,
  GuardianStatusResponse,
  GuardianStatsResponse,
  GuardianRulesResponse,
  GuardianBlocklistsResponse,
  GuardianHealthResponse,
  WatcherStatus,
  WatcherHistoryResponse,
  WatcherAlertsResponse,
  StreakResponse,
} from '@/types/api'
import type { ShieldScanResponse, ShieldFindingsResponse, ShieldModulesResponse } from '@/types/shield'
import {
  mockAssets,
  mockAssetDetail,
  mockScans,
  mockChanges,
  mockSubnets,
  mockSwitches,
  mockTopology,
  mockTopologySubnet,
  mockCompliance,
  mockAnalytics,
  mockRisk,
  mockVulnerabilities,
  mockCertificates,
  mockHealth,
  mockShieldScan,
  mockShieldFindings,
  mockShieldModules,
  mockFirewallDailyStats,
  mockCollectiveStats,
  mockContributionStatus,
  mockFamilyOverview,
  mockFamilyTimeline,
  mockFamilyAlerts,
  mockFirewallEvents,
  mockSampleNotifications,
  mockGuardianStatus,
  mockGuardianStats,
  mockGuardianRules,
  mockGuardianBlocklists,
  mockGuardianHealth,
  mockWatcherStatus,
  mockWatcherHistory,
  mockWatcherAlerts,
  mockFirewallStatus,
  mockFirewallRules,
  mockFirewallConfig,
  mockAgents,
  mockSites,
  mockNetworks,
  mockAgentCommands,
  mockAgentShieldFindings,
  mockOnboardingStart,
  mockOnboardingStatus,
  mockPlans,
  mockCurrentSubscription,
  mockUsage,
  mockTierAccess,
  mockRemediationPlan,
  mockRemediationHistory,
  mockDeadManStatus,
  mockAbuseIPDBSettings,
  mockCollectiveThreats,
  mockCollectiveFeed,
  mockFamilyDevices,
  mockStreak,
} from '@/lib/mock-data'

const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true'

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 30000,
})

/** Wrap data in an AxiosResponse-shaped object for demo mode. */
function mockResponse<T>(data: T): Promise<AxiosResponse<T>> {
  return new Promise((resolve) => {
    // Simulate a small network delay (50-150ms) to feel realistic
    setTimeout(() => {
      resolve({
        data,
        status: 200,
        statusText: 'OK',
        headers: {},
        config: {} as AxiosResponse['config'],
      })
    }, 50 + Math.random() * 100)
  })
}

export const bigrApi = {
  getAssets: (subnet?: string, site?: string, network?: string) => {
    if (DEMO_MODE) return mockResponse(mockAssets(subnet))
    const params: Record<string, string> = {}
    if (subnet) params.subnet = subnet
    if (site) params.site = site
    if (network) params.network = network
    return client.get<AssetsResponse>('/api/data', { params })
  },

  getAssetDetail: (ip: string) =>
    DEMO_MODE
      ? mockResponse(mockAssetDetail(ip))
      : client.get<AssetDetailResponse>(`/api/assets/${ip}`),

  getScans: () =>
    DEMO_MODE
      ? mockResponse(mockScans())
      : client.get<ScansResponse>('/api/scans'),

  getChanges: (limit = 50, site?: string) => {
    if (DEMO_MODE) return mockResponse(mockChanges())
    const params: Record<string, string | number> = { limit }
    if (site) params.site = site
    return client.get<ChangesResponse>('/api/changes', { params })
  },

  getSubnets: () =>
    DEMO_MODE
      ? mockResponse(mockSubnets())
      : client.get<SubnetsResponse>('/api/subnets'),

  getSwitches: () =>
    DEMO_MODE
      ? mockResponse(mockSwitches())
      : client.get<SwitchesResponse>('/api/switches'),

  getTopology: () =>
    DEMO_MODE
      ? mockResponse(mockTopology())
      : client.get<TopologyResponse>('/api/topology'),

  getTopologySubnet: (cidr: string) =>
    DEMO_MODE
      ? mockResponse(mockTopologySubnet(cidr))
      : client.get<TopologyResponse>(`/api/topology/subnet/${encodeURIComponent(cidr)}`),

  getCompliance: () =>
    DEMO_MODE
      ? mockResponse(mockCompliance())
      : client.get<ComplianceResponse>('/api/compliance'),

  getAnalytics: (days = 30) =>
    DEMO_MODE
      ? mockResponse(mockAnalytics())
      : client.get<AnalyticsResponse>('/api/analytics', { params: { days } }),

  getRisk: () =>
    DEMO_MODE
      ? mockResponse(mockRisk())
      : client.get<RiskResponse>('/api/risk'),

  getVulnerabilities: () =>
    DEMO_MODE
      ? mockResponse(mockVulnerabilities())
      : client.get<VulnerabilitiesResponse>('/api/vulnerabilities'),

  getCertificates: () =>
    DEMO_MODE
      ? mockResponse(mockCertificates())
      : client.get<CertificatesResponse>('/api/certificates'),

  getHealth: () =>
    DEMO_MODE
      ? mockResponse(mockHealth())
      : client.get<HealthResponse>('/api/health'),

  getAgents: () =>
    DEMO_MODE
      ? mockResponse({ agents: mockAgents() })
      : client.get<AgentsResponse>('/api/agents'),

  deleteAgent: (agentId: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', deleted: agentId })
      : client.delete<{ status: string; deleted: string }>(`/api/agents/${agentId}`),

  getSites: () =>
    DEMO_MODE
      ? mockResponse({ sites: mockSites() })
      : client.get<SitesResponse>('/api/sites'),

  createAgentCommand: (agentId: string, targets?: string[], shield?: boolean) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', command_id: 'cmd_demo', agent_id: agentId, command_type: 'scan_now', targets: targets || [], shield: shield ?? true })
      : client.post<CreateCommandResponse>(`/api/agents/${agentId}/commands`, {
          command_type: 'scan_now',
          targets: targets || [],
          shield: shield ?? true,
        }),

  getAgentCommands: (agentId: string, status?: string) => {
    if (DEMO_MODE) return mockResponse({ commands: mockAgentCommands(), count: 1 })
    const params: Record<string, string> = {}
    if (status) params.status = status
    return client.get<AgentCommandsResponse>(`/api/agents/${agentId}/commands`, { params })
  },

  getNetworks: () =>
    DEMO_MODE
      ? mockResponse({ networks: mockNetworks() })
      : client.get<NetworksResponse>('/api/networks'),

  renameNetwork: (networkId: string, friendlyName: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok' })
      : client.put(`/api/networks/${networkId}`, { friendly_name: friendlyName }),

  // Firewall
  getFirewallStatus: () =>
    DEMO_MODE
      ? mockResponse(mockFirewallStatus())
      : client.get<FirewallStatus>('/api/firewall/status'),

  getFirewallRules: (ruleType?: string, activeOnly = true) => {
    if (DEMO_MODE) {
      const rules = mockFirewallRules().filter(r => !ruleType || r.rule_type === ruleType)
      return mockResponse({ rules, total: rules.length })
    }
    const params: Record<string, string | boolean> = { active_only: activeOnly }
    if (ruleType) params.rule_type = ruleType
    return client.get<FirewallRulesResponse>('/api/firewall/rules', { params })
  },

  addFirewallRule: (rule: Partial<FirewallRule>) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', rule: { ...rule, id: 'fw_demo' } as FirewallRule, message: 'Kural eklendi.' })
      : client.post<{ status: string; rule: FirewallRule; message: string }>('/api/firewall/rules', rule),

  removeFirewallRule: (ruleId: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', message: 'Kural silindi.', rule_id: ruleId })
      : client.delete<{ status: string; message: string; rule_id: string }>(`/api/firewall/rules/${ruleId}`),

  toggleFirewallRule: (ruleId: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', rule: mockFirewallRules()[0], message: 'Kural durumu degistirildi.' })
      : client.put<{ status: string; rule: FirewallRule; message: string }>(`/api/firewall/rules/${ruleId}/toggle`),

  syncFirewallThreats: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', rules_created: 2, message: '2 tehdit kurali eklendi.' })
      : client.post<{ status: string; rules_created: number; message: string }>('/api/firewall/sync/threats'),

  syncFirewallPorts: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', rules_created: 1, message: '1 port kurali eklendi.' })
      : client.post<{ status: string; rules_created: number; message: string }>('/api/firewall/sync/ports'),

  syncFirewallShield: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', rules_created: 1, findings_checked: 5, message: '1 shield kurali eklendi.' })
      : client.post<{ status: string; rules_created: number; findings_checked: number; message: string }>('/api/firewall/sync/shield'),

  getFirewallEvents: (limit = 100, action?: string) => {
    if (DEMO_MODE) return mockResponse({ events: mockFirewallEvents().slice(0, limit), total: mockFirewallEvents().length })
    const params: Record<string, string | number> = { limit }
    if (action) params.action = action
    return client.get<FirewallEventsResponse>('/api/firewall/events', { params })
  },

  getFirewallConfig: () =>
    DEMO_MODE
      ? mockResponse(mockFirewallConfig())
      : client.get<FirewallConfig>('/api/firewall/config'),

  updateFirewallConfig: (config: FirewallConfig) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', config, message: 'Yapilandirma guncellendi.' })
      : client.put<{ status: string; config: FirewallConfig; message: string }>('/api/firewall/config', config),

  getFirewallDailyStats: () =>
    DEMO_MODE
      ? mockResponse(mockFirewallDailyStats())
      : client.get<FirewallDailyStats>('/api/firewall/stats/daily'),

  installFirewallAdapter: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', message: 'Adapter yuklendi.' })
      : client.post<{ status: string; message: string }>('/api/firewall/adapter/install'),

  getAgentShieldFindings: (site?: string, severity?: string) => {
    if (DEMO_MODE) {
      let findings = mockAgentShieldFindings()
      if (site) findings = findings.filter(f => f.site_name === site)
      if (severity) findings = findings.filter(f => f.severity === severity)
      const counts: Record<string, number> = {}
      findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1 })
      return mockResponse({ findings, total: findings.length, severity_counts: counts })
    }
    const params: Record<string, string> = {}
    if (site) params.site = site
    if (severity) params.severity = severity
    return client.get<ShieldFindingsListResponse>('/api/shield-findings', { params })
  },

  // Shield
  startShieldScan: (target: string, depth?: string, modules?: string[], sensitivity?: string) =>
    DEMO_MODE
      ? mockResponse<ShieldScanResponse>(mockShieldScan())
      : client.post<ShieldScanResponse>('/api/shield/scan', null, { params: { target, depth: depth || 'quick', modules: modules?.join(','), sensitivity } }),

  getShieldScan: (scanId: string) =>
    DEMO_MODE
      ? mockResponse<ShieldScanResponse>(mockShieldScan(scanId))
      : client.get<ShieldScanResponse>(`/api/shield/scan/${scanId}`),

  getShieldFindings: (scanId: string) =>
    DEMO_MODE
      ? mockResponse<ShieldFindingsResponse>(mockShieldFindings(scanId))
      : client.get<ShieldFindingsResponse>(`/api/shield/scan/${scanId}/findings`),

  getShieldModules: () =>
    DEMO_MODE
      ? mockResponse<ShieldModulesResponse>(mockShieldModules())
      : client.get<ShieldModulesResponse>('/api/shield/modules'),

  // Onboarding
  startOnboarding: () =>
    DEMO_MODE
      ? mockResponse(mockOnboardingStart())
      : client.post<OnboardingStartResponse>('/api/onboarding/start'),

  getOnboardingStatus: () =>
    DEMO_MODE
      ? mockResponse(mockOnboardingStatus())
      : client.get<OnboardingStatusResponse>('/api/onboarding/status'),

  nameNetwork: (networkId: string, name: string, type: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', network_id: networkId, name, type, updated: true, message: 'Ag adlandirildi.' })
      : client.post<OnboardingNameResponse>('/api/onboarding/name-network', {
          network_id: networkId,
          name,
          type,
        }),

  completeOnboarding: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', message: 'Kurulum tamamlandi!', motto: 'Aginiz artik BİGR korumasi altinda.' })
      : client.post<OnboardingCompleteResponse>('/api/onboarding/complete'),

  resetOnboarding: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok' })
      : client.post('/api/onboarding/reset'),

  // Subscription & Pricing
  getPlans: () =>
    DEMO_MODE
      ? mockResponse({ plans: mockPlans(), total: 3 })
      : client.get<PlansResponse>('/api/subscription/plans'),

  getCurrentSubscription: (deviceId?: string) => {
    if (DEMO_MODE) return mockResponse(mockCurrentSubscription())
    const params: Record<string, string> = {}
    if (deviceId) params.device_id = deviceId
    return client.get<SubscriptionInfo>('/api/subscription/current', { params })
  },

  activatePlan: (planId: string, deviceId?: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', message: 'Plan aktif edildi.', subscription: mockCurrentSubscription() })
      : client.post<ActivatePlanResponse>('/api/subscription/activate', {
          plan_id: planId,
          device_id: deviceId || undefined,
        }),

  getUsage: (deviceId?: string) => {
    if (DEMO_MODE) return mockResponse(mockUsage())
    const params: Record<string, string> = {}
    if (deviceId) params.device_id = deviceId
    return client.get<UsageInfo>('/api/subscription/usage', { params })
  },

  getTierAccess: (deviceId?: string) => {
    if (DEMO_MODE) return mockResponse(mockTierAccess())
    const params: Record<string, string> = {}
    if (deviceId) params.device_id = deviceId
    return client.get<TierAccessInfo>('/api/subscription/tier-access', { params })
  },

  // Remediation
  getRemediationPlan: (ip?: string) =>
    DEMO_MODE
      ? mockResponse(mockRemediationPlan())
      : ip
        ? client.get<RemediationPlan>(`/api/remediation/plan/${ip}`)
        : client.get<RemediationPlan>('/api/remediation/plan'),

  executeRemediation: (actionId: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', message: 'Aksiyon basariyla uygulandi.', action_id: actionId })
      : client.post<RemediationExecuteResponse>(`/api/remediation/execute/${actionId}`),

  getRemediationHistory: () =>
    DEMO_MODE
      ? mockResponse({ history: mockRemediationHistory(), total: 2 })
      : client.get<RemediationHistoryResponse>('/api/remediation/history'),

  // Dead Man Switch
  getDeadManStatus: () =>
    DEMO_MODE
      ? mockResponse(mockDeadManStatus())
      : client.get<DeadManStatusResponse>('/api/deadman/status'),

  getDeadManAgentStatus: (agentId: string) =>
    DEMO_MODE
      ? mockResponse(mockDeadManStatus().statuses[0])
      : client.get<DeadManStatus>(`/api/deadman/status/${agentId}`),

  updateDeadManConfig: (config: DeadManSwitchConfig) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok' })
      : client.put('/api/deadman/config', config),

  forceDeadManCheck: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', message: 'Kontrol tamamlandi.' })
      : client.post('/api/deadman/check'),

  // AbuseIPDB
  checkAbuseIPDB: (ip: string) =>
    DEMO_MODE
      ? mockResponse({ ip, is_public: true, abuse_confidence_score: 42, total_reports: 7, num_distinct_users: 5, last_reported_at: null, country_code: 'US', isp: 'Cloudflare', usage_type: 'Data Center', bigr_threat_score: 3.2 })
      : client.get<AbuseIPDBCheck>(`/api/threat/abuseipdb/check/${ip}`),

  getAbuseIPDBStatus: () =>
    DEMO_MODE
      ? mockResponse({ enabled: true, api_key_set: true, remaining_calls: 847, daily_limit: 1000, cache_size: 156 })
      : client.get<AbuseIPDBStatus>('/api/threat/abuseipdb/status'),

  getAbuseIPDBBlacklist: (confidenceMinimum = 90, limit = 1000) =>
    DEMO_MODE
      ? mockResponse({ entries: [{ ip: '185.220.101.1', confidence: 100, country: 'DE' }, { ip: '45.148.10.92', confidence: 95, country: 'RU' }], count: 2, confidence_minimum: confidenceMinimum })
      : client.get<AbuseIPDBBlacklistResponse>('/api/threat/abuseipdb/blacklist', {
          params: { confidence_minimum: confidenceMinimum, limit },
        }),

  enrichAsset: (ip: string) =>
    DEMO_MODE
      ? mockResponse({ ip, combined_threat_score: 2.1, sources: ['local', 'abuseipdb'], abuseipdb: null, local_threat: null, status: 'ok' })
      : client.get<AbuseIPDBEnrichment>(`/api/threat/abuseipdb/enrichment/${ip}`),

  getAbuseIPDBSettings: () =>
    DEMO_MODE
      ? mockResponse(mockAbuseIPDBSettings())
      : client.get<AbuseIPDBSettings>('/api/threat/abuseipdb/settings'),

  updateAbuseIPDBSettings: (settings: AbuseIPDBSettingsUpdate) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', api_key_set: true, api_key_masked: 'sk-****...****new', daily_limit: settings.daily_limit, message: 'Ayarlar guncellendi.' })
      : client.put<{ status: string; api_key_set: boolean; api_key_masked: string; daily_limit: number; message: string }>(
          '/api/threat/abuseipdb/settings',
          settings,
        ),

  testAbuseIPDBConnection: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', message: 'API baglantisi basarili.', valid: true, test_ip: '8.8.8.8', abuse_score: 0 })
      : client.post<AbuseIPDBTestResult>('/api/threat/abuseipdb/test'),

  clearAbuseIPDBSettings: () =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', message: 'Ayarlar temizlendi.' })
      : client.delete<{ status: string; message: string }>('/api/threat/abuseipdb/settings'),

  // Language Engine — Notification Humanizer
  humanizeAlert: (request: HumanizeRequest) =>
    DEMO_MODE
      ? mockResponse({ notification: { id: 'demo_hn', title: 'Demo Bildirim', body: request.message, severity: request.severity, icon: '🔔', action_label: null, action_type: null, original_alert_type: request.alert_type, original_message: request.message, generated_by: 'demo', created_at: new Date().toISOString() } })
      : client.post<HumanizeResponse>('/api/language/humanize', request),

  humanizeBatch: (requests: HumanizeRequest[]) =>
    DEMO_MODE
      ? mockResponse({ notifications: [], count: 0 })
      : client.post<HumanizeBatchResponse>('/api/language/humanize/batch', requests),

  getSampleNotifications: () =>
    DEMO_MODE
      ? mockResponse({ samples: mockSampleNotifications(), count: mockSampleNotifications().length })
      : client.get<SampleNotificationsResponse>('/api/language/sample-notifications'),

  // Collective Intelligence
  getCollectiveThreats: (minConfidence = 0.5) =>
    DEMO_MODE
      ? mockResponse({
          threats: mockCollectiveThreats().filter(t => t.confidence >= minConfidence),
          total: mockCollectiveThreats().filter(t => t.confidence >= minConfidence).length,
          min_confidence: minConfidence,
        } as CollectiveThreatsResponse)
      : client.get<CollectiveThreatsResponse>('/api/collective/threats', {
          params: { min_confidence: minConfidence },
        }),

  getCollectiveStats: () =>
    DEMO_MODE
      ? mockResponse(mockCollectiveStats())
      : client.get<CollectiveStats>('/api/collective/stats'),

  getContributionStatus: (agentHash = '') =>
    DEMO_MODE
      ? mockResponse(mockContributionStatus())
      : client.get<ContributionStatus>('/api/collective/contribution', {
          params: { agent_hash: agentHash },
        }),

  getCollectiveFeed: (limit = 20) =>
    DEMO_MODE
      ? mockResponse({
          signals: mockCollectiveFeed().slice(0, limit),
          total: mockCollectiveFeed().length,
        } as CollectiveFeedResponse)
      : client.get<CollectiveFeedResponse>('/api/collective/feed', {
          params: { limit },
        }),

  // Family Shield
  getFamilyOverview: (subscriptionId: string) =>
    DEMO_MODE
      ? mockResponse(mockFamilyOverview())
      : client.get<FamilyOverview>('/api/family/overview', {
          params: { subscription_id: subscriptionId },
        }),

  getFamilyDevices: (subscriptionId: string) =>
    DEMO_MODE
      ? mockResponse(mockFamilyDevices())
      : client.get<FamilyDevice[]>('/api/family/devices', {
          params: { subscription_id: subscriptionId },
        }),

  addFamilyDevice: (subscriptionId: string, request: AddDeviceRequest) =>
    DEMO_MODE
      ? mockResponse({
          id: `dev_${Date.now()}`, name: request.device_name,
          device_type: request.device_type || 'unknown', icon: '📱',
          owner_name: request.owner_name || null, is_online: false,
          last_seen: null, safety_score: 100, safety_level: 'safe',
          open_threats: 0, ip: '192.168.1.200', network_name: 'Ev Agi',
        } as FamilyDevice)
      : client.post<FamilyDevice>('/api/family/devices', request, {
          params: { subscription_id: subscriptionId },
        }),

  updateFamilyDevice: (deviceId: string, request: UpdateDeviceRequest) =>
    DEMO_MODE
      ? mockResponse({
          ...mockFamilyDevices()[0], id: deviceId,
          ...(request.name && { name: request.name }),
          ...(request.device_type && { device_type: request.device_type }),
          ...(request.owner_name !== undefined && { owner_name: request.owner_name }),
        } as FamilyDevice)
      : client.put<FamilyDevice>(`/api/family/devices/${deviceId}`, request),

  removeFamilyDevice: (deviceId: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'deleted', id: deviceId })
      : client.delete(`/api/family/devices/${deviceId}`),

  getFamilyAlerts: (subscriptionId: string, limit = 50) =>
    DEMO_MODE
      ? mockResponse(mockFamilyAlerts())
      : client.get<FamilyAlert[]>('/api/family/alerts', {
          params: { subscription_id: subscriptionId, limit },
        }),

  getFamilyTimeline: (subscriptionId: string, limit = 30) =>
    DEMO_MODE
      ? mockResponse(mockFamilyTimeline())
      : client.get<FamilyTimelineEntry[]>('/api/family/timeline', {
          params: { subscription_id: subscriptionId, limit },
        }),

  // Guardian DNS Filtering
  getGuardianStatus: () =>
    DEMO_MODE
      ? mockResponse(mockGuardianStatus())
      : client.get<GuardianStatusResponse>('/api/guardian/status'),

  getGuardianStats: () =>
    DEMO_MODE
      ? mockResponse(mockGuardianStats())
      : client.get<GuardianStatsResponse>('/api/guardian/stats'),

  getGuardianRules: () =>
    DEMO_MODE
      ? mockResponse({ rules: mockGuardianRules(), total: 3 } as GuardianRulesResponse)
      : client.get<GuardianRulesResponse>('/api/guardian/rules'),

  addGuardianRule: (action: string, domain: string, category = 'custom', reason = '') =>
    DEMO_MODE
      ? mockResponse({ id: `rule_${Date.now()}`, action, domain })
      : client.post<{ id: string; action: string; domain: string }>('/api/guardian/rules', {
          action, domain, category, reason,
        }),

  deleteGuardianRule: (ruleId: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'deleted', id: ruleId })
      : client.delete<{ status: string; id: string }>(`/api/guardian/rules/${ruleId}`),

  updateGuardianBlocklists: () =>
    DEMO_MODE
      ? mockResponse({ status: 'updated', results: { updated: 3, errors: 0 } })
      : client.post<{ status: string; results: unknown }>('/api/guardian/blocklist/update'),

  getGuardianBlocklists: () =>
    DEMO_MODE
      ? mockResponse({ blocklists: mockGuardianBlocklists() } as GuardianBlocklistsResponse)
      : client.get<GuardianBlocklistsResponse>('/api/guardian/blocklists'),

  getGuardianHealth: () =>
    DEMO_MODE
      ? mockResponse(mockGuardianHealth())
      : client.get<GuardianHealthResponse>('/api/guardian/health'),

  // Watcher (Daemon Mode)
  getWatcherStatus: () =>
    DEMO_MODE
      ? mockResponse(mockWatcherStatus())
      : client.get<WatcherStatus>('/api/watcher/status'),

  getWatcherHistory: (limit = 20) =>
    DEMO_MODE
      ? mockResponse({ scans: mockWatcherHistory(), total: 5 } as WatcherHistoryResponse)
      : client.get<WatcherHistoryResponse>('/api/watcher/history', { params: { limit } }),

  getWatcherAlerts: (limit = 50) =>
    DEMO_MODE
      ? mockResponse({ alerts: mockWatcherAlerts(), total: 4 } as WatcherAlertsResponse)
      : client.get<WatcherAlertsResponse>('/api/watcher/alerts', { params: { limit } }),

  triggerWatcherScan: (subnet?: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'triggered', subnet: subnet || '192.168.1.0/24' })
      : client.post<{ status: string; subnet: string }>('/api/watcher/scan-now', null, {
          params: subnet ? { subnet } : {},
        }),

  // Asset Actions
  acknowledgeDevice: (ip: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', ip, message: 'Cihaz tanindi.' })
      : client.post<{ status: string; ip: string; message: string }>(`/api/assets/${ip}/acknowledge`),

  blockDevice: (ip: string) =>
    DEMO_MODE
      ? mockResponse({ status: 'ok', ip, message: 'Cihaz engellendi.' })
      : client.post<{ status: string; ip: string; message: string }>(`/api/assets/${ip}/ignore`),

  // Engagement
  getStreak: (subscriptionId = 'default') =>
    DEMO_MODE
      ? mockResponse(mockStreak())
      : client.get<StreakResponse>('/api/engagement/streak', { params: { subscription_id: subscriptionId } }),
}

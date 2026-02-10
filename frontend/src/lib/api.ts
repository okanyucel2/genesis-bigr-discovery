import axios from 'axios'
import type { AxiosResponse } from 'axios'
import type {
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
  HumanizeRequest,
  HumanizeResponse,
  HumanizeBatchResponse,
  SampleNotificationsResponse,
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
    client.get<AgentsResponse>('/api/agents'),

  getSites: () =>
    client.get<SitesResponse>('/api/sites'),

  createAgentCommand: (agentId: string, targets?: string[], shield?: boolean) =>
    client.post<CreateCommandResponse>(`/api/agents/${agentId}/commands`, {
      command_type: 'scan_now',
      targets: targets || [],
      shield: shield ?? true,
    }),

  getAgentCommands: (agentId: string, status?: string) => {
    const params: Record<string, string> = {}
    if (status) params.status = status
    return client.get<AgentCommandsResponse>(`/api/agents/${agentId}/commands`, { params })
  },

  getNetworks: () =>
    client.get<NetworksResponse>('/api/networks'),

  renameNetwork: (networkId: string, friendlyName: string) =>
    client.put(`/api/networks/${networkId}`, { friendly_name: friendlyName }),

  getAgentShieldFindings: (site?: string, severity?: string) => {
    const params: Record<string, string> = {}
    if (site) params.site = site
    if (severity) params.severity = severity
    return client.get<ShieldFindingsListResponse>('/api/shield-findings', { params })
  },

  // Shield
  startShieldScan: (target: string, depth?: string, modules?: string[]) =>
    DEMO_MODE
      ? mockResponse<ShieldScanResponse>(mockShieldScan())
      : client.post<ShieldScanResponse>('/api/shield/scan', null, { params: { target, depth: depth || 'quick', modules: modules?.join(',') } }),

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
    client.post<OnboardingStartResponse>('/api/onboarding/start'),

  getOnboardingStatus: () =>
    client.get<OnboardingStatusResponse>('/api/onboarding/status'),

  nameNetwork: (networkId: string, name: string, type: string) =>
    client.post<OnboardingNameResponse>('/api/onboarding/name-network', {
      network_id: networkId,
      name,
      type,
    }),

  completeOnboarding: () =>
    client.post<OnboardingCompleteResponse>('/api/onboarding/complete'),

  resetOnboarding: () =>
    client.post('/api/onboarding/reset'),

  // Subscription & Pricing
  getPlans: () =>
    client.get<PlansResponse>('/api/subscription/plans'),

  getCurrentSubscription: (deviceId?: string) => {
    const params: Record<string, string> = {}
    if (deviceId) params.device_id = deviceId
    return client.get<SubscriptionInfo>('/api/subscription/current', { params })
  },

  activatePlan: (planId: string, deviceId?: string) =>
    client.post<ActivatePlanResponse>('/api/subscription/activate', {
      plan_id: planId,
      device_id: deviceId || undefined,
    }),

  getUsage: (deviceId?: string) => {
    const params: Record<string, string> = {}
    if (deviceId) params.device_id = deviceId
    return client.get<UsageInfo>('/api/subscription/usage', { params })
  },

  getTierAccess: (deviceId?: string) => {
    const params: Record<string, string> = {}
    if (deviceId) params.device_id = deviceId
    return client.get<TierAccessInfo>('/api/subscription/tier-access', { params })
  },

  // Remediation
  getRemediationPlan: (ip?: string) =>
    ip
      ? client.get<RemediationPlan>(`/api/remediation/plan/${ip}`)
      : client.get<RemediationPlan>('/api/remediation/plan'),

  executeRemediation: (actionId: string) =>
    client.post<RemediationExecuteResponse>(`/api/remediation/execute/${actionId}`),

  getRemediationHistory: () =>
    client.get<RemediationHistoryResponse>('/api/remediation/history'),

  // Dead Man Switch
  getDeadManStatus: () =>
    client.get<DeadManStatusResponse>('/api/deadman/status'),

  getDeadManAgentStatus: (agentId: string) =>
    client.get<DeadManStatus>(`/api/deadman/status/${agentId}`),

  updateDeadManConfig: (config: DeadManSwitchConfig) =>
    client.put('/api/deadman/config', config),

  forceDeadManCheck: () =>
    client.post('/api/deadman/check'),

  // AbuseIPDB
  checkAbuseIPDB: (ip: string) =>
    client.get<AbuseIPDBCheck>(`/api/threat/abuseipdb/check/${ip}`),

  getAbuseIPDBStatus: () =>
    client.get<AbuseIPDBStatus>('/api/threat/abuseipdb/status'),

  getAbuseIPDBBlacklist: (confidenceMinimum = 90, limit = 1000) =>
    client.get<AbuseIPDBBlacklistResponse>('/api/threat/abuseipdb/blacklist', {
      params: { confidence_minimum: confidenceMinimum, limit },
    }),

  enrichAsset: (ip: string) =>
    client.get<AbuseIPDBEnrichment>(`/api/threat/abuseipdb/enrichment/${ip}`),

  // Language Engine — Notification Humanizer
  humanizeAlert: (request: HumanizeRequest) =>
    client.post<HumanizeResponse>('/api/language/humanize', request),

  humanizeBatch: (requests: HumanizeRequest[]) =>
    client.post<HumanizeBatchResponse>('/api/language/humanize/batch', requests),

  getSampleNotifications: () =>
    client.get<SampleNotificationsResponse>('/api/language/sample-notifications'),
}

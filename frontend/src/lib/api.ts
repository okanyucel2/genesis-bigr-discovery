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
  getAssets: (subnet?: string) =>
    DEMO_MODE
      ? mockResponse(mockAssets(subnet))
      : client.get<AssetsResponse>('/api/data', { params: subnet ? { subnet } : {} }),

  getAssetDetail: (ip: string) =>
    DEMO_MODE
      ? mockResponse(mockAssetDetail(ip))
      : client.get<AssetDetailResponse>(`/api/assets/${ip}`),

  getScans: () =>
    DEMO_MODE
      ? mockResponse(mockScans())
      : client.get<ScansResponse>('/api/scans'),

  getChanges: (limit = 50) =>
    DEMO_MODE
      ? mockResponse(mockChanges())
      : client.get<ChangesResponse>('/api/changes', { params: { limit } }),

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
}

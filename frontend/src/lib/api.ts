import axios from 'axios'
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

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 30000,
})

export const bigrApi = {
  getAssets: (subnet?: string) =>
    client.get<AssetsResponse>('/api/data', { params: subnet ? { subnet } : {} }),

  getAssetDetail: (ip: string) =>
    client.get<AssetDetailResponse>(`/api/assets/${ip}`),

  getScans: () =>
    client.get<ScansResponse>('/api/scans'),

  getChanges: (limit = 50) =>
    client.get<ChangesResponse>('/api/changes', { params: { limit } }),

  getSubnets: () =>
    client.get<SubnetsResponse>('/api/subnets'),

  getSwitches: () =>
    client.get<SwitchesResponse>('/api/switches'),

  getTopology: () =>
    client.get<TopologyResponse>('/api/topology'),

  getTopologySubnet: (cidr: string) =>
    client.get<TopologyResponse>(`/api/topology/subnet/${encodeURIComponent(cidr)}`),

  getCompliance: () =>
    client.get<ComplianceResponse>('/api/compliance'),

  getAnalytics: (days = 30) =>
    client.get<AnalyticsResponse>('/api/analytics', { params: { days } }),

  getRisk: () =>
    client.get<RiskResponse>('/api/risk'),

  getVulnerabilities: () =>
    client.get<VulnerabilitiesResponse>('/api/vulnerabilities'),

  getCertificates: () =>
    client.get<CertificatesResponse>('/api/certificates'),

  getHealth: () =>
    client.get<HealthResponse>('/api/health'),
}

import type { BigrCategory } from './bigr'

// GET /api/data
export interface Asset {
  ip: string
  mac: string
  hostname: string | null
  vendor: string | null
  open_ports: number[]
  os_hint: string | null
  bigr_category: BigrCategory
  bigr_category_tr: string
  confidence_score: number
  confidence_level: string
  scan_method: string
  first_seen: string | null
  last_seen: string | null
  manual_override: boolean
}

export interface AssetsResponse {
  assets: Asset[]
  category_summary: Record<string, number>
  total_assets: number
  target: string
  scan_method: string
  duration_seconds: number | null
}

// GET /api/assets/{ip}
export interface AssetDetailResponse {
  asset: Asset
  history: AssetHistoryEntry[]
}

export interface AssetHistoryEntry {
  scan_id: string
  seen_at: string
  confidence_score: number
  bigr_category: BigrCategory
}

// GET /api/scans
export interface Scan {
  id: string
  target: string
  scan_method: string
  started_at: string
  completed_at: string | null
  total_assets: number
  is_root: boolean
}

export interface ScansResponse {
  scans: Scan[]
}

// GET /api/changes
export interface AssetChange {
  id: number
  ip: string
  mac: string | null
  change_type: string
  field_name: string | null
  old_value: string | null
  new_value: string | null
  detected_at: string
}

export interface ChangesResponse {
  changes: AssetChange[]
}

// GET /api/subnets
export interface Subnet {
  id: number
  cidr: string
  label: string | null
  vlan_id: number | null
  asset_count: number
  last_scanned: string | null
}

export interface SubnetsResponse {
  subnets: Subnet[]
}

// GET /api/switches
export interface Switch {
  host: string
  label: string | null
  community: string
  version: string
  mac_count: number
  last_polled: string | null
}

export interface SwitchesResponse {
  switches: Switch[]
}

// GET /api/topology
export interface TopologyNode {
  id: string
  label: string
  ip: string | null
  mac: string | null
  hostname: string | null
  vendor: string | null
  type: string // gateway, switch, subnet, device
  bigr_category: BigrCategory
  confidence: number
  open_ports: number[]
  size: number
  color: string
  subnet: string | null
  switch_port: string | null
}

export interface TopologyEdge {
  source: string
  target: string
  type: string // gateway, switch, subnet, connection
  label: string | null
}

export interface TopologyResponse {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  stats: {
    total_nodes: number
    total_edges: number
    node_types: Record<string, number>
  }
}

// GET /api/compliance
export interface ComplianceResponse {
  breakdown: {
    compliance_score: number
    grade: string
    total_assets: number
    fully_classified: number
    partially_classified: number
    unclassified: number
    manual_overrides: number
  }
  distribution: {
    ag_ve_sistemler: number
    uygulamalar: number
    iot: number
    tasinabilir: number
    unclassified: number
    total: number
  }
  subnet_compliance: SubnetCompliance[]
  action_items: ActionItem[]
}

export interface SubnetCompliance {
  cidr: string
  label: string | null
  score: number
  grade: string
}

export interface ActionItem {
  priority: string
  type: string
  ip: string
  reason: string
}

// GET /api/analytics
export interface TrendPoint {
  date: string
  value: number
  label: string | null
}

export interface TrendSeries {
  name: string
  points: TrendPoint[]
}

export interface AnalyticsResponse {
  asset_count_trend: TrendSeries | null
  category_trends: TrendSeries[]
  new_vs_removed: TrendSeries | null
  most_changed_assets: MostChangedAsset[]
  scan_frequency: ScanFrequency[]
}

export interface MostChangedAsset {
  ip: string
  change_count: number
  last_change: string
}

export interface ScanFrequency {
  date: string
  scan_count: number
  total_assets: number
}

// GET /api/risk
export interface RiskFactors {
  cve_score: number
  exposure_score: number
  classification_score: number
  age_score: number
  change_score: number
}

export interface RiskProfile {
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  bigr_category: BigrCategory
  risk_score: number
  risk_level: string
  factors: RiskFactors
  top_cve: string | null
}

export interface RiskResponse {
  profiles: RiskProfile[]
  average_risk: number
  max_risk: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  top_risks: RiskProfile[]
}

// GET /api/vulnerabilities
export interface CveEntry {
  cve_id: string
  cvss_score: number
  severity: string
  description: string
  affected_vendor: string
  affected_product: string
  cpe: string | null
  published: string | null
  fix_available: boolean
  cisa_kev: boolean
}

export interface VulnMatch {
  asset_ip: string
  asset_mac: string | null
  asset_vendor: string | null
  cve: CveEntry
  match_type: string
  match_confidence: number
}

export interface AssetVulnSummary {
  ip: string
  total_vulns: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  max_cvss: number
  matches: VulnMatch[]
}

export interface VulnerabilitiesResponse {
  summaries: AssetVulnSummary[]
}

// GET /api/certificates
export interface Certificate {
  ip: string
  port: number
  cn: string | null
  issuer: string | null
  valid_from: string | null
  valid_to: string | null
  days_until_expiry: number | null
  is_self_signed: boolean
  key_size: number | null
  serial_number: string | null
}

export interface CertificatesResponse {
  certificates: Certificate[]
}

// GET /api/health
export interface HealthResponse {
  status: string
  data_file: string
  exists: boolean
}

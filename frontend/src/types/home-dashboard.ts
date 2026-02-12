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
  CollectiveSignalReport,
} from './api'

// Kalkan (Shield) aggregate
export type KalkanState = 'green' | 'yellow' | 'red'

export interface KalkanData {
  score: number
  state: KalkanState
  message: string
  deviceCount: number
  blockedThisMonth: number
  complianceScore: number
  riskScore: number
  firewallScore: number
}

// 4 Hayat Kartlari
export interface VerilerimCard {
  httpsCount: number
  totalCertificates: number
  expiringCerts: number
  selfSignedCerts: number
  complianceGrade: string
}

export interface AilemCard {
  familyName: string
  devices: {
    id: string
    name: string
    icon: string
    ownerName: string | null
    isOnline: boolean
    safetyLevel: string
  }[]
  totalThreats: number
  avgSafetyScore: number
  devicesOnline: number
}

export interface EvimCard {
  totalDevices: number
  deviceTypes: Record<string, number>
  newDevices: {
    ip: string
    mac: string | null
    hostname: string | null
    vendor: string | null
    firstSeen: string | null
  }[]
  lastScan: string | null
}

export interface BolgemCard {
  communityScore: number
  activeAgents: number
  verifiedThreats: number
  isContributing: boolean
  signalsContributed: number
  signalsReceived: number
}

// Timeline
export type TimelineSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type TimelineSource = 'firewall' | 'family' | 'change' | 'collective'

export interface TimelineDetailField {
  icon: string
  label: string
  value: string
}

export interface TimelineDetailAction {
  label: string
  variant: 'primary' | 'secondary' | 'danger'
  icon?: string
  handler: 'block-permanent' | 'view-device' | 'view-rule' | 'suggest-dns' | 'suggest-router' | 'shield-block' | 'setup-shield'
  metadata?: Record<string, string>
  suggested?: boolean
  suggestReason?: string
}

// Shield status — Discovery ↔ Shield communication
export type ShieldDeployment = 'router' | 'standalone' | 'docker' | 'none'

export interface ShieldCapabilities {
  dns: boolean
  firewall: boolean
}

export interface ShieldStatus {
  installed: boolean
  online: boolean
  deployment: ShieldDeployment
  capabilities: ShieldCapabilities
}

export interface TimelineRichDetail {
  summary: string
  fields: TimelineDetailField[]
  actions: TimelineDetailAction[]
  threatContext?: {
    isKnownMalicious: boolean
    threatType?: string
    reputation: 'malicious' | 'suspicious' | 'unknown'
  }
  ruleContext?: {
    category: string
    label: string
    reason: string
    bannerVariant: 'red' | 'purple' | 'blue' | 'orange'
  }
}

export function isRichDetail(d: string | TimelineRichDetail | null): d is TimelineRichDetail {
  return d !== null && typeof d === 'object' && 'summary' in d
}

export interface TimelineItem {
  id: string
  source: TimelineSource
  severity: TimelineSeverity
  message: string
  detail: string | TimelineRichDetail | null
  timestamp: string
  icon: string
  expanded?: boolean
}

// Aggregate dashboard data
export interface HomeDashboardData {
  kalkan: KalkanData
  verilerim: VerilerimCard
  ailem: AilemCard
  evim: EvimCard
  bolgem: BolgemCard
}

// Raw API data used by composable
export interface HomeDashboardRawData {
  compliance: ComplianceResponse | null
  risk: RiskResponse | null
  certificates: CertificatesResponse | null
  family: FamilyOverview | null
  familyAlerts: FamilyAlert[]
  familyTimeline: FamilyTimelineEntry[]
  collectiveStats: CollectiveStats | null
  contribution: ContributionStatus | null
  firewallDailyStats: FirewallDailyStats | null
  firewallEvents: FirewallEvent[]
  changes: AssetChange[]
  notifications: HumanNotification[]
  collectiveThreats: CollectiveSignalReport[]
}

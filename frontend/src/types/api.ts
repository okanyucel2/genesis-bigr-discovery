import type { BigrCategory } from './bigr'

// GET /api/data
export type SensitivityLevel = 'fragile' | 'cautious' | 'safe'

export type DeviceStatus = 'acknowledged' | 'ignored' | 'new' | 'unknown'

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
  manual_category?: string | null
  is_ignored?: number
  sensitivity_level?: SensitivityLevel | null
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
  compliance_score: number
  grade: string
  breakdown: {
    total_assets: number
    fully_classified: number
    partially_classified: number
    unclassified: number
    manual_overrides: number
  }
  distribution: {
    counts: Record<string, number>
    percentages: Record<string, number>
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

// GET /api/agents
export interface AgentNetwork {
  id: string
  ssid: string | null
  gateway_ip: string | null
  friendly_name: string | null
}

export interface Agent {
  id: string
  name: string
  site_name: string
  location: string | null
  is_active: boolean
  registered_at: string
  last_seen: string | null
  status: string // 'online' | 'offline' | 'stale' | 'pending'
  version: string | null
  subnets: string[]
  current_network: AgentNetwork | null
}

export interface AgentsResponse {
  agents: Agent[]
}

// GET /api/sites
export interface SiteSummary {
  site_name: string
  asset_count: number
}

export interface SitesResponse {
  sites: SiteSummary[]
}

// GET /api/networks
export interface NetworkSummary {
  id: string
  fingerprint_hash: string
  gateway_mac: string | null
  gateway_ip: string | null
  ssid: string | null
  friendly_name: string | null
  agent_id: string | null
  first_seen: string
  last_seen: string
  asset_count: number
}

export interface NetworksResponse {
  networks: NetworkSummary[]
}

// Agent commands
export interface AgentCommand {
  id: string
  command_type: string
  params: {
    targets: string[]
    shield: boolean
  }
  status: string // 'pending' | 'ack' | 'running' | 'completed' | 'failed'
  created_at: string
  started_at: string | null
  completed_at: string | null
  result: Record<string, unknown> | null
}

export interface AgentCommandsResponse {
  commands: AgentCommand[]
  count: number
}

export interface CreateCommandResponse {
  status: string
  command_id: string
  agent_id: string
  command_type: string
  targets: string[]
  shield: boolean
}

// POST /api/onboarding/start
export interface OnboardingStartResponse {
  status: string
  network_id: string | null
  ssid: string | null
  gateway_ip: string | null
  gateway_mac: string | null
  safety_score: number
  risk_factors: string[]
  safety_message: string
  safety_detail: string
  known_network: boolean
  open_ports: number[]
  device_count: number
}

// GET /api/onboarding/status
export interface OnboardingStatusResponse {
  step: string
  completed_steps: string[]
  network_info: OnboardingStartResponse | null
  network_name: string | null
  network_type: string | null
  safety_score: number | null
  is_complete: boolean
}

// POST /api/onboarding/name-network
export interface OnboardingNameResponse {
  status: string
  network_id: string
  name: string
  type: string
  updated: boolean
  message: string
}

// POST /api/onboarding/complete
export interface OnboardingCompleteResponse {
  status: string
  message: string
  motto: string
  network?: {
    ssid: string | null
    name: string | null
    type: string | null
    safety_score: number
    risk_count: number
  }
}

// GET /api/subscription/plans
export interface PlanInfo {
  id: string
  name: string
  name_tr: string
  price_usd: number
  max_devices: number
  ai_tiers: string[]
  features: string[]
  features_tr: string[]
}

export interface PlansResponse {
  plans: PlanInfo[]
  total: number
}

// GET /api/subscription/current
export interface SubscriptionInfo {
  device_id: string
  plan_id: string
  plan: PlanInfo
  is_active: boolean
  activated_at: string
  expires_at: string | null
}

// POST /api/subscription/activate
export interface ActivatePlanResponse {
  status: string
  message: string
  subscription: SubscriptionInfo
}

// GET /api/subscription/usage
export interface UsageInfo {
  device_id: string
  plan_id: string
  ai_queries_l0: number
  ai_queries_l1: number
  ai_queries_l2: number
  devices_active: number
  devices_max: number
  period_start: string
  period_end: string
}

// GET /api/subscription/tier-access
export interface TierAccessInfo {
  plan_id: string
  allowed_tiers: string[]
  max_tier: string
  can_use_l1: boolean
  can_use_l2: boolean
}

// GET /api/remediation/plan
export interface RemediationAction {
  id: string
  title: string
  title_tr: string
  description: string
  description_tr: string
  severity: string
  action_type: string
  target_ip: string | null
  target_port: number | null
  auto_fixable: boolean
  estimated_impact: string
}

export interface RemediationPlan {
  asset_ip: string | null
  total_actions: number
  critical_count: number
  auto_fixable_count: number
  actions: RemediationAction[]
  generated_at: string
  ai_tier_used: string
}

export interface RemediationHistoryEntry {
  id: string
  asset_ip: string
  action_type: string
  title: string
  severity: string
  status: string
  executed_at: string | null
  result: string | null
  created_at: string
}

export interface RemediationHistoryResponse {
  history: RemediationHistoryEntry[]
  total: number
}

export interface RemediationExecuteResponse {
  status: string
  message: string
  action_id: string
  command_id?: string
  agent_id?: string
}

// GET /api/deadman/status
export interface DeadManSwitchConfig {
  enabled: boolean
  timeout_minutes: number
  alert_email: string | null
  alert_webhook: string | null
}

export interface DeadManStatus {
  agent_id: string
  agent_name: string
  last_heartbeat: string | null
  minutes_since_heartbeat: number | null
  is_alive: boolean
  alert_triggered: boolean
  config: DeadManSwitchConfig
}

export interface DeadManStatusResponse {
  statuses: DeadManStatus[]
  total_agents: number
  alive_count: number
  alert_count: number
  config: DeadManSwitchConfig
  summary_tr: string
}

// GET /api/threat/abuseipdb/check/{ip}
export interface AbuseIPDBCheck {
  ip: string
  is_public: boolean
  abuse_confidence_score: number
  total_reports: number
  num_distinct_users: number
  last_reported_at: string | null
  country_code: string | null
  isp: string | null
  usage_type: string | null
  bigr_threat_score: number
}

// GET /api/threat/abuseipdb/status
export interface AbuseIPDBStatus {
  enabled: boolean
  api_key_set: boolean
  remaining_calls: number
  daily_limit: number
  cache_size: number
}

// GET /api/threat/abuseipdb/settings
export interface AbuseIPDBSettings {
  api_key_set: boolean
  api_key_masked: string
  daily_limit: number
  remaining_calls: number
  cache_size: number
  source: 'env' | 'file' | 'none'
}

// PUT /api/threat/abuseipdb/settings
export interface AbuseIPDBSettingsUpdate {
  api_key: string
  daily_limit: number
}

// POST /api/threat/abuseipdb/test
export interface AbuseIPDBTestResult {
  status: string
  message: string
  valid: boolean
  test_ip?: string
  abuse_score?: number
}

// GET /api/threat/abuseipdb/blacklist
export interface AbuseIPDBBlacklistEntry {
  ip: string
  confidence: number
  country: string | null
}

export interface AbuseIPDBBlacklistResponse {
  entries: AbuseIPDBBlacklistEntry[]
  count: number
  confidence_minimum: number
}

// GET /api/threat/abuseipdb/enrichment/{ip}
export interface AbuseIPDBEnrichment {
  ip: string
  combined_threat_score: number
  sources: string[]
  abuseipdb: AbuseIPDBCheck | null
  local_threat: Record<string, unknown> | null
  status: string
}

// Language Engine — Human-friendly notifications
export interface HumanNotification {
  id: string
  title: string
  body: string
  severity: string
  icon: string
  action_label: string | null
  action_type: string | null
  original_alert_type: string
  original_message: string
  generated_by: string
  created_at: string
}

export interface HumanizeRequest {
  alert_type: string
  severity: string
  ip?: string
  message: string
  details?: Record<string, unknown>
  device_name?: string
}

export interface HumanizeResponse {
  notification: HumanNotification
}

export interface HumanizeBatchResponse {
  notifications: HumanNotification[]
  count: number
}

export interface SampleNotificationsResponse {
  samples: HumanNotification[]
  count: number
}

// GET /api/collective/threats
export interface CollectiveSignalReport {
  subnet_hash: string
  signal_type: string
  reporter_count: number
  avg_severity: number
  first_seen: string
  last_seen: string
  confidence: number
  is_verified: boolean
}

export interface CollectiveThreatsResponse {
  threats: CollectiveSignalReport[]
  total: number
  min_confidence: number
}

// GET /api/collective/stats
export interface CollectiveStats {
  total_signals: number
  active_agents: number
  verified_threats: number
  subnets_monitored: number
  community_protection_score: number
  last_updated: string
}

// GET /api/collective/contribution
export interface ContributionStatus {
  signals_contributed: number
  signals_received: number
  is_contributing: boolean
  opt_in: boolean
  privacy_level: string
}

// GET /api/collective/feed
export interface CollectiveFeedResponse {
  signals: CollectiveSignalReport[]
  total: number
}

// Family Shield types
export interface FamilyDevice {
  id: string
  name: string
  device_type: string
  icon: string
  owner_name: string | null
  is_online: boolean
  last_seen: string | null
  safety_score: number
  safety_level: string
  open_threats: number
  ip: string | null
  network_name: string | null
}

export interface FamilyOverview {
  family_name: string
  plan_id: string
  devices: FamilyDevice[]
  max_devices: number
  total_threats: number
  avg_safety_score: number
  safety_level: string
  devices_online: number
  last_scan: string | null
}

export interface FamilyAlert {
  id: string
  device_id: string
  device_name: string
  alert_type: string
  severity: string
  message: string
  timestamp: string
  is_read: boolean
}

export interface FamilyTimelineEntry {
  id: string
  device_id: string
  device_name: string
  device_icon: string
  event_type: string
  message: string
  timestamp: string
}

export interface AddDeviceRequest {
  device_name: string
  device_type?: string
  owner_name?: string | null
}

export interface UpdateDeviceRequest {
  name?: string | null
  device_type?: string | null
  owner_name?: string | null
}

// Firewall types
export interface FirewallRule {
  id: string
  rule_type: string
  target: string
  direction: string
  protocol: string
  source: string
  reason: string
  reason_tr: string
  is_active: boolean
  created_at: string
  expires_at: string | null
  hit_count: number
}

export interface FirewallRulesResponse {
  rules: FirewallRule[]
  total: number
}

export interface FirewallEvent {
  id: string
  timestamp: string
  action: string
  rule_id: string | null
  source_ip: string
  dest_ip: string
  dest_port: number
  protocol: string
  process_name: string | null
  direction: string
}

export interface FirewallEventsResponse {
  events: FirewallEvent[]
  total: number
}

export interface FirewallStatus {
  is_enabled: boolean
  platform: string
  engine: string
  total_rules: number
  active_rules: number
  blocked_today: number
  allowed_today: number
  last_updated: string
  protection_level: string
}

export interface FirewallConfig {
  enabled: boolean
  default_action: string
  block_known_threats: boolean
  block_high_risk_ports: boolean
  log_allowed: boolean
  auto_sync_threats: boolean
  protection_level: string
}

export interface FirewallDailyStats {
  date: string
  blocked: number
  allowed: number
  total: number
  block_rate: number
}

// GET /api/shield-findings
export interface AgentShieldFinding {
  id: number
  scan_id: string
  module: string
  severity: string
  title: string | null
  detail: string | null
  target_ip: string | null
  remediation: string | null
  target: string
  site_name: string | null
  agent_id: string | null
  scanned_at: string
}

export interface ShieldFindingsListResponse {
  findings: AgentShieldFinding[]
  total: number
  severity_counts: Record<string, number>
}

// Guardian DNS Filtering
export interface GuardianStatusResponse {
  guardian_active: boolean
  dns_filtering: boolean
  blocked_domains_count: number
  stats: {
    total_queries: number
    blocked_queries: number
    allowed_queries: number
    cache_hit_rate: number
  }
  lifetime_stats: {
    total_queries: number
    blocked_queries: number
    allowed_queries: number
  }
}

export interface GuardianStatsResponse {
  current_period: {
    total_queries: number
    blocked_queries: number
    allowed_queries: number
    cache_hit_rate: number
  }
  lifetime: {
    total_queries: number
    blocked_queries: number
    allowed_queries: number
  }
  top_blocked: { domain: string; count: number; category: string }[]
}

export interface GuardianRule {
  id: string
  action: string
  domain: string
  category: string
  reason: string
  hit_count: number
  created_at: string
}

export interface GuardianRulesResponse {
  rules: GuardianRule[]
  total: number
}

export interface GuardianBlocklist {
  id: string
  name: string
  url: string
  format: string
  category: string
  domain_count: number
  is_enabled: boolean
  last_updated: string | null
}

export interface GuardianBlocklistsResponse {
  blocklists: GuardianBlocklist[]
}

export interface GuardianHealthResponse {
  status: 'healthy' | 'degraded' | 'offline'
  checks: Record<string, { ok: boolean; detail?: string }>
  message?: string
}

// ---------------------------------------------------------------------------
// Watcher (Daemon Mode)
// ---------------------------------------------------------------------------

export interface WatcherTarget {
  subnet: string
  interval_seconds: number
}

export interface WatcherStatus {
  is_running: boolean
  pid: number | null
  uptime_seconds: number
  targets: WatcherTarget[]
  last_scan_at: string | null
  scan_count: number
}

export interface WatcherScan {
  subnet: string
  started_at: string
  completed_at: string
  asset_count: number
  changes_count: number
  status: string
}

export interface WatcherHistoryResponse {
  scans: WatcherScan[]
  total: number
}

export interface WatcherAlert {
  alert_type: string
  severity: string
  ip: string
  message: string
  timestamp: string
}

export interface WatcherAlertsResponse {
  alerts: WatcherAlert[]
  total: number
}

// ---------------------------------------------------------------------------
// Engagement (Safety Streak)
// ---------------------------------------------------------------------------

export interface StreakMilestone {
  badge: string
  title_tr: string
  days_required: number
}

export interface StreakNextMilestone {
  badge: string
  title_tr: string
  days_required: number
  days_remaining: number
}

export interface StreakResponse {
  current_streak_days: number
  longest_streak_days: number
  total_safe_days: number
  milestone: StreakMilestone | null
  next_milestone: StreakNextMilestone | null
}

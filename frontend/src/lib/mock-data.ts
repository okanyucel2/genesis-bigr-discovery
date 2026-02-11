/**
 * Mock data for BİGR Discovery demo mode.
 *
 * Activated by setting VITE_DEMO_MODE=true in the environment.
 * Data simulates a realistic corporate network scan with ~18 assets
 * across two subnets: 192.168.1.0/24 (Office LAN) and 10.0.0.0/24 (Server VLAN).
 */

import type {
  Asset,
  AssetsResponse,
  AssetDetailResponse,
  AssetHistoryEntry,
  ScansResponse,
  Scan,
  ChangesResponse,
  AssetChange,
  SubnetsResponse,
  Subnet,
  SwitchesResponse,
  Switch,
  TopologyResponse,
  TopologyNode,
  TopologyEdge,
  ComplianceResponse,
  SubnetCompliance,
  ActionItem,
  AnalyticsResponse,
  TrendSeries,
  TrendPoint,
  MostChangedAsset,
  ScanFrequency,
  RiskResponse,
  RiskProfile,
  VulnerabilitiesResponse,
  AssetVulnSummary,
  CveEntry,
  CertificatesResponse,
  Certificate,
  HealthResponse,
  FirewallDailyStats,
  CollectiveStats,
  ContributionStatus,
  FamilyOverview,
  FamilyTimelineEntry,
  FamilyAlert,
  FirewallEvent,
  HumanNotification,
} from '@/types/api'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return an ISO datetime string N days ago from "now" (2026-02-09). */
function daysAgo(n: number): string {
  const d = new Date('2026-02-09T14:30:00Z')
  d.setDate(d.getDate() - n)
  return d.toISOString()
}

/** Return a date-only string (YYYY-MM-DD) N days ago. */
function dateOnly(n: number): string {
  const d = new Date('2026-02-09T14:30:00Z')
  d.setDate(d.getDate() - n)
  return d.toISOString().slice(0, 10)
}

/** Return an ISO datetime string N days from now. */
function daysFromNow(n: number): string {
  const d = new Date('2026-02-09T14:30:00Z')
  d.setDate(d.getDate() + n)
  return d.toISOString()
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

const MOCK_ASSETS: Asset[] = [
  // ── Office LAN 192.168.1.0/24 ──
  {
    ip: '192.168.1.1',
    mac: '00:1A:2B:3C:4D:01',
    hostname: 'gw-office-01',
    vendor: 'Cisco',
    open_ports: [22, 80, 443],
    os_hint: 'Cisco IOS 15.x',
    bigr_category: 'ag_ve_sistemler',
    bigr_category_tr: 'Ağ ve Sistemler',
    confidence_score: 0.98,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(90),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.2',
    mac: '00:1A:2B:3C:4D:02',
    hostname: 'sw-floor1',
    vendor: 'Cisco',
    open_ports: [22, 161],
    os_hint: 'Cisco IOS 12.x',
    bigr_category: 'ag_ve_sistemler',
    bigr_category_tr: 'Ağ ve Sistemler',
    confidence_score: 0.96,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(90),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.3',
    mac: '00:1A:2B:3C:4D:03',
    hostname: 'sw-floor2',
    vendor: 'HP',
    open_ports: [22, 80, 161],
    os_hint: 'HP ProCurve',
    bigr_category: 'ag_ve_sistemler',
    bigr_category_tr: 'Ağ ve Sistemler',
    confidence_score: 0.94,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(85),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.10',
    mac: '3C:52:82:AA:11:10',
    hostname: 'fw-perimeter',
    vendor: 'Fortinet',
    open_ports: [22, 443, 541],
    os_hint: 'FortiOS 7.2',
    bigr_category: 'ag_ve_sistemler',
    bigr_category_tr: 'Ağ ve Sistemler',
    confidence_score: 0.97,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(60),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.20',
    mac: 'A4:BB:6D:CC:20:01',
    hostname: 'wap-lobby',
    vendor: 'Ubiquiti',
    open_ports: [22, 443],
    os_hint: 'UniFi OS',
    bigr_category: 'ag_ve_sistemler',
    bigr_category_tr: 'Ağ ve Sistemler',
    confidence_score: 0.91,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(45),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.50',
    mac: 'D4:BE:D9:EE:50:01',
    hostname: 'printer-floor1',
    vendor: 'HP Inc.',
    open_ports: [80, 443, 515, 631, 9100],
    os_hint: 'HP LaserJet FW',
    bigr_category: 'iot',
    bigr_category_tr: 'IoT Cihazlar',
    confidence_score: 0.89,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(70),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.51',
    mac: '00:80:91:FF:51:02',
    hostname: 'cam-entrance',
    vendor: 'Hikvision',
    open_ports: [80, 554, 8000],
    os_hint: 'Embedded Linux',
    bigr_category: 'iot',
    bigr_category_tr: 'IoT Cihazlar',
    confidence_score: 0.85,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(40),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.52',
    mac: '00:80:91:FF:52:03',
    hostname: 'cam-parking',
    vendor: 'Hikvision',
    open_ports: [80, 554, 8000],
    os_hint: 'Embedded Linux',
    bigr_category: 'iot',
    bigr_category_tr: 'IoT Cihazlar',
    confidence_score: 0.84,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(40),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.100',
    mac: 'F0:DE:F1:AA:00:01',
    hostname: 'lt-okan',
    vendor: 'Apple',
    open_ports: [22, 5900],
    os_hint: 'macOS 15.x',
    bigr_category: 'tasinabilir',
    bigr_category_tr: 'Taşınabilir Cihazlar',
    confidence_score: 0.92,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(30),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '192.168.1.101',
    mac: '28:CF:E9:BB:01:02',
    hostname: 'lt-devops-ali',
    vendor: 'Dell',
    open_ports: [22],
    os_hint: 'Ubuntu 24.04',
    bigr_category: 'tasinabilir',
    bigr_category_tr: 'Taşınabilir Cihazlar',
    confidence_score: 0.88,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(25),
    last_seen: daysAgo(1),
    manual_override: false,
  },
  {
    ip: '192.168.1.102',
    mac: '60:F2:62:CC:02:03',
    hostname: null,
    vendor: 'Intel Corporate',
    open_ports: [],
    os_hint: null,
    bigr_category: 'unclassified',
    bigr_category_tr: 'Sınıflandırılmamış',
    confidence_score: 0.35,
    confidence_level: 'low',
    scan_method: 'arp',
    first_seen: daysAgo(3),
    last_seen: daysAgo(1),
    manual_override: false,
  },
  {
    ip: '192.168.1.103',
    mac: 'AC:DE:48:DD:03:04',
    hostname: null,
    vendor: null,
    open_ports: [80],
    os_hint: null,
    bigr_category: 'unclassified',
    bigr_category_tr: 'Sınıflandırılmamış',
    confidence_score: 0.28,
    confidence_level: 'low',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(1),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  // ── Server VLAN 10.0.0.0/24 ──
  {
    ip: '10.0.0.1',
    mac: '00:1A:2B:3C:4D:A1',
    hostname: 'gw-server',
    vendor: 'Cisco',
    open_ports: [22, 443],
    os_hint: 'Cisco IOS XE 17.x',
    bigr_category: 'ag_ve_sistemler',
    bigr_category_tr: 'Ağ ve Sistemler',
    confidence_score: 0.99,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(120),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '10.0.0.10',
    mac: '00:25:90:EE:10:01',
    hostname: 'web-prod-01',
    vendor: 'Dell',
    open_ports: [22, 80, 443, 8080],
    os_hint: 'Ubuntu 22.04 LTS',
    bigr_category: 'uygulamalar',
    bigr_category_tr: 'Uygulamalar',
    confidence_score: 0.95,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(100),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '10.0.0.11',
    mac: '00:25:90:EE:11:02',
    hostname: 'web-prod-02',
    vendor: 'Dell',
    open_ports: [22, 80, 443, 8080],
    os_hint: 'Ubuntu 22.04 LTS',
    bigr_category: 'uygulamalar',
    bigr_category_tr: 'Uygulamalar',
    confidence_score: 0.95,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(100),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '10.0.0.20',
    mac: '00:25:90:EE:20:03',
    hostname: 'db-postgres-01',
    vendor: 'HP',
    open_ports: [22, 5432],
    os_hint: 'Debian 12',
    bigr_category: 'uygulamalar',
    bigr_category_tr: 'Uygulamalar',
    confidence_score: 0.93,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(100),
    last_seen: daysAgo(0),
    manual_override: true,
  },
  {
    ip: '10.0.0.30',
    mac: '00:25:90:EE:30:04',
    hostname: 'mail-exchange',
    vendor: 'HP',
    open_ports: [22, 25, 443, 587, 993],
    os_hint: 'Windows Server 2022',
    bigr_category: 'uygulamalar',
    bigr_category_tr: 'Uygulamalar',
    confidence_score: 0.91,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(110),
    last_seen: daysAgo(0),
    manual_override: false,
  },
  {
    ip: '10.0.0.40',
    mac: '2C:F0:5D:FF:40:05',
    hostname: 'nas-backup',
    vendor: 'Synology',
    open_ports: [22, 80, 443, 5000, 5001],
    os_hint: 'DSM 7.2',
    bigr_category: 'ag_ve_sistemler',
    bigr_category_tr: 'Ağ ve Sistemler',
    confidence_score: 0.87,
    confidence_level: 'high',
    scan_method: 'arp+nmap',
    first_seen: daysAgo(80),
    last_seen: daysAgo(0),
    manual_override: false,
  },
]

// ---------------------------------------------------------------------------
// Category summary helper
// ---------------------------------------------------------------------------

function buildCategorySummary(assets: Asset[]): Record<string, number> {
  const summary: Record<string, number> = {}
  for (const a of assets) {
    summary[a.bigr_category] = (summary[a.bigr_category] || 0) + 1
  }
  return summary
}

// ---------------------------------------------------------------------------
// Public mock data functions
// ---------------------------------------------------------------------------

export function mockAssets(subnet?: string): AssetsResponse {
  let filtered = MOCK_ASSETS
  if (subnet) {
    const prefix = subnet.replace(/\.0\/\d+$/, '.')
    filtered = MOCK_ASSETS.filter((a) => a.ip.startsWith(prefix))
  }
  return {
    assets: filtered,
    category_summary: buildCategorySummary(filtered),
    total_assets: filtered.length,
    target: subnet || '192.168.1.0/24',
    scan_method: 'arp+nmap',
    duration_seconds: 12.4,
  }
}

export function mockAssetDetail(ip: string): AssetDetailResponse {
  // MOCK_ASSETS is guaranteed non-empty; fallback to first entry for unknown IPs
  const fallback = MOCK_ASSETS[0] as Asset
  const asset = MOCK_ASSETS.find((a) => a.ip === ip) ?? fallback
  const history: AssetHistoryEntry[] = [
    {
      scan_id: 'scan-0001',
      seen_at: daysAgo(7),
      confidence_score: asset.confidence_score - 0.02,
      bigr_category: asset.bigr_category,
    },
    {
      scan_id: 'scan-0002',
      seen_at: daysAgo(3),
      confidence_score: asset.confidence_score - 0.01,
      bigr_category: asset.bigr_category,
    },
    {
      scan_id: 'scan-0003',
      seen_at: daysAgo(0),
      confidence_score: asset.confidence_score,
      bigr_category: asset.bigr_category,
    },
  ]
  return { asset, history }
}

export function mockScans(): ScansResponse {
  const scans: Scan[] = [
    {
      id: 'scan-0001',
      target: '192.168.1.0/24',
      scan_method: 'arp+nmap',
      started_at: daysAgo(7),
      completed_at: daysAgo(7),
      total_assets: 11,
      is_root: true,
    },
    {
      id: 'scan-0002',
      target: '10.0.0.0/24',
      scan_method: 'arp+nmap',
      started_at: daysAgo(5),
      completed_at: daysAgo(5),
      total_assets: 6,
      is_root: true,
    },
    {
      id: 'scan-0003',
      target: '192.168.1.0/24',
      scan_method: 'arp+nmap',
      started_at: daysAgo(3),
      completed_at: daysAgo(3),
      total_assets: 12,
      is_root: true,
    },
    {
      id: 'scan-0004',
      target: '10.0.0.0/24',
      scan_method: 'arp+nmap',
      started_at: daysAgo(1),
      completed_at: daysAgo(1),
      total_assets: 6,
      is_root: true,
    },
    {
      id: 'scan-0005',
      target: '192.168.1.0/24',
      scan_method: 'arp+nmap',
      started_at: daysAgo(0),
      completed_at: daysAgo(0),
      total_assets: 12,
      is_root: false,
    },
  ]
  return { scans }
}

export function mockChanges(): ChangesResponse {
  const changes: AssetChange[] = [
    {
      id: 1,
      ip: '192.168.1.102',
      mac: '60:F2:62:CC:02:03',
      change_type: 'new_asset',
      field_name: null,
      old_value: null,
      new_value: null,
      detected_at: daysAgo(3),
    },
    {
      id: 2,
      ip: '192.168.1.103',
      mac: 'AC:DE:48:DD:03:04',
      change_type: 'new_asset',
      field_name: null,
      old_value: null,
      new_value: null,
      detected_at: daysAgo(1),
    },
    {
      id: 3,
      ip: '192.168.1.50',
      mac: 'D4:BE:D9:EE:50:01',
      change_type: 'port_change',
      field_name: 'open_ports',
      old_value: '[80, 443, 9100]',
      new_value: '[80, 443, 515, 631, 9100]',
      detected_at: daysAgo(2),
    },
    {
      id: 4,
      ip: '10.0.0.10',
      mac: '00:25:90:EE:10:01',
      change_type: 'port_change',
      field_name: 'open_ports',
      old_value: '[22, 80, 443]',
      new_value: '[22, 80, 443, 8080]',
      detected_at: daysAgo(4),
    },
    {
      id: 5,
      ip: '192.168.1.20',
      mac: 'A4:BB:6D:CC:20:01',
      change_type: 'vendor_change',
      field_name: 'vendor',
      old_value: 'Ubiquiti Networks',
      new_value: 'Ubiquiti',
      detected_at: daysAgo(5),
    },
    {
      id: 6,
      ip: '10.0.0.20',
      mac: '00:25:90:EE:20:03',
      change_type: 'category_override',
      field_name: 'bigr_category',
      old_value: 'ag_ve_sistemler',
      new_value: 'uygulamalar',
      detected_at: daysAgo(6),
    },
  ]
  return { changes }
}

export function mockSubnets(): SubnetsResponse {
  const subnets: Subnet[] = [
    {
      id: 1,
      cidr: '192.168.1.0/24',
      label: 'Office LAN',
      vlan_id: 10,
      asset_count: 12,
      last_scanned: daysAgo(0),
    },
    {
      id: 2,
      cidr: '10.0.0.0/24',
      label: 'Server VLAN',
      vlan_id: 20,
      asset_count: 6,
      last_scanned: daysAgo(1),
    },
  ]
  return { subnets }
}

export function mockSwitches(): SwitchesResponse {
  const switches: Switch[] = [
    {
      host: '192.168.1.2',
      label: 'Floor 1 Switch',
      community: 'public',
      version: '2c',
      mac_count: 8,
      last_polled: daysAgo(0),
    },
    {
      host: '192.168.1.3',
      label: 'Floor 2 Switch',
      community: 'public',
      version: '2c',
      mac_count: 4,
      last_polled: daysAgo(0),
    },
  ]
  return { switches }
}

export function mockTopology(): TopologyResponse {
  const nodes: TopologyNode[] = [
    // Gateways
    {
      id: 'gw-192.168.1.1',
      label: 'gw-office-01',
      ip: '192.168.1.1',
      mac: '00:1A:2B:3C:4D:01',
      hostname: 'gw-office-01',
      vendor: 'Cisco',
      type: 'gateway',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.98,
      open_ports: [22, 80, 443],
      size: 40,
      color: '#ef4444',
      subnet: '192.168.1.0/24',
      switch_port: null,
    },
    {
      id: 'gw-10.0.0.1',
      label: 'gw-server',
      ip: '10.0.0.1',
      mac: '00:1A:2B:3C:4D:A1',
      hostname: 'gw-server',
      vendor: 'Cisco',
      type: 'gateway',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.99,
      open_ports: [22, 443],
      size: 40,
      color: '#ef4444',
      subnet: '10.0.0.0/24',
      switch_port: null,
    },
    // Switches
    {
      id: 'sw-192.168.1.2',
      label: 'sw-floor1',
      ip: '192.168.1.2',
      mac: '00:1A:2B:3C:4D:02',
      hostname: 'sw-floor1',
      vendor: 'Cisco',
      type: 'switch',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.96,
      open_ports: [22, 161],
      size: 35,
      color: '#f97316',
      subnet: '192.168.1.0/24',
      switch_port: null,
    },
    {
      id: 'sw-192.168.1.3',
      label: 'sw-floor2',
      ip: '192.168.1.3',
      mac: '00:1A:2B:3C:4D:03',
      hostname: 'sw-floor2',
      vendor: 'HP',
      type: 'switch',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.94,
      open_ports: [22, 80, 161],
      size: 35,
      color: '#f97316',
      subnet: '192.168.1.0/24',
      switch_port: null,
    },
    // Firewall
    {
      id: 'dev-192.168.1.10',
      label: 'fw-perimeter',
      ip: '192.168.1.10',
      mac: '3C:52:82:AA:11:10',
      hostname: 'fw-perimeter',
      vendor: 'Fortinet',
      type: 'device',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.97,
      open_ports: [22, 443, 541],
      size: 30,
      color: '#3b82f6',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/1',
    },
    // WAP
    {
      id: 'dev-192.168.1.20',
      label: 'wap-lobby',
      ip: '192.168.1.20',
      mac: 'A4:BB:6D:CC:20:01',
      hostname: 'wap-lobby',
      vendor: 'Ubiquiti',
      type: 'device',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.91,
      open_ports: [22, 443],
      size: 25,
      color: '#3b82f6',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/5',
    },
    // IoT
    {
      id: 'dev-192.168.1.50',
      label: 'printer-floor1',
      ip: '192.168.1.50',
      mac: 'D4:BE:D9:EE:50:01',
      hostname: 'printer-floor1',
      vendor: 'HP Inc.',
      type: 'device',
      bigr_category: 'iot',
      confidence: 0.89,
      open_ports: [80, 443, 515, 631, 9100],
      size: 20,
      color: '#10b981',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/8',
    },
    {
      id: 'dev-192.168.1.51',
      label: 'cam-entrance',
      ip: '192.168.1.51',
      mac: '00:80:91:FF:51:02',
      hostname: 'cam-entrance',
      vendor: 'Hikvision',
      type: 'device',
      bigr_category: 'iot',
      confidence: 0.85,
      open_ports: [80, 554, 8000],
      size: 18,
      color: '#10b981',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/9',
    },
    {
      id: 'dev-192.168.1.52',
      label: 'cam-parking',
      ip: '192.168.1.52',
      mac: '00:80:91:FF:52:03',
      hostname: 'cam-parking',
      vendor: 'Hikvision',
      type: 'device',
      bigr_category: 'iot',
      confidence: 0.84,
      open_ports: [80, 554, 8000],
      size: 18,
      color: '#10b981',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/10',
    },
    // Portable
    {
      id: 'dev-192.168.1.100',
      label: 'lt-okan',
      ip: '192.168.1.100',
      mac: 'F0:DE:F1:AA:00:01',
      hostname: 'lt-okan',
      vendor: 'Apple',
      type: 'device',
      bigr_category: 'tasinabilir',
      confidence: 0.92,
      open_ports: [22, 5900],
      size: 20,
      color: '#f59e0b',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/15',
    },
    {
      id: 'dev-192.168.1.101',
      label: 'lt-devops-ali',
      ip: '192.168.1.101',
      mac: '28:CF:E9:BB:01:02',
      hostname: 'lt-devops-ali',
      vendor: 'Dell',
      type: 'device',
      bigr_category: 'tasinabilir',
      confidence: 0.88,
      open_ports: [22],
      size: 20,
      color: '#f59e0b',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/16',
    },
    // Unclassified
    {
      id: 'dev-192.168.1.102',
      label: '192.168.1.102',
      ip: '192.168.1.102',
      mac: '60:F2:62:CC:02:03',
      hostname: null,
      vendor: 'Intel Corporate',
      type: 'device',
      bigr_category: 'unclassified',
      confidence: 0.35,
      open_ports: [],
      size: 15,
      color: '#6b7280',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/20',
    },
    {
      id: 'dev-192.168.1.103',
      label: '192.168.1.103',
      ip: '192.168.1.103',
      mac: 'AC:DE:48:DD:03:04',
      hostname: null,
      vendor: null,
      type: 'device',
      bigr_category: 'unclassified',
      confidence: 0.28,
      open_ports: [80],
      size: 15,
      color: '#6b7280',
      subnet: '192.168.1.0/24',
      switch_port: 'Gi0/21',
    },
    // Server VLAN devices
    {
      id: 'dev-10.0.0.10',
      label: 'web-prod-01',
      ip: '10.0.0.10',
      mac: '00:25:90:EE:10:01',
      hostname: 'web-prod-01',
      vendor: 'Dell',
      type: 'device',
      bigr_category: 'uygulamalar',
      confidence: 0.95,
      open_ports: [22, 80, 443, 8080],
      size: 25,
      color: '#8b5cf6',
      subnet: '10.0.0.0/24',
      switch_port: null,
    },
    {
      id: 'dev-10.0.0.11',
      label: 'web-prod-02',
      ip: '10.0.0.11',
      mac: '00:25:90:EE:11:02',
      hostname: 'web-prod-02',
      vendor: 'Dell',
      type: 'device',
      bigr_category: 'uygulamalar',
      confidence: 0.95,
      open_ports: [22, 80, 443, 8080],
      size: 25,
      color: '#8b5cf6',
      subnet: '10.0.0.0/24',
      switch_port: null,
    },
    {
      id: 'dev-10.0.0.20',
      label: 'db-postgres-01',
      ip: '10.0.0.20',
      mac: '00:25:90:EE:20:03',
      hostname: 'db-postgres-01',
      vendor: 'HP',
      type: 'device',
      bigr_category: 'uygulamalar',
      confidence: 0.93,
      open_ports: [22, 5432],
      size: 25,
      color: '#8b5cf6',
      subnet: '10.0.0.0/24',
      switch_port: null,
    },
    {
      id: 'dev-10.0.0.30',
      label: 'mail-exchange',
      ip: '10.0.0.30',
      mac: '00:25:90:EE:30:04',
      hostname: 'mail-exchange',
      vendor: 'HP',
      type: 'device',
      bigr_category: 'uygulamalar',
      confidence: 0.91,
      open_ports: [22, 25, 443, 587, 993],
      size: 25,
      color: '#8b5cf6',
      subnet: '10.0.0.0/24',
      switch_port: null,
    },
    {
      id: 'dev-10.0.0.40',
      label: 'nas-backup',
      ip: '10.0.0.40',
      mac: '2C:F0:5D:FF:40:05',
      hostname: 'nas-backup',
      vendor: 'Synology',
      type: 'device',
      bigr_category: 'ag_ve_sistemler',
      confidence: 0.87,
      open_ports: [22, 80, 443, 5000, 5001],
      size: 22,
      color: '#3b82f6',
      subnet: '10.0.0.0/24',
      switch_port: null,
    },
  ]

  const edges: TopologyEdge[] = [
    // Gateway inter-connect
    { source: 'gw-192.168.1.1', target: 'gw-10.0.0.1', type: 'gateway', label: 'trunk' },
    // Office gateway -> switches
    { source: 'gw-192.168.1.1', target: 'sw-192.168.1.2', type: 'switch', label: 'Gi0/24' },
    { source: 'gw-192.168.1.1', target: 'sw-192.168.1.3', type: 'switch', label: 'Gi0/23' },
    // Switch 1 -> devices
    { source: 'sw-192.168.1.2', target: 'dev-192.168.1.10', type: 'connection', label: 'Gi0/1' },
    { source: 'sw-192.168.1.2', target: 'dev-192.168.1.20', type: 'connection', label: 'Gi0/5' },
    { source: 'sw-192.168.1.2', target: 'dev-192.168.1.50', type: 'connection', label: 'Gi0/8' },
    { source: 'sw-192.168.1.2', target: 'dev-192.168.1.51', type: 'connection', label: 'Gi0/9' },
    { source: 'sw-192.168.1.2', target: 'dev-192.168.1.52', type: 'connection', label: 'Gi0/10' },
    // Switch 2 -> devices
    { source: 'sw-192.168.1.3', target: 'dev-192.168.1.100', type: 'connection', label: 'Gi0/15' },
    { source: 'sw-192.168.1.3', target: 'dev-192.168.1.101', type: 'connection', label: 'Gi0/16' },
    { source: 'sw-192.168.1.3', target: 'dev-192.168.1.102', type: 'connection', label: 'Gi0/20' },
    { source: 'sw-192.168.1.3', target: 'dev-192.168.1.103', type: 'connection', label: 'Gi0/21' },
    // Server VLAN gateway -> devices (direct, no managed switch)
    { source: 'gw-10.0.0.1', target: 'dev-10.0.0.10', type: 'connection', label: null },
    { source: 'gw-10.0.0.1', target: 'dev-10.0.0.11', type: 'connection', label: null },
    { source: 'gw-10.0.0.1', target: 'dev-10.0.0.20', type: 'connection', label: null },
    { source: 'gw-10.0.0.1', target: 'dev-10.0.0.30', type: 'connection', label: null },
    { source: 'gw-10.0.0.1', target: 'dev-10.0.0.40', type: 'connection', label: null },
  ]

  return {
    nodes,
    edges,
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: {
        gateway: 2,
        switch: 2,
        device: nodes.length - 4,
      },
    },
  }
}

export function mockTopologySubnet(cidr: string): TopologyResponse {
  const full = mockTopology()
  const prefix = cidr.replace(/\.0\/\d+$/, '.')
  const filtered = full.nodes.filter(
    (n) => n.ip && n.ip.startsWith(prefix),
  )
  const nodeIds = new Set(filtered.map((n) => n.id))
  const filteredEdges = full.edges.filter(
    (e) => nodeIds.has(e.source) && nodeIds.has(e.target),
  )
  return {
    nodes: filtered,
    edges: filteredEdges,
    stats: {
      total_nodes: filtered.length,
      total_edges: filteredEdges.length,
      node_types: filtered.reduce(
        (acc, n) => {
          acc[n.type] = (acc[n.type] || 0) + 1
          return acc
        },
        {} as Record<string, number>,
      ),
    },
  }
}

export function mockCompliance(): ComplianceResponse {
  const total = MOCK_ASSETS.length
  const fullyClassified = MOCK_ASSETS.filter(
    (a) => a.bigr_category !== 'unclassified' && a.confidence_score >= 0.7,
  ).length
  const partiallyClassified = MOCK_ASSETS.filter(
    (a) => a.bigr_category !== 'unclassified' && a.confidence_score < 0.7,
  ).length
  const unclassified = MOCK_ASSETS.filter(
    (a) => a.bigr_category === 'unclassified',
  ).length
  const manualOverrides = MOCK_ASSETS.filter((a) => a.manual_override).length

  const counts = buildCategorySummary(MOCK_ASSETS)
  const percentages: Record<string, number> = {}
  for (const [k, v] of Object.entries(counts)) {
    percentages[k] = Math.round((v / total) * 100)
  }

  const subnetCompliance: SubnetCompliance[] = [
    { cidr: '192.168.1.0/24', label: 'Office LAN', score: 78.5, grade: 'B' },
    { cidr: '10.0.0.0/24', label: 'Server VLAN', score: 95.0, grade: 'A' },
  ]

  const actionItems: ActionItem[] = [
    {
      priority: 'high',
      type: 'classify',
      ip: '192.168.1.102',
      reason: 'Unknown device with Intel NIC detected 3 days ago - needs classification',
    },
    {
      priority: 'high',
      type: 'classify',
      ip: '192.168.1.103',
      reason: 'Unidentified device with open HTTP port - potential rogue device',
    },
    {
      priority: 'medium',
      type: 'review',
      ip: '192.168.1.51',
      reason: 'Hikvision camera with known CVE exposure - review firmware version',
    },
    {
      priority: 'low',
      type: 'update',
      ip: '10.0.0.30',
      reason: 'Mail server running Windows Server 2022 - verify latest patches applied',
    },
  ]

  return {
    compliance_score: 82.4,
    grade: 'B+',
    breakdown: {
      total_assets: total,
      fully_classified: fullyClassified,
      partially_classified: partiallyClassified,
      unclassified,
      manual_overrides: manualOverrides,
    },
    distribution: { counts, percentages, total },
    subnet_compliance: subnetCompliance,
    action_items: actionItems,
  }
}

export function mockAnalytics(): AnalyticsResponse {
  // 7-day asset count trend
  const assetCountTrend: TrendSeries = {
    name: 'Total Assets',
    points: Array.from({ length: 7 }, (_, i): TrendPoint => {
      const day = 6 - i
      return {
        date: dateOnly(day),
        value: 15 + Math.floor(i * 0.5),
        label: null,
      }
    }),
  }

  // Category trends
  const categories: { name: string; base: number; growth: number }[] = [
    { name: 'ag_ve_sistemler', base: 6, growth: 0.2 },
    { name: 'uygulamalar', base: 4, growth: 0 },
    { name: 'iot', base: 2, growth: 0.15 },
    { name: 'tasinabilir', base: 2, growth: 0 },
    { name: 'unclassified', base: 0, growth: 0.3 },
  ]
  const categoryTrends: TrendSeries[] = categories.map((cat) => ({
    name: cat.name,
    points: Array.from({ length: 7 }, (_, i): TrendPoint => ({
      date: dateOnly(6 - i),
      value: Math.round(cat.base + i * cat.growth),
      label: null,
    })),
  }))

  const newVsRemoved: TrendSeries = {
    name: 'New vs Removed',
    points: [
      { date: dateOnly(6), value: 1, label: 'new' },
      { date: dateOnly(5), value: 0, label: 'removed' },
      { date: dateOnly(4), value: 0, label: null },
      { date: dateOnly(3), value: 1, label: 'new' },
      { date: dateOnly(2), value: 0, label: null },
      { date: dateOnly(1), value: 1, label: 'new' },
      { date: dateOnly(0), value: 0, label: null },
    ],
  }

  const mostChangedAssets: MostChangedAsset[] = [
    { ip: '192.168.1.50', change_count: 4, last_change: daysAgo(2) },
    { ip: '10.0.0.10', change_count: 3, last_change: daysAgo(4) },
    { ip: '192.168.1.20', change_count: 2, last_change: daysAgo(5) },
  ]

  const scanFrequency: ScanFrequency[] = Array.from(
    { length: 7 },
    (_, i): ScanFrequency => ({
      date: dateOnly(6 - i),
      scan_count: i % 2 === 0 ? 1 : 2,
      total_assets: 15 + Math.floor(i * 0.5),
    }),
  )

  return {
    asset_count_trend: assetCountTrend,
    category_trends: categoryTrends,
    new_vs_removed: newVsRemoved,
    most_changed_assets: mostChangedAssets,
    scan_frequency: scanFrequency,
  }
}

export function mockRisk(): RiskResponse {
  const profiles: RiskProfile[] = [
    {
      ip: '192.168.1.51',
      mac: '00:80:91:FF:51:02',
      hostname: 'cam-entrance',
      vendor: 'Hikvision',
      bigr_category: 'iot',
      risk_score: 8.7,
      risk_level: 'critical',
      factors: {
        cve_score: 9.8,
        exposure_score: 7.5,
        classification_score: 2.0,
        age_score: 6.0,
        change_score: 3.0,
      },
      top_cve: 'CVE-2023-28808',
    },
    {
      ip: '192.168.1.103',
      mac: 'AC:DE:48:DD:03:04',
      hostname: null,
      vendor: null,
      bigr_category: 'unclassified',
      risk_score: 7.9,
      risk_level: 'high',
      factors: {
        cve_score: 0.0,
        exposure_score: 8.0,
        classification_score: 10.0,
        age_score: 9.0,
        change_score: 5.0,
      },
      top_cve: null,
    },
    {
      ip: '192.168.1.52',
      mac: '00:80:91:FF:52:03',
      hostname: 'cam-parking',
      vendor: 'Hikvision',
      bigr_category: 'iot',
      risk_score: 7.2,
      risk_level: 'high',
      factors: {
        cve_score: 9.8,
        exposure_score: 5.5,
        classification_score: 2.0,
        age_score: 6.0,
        change_score: 2.0,
      },
      top_cve: 'CVE-2023-28808',
    },
    {
      ip: '10.0.0.30',
      mac: '00:25:90:EE:30:04',
      hostname: 'mail-exchange',
      vendor: 'HP',
      bigr_category: 'uygulamalar',
      risk_score: 6.1,
      risk_level: 'medium',
      factors: {
        cve_score: 7.5,
        exposure_score: 6.0,
        classification_score: 1.0,
        age_score: 4.0,
        change_score: 2.0,
      },
      top_cve: 'CVE-2024-21413',
    },
    {
      ip: '192.168.1.102',
      mac: '60:F2:62:CC:02:03',
      hostname: null,
      vendor: 'Intel Corporate',
      bigr_category: 'unclassified',
      risk_score: 5.8,
      risk_level: 'medium',
      factors: {
        cve_score: 0.0,
        exposure_score: 4.0,
        classification_score: 10.0,
        age_score: 8.0,
        change_score: 3.0,
      },
      top_cve: null,
    },
    {
      ip: '192.168.1.50',
      mac: 'D4:BE:D9:EE:50:01',
      hostname: 'printer-floor1',
      vendor: 'HP Inc.',
      bigr_category: 'iot',
      risk_score: 4.3,
      risk_level: 'medium',
      factors: {
        cve_score: 5.3,
        exposure_score: 5.0,
        classification_score: 1.5,
        age_score: 3.0,
        change_score: 4.0,
      },
      top_cve: 'CVE-2024-24794',
    },
    {
      ip: '10.0.0.10',
      mac: '00:25:90:EE:10:01',
      hostname: 'web-prod-01',
      vendor: 'Dell',
      bigr_category: 'uygulamalar',
      risk_score: 3.5,
      risk_level: 'low',
      factors: {
        cve_score: 4.0,
        exposure_score: 4.5,
        classification_score: 0.5,
        age_score: 2.0,
        change_score: 3.5,
      },
      top_cve: 'CVE-2024-6387',
    },
    {
      ip: '192.168.1.1',
      mac: '00:1A:2B:3C:4D:01',
      hostname: 'gw-office-01',
      vendor: 'Cisco',
      bigr_category: 'ag_ve_sistemler',
      risk_score: 2.1,
      risk_level: 'low',
      factors: {
        cve_score: 3.0,
        exposure_score: 2.5,
        classification_score: 0.2,
        age_score: 1.5,
        change_score: 1.0,
      },
      top_cve: null,
    },
  ]

  const critical = profiles.filter((p) => p.risk_level === 'critical').length
  const high = profiles.filter((p) => p.risk_level === 'high').length
  const medium = profiles.filter((p) => p.risk_level === 'medium').length
  const low = profiles.filter((p) => p.risk_level === 'low').length

  return {
    profiles,
    average_risk: +(
      profiles.reduce((s, p) => s + p.risk_score, 0) / profiles.length
    ).toFixed(1),
    max_risk: Math.max(...profiles.map((p) => p.risk_score)),
    critical_count: critical,
    high_count: high,
    medium_count: medium,
    low_count: low,
    top_risks: profiles.slice(0, 3),
  }
}

export function mockVulnerabilities(): VulnerabilitiesResponse {
  const cveHikvision: CveEntry = {
    cve_id: 'CVE-2023-28808',
    cvss_score: 9.8,
    severity: 'critical',
    description:
      'Hikvision Hybrid SAN/Cluster Storage products allow unauthorized access via crafted messages to the web-based management interface.',
    affected_vendor: 'Hikvision',
    affected_product: 'DS-A71024/48/72R',
    cpe: 'cpe:2.3:h:hikvision:*:*:*:*:*:*:*:*:*',
    published: '2023-05-10T00:00:00Z',
    fix_available: true,
    cisa_kev: true,
  }

  const cveOutlook: CveEntry = {
    cve_id: 'CVE-2024-21413',
    cvss_score: 9.8,
    severity: 'critical',
    description:
      'Microsoft Outlook Remote Code Execution Vulnerability - Moniker Link variant allows bypassing Protected View.',
    affected_vendor: 'Microsoft',
    affected_product: 'Outlook',
    cpe: 'cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*',
    published: '2024-02-13T00:00:00Z',
    fix_available: true,
    cisa_kev: true,
  }

  const cveLaserJet: CveEntry = {
    cve_id: 'CVE-2024-24794',
    cvss_score: 5.3,
    severity: 'medium',
    description:
      'HP LaserJet Pro printers may disclose sensitive information via SNMP due to improper access controls.',
    affected_vendor: 'HP',
    affected_product: 'LaserJet Pro',
    cpe: 'cpe:2.3:h:hp:laserjet_pro:*:*:*:*:*:*:*:*',
    published: '2024-03-18T00:00:00Z',
    fix_available: true,
    cisa_kev: false,
  }

  const cveRegresshion: CveEntry = {
    cve_id: 'CVE-2024-6387',
    cvss_score: 8.1,
    severity: 'high',
    description:
      'RegreSSHion: Remote Code Execution in OpenSSH server (sshd) via race condition in signal handler.',
    affected_vendor: 'OpenSSH',
    affected_product: 'OpenSSH',
    cpe: 'cpe:2.3:a:openssh:openssh:*:*:*:*:*:*:*:*',
    published: '2024-07-01T00:00:00Z',
    fix_available: true,
    cisa_kev: false,
  }

  const summaries: AssetVulnSummary[] = [
    {
      ip: '192.168.1.51',
      total_vulns: 1,
      critical_count: 1,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      max_cvss: 9.8,
      matches: [
        {
          asset_ip: '192.168.1.51',
          asset_mac: '00:80:91:FF:51:02',
          asset_vendor: 'Hikvision',
          cve: cveHikvision,
          match_type: 'vendor',
          match_confidence: 0.85,
        },
      ],
    },
    {
      ip: '192.168.1.52',
      total_vulns: 1,
      critical_count: 1,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      max_cvss: 9.8,
      matches: [
        {
          asset_ip: '192.168.1.52',
          asset_mac: '00:80:91:FF:52:03',
          asset_vendor: 'Hikvision',
          cve: cveHikvision,
          match_type: 'vendor',
          match_confidence: 0.85,
        },
      ],
    },
    {
      ip: '10.0.0.30',
      total_vulns: 1,
      critical_count: 1,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      max_cvss: 9.8,
      matches: [
        {
          asset_ip: '10.0.0.30',
          asset_mac: '00:25:90:EE:30:04',
          asset_vendor: 'HP',
          cve: cveOutlook,
          match_type: 'product',
          match_confidence: 0.75,
        },
      ],
    },
    {
      ip: '192.168.1.50',
      total_vulns: 1,
      critical_count: 0,
      high_count: 0,
      medium_count: 1,
      low_count: 0,
      max_cvss: 5.3,
      matches: [
        {
          asset_ip: '192.168.1.50',
          asset_mac: 'D4:BE:D9:EE:50:01',
          asset_vendor: 'HP Inc.',
          cve: cveLaserJet,
          match_type: 'vendor',
          match_confidence: 0.70,
        },
      ],
    },
    {
      ip: '10.0.0.10',
      total_vulns: 1,
      critical_count: 0,
      high_count: 1,
      medium_count: 0,
      low_count: 0,
      max_cvss: 8.1,
      matches: [
        {
          asset_ip: '10.0.0.10',
          asset_mac: '00:25:90:EE:10:01',
          asset_vendor: 'Dell',
          cve: cveRegresshion,
          match_type: 'port',
          match_confidence: 0.60,
        },
      ],
    },
  ]

  return { summaries }
}

export function mockCertificates(): CertificatesResponse {
  const certificates: Certificate[] = [
    {
      ip: '10.0.0.10',
      port: 443,
      cn: 'web-prod-01.corp.local',
      issuer: 'DigiCert SHA2 Extended Validation Server CA',
      valid_from: '2025-06-15T00:00:00Z',
      valid_to: daysFromNow(185),
      days_until_expiry: 185,
      is_self_signed: false,
      key_size: 2048,
      serial_number: '0A:3B:7C:8D:9E:0F:1A:2B',
    },
    {
      ip: '10.0.0.11',
      port: 443,
      cn: 'web-prod-02.corp.local',
      issuer: 'DigiCert SHA2 Extended Validation Server CA',
      valid_from: '2025-06-15T00:00:00Z',
      valid_to: daysFromNow(185),
      days_until_expiry: 185,
      is_self_signed: false,
      key_size: 2048,
      serial_number: '0A:3B:7C:8D:9E:0F:1A:2C',
    },
    {
      ip: '10.0.0.30',
      port: 443,
      cn: 'mail.corp.local',
      issuer: 'CN=corp-CA, O=Corp Ltd',
      valid_from: '2025-01-10T00:00:00Z',
      valid_to: daysFromNow(12),
      days_until_expiry: 12,
      is_self_signed: false,
      key_size: 4096,
      serial_number: '1F:2E:3D:4C:5B:6A:7F:8E',
    },
    {
      ip: '192.168.1.50',
      port: 443,
      cn: 'HP LaserJet Pro',
      issuer: 'CN=HP LaserJet Pro',
      valid_from: '2023-01-01T00:00:00Z',
      valid_to: daysFromNow(690),
      days_until_expiry: 690,
      is_self_signed: true,
      key_size: 1024,
      serial_number: 'AB:CD:EF:01:23:45:67:89',
    },
  ]
  return { certificates }
}

export function mockHealth(): HealthResponse {
  return {
    status: 'ok',
    data_file: 'demo_mode',
    exists: true,
  }
}

// ---------------------------------------------------------------------------
// Shield Mock Data
// ---------------------------------------------------------------------------

import type { ShieldFinding, ModuleScore, ShieldScanResponse, ShieldFindingsResponse, ShieldModulesResponse } from '@/types/shield'

const mockShieldFindings_data: ShieldFinding[] = [
  // ── TLS Findings ──
  {
    id: 'sf_001',
    scan_id: 'sh_demo001',
    module: 'tls',
    severity: 'high',
    title: 'TLS 1.0 Protocol Enabled',
    description: 'The server supports TLS 1.0 which has known vulnerabilities including BEAST and POODLE attacks.',
    remediation: 'Disable TLS 1.0 and 1.1 in your web server configuration. For Nginx: ssl_protocols TLSv1.2 TLSv1.3;',
    target_ip: '93.184.216.34',
    target_port: 443,
    evidence: { protocol: 'TLSv1.0', cipher: 'AES256-SHA' },
    attack_technique: 'T1557',
    attack_tactic: 'Credential Access',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_002',
    scan_id: 'sh_demo001',
    module: 'tls',
    severity: 'medium',
    title: 'Weak Cipher Suites Accepted',
    description: 'The server accepts cipher suites using CBC mode which are vulnerable to padding oracle attacks.',
    remediation: 'Configure your server to prefer AEAD cipher suites (GCM, ChaCha20-Poly1305). Disable CBC-mode ciphers.',
    target_ip: '93.184.216.34',
    target_port: 443,
    evidence: { weak_ciphers: ['AES256-SHA', 'AES128-SHA', 'DES-CBC3-SHA'] },
    attack_technique: 'T1557',
    attack_tactic: 'Credential Access',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_003',
    scan_id: 'sh_demo001',
    module: 'tls',
    severity: 'low',
    title: 'Certificate Expires in 28 Days',
    description: 'The TLS certificate will expire within 30 days. Renew before expiry to avoid service disruption.',
    remediation: 'Renew your TLS certificate. Consider using Let\'s Encrypt for automatic renewal.',
    target_ip: '93.184.216.34',
    target_port: 443,
    evidence: { expires: '2026-03-09T00:00:00Z', days_remaining: 28 },
    attack_technique: null,
    attack_tactic: null,
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  // ── Port Findings ──
  {
    id: 'sf_010',
    scan_id: 'sh_demo001',
    module: 'ports',
    severity: 'info',
    title: 'Port 22 (SSH) Open',
    description: 'SSH service is running on port 22. This is a common administrative port.',
    remediation: 'Ensure SSH access is restricted to authorized IPs via firewall rules. Use key-based authentication.',
    target_ip: '93.184.216.34',
    target_port: 22,
    evidence: { service: 'SSH', banner: 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.6' },
    attack_technique: null,
    attack_tactic: null,
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_011',
    scan_id: 'sh_demo001',
    module: 'ports',
    severity: 'info',
    title: 'Port 80 (HTTP) Open',
    description: 'HTTP service is running on port 80. Ensure HTTPS redirect is in place.',
    remediation: 'Configure automatic redirect from HTTP to HTTPS on port 443.',
    target_ip: '93.184.216.34',
    target_port: 80,
    evidence: { service: 'HTTP', banner: 'nginx' },
    attack_technique: null,
    attack_tactic: null,
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_012',
    scan_id: 'sh_demo001',
    module: 'ports',
    severity: 'info',
    title: 'Port 443 (HTTPS) Open',
    description: 'HTTPS service is running on port 443. This is the expected secure web port.',
    remediation: 'No action needed. This is the standard secure web port.',
    target_ip: '93.184.216.34',
    target_port: 443,
    evidence: { service: 'HTTPS', banner: 'nginx' },
    attack_technique: null,
    attack_tactic: null,
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_013',
    scan_id: 'sh_demo001',
    module: 'ports',
    severity: 'high',
    title: 'MySQL (3306) Exposed to Internet',
    description: 'MySQL database service is directly accessible from the internet on port 3306. This poses a severe risk of data breach through brute-force or exploitation.',
    remediation: 'Block port 3306 at the firewall level. Use SSH tunneling or VPN for remote database access. Never expose database ports to the public internet.',
    target_ip: '93.184.216.34',
    target_port: 3306,
    evidence: { service: 'MySQL', banner: '5.7.42-0ubuntu0.18.04.1', state: 'open' },
    attack_technique: 'T1190',
    attack_tactic: 'Initial Access',
    cve_id: null,
    cvss_score: 8.1,
    epss_score: 0.15,
    cisa_kev: false,
  },
  {
    id: 'sf_014',
    scan_id: 'sh_demo001',
    module: 'ports',
    severity: 'high',
    title: 'Redis (6379) Exposed to Internet',
    description: 'Redis cache service is directly accessible from the internet on port 6379. Redis often runs without authentication, allowing arbitrary data access or remote code execution.',
    remediation: 'Block port 6379 at the firewall. If remote access is needed, use Redis AUTH, TLS, and restrict via firewall rules. Bind to localhost: bind 127.0.0.1',
    target_ip: '93.184.216.34',
    target_port: 6379,
    evidence: { service: 'Redis', banner: 'redis_version:7.0.15', auth_required: false },
    attack_technique: 'T1190',
    attack_tactic: 'Initial Access',
    cve_id: null,
    cvss_score: 9.0,
    epss_score: 0.25,
    cisa_kev: false,
  },
  // ── Header Findings ──
  {
    id: 'sf_020',
    scan_id: 'sh_demo001',
    module: 'headers',
    severity: 'high',
    title: 'Missing Strict-Transport-Security (HSTS)',
    description: 'The server does not send the Strict-Transport-Security header. Without HSTS, browsers may connect over insecure HTTP, enabling man-in-the-middle and downgrade attacks.',
    remediation: 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    target_ip: '93.184.216.34',
    target_port: 443,
    evidence: { header: 'Strict-Transport-Security', present: false },
    attack_technique: 'T1557.002',
    attack_tactic: 'Credential Access',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_021',
    scan_id: 'sh_demo001',
    module: 'headers',
    severity: 'medium',
    title: 'Missing Content-Security-Policy (CSP)',
    description: 'No Content-Security-Policy header is set. CSP helps prevent cross-site scripting (XSS) and data injection attacks by restricting resource loading.',
    remediation: 'Add a Content-Security-Policy header. Start with a report-only policy: Content-Security-Policy-Report-Only: default-src \'self\'',
    target_ip: '93.184.216.34',
    target_port: 443,
    evidence: { header: 'Content-Security-Policy', present: false },
    attack_technique: 'T1059.007',
    attack_tactic: 'Execution',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_022',
    scan_id: 'sh_demo001',
    module: 'headers',
    severity: 'medium',
    title: 'Server Header Leaking Version Info',
    description: 'The Server response header reveals software and version information: "nginx/1.24.0". This helps attackers identify specific vulnerabilities for this version.',
    remediation: 'Configure your web server to suppress version information. For Nginx: server_tokens off;',
    target_ip: '93.184.216.34',
    target_port: 443,
    evidence: { header: 'Server', value: 'nginx/1.24.0', info_leak: true },
    attack_technique: 'T1592',
    attack_tactic: 'Reconnaissance',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  // ── DNS Findings ──
  {
    id: 'sf_030',
    scan_id: 'sh_demo001',
    module: 'dns',
    severity: 'high',
    title: 'DMARC Policy Set to None',
    description: 'The DMARC record exists but the policy is set to "none", providing no enforcement against email spoofing. Attackers can send emails impersonating your domain.',
    remediation: 'Update your DMARC record to enforce policy: v=DMARC1; p=reject; rua=mailto:dmarc@example.com. Transition through p=quarantine first if needed.',
    target_ip: '93.184.216.34',
    target_port: null,
    evidence: { record: 'v=DMARC1; p=none; rua=mailto:dmarc@example.com', policy: 'none' },
    attack_technique: 'T1566.001',
    attack_tactic: 'Initial Access',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_031',
    scan_id: 'sh_demo001',
    module: 'dns',
    severity: 'medium',
    title: 'No DKIM Record Found',
    description: 'No DKIM (DomainKeys Identified Mail) record was found for the domain. DKIM allows recipients to verify that emails are authorized and unaltered.',
    remediation: 'Configure DKIM signing on your mail server and publish the public key as a DNS TXT record: selector._domainkey.example.com',
    target_ip: '93.184.216.34',
    target_port: null,
    evidence: { selector: 'default', record_found: false },
    attack_technique: 'T1566.001',
    attack_tactic: 'Initial Access',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'sf_032',
    scan_id: 'sh_demo001',
    module: 'dns',
    severity: 'low',
    title: 'No CAA Record Found',
    description: 'No Certificate Authority Authorization (CAA) DNS record is set. CAA records restrict which Certificate Authorities can issue certificates for your domain.',
    remediation: 'Add a CAA record to restrict certificate issuance: example.com. CAA 0 issue "letsencrypt.org"',
    target_ip: '93.184.216.34',
    target_port: null,
    evidence: { record_type: 'CAA', found: false },
    attack_technique: null,
    attack_tactic: null,
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  // ── CVE Findings ──
  {
    id: 'f-cve-1',
    scan_id: 'sh_demo001',
    module: 'cve',
    severity: 'critical' as const,
    title: 'CVE-2024-6387 (RegreSSHion) - OpenSSH RCE',
    description: 'Race condition in OpenSSH sshd allows unauthenticated remote code execution on glibc-based Linux systems.',
    remediation: 'Update OpenSSH to 9.8p1 or later. Apply vendor patches immediately.',
    target_ip: '192.168.1.10',
    target_port: 22,
    evidence: { service: 'openssh', version: '8.9p1', cpe: 'cpe:2.3:a:openbsd:openssh:8.9p1' },
    attack_technique: 'T1133',
    attack_tactic: 'Initial Access',
    cve_id: 'CVE-2024-6387',
    cvss_score: 8.1,
    epss_score: 0.95,
    cisa_kev: true,
  },
  {
    id: 'f-cve-2',
    scan_id: 'sh_demo001',
    module: 'cve',
    severity: 'critical' as const,
    title: 'CVE-2024-3094 - XZ Utils Backdoor',
    description: 'Malicious code in xz/liblzma allowing SSH authentication bypass via crafted payloads.',
    remediation: 'Downgrade xz-utils to 5.4.x or update to 5.6.2+.',
    target_ip: '192.168.1.10',
    target_port: 22,
    evidence: { service: 'openssh', version: '8.9p1', related_package: 'xz-utils 5.6.0' },
    attack_technique: 'T1195.002',
    attack_tactic: 'Initial Access',
    cve_id: 'CVE-2024-3094',
    cvss_score: 10.0,
    epss_score: 0.78,
    cisa_kev: true,
  },
  {
    id: 'f-cve-3',
    scan_id: 'sh_demo001',
    module: 'cve',
    severity: 'high' as const,
    title: 'CVE-2023-44487 - HTTP/2 Rapid Reset DDoS',
    description: 'HTTP/2 protocol vulnerability allows denial of service via rapid stream resets.',
    remediation: 'Update web server and apply HTTP/2 rate limiting configuration.',
    target_ip: '192.168.1.10',
    target_port: 443,
    evidence: { service: 'nginx', version: '1.24.0', cpe: 'cpe:2.3:a:f5:nginx:1.24.0' },
    attack_technique: 'T1190',
    attack_tactic: 'Initial Access',
    cve_id: 'CVE-2023-44487',
    cvss_score: 7.5,
    epss_score: 0.62,
    cisa_kev: true,
  },
  {
    id: 'f-cve-4',
    scan_id: 'sh_demo001',
    module: 'cve',
    severity: 'medium' as const,
    title: 'CVE-2023-5678 - OpenSSL Timing Side-Channel',
    description: 'Timing oracle in OpenSSL DH key generation may leak private key material.',
    remediation: 'Update OpenSSL to 3.2.1 or later.',
    target_ip: '192.168.1.10',
    target_port: 443,
    evidence: { service: 'nginx', version: '1.24.0', library: 'openssl 3.0.13' },
    attack_technique: 'T1557',
    attack_tactic: 'Credential Access',
    cve_id: 'CVE-2023-5678',
    cvss_score: 5.3,
    epss_score: 0.12,
    cisa_kev: false,
  },
  {
    id: 'f-cve-5',
    scan_id: 'sh_demo001',
    module: 'cve',
    severity: 'low' as const,
    title: 'CVE-2024-2961 - MySQL Information Disclosure',
    description: 'MySQL server may expose internal error messages to unauthenticated clients.',
    remediation: 'Update MySQL to latest patch version and restrict error verbosity.',
    target_ip: '192.168.1.10',
    target_port: 3306,
    evidence: { service: 'mysql', version: '8.0.35', cpe: 'cpe:2.3:a:oracle:mysql:8.0.35' },
    attack_technique: 'T1190',
    attack_tactic: 'Initial Access',
    cve_id: 'CVE-2024-2961',
    cvss_score: 3.7,
    epss_score: 0.05,
    cisa_kev: false,
  },
  // ── Credential Findings ──
  {
    id: 'f-creds-1',
    scan_id: 'sh_demo001',
    module: 'creds',
    severity: 'critical' as const,
    title: 'Redis Accessible Without Authentication',
    description: 'Redis on port 6379 accepts connections without any authentication. An attacker can read, modify, or delete all cached data and potentially achieve remote code execution.',
    remediation: 'Set a strong password with "requirepass" in redis.conf. Bind to localhost: bind 127.0.0.1. Enable TLS for remote access.',
    target_ip: '93.184.216.34',
    target_port: 6379,
    evidence: { service: 'redis', port: 6379, auth_required: false, response: '+PONG' },
    attack_technique: 'T1078',
    attack_tactic: 'Persistence',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'f-creds-2',
    scan_id: 'sh_demo001',
    module: 'creds',
    severity: 'high' as const,
    title: 'phpMyAdmin Panel Accessible Without Authentication',
    description: 'phpMyAdmin web interface at /phpmyadmin is accessible without login. This exposes full database management capabilities.',
    remediation: 'Restrict access to /phpmyadmin via IP whitelist, add HTTP basic auth, or remove phpMyAdmin from production servers.',
    target_ip: '93.184.216.34',
    target_port: 80,
    evidence: { service: 'web_admin', port: 80, path: '/phpmyadmin', http_status: 200 },
    attack_technique: 'T1078',
    attack_tactic: 'Initial Access',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  // ── OWASP Findings ──
  {
    id: 'f-owasp-1',
    scan_id: 'sh_demo001',
    module: 'owasp',
    severity: 'high' as const,
    title: 'SQL Injection Detected (Error-Based)',
    description: 'The application returns SQL error messages when injecting a single quote character, indicating potential SQL injection vulnerability.',
    remediation: 'Use parameterized queries/prepared statements. Never concatenate user input into SQL queries. Implement input validation.',
    target_ip: '93.184.216.34',
    target_port: 80,
    evidence: { probe: 'sqli', path: '/?id=1\'', error_pattern: 'you have an error in your sql syntax', http_status: 500 },
    attack_technique: 'T1190',
    attack_tactic: 'Initial Access',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'f-owasp-2',
    scan_id: 'sh_demo001',
    module: 'owasp',
    severity: 'medium' as const,
    title: 'Git Repository Exposed',
    description: 'The /.git/HEAD file is publicly accessible, potentially exposing source code, credentials, and commit history.',
    remediation: 'Block access to .git directories in web server config. For Nginx: location ~ /\\.git { deny all; }',
    target_ip: '93.184.216.34',
    target_port: 443,
    evidence: { probe: 'info_disclosure', path: '/.git/HEAD', content_preview: 'ref: refs/heads/main', http_status: 200 },
    attack_technique: 'T1190',
    attack_tactic: 'Initial Access',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
  {
    id: 'f-owasp-3',
    scan_id: 'sh_demo001',
    module: 'owasp',
    severity: 'low' as const,
    title: 'Spring Actuator Health Endpoint Exposed',
    description: 'The /actuator/health endpoint is publicly accessible. While this specific endpoint may be low risk, it confirms Spring framework usage and other actuator endpoints may be exposed.',
    remediation: 'Restrict actuator endpoints to internal networks only. In application.yml: management.endpoints.web.exposure.include=health and secure with authentication.',
    target_ip: '93.184.216.34',
    target_port: 8080,
    evidence: { probe: 'info_disclosure', path: '/actuator/health', content_preview: '{"status":"UP"}', http_status: 200 },
    attack_technique: 'T1592',
    attack_tactic: 'Reconnaissance',
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
  },
]

const mockModuleScores: Record<string, ModuleScore> = {
  tls: { module: 'tls', score: 72, total_checks: 8, passed_checks: 6, findings_count: 3 },
  ports: { module: 'ports', score: 60, total_checks: 12, passed_checks: 7, findings_count: 2 },
  headers: { module: 'headers', score: 50, total_checks: 8, passed_checks: 4, findings_count: 3 },
  dns: { module: 'dns', score: 65, total_checks: 5, passed_checks: 3, findings_count: 3 },
  cve: { module: 'cve', score: 35, total_checks: 5, passed_checks: 1, findings_count: 5 },
  creds: { module: 'creds', score: 50, total_checks: 6, passed_checks: 4, findings_count: 2 },
  owasp: { module: 'owasp', score: 67, total_checks: 5, passed_checks: 3, findings_count: 3 },
}

export function mockShieldScan(scanId?: string): ShieldScanResponse {
  return {
    scan: {
      id: scanId || 'sh_demo001',
      target: 'example.com',
      target_type: 'domain',
      status: 'completed',
      created_at: daysAgo(0),
      started_at: daysAgo(0),
      completed_at: daysAgo(0),
      shield_score: 52,
      grade: 'D',
      scan_depth: 'deep',
      modules_enabled: ['tls', 'ports', 'headers', 'dns', 'cve', 'creds', 'owasp'],
      total_checks: 49,
      passed_checks: 28,
      failed_checks: 16,
      warning_checks: 5,
      findings: mockShieldFindings_data,
      module_scores: mockModuleScores,
      duration_seconds: 22.7,
    },
  }
}

export function mockShieldFindings(_scanId?: string): ShieldFindingsResponse {
  return {
    findings: mockShieldFindings_data,
    total: mockShieldFindings_data.length,
  }
}

export function mockShieldModules(): ShieldModulesResponse {
  return {
    modules: [
      { name: 'tls', description: 'TLS/SSL certificate and protocol validation', weight: 20, available: true },
      { name: 'ports', description: 'Port scanning and service detection', weight: 20, available: true },
      { name: 'cve', description: 'CVE vulnerability matching', weight: 25, available: true },
      { name: 'headers', description: 'HTTP security headers check', weight: 10, available: true },
      { name: 'dns', description: 'DNS security (SPF/DKIM/DMARC)', weight: 10, available: true },
      { name: 'creds', description: 'Default credential testing', weight: 10, available: true },
      { name: 'owasp', description: 'OWASP basic web probes', weight: 5, available: true },
    ],
  }
}

// ---------------------------------------------------------------------------
// Home Dashboard Mock Data
// ---------------------------------------------------------------------------

export function mockFirewallDailyStats(): FirewallDailyStats {
  return {
    date: dateOnly(0),
    blocked: 47,
    allowed: 1283,
    total: 1330,
    block_rate: 3.5,
  }
}

export function mockCollectiveStats(): CollectiveStats {
  return {
    total_signals: 2847,
    active_agents: 156,
    verified_threats: 23,
    subnets_monitored: 412,
    community_protection_score: 78,
    last_updated: daysAgo(0),
  }
}

export function mockContributionStatus(): ContributionStatus {
  return {
    signals_contributed: 34,
    signals_received: 127,
    is_contributing: true,
    opt_in: true,
    privacy_level: 'anonymous',
  }
}

export function mockFamilyOverview(): FamilyOverview {
  return {
    family_name: 'Yucel Ailesi',
    plan_id: 'family_plus',
    devices: [
      {
        id: 'dev_001',
        name: 'Okan\'in Telefonu',
        device_type: 'phone',
        icon: '📱',
        owner_name: 'Okan',
        is_online: true,
        last_seen: daysAgo(0),
        safety_score: 92,
        safety_level: 'safe',
        open_threats: 0,
        ip: '192.168.1.101',
        network_name: 'Ev Agi',
      },
      {
        id: 'dev_002',
        name: 'Salon TV',
        device_type: 'smart_tv',
        icon: '📺',
        owner_name: null,
        is_online: true,
        last_seen: daysAgo(0),
        safety_score: 78,
        safety_level: 'warning',
        open_threats: 1,
        ip: '192.168.1.102',
        network_name: 'Ev Agi',
      },
      {
        id: 'dev_003',
        name: 'MacBook Pro',
        device_type: 'laptop',
        icon: '💻',
        owner_name: 'Okan',
        is_online: true,
        last_seen: daysAgo(0),
        safety_score: 95,
        safety_level: 'safe',
        open_threats: 0,
        ip: '192.168.1.103',
        network_name: 'Ev Agi',
      },
      {
        id: 'dev_004',
        name: 'iPad',
        device_type: 'tablet',
        icon: '📱',
        owner_name: 'Aile',
        is_online: false,
        last_seen: daysAgo(1),
        safety_score: 88,
        safety_level: 'safe',
        open_threats: 0,
        ip: '192.168.1.104',
        network_name: 'Ev Agi',
      },
    ],
    max_devices: 15,
    total_threats: 1,
    avg_safety_score: 88,
    safety_level: 'safe',
    devices_online: 3,
    last_scan: daysAgo(0),
  }
}

export function mockFamilyTimeline(): FamilyTimelineEntry[] {
  return [
    {
      id: 'ft_001',
      device_id: 'dev_002',
      device_name: 'Salon TV',
      device_icon: '📺',
      event_type: 'threat_blocked',
      message: 'Supheli baglanti engellendi (tracking.ad-network.com)',
      timestamp: daysAgo(0),
    },
    {
      id: 'ft_002',
      device_id: 'dev_001',
      device_name: 'Okan\'in Telefonu',
      device_icon: '📱',
      event_type: 'device_online',
      message: 'Cihaz aga baglandi',
      timestamp: daysAgo(0),
    },
    {
      id: 'ft_003',
      device_id: 'dev_003',
      device_name: 'MacBook Pro',
      device_icon: '💻',
      event_type: 'scan_complete',
      message: 'Guvenlik taramasi tamamlandi - temiz',
      timestamp: daysAgo(0),
    },
    {
      id: 'ft_004',
      device_id: 'dev_004',
      device_name: 'iPad',
      device_icon: '📱',
      event_type: 'device_offline',
      message: 'Cihaz cevrimdisi oldu',
      timestamp: daysAgo(1),
    },
  ]
}

export function mockFamilyAlerts(): FamilyAlert[] {
  return [
    {
      id: 'fa_001',
      device_id: 'dev_002',
      device_name: 'Salon TV',
      alert_type: 'suspicious_connection',
      severity: 'medium',
      message: 'TV bilinmeyen bir sunucuya veri gonderiyor',
      timestamp: daysAgo(0),
      is_read: false,
    },
  ]
}

export function mockFirewallEvents(): FirewallEvent[] {
  return [
    {
      id: 'fe_001',
      timestamp: daysAgo(0),
      action: 'block',
      rule_id: 'rule_threat_001',
      source_ip: '45.33.32.156',
      dest_ip: '192.168.1.102',
      dest_port: 8443,
      protocol: 'tcp',
      process_name: null,
      direction: 'inbound',
    },
    {
      id: 'fe_002',
      timestamp: daysAgo(0),
      action: 'block',
      rule_id: 'rule_ad_001',
      source_ip: '192.168.1.102',
      dest_ip: '104.21.67.89',
      dest_port: 443,
      protocol: 'tcp',
      process_name: 'smarttv-app',
      direction: 'outbound',
    },
    {
      id: 'fe_003',
      timestamp: daysAgo(0),
      action: 'allow',
      rule_id: null,
      source_ip: '192.168.1.103',
      dest_ip: '140.82.121.4',
      dest_port: 443,
      protocol: 'tcp',
      process_name: 'chrome',
      direction: 'outbound',
    },
    {
      id: 'fe_004',
      timestamp: daysAgo(1),
      action: 'block',
      rule_id: 'rule_port_001',
      source_ip: '89.248.167.131',
      dest_ip: '192.168.1.1',
      dest_port: 23,
      protocol: 'tcp',
      process_name: null,
      direction: 'inbound',
    },
    {
      id: 'fe_005',
      timestamp: daysAgo(1),
      action: 'block',
      rule_id: 'rule_threat_002',
      source_ip: '185.220.101.42',
      dest_ip: '192.168.1.1',
      dest_port: 22,
      protocol: 'tcp',
      process_name: null,
      direction: 'inbound',
    },
  ]
}

export function mockSampleNotifications(): HumanNotification[] {
  return [
    {
      id: 'hn_001',
      title: 'Supheli Baglanti Engellendi',
      body: 'Salon TV\'niz bilinmeyen bir sunucuya baglanmaya calisti. Guvenlik duvariniz bu baglantiyi engelledi.',
      severity: 'medium',
      icon: '🛡️',
      action_label: 'Detaylari Gor',
      action_type: 'navigate',
      original_alert_type: 'firewall_block',
      original_message: 'Outbound connection blocked to 104.21.67.89:443',
      generated_by: 'humanizer',
      created_at: daysAgo(0),
    },
    {
      id: 'hn_002',
      title: 'Sertifika Suresi Yaklasiyor',
      body: 'Web sunucunuzun TLS sertifikasi 15 gun icinde sona erecek. Yenilemek icin harekete gecin.',
      severity: 'low',
      icon: '🔐',
      action_label: 'Sertifikalari Gor',
      action_type: 'navigate',
      original_alert_type: 'cert_expiry',
      original_message: 'Certificate for 10.0.0.2:443 expires in 15 days',
      generated_by: 'humanizer',
      created_at: daysAgo(1),
    },
    {
      id: 'hn_003',
      title: 'Yeni Cihaz Algilandi',
      body: 'Aginizda yeni bir cihaz goruldu: Apple iPhone (192.168.1.120). Taniyor musunuz?',
      severity: 'info',
      icon: '📱',
      action_label: 'Tani',
      action_type: 'identify',
      original_alert_type: 'new_device',
      original_message: 'New device detected: 00:AA:BB:CC:DD:EE at 192.168.1.120',
      generated_by: 'humanizer',
      created_at: daysAgo(2),
    },
  ]
}

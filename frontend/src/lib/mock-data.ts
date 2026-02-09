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

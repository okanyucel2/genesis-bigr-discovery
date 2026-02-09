// Shield scan types

export type ScanDepth = 'quick' | 'standard' | 'deep'
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed'
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type ShieldGrade = 'A+' | 'A' | 'B+' | 'B' | 'C+' | 'C' | 'D' | 'F'

export interface ShieldFinding {
  id: string
  scan_id: string
  module: string
  severity: FindingSeverity
  title: string
  description: string
  remediation: string
  target_ip: string
  target_port: number | null
  evidence: Record<string, unknown>
  attack_technique: string | null
  attack_tactic: string | null
  cve_id: string | null
  cvss_score: number | null
  epss_score: number | null
  cisa_kev: boolean
}

export interface ModuleScore {
  module: string
  score: number
  total_checks: number
  passed_checks: number
  findings_count: number
}

export interface ShieldScan {
  id: string
  target: string
  target_type: string
  status: ScanStatus
  created_at: string
  started_at: string | null
  completed_at: string | null
  shield_score: number | null
  grade: ShieldGrade | null
  scan_depth: ScanDepth
  modules_enabled: string[]
  total_checks: number
  passed_checks: number
  failed_checks: number
  warning_checks: number
  findings: ShieldFinding[]
  module_scores: Record<string, ModuleScore>
  duration_seconds: number | null
}

export interface ShieldScanResponse {
  scan: ShieldScan
}

export interface ShieldFindingsResponse {
  findings: ShieldFinding[]
  total: number
}

export interface ShieldModulesResponse {
  modules: Array<{
    name: string
    description: string
    weight: number
    available: boolean
  }>
}

export interface ShieldPrediction {
  id: string
  target: string
  fingerprint: Record<string, unknown>
  predicted_score: number
  confidence: number
  likely_findings: Array<{
    cve_id: string
    probability: number
    severity: FindingSeverity
  }>
  similar_targets_count: number
  created_at: string
  verified_by_scan: string | null
  prediction_accuracy: number | null
}

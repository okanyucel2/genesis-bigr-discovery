import { describe, it, expect } from 'vitest'
import { getRuleCategory, buildBlockReason } from '@/lib/rule-descriptions'

describe('getRuleCategory', () => {
  it('returns threat category for rule_threat_* rules', () => {
    const cat = getRuleCategory('rule_threat_001')
    expect(cat).not.toBeNull()
    expect(cat!.category).toBe('threat')
    expect(cat!.label).toBe('Tehdit Korumasi')
  })

  it('returns ad category for rule_ad_* rules', () => {
    const cat = getRuleCategory('rule_ad_001')
    expect(cat).not.toBeNull()
    expect(cat!.category).toBe('ad')
    expect(cat!.label).toBe('Reklam Engellendi')
    expect(cat!.bannerVariant).toBe('purple')
  })

  it('returns port category for rule_port_* rules', () => {
    const cat = getRuleCategory('rule_port_001')
    expect(cat).not.toBeNull()
    expect(cat!.category).toBe('port')
  })

  it('returns null for unknown rule prefix', () => {
    expect(getRuleCategory('custom_rule_123')).toBeNull()
  })

  it('returns null for null rule_id', () => {
    expect(getRuleCategory(null)).toBeNull()
  })
})

describe('buildBlockReason', () => {
  it('includes process name for ad rules with process', () => {
    const reason = buildBlockReason('rule_ad_001', 'smarttv-app')
    expect(reason).toBe('smarttv-app uygulamasi reklam/izleme agina erismek istedi')
  })

  it('uses generic ad description when no process', () => {
    const reason = buildBlockReason('rule_ad_001', null)
    expect(reason).toBe('Reklam veya izleme agina erisim engellendi')
  })

  it('returns port-specific reason for port rules', () => {
    const reason = buildBlockReason('rule_port_001', null)
    expect(reason).toContain('Guvenli olmayan porta')
  })

  it('returns threat description for threat rules', () => {
    const reason = buildBlockReason('rule_threat_001', null)
    expect(reason).toContain('tehdit')
  })

  it('returns null for unknown rule', () => {
    expect(buildBlockReason('unknown_rule', null)).toBeNull()
  })

  it('returns null for null rule_id', () => {
    expect(buildBlockReason(null, null)).toBeNull()
  })
})

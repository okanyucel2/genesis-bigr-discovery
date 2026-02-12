import { describe, it, expect } from 'vitest'
import { checkIpReputation, getThreatContext } from '@/lib/threat-intel'

describe('checkIpReputation', () => {
  it('returns malicious entry for known attacker IP', () => {
    const result = checkIpReputation('45.33.32.156')
    expect(result).not.toBeNull()
    expect(result!.reputation).toBe('malicious')
    expect(result!.label).toBe('Bilinen Saldirgan')
  })

  it('returns malicious entry for known scanner IP', () => {
    const result = checkIpReputation('89.248.167.131')
    expect(result).not.toBeNull()
    expect(result!.reputation).toBe('malicious')
    expect(result!.label).toBe('Port Tarayici')
  })

  it('returns suspicious entry for Tor exit node', () => {
    const result = checkIpReputation('185.220.101.42')
    expect(result).not.toBeNull()
    expect(result!.reputation).toBe('suspicious')
    expect(result!.label).toBe('Tor Cikis Noktasi')
  })

  it('returns null for unknown IP', () => {
    expect(checkIpReputation('192.168.1.1')).toBeNull()
    expect(checkIpReputation('8.8.8.8')).toBeNull()
  })
})

describe('getThreatContext', () => {
  it('checks source IP for inbound traffic', () => {
    const ctx = getThreatContext('45.33.32.156', '192.168.1.1', 'inbound')
    expect(ctx).toBeDefined()
    expect(ctx!.isKnownMalicious).toBe(true)
    expect(ctx!.reputation).toBe('malicious')
    expect(ctx!.threatType).toBe('Bilinen Saldirgan')
  })

  it('checks dest IP for outbound traffic', () => {
    const ctx = getThreatContext('192.168.1.1', '89.248.167.131', 'outbound')
    expect(ctx).toBeDefined()
    expect(ctx!.isKnownMalicious).toBe(true)
    expect(ctx!.threatType).toBe('Port Tarayici')
  })

  it('returns undefined when no threat found', () => {
    const ctx = getThreatContext('192.168.1.1', '8.8.8.8', 'outbound')
    expect(ctx).toBeUndefined()
  })

  it('ignores dest IP for inbound when dest is clean', () => {
    // Source is clean, dest is malicious but direction is inbound → checks source only
    const ctx = getThreatContext('192.168.1.1', '45.33.32.156', 'inbound')
    expect(ctx).toBeUndefined()
  })

  it('returns suspicious reputation for Tor exit node', () => {
    const ctx = getThreatContext('185.220.101.42', '192.168.1.1', 'inbound')
    expect(ctx).toBeDefined()
    expect(ctx!.isKnownMalicious).toBe(false)
    expect(ctx!.reputation).toBe('suspicious')
  })
})

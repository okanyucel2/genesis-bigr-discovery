import { describe, it, expect } from 'vitest'
import { guessDeviceFromVendor, getDeviceIcon } from '@/lib/device-icons'

describe('guessDeviceFromVendor', () => {
  it('detects Apple device', () => {
    const result = guessDeviceFromVendor('Apple')
    expect(result.type).toBe('phone')
    expect(result.icon).toBe('📱')
    expect(result.label).toContain('Apple')
  })

  it('detects Samsung device', () => {
    const result = guessDeviceFromVendor('Samsung Electronics')
    expect(result.type).toBe('phone')
  })

  it('detects LG TV', () => {
    const result = guessDeviceFromVendor('LG Electronics')
    expect(result.type).toBe('smart_tv')
    expect(result.icon).toBe('📺')
  })

  it('detects TP-Link router', () => {
    const result = guessDeviceFromVendor('TP-Link')
    expect(result.type).toBe('router')
    expect(result.icon).toBe('📡')
  })

  it('detects Intel laptop', () => {
    const result = guessDeviceFromVendor('Intel Corporate')
    expect(result.type).toBe('laptop')
    expect(result.icon).toBe('💻')
  })

  it('returns unknown for null vendor', () => {
    const result = guessDeviceFromVendor(null)
    expect(result.type).toBe('unknown')
    expect(result.icon).toBe('❓')
  })

  it('returns unknown for unrecognized vendor', () => {
    const result = guessDeviceFromVendor('XYZ Corporation')
    expect(result.type).toBe('unknown')
  })

  it('is case insensitive', () => {
    const result = guessDeviceFromVendor('APPLE')
    expect(result.type).toBe('phone')
  })
})

describe('getDeviceIcon', () => {
  it('returns correct icons for known types', () => {
    expect(getDeviceIcon('phone')).toBe('📱')
    expect(getDeviceIcon('laptop')).toBe('💻')
    expect(getDeviceIcon('smart_tv')).toBe('📺')
    expect(getDeviceIcon('router')).toBe('📡')
    expect(getDeviceIcon('printer')).toBe('🖨️')
    expect(getDeviceIcon('gaming')).toBe('🎮')
  })

  it('returns ? for unknown type', () => {
    expect(getDeviceIcon('xyz')).toBe('❓')
  })
})

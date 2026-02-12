import { describe, it, expect } from 'vitest'
import { guessDeviceFromVendor, getDeviceIcon, resolveDeviceName, buildDeviceLookup } from '@/lib/device-icons'

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

describe('resolveDeviceName', () => {
  it('prefers hostname over vendor', () => {
    expect(resolveDeviceName('192.168.1.1', 'MacBook Pro', 'Apple')).toBe('MacBook Pro')
  })

  it('falls back to vendor when no hostname', () => {
    expect(resolveDeviceName('192.168.1.1', null, 'Intel Corporate')).toBe('Intel Corporate Cihaz')
  })

  it('falls back to IP when nothing available', () => {
    expect(resolveDeviceName('192.168.1.103', null, null)).toBe('192.168.1.103')
  })
})

describe('buildDeviceLookup', () => {
  it('builds IP to name map', () => {
    const assets = [
      { ip: '192.168.1.100', hostname: 'lt-okan', vendor: 'Apple' },
      { ip: '192.168.1.102', hostname: null, vendor: 'Intel Corporate' },
      { ip: '192.168.1.103', hostname: null, vendor: null },
    ]
    const lookup = buildDeviceLookup(assets)
    expect(lookup['192.168.1.100']).toBe('lt-okan')
    expect(lookup['192.168.1.102']).toBe('Intel Corporate Cihaz')
    expect(lookup['192.168.1.103']).toBe('192.168.1.103')
  })
})

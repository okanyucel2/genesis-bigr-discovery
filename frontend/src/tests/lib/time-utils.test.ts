import { describe, it, expect, vi, afterEach } from 'vitest'
import { relativeTime } from '@/lib/time-utils'

describe('relativeTime', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  function freezeTime(isoString: string) {
    vi.useFakeTimers()
    vi.setSystemTime(new Date(isoString))
  }

  it('returns "Simdi" for recent timestamps', () => {
    freezeTime('2026-02-09T12:00:00Z')
    expect(relativeTime('2026-02-09T11:59:30Z')).toBe('Simdi')
  })

  it('returns minutes for <1h', () => {
    freezeTime('2026-02-09T12:00:00Z')
    expect(relativeTime('2026-02-09T11:45:00Z')).toBe('15 dakika once')
  })

  it('returns hours for <24h', () => {
    freezeTime('2026-02-09T12:00:00Z')
    expect(relativeTime('2026-02-09T09:00:00Z')).toBe('3 saat once')
  })

  it('returns "Dun" for 1 day ago', () => {
    freezeTime('2026-02-09T12:00:00Z')
    expect(relativeTime('2026-02-08T12:00:00Z')).toBe('Dun')
  })

  it('returns days for <7 days', () => {
    freezeTime('2026-02-09T12:00:00Z')
    expect(relativeTime('2026-02-06T12:00:00Z')).toBe('3 gun once')
  })

  it('returns weeks for <30 days', () => {
    freezeTime('2026-02-09T12:00:00Z')
    expect(relativeTime('2026-01-26T12:00:00Z')).toBe('2 hafta once')
  })

  it('returns months for <365 days', () => {
    freezeTime('2026-02-09T12:00:00Z')
    expect(relativeTime('2025-11-09T12:00:00Z')).toBe('3 ay once')
  })

  it('returns years for >365 days', () => {
    freezeTime('2026-02-09T12:00:00Z')
    expect(relativeTime('2024-02-09T12:00:00Z')).toBe('2 yil once')
  })
})

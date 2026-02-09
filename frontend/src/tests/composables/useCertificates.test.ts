import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useCertificates } from '@/composables/useCertificates'
import type { CertificatesResponse, Certificate } from '@/types/api'

const mockCertificate: Certificate = {
  ip: '192.168.1.10',
  port: 443,
  cn: 'web-server.local',
  issuer: "Let's Encrypt Authority X3",
  valid_from: '2025-01-01T00:00:00Z',
  valid_to: '2025-04-01T00:00:00Z',
  days_until_expiry: 45,
  is_self_signed: false,
  key_size: 2048,
  serial_number: 'ABCDEF1234567890',
}

const mockExpiredCert: Certificate = {
  ip: '192.168.1.50',
  port: 8443,
  cn: 'expired.local',
  issuer: 'Self',
  valid_from: '2024-01-01T00:00:00Z',
  valid_to: '2024-12-31T00:00:00Z',
  days_until_expiry: -40,
  is_self_signed: true,
  key_size: 1024,
  serial_number: 'DEADBEEF',
}

const mockCertResponse: CertificatesResponse = {
  certificates: [mockCertificate, mockExpiredCert],
}

vi.mock('@/lib/api', () => ({
  bigrApi: {
    getCertificates: vi.fn(),
  },
}))

import { bigrApi } from '@/lib/api'

const mockedGetCertificates = vi.mocked(bigrApi.getCertificates)

describe('useCertificates', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('initializes with default values', () => {
    const { data, loading, error } = useCertificates()

    expect(data.value).toBeNull()
    expect(loading.value).toBe(false)
    expect(error.value).toBeNull()
  })

  it('sets loading state correctly during fetch', async () => {
    let resolvePromise: (value: unknown) => void
    const pendingPromise = new Promise((resolve) => {
      resolvePromise = resolve
    })

    mockedGetCertificates.mockReturnValue(
      pendingPromise as ReturnType<typeof bigrApi.getCertificates>,
    )

    const { loading, fetchCertificates } = useCertificates()
    expect(loading.value).toBe(false)

    const fetchPromise = fetchCertificates()
    expect(loading.value).toBe(true)

    resolvePromise!({ data: mockCertResponse })
    await fetchPromise

    expect(loading.value).toBe(false)
  })

  it('populates data on successful fetch', async () => {
    mockedGetCertificates.mockResolvedValue({
      data: mockCertResponse,
    } as Awaited<ReturnType<typeof bigrApi.getCertificates>>)

    const { data, fetchCertificates } = useCertificates()

    await fetchCertificates()

    expect(data.value).not.toBeNull()
    expect(data.value!.certificates).toHaveLength(2)
    expect(data.value!.certificates[0]!.ip).toBe('192.168.1.10')
    expect(data.value!.certificates[0]!.cn).toBe('web-server.local')
    expect(data.value!.certificates[1]!.is_self_signed).toBe(true)
    expect(data.value!.certificates[1]!.days_until_expiry).toBe(-40)
  })

  it('sets error on failed fetch', async () => {
    mockedGetCertificates.mockRejectedValue(new Error('Network error'))

    const { error, loading, fetchCertificates } = useCertificates()

    await fetchCertificates()

    expect(error.value).toBe('Network error')
    expect(loading.value).toBe(false)
  })

  it('uses fallback error message for non-Error objects', async () => {
    mockedGetCertificates.mockRejectedValue('unknown failure')

    const { error, fetchCertificates } = useCertificates()

    await fetchCertificates()

    expect(error.value).toBe('Failed to load certificate data')
  })

  it('clears error on new fetch attempt', async () => {
    mockedGetCertificates.mockRejectedValueOnce(new Error('First error'))

    const { error, fetchCertificates } = useCertificates()

    await fetchCertificates()
    expect(error.value).toBe('First error')

    mockedGetCertificates.mockResolvedValueOnce({
      data: mockCertResponse,
    } as Awaited<ReturnType<typeof bigrApi.getCertificates>>)

    await fetchCertificates()
    expect(error.value).toBeNull()
  })
})

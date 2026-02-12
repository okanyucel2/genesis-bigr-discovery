import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import FindingsList from '@/components/shield/FindingsList.vue'
import type { ShieldFinding, FindingSeverity } from '@/types/shield'

const iconStubs = {
  ChevronDown: { template: '<span>v</span>' },
  ChevronRight: { template: '<span>></span>' },
  CheckCircle: { template: '<span>check</span>' },
  ExternalLink: { template: '<span>ext</span>' },
}

function makeFinding(overrides: Partial<ShieldFinding> = {}): ShieldFinding {
  return {
    id: 'f1',
    scan_id: 'sh_001',
    module: 'tls',
    severity: 'high',
    title: 'Weak TLS',
    description: 'TLS 1.0 detected',
    remediation: 'Upgrade to TLS 1.3',
    target_ip: '10.0.0.1',
    target_port: 443,
    evidence: {},
    attack_technique: null,
    attack_tactic: null,
    cve_id: null,
    cvss_score: null,
    epss_score: null,
    cisa_kev: false,
    ...overrides,
  }
}

function mountFindings(findings: ShieldFinding[]) {
  return mount(FindingsList, {
    props: { findings },
    global: { stubs: iconStubs },
  })
}

describe('FindingsList', () => {
  it('shows "No findings" empty state when findings array is empty', () => {
    const wrapper = mountFindings([])

    expect(wrapper.text()).toContain('No findings')
    expect(wrapper.text()).toContain('Your target looks secure!')
  })

  it('shows findings count in header', () => {
    const findings = [
      makeFinding({ id: 'f1' }),
      makeFinding({ id: 'f2' }),
      makeFinding({ id: 'f3' }),
    ]
    const wrapper = mountFindings(findings)

    expect(wrapper.text()).toContain('(3)')
  })

  it('renders correct number of finding rows', () => {
    const findings = [
      makeFinding({ id: 'f1' }),
      makeFinding({ id: 'f2' }),
    ]
    const wrapper = mountFindings(findings)

    const rows = wrapper.findAll('button')
    expect(rows).toHaveLength(2)
  })

  it('shows severity labels (CRITICAL, HIGH, MEDIUM)', () => {
    const findings = [
      makeFinding({ id: 'f1', severity: 'critical' }),
      makeFinding({ id: 'f2', severity: 'high' }),
      makeFinding({ id: 'f3', severity: 'medium' }),
    ]
    const wrapper = mountFindings(findings)

    const text = wrapper.text()
    expect(text).toContain('CRITICAL')
    expect(text).toContain('HIGH')
    expect(text).toContain('MEDIUM')
  })

  it('sorts findings by severity (critical first)', () => {
    const findings = [
      makeFinding({ id: 'f1', severity: 'low', title: 'Low issue' }),
      makeFinding({ id: 'f2', severity: 'critical', title: 'Critical issue' }),
      makeFinding({ id: 'f3', severity: 'medium', title: 'Medium issue' }),
    ]
    const wrapper = mountFindings(findings)

    const rows = wrapper.findAll('button')
    expect(rows[0].text()).toContain('Critical issue')
    expect(rows[1].text()).toContain('Medium issue')
    expect(rows[2].text()).toContain('Low issue')
  })

  it('shows CVE ID when present, "--" when null', () => {
    const findings = [
      makeFinding({ id: 'f1', cve_id: 'CVE-2024-1234' }),
      makeFinding({ id: 'f2', cve_id: null }),
    ]
    const wrapper = mountFindings(findings)

    const text = wrapper.text()
    expect(text).toContain('CVE-2024-1234')
    expect(text).toContain('--')
  })

  it('formats target with port (e.g. "10.0.0.1:443")', () => {
    const findings = [
      makeFinding({ id: 'f1', target_ip: '10.0.0.1', target_port: 443 }),
    ]
    const wrapper = mountFindings(findings)

    expect(wrapper.text()).toContain('10.0.0.1:443')
  })

  it('formats target without port when target_port is null', () => {
    const findings = [
      makeFinding({ id: 'f1', target_ip: '192.168.1.1', target_port: null }),
    ]
    const wrapper = mountFindings(findings)

    expect(wrapper.text()).toContain('192.168.1.1')
    expect(wrapper.text()).not.toContain('192.168.1.1:')
  })

  it('clicking a row expands to show description and remediation', async () => {
    const findings = [
      makeFinding({
        id: 'f1',
        description: 'TLS 1.0 detected',
        remediation: 'Upgrade to TLS 1.3',
      }),
    ]
    const wrapper = mountFindings(findings)

    // Before click, expanded content should not be visible
    expect(wrapper.text()).not.toContain('Description')
    expect(wrapper.text()).not.toContain('Remediation')

    // Click the row to expand
    await wrapper.find('button').trigger('click')

    expect(wrapper.text()).toContain('Description')
    expect(wrapper.text()).toContain('TLS 1.0 detected')
    expect(wrapper.text()).toContain('Remediation')
    expect(wrapper.text()).toContain('Upgrade to TLS 1.3')
  })

  it('clicking an expanded row collapses it', async () => {
    const findings = [makeFinding({ id: 'f1', description: 'TLS 1.0 detected' })]
    const wrapper = mountFindings(findings)

    // Expand
    await wrapper.find('button').trigger('click')
    expect(wrapper.text()).toContain('TLS 1.0 detected')

    // Collapse
    await wrapper.find('button').trigger('click')
    expect(wrapper.text()).not.toContain('Description')
  })

  it('shows CVSS and EPSS in expanded view', async () => {
    const findings = [
      makeFinding({
        id: 'f1',
        cvss_score: 9.8,
        epss_score: 0.456,
      }),
    ]
    const wrapper = mountFindings(findings)

    await wrapper.find('button').trigger('click')

    expect(wrapper.text()).toContain('CVSS:')
    expect(wrapper.text()).toContain('9.8')
    expect(wrapper.text()).toContain('EPSS:')
    expect(wrapper.text()).toContain('45.6%')
  })

  it('shows CISA KEV badge when cisa_kev is true', async () => {
    const findings = [makeFinding({ id: 'f1', cisa_kev: true })]
    const wrapper = mountFindings(findings)

    await wrapper.find('button').trigger('click')

    expect(wrapper.text()).toContain('CISA KEV')
  })

  it('does not show CVSS/EPSS when scores are null', async () => {
    const findings = [
      makeFinding({ id: 'f1', cvss_score: null, epss_score: null }),
    ]
    const wrapper = mountFindings(findings)

    await wrapper.find('button').trigger('click')

    expect(wrapper.text()).not.toContain('CVSS:')
    expect(wrapper.text()).not.toContain('EPSS:')
  })
})

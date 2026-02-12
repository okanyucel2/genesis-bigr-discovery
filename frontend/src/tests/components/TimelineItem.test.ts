import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineItem from '@/components/home/TimelineItem.vue'
import type { TimelineItem as TimelineItemType, TimelineRichDetail } from '@/types/home-dashboard'

function makeItem(overrides: Partial<TimelineItemType> = {}): TimelineItemType {
  return {
    id: 'test_1',
    source: 'firewall',
    severity: 'medium',
    message: 'Test mesaji',
    detail: 'Detay bilgisi',
    timestamp: new Date().toISOString(),
    icon: '🛡️',
    ...overrides,
  }
}

function makeRichDetail(overrides: Partial<TimelineRichDetail> = {}): TimelineRichDetail {
  return {
    summary: '45.33.32.156 adresindan gelen TCP baglantisi engellendi.',
    fields: [
      { icon: '🔌', label: 'Protokol', value: 'TCP' },
      { icon: '↙️', label: 'Yon', value: 'Gelen' },
      { icon: '⚙️', label: 'Islem', value: 'smarttv-app' },
      { icon: '📋', label: 'Kural', value: 'rule_threat_001' },
    ],
    actions: [
      { label: 'Kalici Engelle', variant: 'danger', icon: '🚫', handler: 'block-permanent', metadata: { ip: '45.33.32.156' } },
      { label: 'Kural Detayi', variant: 'secondary', icon: '📋', handler: 'view-rule', metadata: { ruleId: 'rule_threat_001' } },
    ],
    threatContext: {
      isKnownMalicious: true,
      threatType: 'Port Tarayici',
      reputation: 'malicious',
    },
    ...overrides,
  }
}

describe('TimelineItem', () => {
  it('renders message and icon', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem(), expanded: false },
    })

    expect(wrapper.text()).toContain('Test mesaji')
    expect(wrapper.text()).toContain('🛡️')
  })

  it('applies critical severity class', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ severity: 'critical' }), expanded: false },
    })

    expect(wrapper.find('.border-l-rose-500').exists()).toBe(true)
  })

  it('applies medium severity class', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ severity: 'medium' }), expanded: false },
    })

    expect(wrapper.find('.border-l-yellow-500').exists()).toBe(true)
  })

  it('shows Detay button when detail exists', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem(), expanded: false },
    })

    expect(wrapper.text()).toContain('Detay')
  })

  it('hides Detay button when no detail', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: null }), expanded: false },
    })

    expect(wrapper.text()).not.toContain('Detay')
  })

  it('shows detail content when expanded', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem(), expanded: true },
    })

    expect(wrapper.text()).toContain('Detay bilgisi')
    expect(wrapper.text()).toContain('Gizle')
  })

  it('emits toggle on click', async () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem(), expanded: false },
    })

    await wrapper.find('.timeline-item').trigger('click')
    expect(wrapper.emitted('toggle')).toHaveLength(1)
  })

  it('renders rich detail summary when expanded', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: makeRichDetail() }), expanded: true },
    })

    expect(wrapper.find('.rich-summary').exists()).toBe(true)
    expect(wrapper.text()).toContain('TCP baglantisi engellendi')
  })

  it('shows threat banner for malicious IP', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: makeRichDetail() }), expanded: true },
    })

    expect(wrapper.find('.threat-banner').exists()).toBe(true)
    expect(wrapper.text()).toContain('Bilinen Tehdit')
    expect(wrapper.text()).toContain('Port Tarayici')
  })

  it('hides threat banner when no threat context', () => {
    const wrapper = mount(TimelineItem, {
      props: {
        item: makeItem({
          detail: makeRichDetail({ threatContext: undefined }),
        }),
        expanded: true,
      },
    })

    expect(wrapper.find('.threat-banner').exists()).toBe(false)
  })

  it('renders field grid with all fields', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: makeRichDetail() }), expanded: true },
    })

    expect(wrapper.find('.detail-fields').exists()).toBe(true)
    expect(wrapper.text()).toContain('Protokol')
    expect(wrapper.text()).toContain('TCP')
    expect(wrapper.text()).toContain('Yon')
    expect(wrapper.text()).toContain('Gelen')
    expect(wrapper.text()).toContain('Islem')
    expect(wrapper.text()).toContain('smarttv-app')
    expect(wrapper.text()).toContain('Kural')
    expect(wrapper.text()).toContain('rule_threat_001')
  })

  it('renders action buttons', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: makeRichDetail() }), expanded: true },
    })

    expect(wrapper.find('.detail-actions').exists()).toBe(true)
    expect(wrapper.text()).toContain('Kalici Engelle')
    expect(wrapper.text()).toContain('Kural Detayi')
  })

  it('emits blockIp when block action clicked', async () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: makeRichDetail() }), expanded: true },
    })

    const buttons = wrapper.findAll('.detail-actions button')
    await buttons[0]!.trigger('click')
    expect(wrapper.emitted('blockIp')).toHaveLength(1)
    expect(wrapper.emitted('blockIp')![0]).toEqual(['45.33.32.156'])
  })

  it('emits viewRule when rule action clicked', async () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: makeRichDetail() }), expanded: true },
    })

    const buttons = wrapper.findAll('.detail-actions button')
    await buttons[1]!.trigger('click')
    expect(wrapper.emitted('viewRule')).toHaveLength(1)
    expect(wrapper.emitted('viewRule')![0]).toEqual(['rule_threat_001'])
  })

  it('still renders string detail as monospace fallback', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: 'Plain text detail' }), expanded: true },
    })

    expect(wrapper.find('.font-mono').exists()).toBe(true)
    expect(wrapper.text()).toContain('Plain text detail')
    expect(wrapper.find('.rich-summary').exists()).toBe(false)
  })

  it('shows rule banner for ad-blocking when no threat context', () => {
    const wrapper = mount(TimelineItem, {
      props: {
        item: makeItem({
          detail: makeRichDetail({
            threatContext: undefined,
            ruleContext: {
              category: 'ad',
              label: 'Reklam Engellendi',
              reason: 'smarttv-app uygulamasi reklam/izleme agina erismek istedi',
              bannerVariant: 'purple',
            },
          }),
        }),
        expanded: true,
      },
    })

    expect(wrapper.find('.rule-banner').exists()).toBe(true)
    expect(wrapper.text()).toContain('Reklam Engellendi')
    expect(wrapper.text()).toContain('smarttv-app')
  })

  it('hides rule banner when threat banner is shown', () => {
    const wrapper = mount(TimelineItem, {
      props: {
        item: makeItem({
          detail: makeRichDetail({
            ruleContext: {
              category: 'threat',
              label: 'Tehdit Korumasi',
              reason: 'Bilinen tehdit kaynagiyla iletisim engellendi',
              bannerVariant: 'red',
            },
          }),
        }),
        expanded: true,
      },
    })

    // Threat banner takes priority
    expect(wrapper.find('.threat-banner').exists()).toBe(true)
    expect(wrapper.find('.rule-banner').exists()).toBe(false)
  })

  it('renders suggested actions with dashed style and reason', () => {
    const wrapper = mount(TimelineItem, {
      props: {
        item: makeItem({
          detail: makeRichDetail({
            actions: [
              { label: 'DNS ile Kalici Engelle', variant: 'primary', icon: '🌐', handler: 'suggest-dns', metadata: { ip: '1.2.3.4' }, suggested: true, suggestReason: 'Mevcut engelleme gecici — DNS filtreleme tum agi kalici olarak korur' },
              { label: "Router'da Kalici Engelle", variant: 'secondary', icon: '📡', handler: 'suggest-router', metadata: { ip: '1.2.3.4' }, suggested: true, suggestReason: "Router'a kalici kural ekleyerek bu IP'nin tekrar erisimini engelleyin" },
              { label: 'Kural Detayi', variant: 'secondary', icon: '📋', handler: 'view-rule', metadata: { ruleId: 'r1' } },
            ],
          }),
        }),
        expanded: true,
      },
    })

    expect(wrapper.find('.suggested-actions').exists()).toBe(true)
    expect(wrapper.text()).toContain('Onerilen')
    expect(wrapper.text()).toContain('DNS ile Kalici Engelle')
    expect(wrapper.text()).toContain("Router'da Kalici Engelle")
    // Direct action still in normal section
    expect(wrapper.find('.detail-actions').exists()).toBe(true)
    expect(wrapper.text()).toContain('Kural Detayi')
  })

  it('hides suggested section when no suggested actions', () => {
    const wrapper = mount(TimelineItem, {
      props: { item: makeItem({ detail: makeRichDetail() }), expanded: true },
    })

    expect(wrapper.find('.suggested-actions').exists()).toBe(false)
  })

  it('shows suspicious banner for suspicious reputation', () => {
    const wrapper = mount(TimelineItem, {
      props: {
        item: makeItem({
          detail: makeRichDetail({
            threatContext: {
              isKnownMalicious: false,
              threatType: 'Tor Cikis Noktasi',
              reputation: 'suspicious',
            },
          }),
        }),
        expanded: true,
      },
    })

    expect(wrapper.find('.threat-banner').exists()).toBe(true)
    expect(wrapper.text()).toContain('Suphelendi')
    expect(wrapper.text()).toContain('Tor Cikis Noktasi')
  })
})

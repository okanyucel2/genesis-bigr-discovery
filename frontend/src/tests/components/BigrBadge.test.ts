import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import BigrBadge from '@/components/shared/BigrBadge.vue'
import { BIGR_CATEGORIES, type BigrCategory } from '@/types/bigr'

describe('BigrBadge', () => {
  const categories: BigrCategory[] = [
    'ag_ve_sistemler',
    'uygulamalar',
    'iot',
    'tasinabilir',
    'unclassified',
  ]

  it.each(categories)('renders correct label for category "%s"', (category) => {
    const wrapper = mount(BigrBadge, {
      props: { category },
    })
    expect(wrapper.text()).toContain(BIGR_CATEGORIES[category].label)
  })

  it('renders icon when showIcon is true (default)', () => {
    const wrapper = mount(BigrBadge, {
      props: { category: 'ag_ve_sistemler' },
    })
    // The lucide icon renders as an SVG element
    expect(wrapper.find('svg').exists()).toBe(true)
  })

  it('does not render icon when showIcon is false', () => {
    const wrapper = mount(BigrBadge, {
      props: { category: 'ag_ve_sistemler', showIcon: false },
    })
    expect(wrapper.find('svg').exists()).toBe(false)
  })

  it.each(categories)(
    'applies correct color classes for category "%s"',
    (category) => {
      const wrapper = mount(BigrBadge, {
        props: { category },
      })
      const info = BIGR_CATEGORIES[category]
      const el = wrapper.find('span')
      const classes = el.classes().join(' ')
      for (const cls of info.bgClass.split(' ')) {
        expect(classes).toContain(cls)
      }
    },
  )

  it('applies correct text color class for each category', () => {
    for (const category of categories) {
      const wrapper = mount(BigrBadge, {
        props: { category },
      })
      const info = BIGR_CATEGORIES[category]
      const rootEl = wrapper.find('span')
      const classes = rootEl.classes().join(' ')
      // textClass like 'text-blue-400' should appear in classes
      expect(classes).toContain(info.textClass)
    }
  })

  it('applies correct bg color class for each category', () => {
    for (const category of categories) {
      const wrapper = mount(BigrBadge, {
        props: { category },
      })
      const info = BIGR_CATEGORIES[category]
      const rootEl = wrapper.find('span')
      const classes = rootEl.classes().join(' ')
      // bgClass like 'bg-blue-500/20' should appear in classes
      expect(classes).toContain(info.bgClass)
    }
  })
})

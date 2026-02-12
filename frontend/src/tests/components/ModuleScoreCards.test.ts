import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import ModuleScoreCards from '@/components/shield/ModuleScoreCards.vue'
import type { ModuleScore } from '@/types/shield'

const mockScores: Record<string, ModuleScore> = {
  tls: { module: 'tls', score: 85, total_checks: 8, passed_checks: 6, findings_count: 2 },
  ports: { module: 'ports', score: 55, total_checks: 10, passed_checks: 5, findings_count: 5 },
  headers: { module: 'headers', score: 70, total_checks: 6, passed_checks: 4, findings_count: 1 },
}

describe('ModuleScoreCards', () => {
  it('shows "No module scores available" when scores is empty', () => {
    const wrapper = mount(ModuleScoreCards, {
      props: { scores: {} },
    })

    expect(wrapper.text()).toContain('No module scores available')
  })

  it('renders correct number of module cards', () => {
    const wrapper = mount(ModuleScoreCards, {
      props: { scores: mockScores },
    })

    const cards = wrapper.findAll('.glass-card')
    expect(cards).toHaveLength(3)
  })

  it('shows mapped module labels (tls→TLS, ports→Ports)', () => {
    const wrapper = mount(ModuleScoreCards, {
      props: { scores: mockScores },
    })

    const labels = wrapper.findAll('.text-sm.font-medium.text-slate-300')
    const labelTexts = labels.map((el) => el.text())

    expect(labelTexts).toContain('TLS')
    expect(labelTexts).toContain('Ports')
    expect(labelTexts).toContain('Headers')
  })

  it('falls back to uppercased key for unmapped modules', () => {
    const customScores: Record<string, ModuleScore> = {
      firewall: { module: 'firewall', score: 90, total_checks: 5, passed_checks: 5, findings_count: 0 },
    }

    const wrapper = mount(ModuleScoreCards, {
      props: { scores: customScores },
    })

    expect(wrapper.text()).toContain('FIREWALL')
  })

  it('shows module score value', () => {
    const wrapper = mount(ModuleScoreCards, {
      props: { scores: mockScores },
    })

    const scoreElements = wrapper.findAll('.text-sm.font-bold.tabular-nums')
    const scoreTexts = scoreElements.map((el) => el.text())

    expect(scoreTexts).toContain('85')
    expect(scoreTexts).toContain('55')
    expect(scoreTexts).toContain('70')
  })

  it('shows checks count (e.g. "6/8 checks")', () => {
    const wrapper = mount(ModuleScoreCards, {
      props: { scores: mockScores },
    })

    expect(wrapper.text()).toContain('6/8 checks')
    expect(wrapper.text()).toContain('5/10 checks')
    expect(wrapper.text()).toContain('4/6 checks')
  })

  it('shows findings count when > 0', () => {
    const wrapper = mount(ModuleScoreCards, {
      props: { scores: mockScores },
    })

    expect(wrapper.text()).toContain('2 findings')
    expect(wrapper.text()).toContain('5 findings')
    expect(wrapper.text()).toContain('1 finding')
  })

  it('does not show findings text when findings_count is 0', () => {
    const zeroFindingsScores: Record<string, ModuleScore> = {
      tls: { module: 'tls', score: 100, total_checks: 8, passed_checks: 8, findings_count: 0 },
    }

    const wrapper = mount(ModuleScoreCards, {
      props: { scores: zeroFindingsScores },
    })

    expect(wrapper.text()).not.toContain('finding')
  })

  it('uses singular "finding" when findings_count is 1', () => {
    const singleFinding: Record<string, ModuleScore> = {
      headers: { module: 'headers', score: 70, total_checks: 6, passed_checks: 4, findings_count: 1 },
    }

    const wrapper = mount(ModuleScoreCards, {
      props: { scores: singleFinding },
    })

    expect(wrapper.text()).toContain('1 finding')
    expect(wrapper.text()).not.toContain('1 findings')
  })

  describe('score color classes', () => {
    it('applies emerald color for score >= 80', () => {
      const highScore: Record<string, ModuleScore> = {
        tls: { module: 'tls', score: 85, total_checks: 8, passed_checks: 6, findings_count: 2 },
      }

      const wrapper = mount(ModuleScoreCards, {
        props: { scores: highScore },
      })

      const scoreEl = wrapper.find('.text-sm.font-bold.tabular-nums')
      expect(scoreEl.classes()).toContain('text-emerald-400')

      const barEl = wrapper.find('.h-full.rounded-full')
      expect(barEl.classes()).toContain('bg-emerald-400')
    })

    it('applies amber color for score >= 60 and < 80', () => {
      const midScore: Record<string, ModuleScore> = {
        headers: { module: 'headers', score: 70, total_checks: 6, passed_checks: 4, findings_count: 1 },
      }

      const wrapper = mount(ModuleScoreCards, {
        props: { scores: midScore },
      })

      const scoreEl = wrapper.find('.text-sm.font-bold.tabular-nums')
      expect(scoreEl.classes()).toContain('text-amber-400')

      const barEl = wrapper.find('.h-full.rounded-full')
      expect(barEl.classes()).toContain('bg-amber-400')
    })

    it('applies rose color for score < 60', () => {
      const lowScore: Record<string, ModuleScore> = {
        ports: { module: 'ports', score: 55, total_checks: 10, passed_checks: 5, findings_count: 5 },
      }

      const wrapper = mount(ModuleScoreCards, {
        props: { scores: lowScore },
      })

      const scoreEl = wrapper.find('.text-sm.font-bold.tabular-nums')
      expect(scoreEl.classes()).toContain('text-rose-400')

      const barEl = wrapper.find('.h-full.rounded-full')
      expect(barEl.classes()).toContain('bg-rose-400')
    })

    it('applies emerald at boundary score of exactly 80', () => {
      const boundaryScore: Record<string, ModuleScore> = {
        dns: { module: 'dns', score: 80, total_checks: 4, passed_checks: 3, findings_count: 1 },
      }

      const wrapper = mount(ModuleScoreCards, {
        props: { scores: boundaryScore },
      })

      const scoreEl = wrapper.find('.text-sm.font-bold.tabular-nums')
      expect(scoreEl.classes()).toContain('text-emerald-400')
    })

    it('applies amber at boundary score of exactly 60', () => {
      const boundaryScore: Record<string, ModuleScore> = {
        cve: { module: 'cve', score: 60, total_checks: 5, passed_checks: 3, findings_count: 2 },
      }

      const wrapper = mount(ModuleScoreCards, {
        props: { scores: boundaryScore },
      })

      const scoreEl = wrapper.find('.text-sm.font-bold.tabular-nums')
      expect(scoreEl.classes()).toContain('text-amber-400')
    })
  })

  it('sets progress bar width based on score percentage', () => {
    const wrapper = mount(ModuleScoreCards, {
      props: { scores: { tls: mockScores.tls } },
    })

    const barEl = wrapper.find('.h-full.rounded-full')
    expect(barEl.attributes('style')).toContain('width: 85%')
  })
})

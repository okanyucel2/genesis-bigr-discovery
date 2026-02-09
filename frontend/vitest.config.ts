import { createVitestConfig } from '@genesis/vitest-config'
import { COVERAGE_PRESETS } from '@genesis/vitest-config/presets'

export default createVitestConfig({
  environment: 'happy-dom',
  coverage: COVERAGE_PRESETS.minimal,
})

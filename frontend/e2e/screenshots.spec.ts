import { test } from '@playwright/test'

const BASE_URL = 'http://localhost:19978'

const pages = [
  { name: 'dashboard', path: '/' },
  { name: 'assets', path: '/assets' },
  { name: 'topology', path: '/topology' },
  { name: 'compliance', path: '/compliance' },
  { name: 'analytics', path: '/analytics' },
  { name: 'vulnerabilities', path: '/vulnerabilities' },
  { name: 'risk', path: '/risk' },
  { name: 'certificates', path: '/certificates' },
  { name: 'settings', path: '/settings' },
]

for (const page of pages) {
  test(`screenshot: ${page.name}`, async ({ browser }) => {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      colorScheme: 'dark',
    })
    const tab = await context.newPage()
    await tab.goto(`${BASE_URL}${page.path}`, { waitUntil: 'networkidle' })
    await tab.waitForTimeout(1500)
    await tab.screenshot({
      path: `e2e/screenshots/${page.name}.png`,
      fullPage: true,
    })
    await context.close()
  })
}

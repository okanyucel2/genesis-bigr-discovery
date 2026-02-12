/** MAC vendor prefix → device type + Turkish label */

interface DeviceGuess {
  type: string
  icon: string
  label: string
}

const VENDOR_MAP: Record<string, DeviceGuess> = {
  apple: { type: 'phone', icon: '📱', label: 'Apple Cihaz' },
  samsung: { type: 'phone', icon: '📱', label: 'Samsung Cihaz' },
  google: { type: 'phone', icon: '📱', label: 'Google Cihaz' },
  huawei: { type: 'phone', icon: '📱', label: 'Huawei Cihaz' },
  xiaomi: { type: 'phone', icon: '📱', label: 'Xiaomi Cihaz' },
  lg: { type: 'smart_tv', icon: '📺', label: 'LG TV' },
  sony: { type: 'smart_tv', icon: '📺', label: 'Sony TV' },
  tp_link: { type: 'router', icon: '📡', label: 'TP-Link Router' },
  'tp-link': { type: 'router', icon: '📡', label: 'TP-Link Router' },
  netgear: { type: 'router', icon: '📡', label: 'Netgear Router' },
  asus: { type: 'router', icon: '📡', label: 'Asus Router' },
  cisco: { type: 'router', icon: '📡', label: 'Cisco Cihaz' },
  intel: { type: 'laptop', icon: '💻', label: 'Bilgisayar' },
  dell: { type: 'laptop', icon: '💻', label: 'Dell Bilgisayar' },
  hp: { type: 'laptop', icon: '💻', label: 'HP Bilgisayar' },
  lenovo: { type: 'laptop', icon: '💻', label: 'Lenovo Bilgisayar' },
  amazon: { type: 'iot', icon: '🔊', label: 'Amazon Echo' },
  sonos: { type: 'iot', icon: '🔊', label: 'Sonos Hoparlor' },
  nest: { type: 'iot', icon: '🌡️', label: 'Nest Cihaz' },
  ring: { type: 'iot', icon: '📹', label: 'Ring Kamera' },
  philips: { type: 'iot', icon: '💡', label: 'Philips Hue' },
  epson: { type: 'printer', icon: '🖨️', label: 'Epson Yazici' },
  brother: { type: 'printer', icon: '🖨️', label: 'Brother Yazici' },
  canon: { type: 'printer', icon: '🖨️', label: 'Canon Yazici' },
  xbox: { type: 'gaming', icon: '🎮', label: 'Xbox' },
  nintendo: { type: 'gaming', icon: '🎮', label: 'Nintendo' },
  playstation: { type: 'gaming', icon: '🎮', label: 'PlayStation' },
}

const DEFAULT_GUESS: DeviceGuess = { type: 'unknown', icon: '❓', label: 'Bilinmeyen Cihaz' }

export function guessDeviceFromVendor(vendor: string | null): DeviceGuess {
  if (!vendor) return DEFAULT_GUESS
  const normalized = vendor.toLowerCase().replace(/[_\s-]/g, '')
  for (const [key, guess] of Object.entries(VENDOR_MAP)) {
    if (normalized.includes(key.replace(/[_\s-]/g, ''))) {
      return guess
    }
  }
  return DEFAULT_GUESS
}

/**
 * Best human-readable name for a device.
 * Priority: hostname > vendor > ip (last resort)
 */
export function resolveDeviceName(
  ip: string,
  hostname: string | null,
  vendor: string | null,
  friendlyName?: string | null,
): string {
  if (friendlyName) return friendlyName
  if (hostname) return hostname
  if (vendor) return `${vendor} Cihaz`
  return ip
}

/**
 * Build an IP → display name lookup map from an asset list.
 */
export function buildDeviceLookup(
  assets: { ip: string; hostname: string | null; vendor: string | null }[],
): Record<string, string> {
  const map: Record<string, string> = {}
  for (const a of assets) {
    map[a.ip] = resolveDeviceName(a.ip, a.hostname, a.vendor)
  }
  return map
}

export function getDeviceIcon(deviceType: string): string {
  const iconMap: Record<string, string> = {
    phone: '📱',
    tablet: '📱',
    laptop: '💻',
    desktop: '🖥️',
    smart_tv: '📺',
    router: '📡',
    printer: '🖨️',
    iot: '🏠',
    gaming: '🎮',
    camera: '📹',
    speaker: '🔊',
  }
  return iconMap[deviceType] ?? '❓'
}

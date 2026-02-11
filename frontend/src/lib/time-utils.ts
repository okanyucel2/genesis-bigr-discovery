/** Turkish relative time formatting */

export function relativeTime(timestamp: string): string {
  const now = new Date()
  const date = new Date(timestamp)
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)

  if (diffSec < 60) return 'Simdi'
  if (diffMin < 60) return `${diffMin} dakika once`
  if (diffHour < 24) return `${diffHour} saat once`
  if (diffDay === 1) return 'Dun'
  if (diffDay < 7) return `${diffDay} gun once`
  if (diffDay < 30) {
    const weeks = Math.floor(diffDay / 7)
    return `${weeks} hafta once`
  }
  if (diffDay < 365) {
    const months = Math.floor(diffDay / 30)
    return `${months} ay once`
  }
  const years = Math.floor(diffDay / 365)
  return `${years} yil once`
}

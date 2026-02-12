export interface ThreatEntry {
  ip: string
  reputation: 'malicious' | 'suspicious'
  threatType: string
  label: string
}

const knownThreats: ThreatEntry[] = [
  { ip: '45.33.32.156', reputation: 'malicious', threatType: 'attacker', label: 'Bilinen Saldirgan' },
  { ip: '89.248.167.131', reputation: 'malicious', threatType: 'scanner', label: 'Port Tarayici' },
  { ip: '185.220.101.42', reputation: 'suspicious', threatType: 'tor_exit', label: 'Tor Cikis Noktasi' },
]

export function checkIpReputation(ip: string): ThreatEntry | null {
  return knownThreats.find((t) => t.ip === ip) ?? null
}

export interface ThreatContext {
  isKnownMalicious: boolean
  threatType?: string
  reputation: 'malicious' | 'suspicious' | 'unknown'
}

export function getThreatContext(
  sourceIp: string,
  destIp: string,
  direction: string,
): ThreatContext | undefined {
  const relevantIp = direction === 'inbound' ? sourceIp : destIp
  const entry = checkIpReputation(relevantIp)

  if (!entry) return undefined

  return {
    isKnownMalicious: entry.reputation === 'malicious',
    threatType: entry.label,
    reputation: entry.reputation,
  }
}

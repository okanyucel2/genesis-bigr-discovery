export interface RuleCategory {
  category: 'threat' | 'ad' | 'port' | 'malware' | 'parental' | 'unknown'
  label: string
  description: string
  bannerVariant: 'red' | 'purple' | 'blue' | 'orange'
}

const rulePrefixes: { prefix: string; category: RuleCategory }[] = [
  {
    prefix: 'rule_threat_',
    category: {
      category: 'threat',
      label: 'Tehdit Korumasi',
      description: 'Bilinen tehdit kaynagiyla iletisim engellendi',
      bannerVariant: 'red',
    },
  },
  {
    prefix: 'rule_ad_',
    category: {
      category: 'ad',
      label: 'Reklam Engellendi',
      description: 'Reklam veya izleme agina erisim engellendi',
      bannerVariant: 'purple',
    },
  },
  {
    prefix: 'rule_port_',
    category: {
      category: 'port',
      label: 'Port Korumasi',
      description: 'Guvenli olmayan port erisimi engellendi',
      bannerVariant: 'blue',
    },
  },
  {
    prefix: 'rule_malware_',
    category: {
      category: 'malware',
      label: 'Zararli Yazilim Korumasi',
      description: 'Zararli yazilim iletisimi engellendi',
      bannerVariant: 'red',
    },
  },
  {
    prefix: 'rule_parental_',
    category: {
      category: 'parental',
      label: 'Ebeveyn Kontrolu',
      description: 'Ebeveyn kontrolu kurali ile engellendi',
      bannerVariant: 'orange',
    },
  },
]

export function getRuleCategory(ruleId: string | null): RuleCategory | null {
  if (!ruleId) return null
  const match = rulePrefixes.find((r) => ruleId.startsWith(r.prefix))
  return match?.category ?? null
}

export function buildBlockReason(
  ruleId: string | null,
  processName: string | null,
): string | null {
  const cat = getRuleCategory(ruleId)
  if (!cat) return null

  if (cat.category === 'ad' && processName) {
    return `${processName} uygulamasi reklam/izleme agina erismek istedi`
  }
  if (cat.category === 'ad') {
    return 'Reklam veya izleme agina erisim engellendi'
  }
  if (cat.category === 'port') {
    return 'Guvenli olmayan porta erisim tespit edildi'
  }

  return cat.description
}

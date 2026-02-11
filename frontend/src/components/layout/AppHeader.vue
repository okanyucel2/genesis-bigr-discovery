<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { Activity } from 'lucide-vue-next'
import { bigrApi } from '@/lib/api'

const route = useRoute()

const PAGE_TITLES: Record<string, string> = {
  dashboard: 'Genel Bakış',
  assets: 'Cihazlar',
  'asset-detail': 'Cihaz Detayı',
  topology: 'Ağ Haritası',
  compliance: 'Uyumluluk',
  analytics: 'Analitik',
  vulnerabilities: 'Açıklar',
  risk: 'Risk Değerlendirme',
  certificates: 'TLS Sertifikaları',
  shield: 'Kalkan',
  'shield-scan': 'Kalkan',
  'shield-findings': 'Bulgular',
  notifications: 'Bildirimler',
  collective: 'Topluluk',
  family: 'Aile',
  firewall: 'Güvenlik Duvarı',
  remediation: 'Onarım',
  agents: 'Ajanlar',
  pricing: 'Fiyatlandırma',
  settings: 'Ayarlar',
  onboarding: 'Hoş Geldin',
  'not-found': 'Sayfa Bulunamadı',
}

const pageTitle = computed(() => {
  const name = route.name as string
  return PAGE_TITLES[name] || 'BIGR Discovery'
})

const healthStatus = ref<'ok' | 'error' | 'loading'>('loading')
let healthInterval: ReturnType<typeof setInterval> | null = null

async function checkHealth() {
  try {
    const res = await bigrApi.getHealth()
    healthStatus.value = res.data.status === 'ok' ? 'ok' : 'error'
  } catch {
    healthStatus.value = 'error'
  }
}

onMounted(() => {
  checkHealth()
  healthInterval = setInterval(checkHealth, 30000)
})

onUnmounted(() => {
  if (healthInterval) clearInterval(healthInterval)
})
</script>

<template>
  <header
    class="flex h-14 shrink-0 items-center justify-between border-b border-[var(--border-glass)] bg-[var(--bg-glass-heavy)] px-6"
  >
    <h2 class="text-lg font-semibold text-slate-100">{{ pageTitle }}</h2>

    <div class="flex items-center gap-4">
      <!-- Health indicator -->
      <div class="flex items-center gap-2 text-xs text-slate-400">
        <Activity class="h-3.5 w-3.5" />
        <span>API</span>
        <span
          class="inline-block h-2 w-2 rounded-full"
          :class="{
            'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.6)]': healthStatus === 'ok',
            'bg-red-400 shadow-[0_0_6px_rgba(248,113,113,0.6)]': healthStatus === 'error',
            'bg-amber-400 animate-pulse': healthStatus === 'loading',
          }"
        />
      </div>
    </div>
  </header>
</template>

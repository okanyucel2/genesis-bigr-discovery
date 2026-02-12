<script setup lang="ts">
import { onMounted } from 'vue'
import { useHomeDashboard } from '@/composables/useHomeDashboard'
import { useShieldStatus } from '@/composables/useShieldStatus'
import KalkanShield from '@/components/home/KalkanShield.vue'
import HayatKarti from '@/components/home/HayatKarti.vue'
import VerilerimContent from '@/components/home/VerilerimContent.vue'
import AilemContent from '@/components/home/AilemContent.vue'
import EvimContent from '@/components/home/EvimContent.vue'
import BolgemContent from '@/components/home/BolgemContent.vue'
import SecurityTimeline from '@/components/home/SecurityTimeline.vue'
import { Loader2 } from 'lucide-vue-next'

const {
  loading,
  error,
  kalkan,
  verilerim,
  ailem,
  evim,
  bolgem,
  deviceLookup,
  localIp,
  firewallEvents,
  familyTimeline,
  changes,
  fetchDashboard,
} = useHomeDashboard()

const { shieldStatus, fetchShieldStatus } = useShieldStatus()

function cardStatus(card: 'verilerim' | 'ailem' | 'evim' | 'bolgem'): 'ok' | 'warning' | 'danger' {
  switch (card) {
    case 'verilerim':
      return verilerim.value.expiringCerts > 0 ? 'warning' : 'ok'
    case 'ailem':
      return ailem.value.totalThreats > 0 ? 'danger' : 'ok'
    case 'evim':
      return evim.value.newDevices.length > 0 ? 'warning' : 'ok'
    case 'bolgem':
      return bolgem.value.verifiedThreats > 5 ? 'warning' : 'ok'
  }
}

onMounted(() => {
  fetchDashboard()
  fetchShieldStatus()
})
</script>

<template>
  <div class="home-dashboard space-y-6">
    <!-- Loading -->
    <div v-if="loading" class="flex min-h-[60vh] items-center justify-center">
      <div class="flex flex-col items-center gap-3">
        <Loader2 class="h-8 w-8 animate-spin text-cyan-400" />
        <p class="text-sm text-slate-400">Veriler yukleniyor...</p>
      </div>
    </div>

    <!-- Error -->
    <div v-else-if="error" class="flex min-h-[60vh] items-center justify-center">
      <div class="max-w-sm text-center">
        <p class="text-base font-medium text-rose-400">{{ error }}</p>
        <button
          class="mt-4 rounded-lg bg-cyan-500/20 px-4 py-2 text-sm text-cyan-300 transition-colors hover:bg-cyan-500/30"
          @click="fetchDashboard"
        >
          Tekrar Dene
        </button>
      </div>
    </div>

    <!-- Dashboard Content -->
    <template v-else>
      <!-- Kalkan (Shield) — top section -->
      <KalkanShield :data="kalkan" />

      <!-- 4 Hayat Kartlari — 2x2 grid -->
      <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
        <!-- Cards with warnings sort to top on mobile -->
        <HayatKarti
          title="Verilerim"
          icon="🔐"
          :status="cardStatus('verilerim')"
          :class="{ 'order-first': cardStatus('verilerim') !== 'ok' }"
        >
          <VerilerimContent :data="verilerim" />
        </HayatKarti>

        <HayatKarti
          title="Ailem"
          icon="👨‍👩‍👧‍👦"
          :status="cardStatus('ailem')"
          :class="{ 'order-first': cardStatus('ailem') === 'danger' }"
        >
          <AilemContent :data="ailem" />
        </HayatKarti>

        <HayatKarti
          title="Evim"
          icon="🏠"
          :status="cardStatus('evim')"
          :class="{ 'order-first md:order-none': cardStatus('evim') !== 'ok' }"
        >
          <EvimContent :data="evim" />
        </HayatKarti>

        <HayatKarti
          title="Bolgem"
          icon="🌍"
          :status="cardStatus('bolgem')"
        >
          <BolgemContent :data="bolgem" />
        </HayatKarti>
      </div>

      <!-- Security Timeline -->
      <SecurityTimeline
        :firewall-events="firewallEvents"
        :family-timeline="familyTimeline"
        :changes="changes"
        :device-lookup="deviceLookup"
        :local-ip="localIp"
        :shield-status="shieldStatus"
      />
    </template>
  </div>
</template>

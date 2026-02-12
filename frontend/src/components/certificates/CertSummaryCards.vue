<script setup lang="ts">
import { computed } from 'vue'
import { Lock, Clock, XCircle, Fingerprint, KeyRound } from 'lucide-vue-next'
import type { Certificate } from '@/types/api'

const props = defineProps<{
  certificates: Certificate[]
}>()

const stats = computed(() => {
  const total = props.certificates.length
  let expiringSoon = 0
  let expired = 0
  let selfSigned = 0
  let weakKeys = 0

  for (const cert of props.certificates) {
    if (cert.days_until_expiry !== null) {
      if (cert.days_until_expiry < 0) {
        expired++
      } else if (cert.days_until_expiry <= 30) {
        expiringSoon++
      }
    }
    if (cert.is_self_signed) {
      selfSigned++
    }
    if (cert.key_size !== null && cert.key_size < 2048) {
      weakKeys++
    }
  }

  return { total, expiringSoon, expired, selfSigned, weakKeys }
})
</script>

<template>
  <div class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
    <!-- Total Certs -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Toplam Sertifika</p>
          <p class="mt-2 text-2xl font-bold text-white tabular-nums">{{ stats.total }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10">
          <Lock class="h-5 w-5 text-cyan-400" />
        </div>
      </div>
    </div>

    <!-- Expiring Soon -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Yakında Sona Erecek</p>
          <p class="mt-2 text-2xl font-bold text-amber-400 tabular-nums">{{ stats.expiringSoon }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-500/10">
          <Clock class="h-5 w-5 text-amber-400" />
        </div>
      </div>
    </div>

    <!-- Expired -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Süresi Dolmuş</p>
          <p class="mt-2 text-2xl font-bold text-rose-400 tabular-nums">{{ stats.expired }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-rose-500/10">
          <XCircle class="h-5 w-5 text-rose-400" />
        </div>
      </div>
    </div>

    <!-- Self-Signed -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Kendi İmzalı</p>
          <p class="mt-2 text-2xl font-bold text-slate-400 tabular-nums">{{ stats.selfSigned }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-slate-500/10">
          <Fingerprint class="h-5 w-5 text-slate-400" />
        </div>
      </div>
    </div>

    <!-- Weak Keys -->
    <div class="glass-card rounded-xl p-5">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <p class="text-xs font-medium uppercase tracking-wider text-slate-400">Zayıf Anahtarlar</p>
          <p class="mt-2 text-2xl font-bold text-purple-400 tabular-nums">{{ stats.weakKeys }}</p>
        </div>
        <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-purple-500/10">
          <KeyRound class="h-5 w-5 text-purple-400" />
        </div>
      </div>
    </div>
  </div>
</template>

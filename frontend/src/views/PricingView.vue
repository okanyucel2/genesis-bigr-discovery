<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useSubscriptionStore } from '@/stores/subscription'
import { Shield, Zap, Users, Check, ChevronDown, ChevronUp } from 'lucide-vue-next'
import type { PlanInfo } from '@/types/api'

const store = useSubscriptionStore()
const expandedFaq = ref<number | null>(null)

onMounted(async () => {
  await store.loadAll()
})

const planIcons = {
  free: Shield,
  nomad: Zap,
  family: Users,
}

const planAccents = {
  free: {
    border: 'border-slate-600',
    bg: 'bg-slate-800/50',
    btn: 'bg-slate-700 hover:bg-slate-600 text-slate-300',
    ring: '',
    badge: '',
  },
  nomad: {
    border: 'border-cyan-500/50',
    bg: 'bg-slate-800/50',
    btn: 'bg-cyan-600 hover:bg-cyan-500 text-white',
    ring: '',
    badge: '',
  },
  family: {
    border: 'border-emerald-500/50',
    bg: 'bg-gradient-to-b from-emerald-900/20 to-slate-800/50',
    btn: 'bg-emerald-600 hover:bg-emerald-500 text-white',
    ring: 'ring-2 ring-emerald-500/40 shadow-[0_0_30px_rgba(16,185,129,0.15)]',
    badge: 'En Populer',
  },
}

function getPlanStyle(planId: string) {
  return planAccents[planId as keyof typeof planAccents] || planAccents.free
}

function getIcon(planId: string) {
  return planIcons[planId as keyof typeof planIcons] || Shield
}

function getButtonLabel(plan: PlanInfo) {
  if (plan.id === store.currentPlanId) return 'Su Anki Plan'
  if (plan.id === 'free') return 'Ucretsiz Basla'
  if (plan.id === 'nomad') return 'Yukselt'
  return 'Aile Kalkanini Aktiflestir'
}

function isCurrentPlan(planId: string) {
  return planId === store.currentPlanId
}

async function handleActivate(planId: string) {
  if (isCurrentPlan(planId)) return
  await store.activatePlan(planId)
}

function toggleFaq(index: number) {
  expandedFaq.value = expandedFaq.value === index ? null : index
}

const faqs = [
  {
    q: 'Ucretsiz plan ne kadar sureli?',
    a: 'Ucretsiz plan sonsuza kadar gecerlidir. Tek cihaz ve yerel AI tarama ile aginizi korumaya hemen baslayabilirsiniz.',
  },
  {
    q: 'Planimı istedigim zaman degistirebilir miyim?',
    a: 'Evet! Istediginiz zaman planlar arasi gecis yapabilirsiniz. Yukseltme aninda aktif olur, indirgeme ise mevcut donemin sonunda gecerli olur.',
  },
  {
    q: 'Dead Man Switch nedir?',
    a: 'Aile Kalkani planindaki Dead Man Switch, belirlediginiz sure icerisinde sisteme erisim olmazsa, otomatik olarak belirlediginiz kisiye bildirim gonderir. Ailenizin guvenligi icin tasarlanmistir.',
  },
  {
    q: 'AI katmanlari (L0/L1/L2) ne anlama geliyor?',
    a: 'L0 cihazinizdaki yerel AI modelidir (ucretsiz, hizli, gizli). L1 bulut tabanlı hizli dogrulamadir. L2 ise en guclu derin analiz katmanidir ve sadece Aile Kalkani planinda kullanilabilir.',
  },
  {
    q: 'Verilerim guvende mi?',
    a: 'L0 katmaninda tum veriler cihazinizda kalir. L1/L2 kullanildiginda sadece anonim ag verileri islenir, kisisel bilgi paylasilmaz.',
  },
]
</script>

<template>
  <div class="min-h-screen px-4 py-8 sm:px-6 lg:px-8">
    <!-- Header -->
    <div class="mx-auto max-w-5xl text-center mb-12">
      <h1 class="text-3xl font-bold tracking-tight text-white sm:text-4xl">
        Dijital Korumani Sec
      </h1>
      <p class="mt-4 text-lg text-slate-400">
        Sen kahveni yudumla, arkani biz kollariz.
      </p>
    </div>

    <!-- Activation success message -->
    <Transition name="fade">
      <div
        v-if="store.activationMessage"
        class="mx-auto max-w-5xl mb-6 rounded-lg border border-emerald-500/30 bg-emerald-900/20 px-4 py-3 text-center text-emerald-300"
      >
        {{ store.activationMessage }}
      </div>
    </Transition>

    <!-- Error -->
    <Transition name="fade">
      <div
        v-if="store.error"
        class="mx-auto max-w-5xl mb-6 rounded-lg border border-red-500/30 bg-red-900/20 px-4 py-3 text-center text-red-300"
      >
        {{ store.error }}
      </div>
    </Transition>

    <!-- Loading -->
    <div v-if="store.isLoading" class="text-center text-slate-500 py-12">
      Planlar yukleniyor...
    </div>

    <!-- Pricing Cards -->
    <div
      v-else
      class="mx-auto max-w-5xl grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3"
    >
      <div
        v-for="plan in store.plans"
        :key="plan.id"
        class="relative flex flex-col rounded-2xl border p-6 transition-all duration-300 hover:translate-y-[-2px]"
        :class="[
          getPlanStyle(plan.id).border,
          getPlanStyle(plan.id).bg,
          getPlanStyle(plan.id).ring,
        ]"
      >
        <!-- Popular badge -->
        <div
          v-if="getPlanStyle(plan.id).badge"
          class="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-emerald-500 px-4 py-1 text-xs font-bold text-white shadow-lg"
        >
          {{ getPlanStyle(plan.id).badge }}
        </div>

        <!-- Current plan indicator -->
        <div
          v-if="isCurrentPlan(plan.id)"
          class="absolute top-3 right-3 rounded-full bg-cyan-500/20 px-3 py-0.5 text-[10px] font-semibold text-cyan-400 ring-1 ring-cyan-500/30"
        >
          Aktif
        </div>

        <!-- Plan icon & name -->
        <div class="flex items-center gap-3 mb-4">
          <div
            class="flex h-10 w-10 items-center justify-center rounded-xl"
            :class="
              plan.id === 'family'
                ? 'bg-emerald-500/20'
                : plan.id === 'nomad'
                  ? 'bg-cyan-500/20'
                  : 'bg-slate-700'
            "
          >
            <component
              :is="getIcon(plan.id)"
              class="h-5 w-5"
              :class="
                plan.id === 'family'
                  ? 'text-emerald-400'
                  : plan.id === 'nomad'
                    ? 'text-cyan-400'
                    : 'text-slate-400'
              "
            />
          </div>
          <div>
            <h3 class="text-lg font-semibold text-white">{{ plan.name_tr }}</h3>
            <p class="text-xs text-slate-500">{{ plan.name }}</p>
          </div>
        </div>

        <!-- Price -->
        <div class="mb-6">
          <span class="text-4xl font-extrabold text-white">
            {{ plan.price_usd === 0 ? 'Ucretsiz' : `$${plan.price_usd.toFixed(2)}` }}
          </span>
          <span v-if="plan.price_usd > 0" class="text-sm text-slate-400 ml-1">/ay</span>
        </div>

        <!-- Feature list -->
        <ul class="flex-1 space-y-3 mb-6">
          <li
            v-for="(feature, i) in plan.features_tr"
            :key="i"
            class="flex items-start gap-2 text-sm"
          >
            <Check
              class="mt-0.5 h-4 w-4 shrink-0"
              :class="
                plan.id === 'family'
                  ? 'text-emerald-400'
                  : plan.id === 'nomad'
                    ? 'text-cyan-400'
                    : 'text-slate-500'
              "
            />
            <span class="text-slate-300">{{ feature }}</span>
          </li>
        </ul>

        <!-- AI tiers indicator -->
        <div class="mb-4 flex gap-1.5">
          <span
            v-for="tier in plan.ai_tiers"
            :key="tier"
            class="rounded-md px-2 py-0.5 text-[10px] font-bold"
            :class="
              tier === 'L2'
                ? 'bg-purple-500/20 text-purple-300 ring-1 ring-purple-500/30'
                : tier === 'L1'
                  ? 'bg-cyan-500/20 text-cyan-300 ring-1 ring-cyan-500/30'
                  : 'bg-slate-700 text-slate-400 ring-1 ring-slate-600'
            "
          >
            {{ tier }}
          </span>
        </div>

        <!-- CTA Button -->
        <button
          class="w-full rounded-xl py-3 text-sm font-semibold transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
          :class="[
            isCurrentPlan(plan.id)
              ? 'bg-slate-700/50 text-slate-500 cursor-default'
              : getPlanStyle(plan.id).btn,
          ]"
          :disabled="store.isActivating || isCurrentPlan(plan.id)"
          @click="handleActivate(plan.id)"
        >
          <span v-if="store.isActivating" class="inline-flex items-center gap-2">
            <svg class="h-4 w-4 animate-spin" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Islem yapiliyor...
          </span>
          <span v-else>{{ getButtonLabel(plan) }}</span>
        </button>

        <!-- Device limit -->
        <p class="mt-3 text-center text-xs text-slate-500">
          Maks {{ plan.max_devices }} cihaz
        </p>
      </div>
    </div>

    <!-- FAQ Section -->
    <div class="mx-auto max-w-3xl mt-16">
      <h2 class="text-2xl font-bold text-white text-center mb-8">
        Sikca Sorulan Sorular
      </h2>
      <div class="space-y-3">
        <div
          v-for="(faq, index) in faqs"
          :key="index"
          class="rounded-xl border border-slate-700/50 bg-slate-800/30 overflow-hidden transition-all duration-200"
        >
          <button
            class="flex w-full items-center justify-between px-5 py-4 text-left text-sm font-medium text-slate-200 hover:text-white transition-colors"
            @click="toggleFaq(index)"
          >
            <span>{{ faq.q }}</span>
            <component
              :is="expandedFaq === index ? ChevronUp : ChevronDown"
              class="h-4 w-4 shrink-0 text-slate-500"
            />
          </button>
          <Transition name="faq">
            <div v-if="expandedFaq === index" class="px-5 pb-4">
              <p class="text-sm text-slate-400 leading-relaxed">{{ faq.a }}</p>
            </div>
          </Transition>
        </div>
      </div>
    </div>

    <!-- Bottom CTA -->
    <div class="mx-auto max-w-3xl mt-12 text-center">
      <p class="text-sm text-slate-500">
        Tum planlar 30 gun para iade garantisi ile gelir.
        Sorulariniz icin
        <a href="mailto:destek@bigr.app" class="text-cyan-400 hover:underline">destek@bigr.app</a>
        adresine yazabilirsiniz.
      </p>
    </div>
  </div>
</template>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.faq-enter-active {
  transition: all 0.2s ease-out;
}
.faq-leave-active {
  transition: all 0.15s ease-in;
}
.faq-enter-from {
  opacity: 0;
  max-height: 0;
}
.faq-enter-to {
  opacity: 1;
  max-height: 200px;
}
.faq-leave-from {
  opacity: 1;
  max-height: 200px;
}
.faq-leave-to {
  opacity: 0;
  max-height: 0;
}
</style>

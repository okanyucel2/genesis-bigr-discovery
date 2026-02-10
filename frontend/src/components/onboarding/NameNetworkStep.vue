<script setup lang="ts">
import { ref } from 'vue'
import { useOnboardingStore } from '@/stores/onboarding'
import type { NetworkType } from '@/stores/onboarding'

const emit = defineEmits<{
  advance: []
}>()

const store = useOnboardingStore()

const name = ref('')
const selectedType = ref<NetworkType>('home')
const submitting = ref(false)

const typeOptions: Array<{ value: NetworkType; label: string; icon: string }> = [
  { value: 'home', label: 'Evim', icon: 'M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25' },
  { value: 'work', label: 'Is', icon: 'M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21' },
  { value: 'cafe', label: 'Kafe', icon: 'M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.048 8.287 8.287 0 009 9.6a8.983 8.983 0 013.361-6.867 8.21 8.21 0 003 2.48z' },
  { value: 'other', label: 'Diger', icon: 'M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z' },
]

function selectType(type: NetworkType) {
  selectedType.value = type
  // Auto-fill name based on type if empty
  if (!name.value) {
    const labels: Record<NetworkType, string> = {
      home: 'Evim',
      work: 'Is Agi',
      cafe: 'Kafe',
      other: '',
    }
    name.value = labels[type]
  }
}

async function handleSubmit() {
  if (!name.value.trim()) return
  submitting.value = true
  await store.submitNetworkName(name.value.trim(), selectedType.value)
  submitting.value = false
  emit('advance')
}
</script>

<template>
  <div class="flex flex-col items-center justify-center min-h-[60vh] px-6">
    <div class="w-full max-w-md space-y-6">
      <!-- Title -->
      <div class="text-center mb-2">
        <h2 class="text-xl font-bold text-white sm:text-2xl">
          Bu aga bir isim ver
        </h2>
        <p class="mt-2 text-sm text-slate-400">
          Seni her geldiginde taniyacagim
        </p>
      </div>

      <!-- Network Type Buttons -->
      <div class="grid grid-cols-4 gap-2">
        <button
          v-for="opt in typeOptions"
          :key="opt.value"
          class="flex flex-col items-center gap-1.5 rounded-xl border py-3 px-2 text-xs transition-all"
          :class="
            selectedType === opt.value
              ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-400'
              : 'border-white/10 bg-white/5 text-slate-400 hover:border-white/20 hover:bg-white/8'
          "
          @click="selectType(opt.value)"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            class="h-5 w-5"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              :d="opt.icon"
            />
          </svg>
          <span class="font-medium">{{ opt.label }}</span>
        </button>
      </div>

      <!-- Name Input -->
      <div>
        <input
          v-model="name"
          type="text"
          placeholder="Ag ismi gir..."
          maxlength="50"
          class="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-cyan-500/50 focus:bg-white/8"
          @keyup.enter="handleSubmit"
        />
      </div>

      <!-- Submit Button -->
      <button
        class="w-full rounded-xl py-3 text-sm font-medium transition-all disabled:opacity-40"
        :class="
          name.trim()
            ? 'bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/30 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]'
            : 'bg-white/5 border border-white/10 text-slate-500 cursor-not-allowed'
        "
        :disabled="!name.trim() || submitting"
        @click="handleSubmit"
      >
        <span v-if="submitting">Kaydediliyor...</span>
        <span v-else>Kaydet ve Devam Et</span>
      </button>

      <!-- Skip Option -->
      <button
        class="w-full text-center text-xs text-slate-500 hover:text-slate-400 transition-colors"
        @click="store.submitNetworkName('Ag', 'other'); emit('advance')"
      >
        Sonra isimlendiririm
      </button>
    </div>
  </div>
</template>

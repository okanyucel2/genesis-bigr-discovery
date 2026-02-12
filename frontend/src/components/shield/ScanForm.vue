<script setup lang="ts">
import { ref } from 'vue'
import { Shield, Loader2 } from 'lucide-vue-next'
import type { ScanDepth } from '@/types/shield'
import type { SensitivityLevel } from '@/types/api'

const props = defineProps<{
  scanning?: boolean
}>()

const emit = defineEmits<{
  scan: [target: string, depth: ScanDepth, sensitivity: SensitivityLevel]
}>()

const target = ref('')
const depth = ref<ScanDepth>('standard')
const sensitivity = ref<SensitivityLevel>('safe')

const depths: { value: ScanDepth; label: string; desc: string }[] = [
  { value: 'quick', label: 'Hızlı', desc: '~30s' },
  { value: 'standard', label: 'Standart', desc: '~2min' },
  { value: 'deep', label: 'Derin', desc: '~5min' },
]

const sensitivities: { value: SensitivityLevel; label: string; desc: string }[] = [
  { value: 'safe', label: 'Tam', desc: 'Tum moduller' },
  { value: 'cautious', label: 'Dikkatli', desc: 'Exploit yok' },
  { value: 'fragile', label: 'Hassas', desc: 'Sadece pasif' },
]

function handleSubmit() {
  const trimmed = target.value.trim()
  if (!trimmed) return
  emit('scan', trimmed, depth.value, sensitivity.value)
}
</script>

<template>
  <div class="glass-card rounded-xl p-5">
    <form @submit.prevent="handleSubmit" class="space-y-4">
      <!-- Target input -->
      <div>
        <label class="mb-1.5 block text-sm font-medium text-slate-300">
          Hedef
        </label>
        <input
          v-model="target"
          type="text"
          placeholder="example.com veya 192.168.1.0/24"
          :disabled="props.scanning"
          class="w-full rounded-lg border border-[var(--border-glass)] bg-white/5 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-cyan-500/50 focus:bg-white/10 disabled:opacity-50"
        />
      </div>

      <!-- Depth selector -->
      <div>
        <label class="mb-1.5 block text-sm font-medium text-slate-300">
          Tarama Derinliği
        </label>
        <div class="flex gap-2">
          <button
            v-for="d in depths"
            :key="d.value"
            type="button"
            :disabled="props.scanning"
            @click="depth = d.value"
            :class="[
              'flex-1 rounded-lg border px-3 py-2 text-center text-sm transition-all',
              depth === d.value
                ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-400'
                : 'border-[var(--border-glass)] bg-white/5 text-slate-400 hover:bg-white/10 hover:text-slate-300',
              props.scanning ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer',
            ]"
          >
            <div class="font-medium">{{ d.label }}</div>
            <div class="mt-0.5 text-xs opacity-60">{{ d.desc }}</div>
          </button>
        </div>
      </div>

      <!-- Sensitivity selector -->
      <div>
        <label class="mb-1.5 block text-sm font-medium text-slate-300">
          Cihaz Duyarlılığı
        </label>
        <div class="flex gap-2">
          <button
            v-for="s in sensitivities"
            :key="s.value"
            type="button"
            :disabled="props.scanning"
            @click="sensitivity = s.value"
            :class="[
              'flex-1 rounded-lg border px-3 py-2 text-center text-sm transition-all',
              sensitivity === s.value
                ? s.value === 'fragile'
                  ? 'border-amber-500/50 bg-amber-500/10 text-amber-400'
                  : s.value === 'cautious'
                    ? 'border-yellow-500/50 bg-yellow-500/10 text-yellow-400'
                    : 'border-cyan-500/50 bg-cyan-500/10 text-cyan-400'
                : 'border-[var(--border-glass)] bg-white/5 text-slate-400 hover:bg-white/10 hover:text-slate-300',
              props.scanning ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer',
            ]"
          >
            <div class="font-medium">{{ s.label }}</div>
            <div class="mt-0.5 text-xs opacity-60">{{ s.desc }}</div>
          </button>
        </div>
      </div>

      <!-- Submit button -->
      <button
        type="submit"
        :disabled="!target.trim() || props.scanning"
        :class="[
          'flex w-full items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all',
          !target.trim() || props.scanning
            ? 'cursor-not-allowed bg-white/5 text-slate-500'
            : 'bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30',
        ]"
      >
        <Loader2 v-if="props.scanning" class="h-4 w-4 animate-spin" />
        <Shield v-else class="h-4 w-4" />
        {{ props.scanning ? 'Taranıyor...' : 'Taramayı Başlat' }}
      </button>
    </form>
  </div>
</template>

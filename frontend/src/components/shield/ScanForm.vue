<script setup lang="ts">
import { ref } from 'vue'
import { Shield, Loader2 } from 'lucide-vue-next'
import type { ScanDepth } from '@/types/shield'

const props = defineProps<{
  scanning?: boolean
}>()

const emit = defineEmits<{
  scan: [target: string, depth: ScanDepth]
}>()

const target = ref('')
const depth = ref<ScanDepth>('standard')

const depths: { value: ScanDepth; label: string; desc: string }[] = [
  { value: 'quick', label: 'Quick', desc: '~30s' },
  { value: 'standard', label: 'Standard', desc: '~2min' },
  { value: 'deep', label: 'Deep', desc: '~5min' },
]

function handleSubmit() {
  const trimmed = target.value.trim()
  if (!trimmed) return
  emit('scan', trimmed, depth.value)
}
</script>

<template>
  <div class="glass-card rounded-xl p-5">
    <form @submit.prevent="handleSubmit" class="space-y-4">
      <!-- Target input -->
      <div>
        <label class="mb-1.5 block text-sm font-medium text-slate-300">
          Target
        </label>
        <input
          v-model="target"
          type="text"
          placeholder="example.com or 192.168.1.0/24"
          :disabled="props.scanning"
          class="w-full rounded-lg border border-[var(--border-glass)] bg-white/5 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-cyan-500/50 focus:bg-white/10 disabled:opacity-50"
        />
      </div>

      <!-- Depth selector -->
      <div>
        <label class="mb-1.5 block text-sm font-medium text-slate-300">
          Scan Depth
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
        {{ props.scanning ? 'Scanning...' : 'Start Scan' }}
      </button>
    </form>
  </div>
</template>

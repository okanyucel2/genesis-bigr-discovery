<script setup lang="ts">
import { type Component } from 'vue'

defineProps<{
  label: string
  value: string | number
  icon?: Component
  trend?: number
  color?: string
}>()
</script>

<template>
  <div class="glass-card rounded-xl p-5">
    <div class="flex items-start justify-between">
      <div class="flex-1 min-w-0">
        <p class="text-xs font-medium uppercase tracking-wider text-slate-400">
          {{ label }}
        </p>
        <p class="mt-2 text-2xl font-bold text-white tabular-nums">
          {{ value }}
        </p>
        <div v-if="trend !== undefined" class="mt-1 flex items-center gap-1">
          <span
            class="text-xs font-medium"
            :class="
              trend > 0
                ? 'text-emerald-400'
                : trend < 0
                  ? 'text-rose-400'
                  : 'text-slate-500'
            "
          >
            {{ trend > 0 ? '+' : '' }}{{ trend }}%
          </span>
          <span class="text-[10px] text-slate-500">son taramaya göre</span>
        </div>
      </div>
      <div
        v-if="icon"
        class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg"
        :class="color ? '' : 'bg-cyan-500/10'"
        :style="color ? { background: color + '1a' } : {}"
      >
        <component
          :is="icon"
          class="h-5 w-5"
          :class="color ? '' : 'text-cyan-400'"
          :style="color ? { color } : {}"
        />
      </div>
    </div>
  </div>
</template>

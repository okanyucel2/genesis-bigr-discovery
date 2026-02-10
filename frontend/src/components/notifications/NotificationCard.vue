<script setup lang="ts">
import { ref, computed } from 'vue'
import {
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Info,
  Wrench,
  Search,
  X,
} from 'lucide-vue-next'
import type { Component } from 'vue'
import type { HumanNotification } from '@/types/api'

interface SeverityStyle {
  bg: string
  border: string
  text: string
  dot: string
  icon: Component
}

const props = defineProps<{
  notification: HumanNotification
  isRead?: boolean
}>()

defineEmits<{
  action: [actionType: string]
  dismiss: []
}>()

const showTechnical = ref(false)

const defaultStyle: SeverityStyle = {
  bg: 'bg-cyan-500/5',
  border: 'border-cyan-500/20',
  text: 'text-cyan-400',
  dot: 'bg-cyan-400',
  icon: Info,
}

const severityStyles: Record<string, SeverityStyle> = {
  critical: {
    bg: 'bg-red-500/5',
    border: 'border-red-500/20',
    text: 'text-red-400',
    dot: 'bg-red-400',
    icon: AlertTriangle,
  },
  warning: {
    bg: 'bg-amber-500/5',
    border: 'border-amber-500/20',
    text: 'text-amber-400',
    dot: 'bg-amber-400',
    icon: AlertTriangle,
  },
  info: defaultStyle,
}

const actionIcons: Record<string, Component> = {
  fix_it: Wrench,
  investigate: Search,
  dismiss: X,
}

const config = computed<SeverityStyle>(() =>
  severityStyles[props.notification.severity] ?? defaultStyle,
)

const ActionIcon = computed<Component | null>(() => {
  const at = props.notification.action_type
  return at ? (actionIcons[at] ?? Search) : null
})
</script>

<template>
  <div
    class="group relative overflow-hidden rounded-xl border transition-all duration-300 hover:shadow-lg"
    :class="[
      config.bg,
      config.border,
      isRead ? 'opacity-70' : 'opacity-100',
    ]"
  >
    <!-- Unread indicator -->
    <div
      v-if="!isRead"
      class="absolute left-0 top-0 h-full w-1 rounded-l-xl"
      :class="config.dot"
    />

    <div class="p-4 pl-5">
      <!-- Header row -->
      <div class="flex items-start justify-between gap-3">
        <div class="flex items-start gap-3">
          <!-- Icon -->
          <div class="mt-0.5 text-xl leading-none">
            {{ notification.icon }}
          </div>

          <!-- Title + body -->
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <h3 class="text-sm font-semibold text-white">
                {{ notification.title }}
              </h3>
              <span
                class="inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider"
                :class="[config.bg, config.text, config.border, 'border']"
              >
                {{ notification.severity }}
              </span>
              <span
                class="inline-flex rounded-full bg-white/5 px-2 py-0.5 text-[10px] text-slate-500"
              >
                {{ notification.generated_by }}
              </span>
            </div>
            <p class="mt-1.5 text-sm leading-relaxed text-slate-300">
              {{ notification.body }}
            </p>
          </div>
        </div>

        <!-- Dismiss button -->
        <button
          class="shrink-0 rounded-lg p-1 text-slate-600 opacity-0 transition-opacity hover:bg-white/5 hover:text-slate-400 group-hover:opacity-100"
          @click="$emit('dismiss')"
        >
          <X class="h-4 w-4" />
        </button>
      </div>

      <!-- Action row -->
      <div class="mt-3 flex items-center justify-between">
        <div class="flex items-center gap-2">
          <!-- Action button -->
          <button
            v-if="notification.action_label"
            class="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors"
            :class="
              notification.severity === 'critical'
                ? 'bg-red-500/10 text-red-400 hover:bg-red-500/20'
                : notification.severity === 'warning'
                  ? 'bg-amber-500/10 text-amber-400 hover:bg-amber-500/20'
                  : 'bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20'
            "
            @click="$emit('action', notification.action_type || 'investigate')"
          >
            <component :is="ActionIcon" v-if="ActionIcon" class="h-3.5 w-3.5" />
            {{ notification.action_label }}
          </button>

          <!-- Technical details toggle -->
          <button
            class="flex items-center gap-1 rounded-lg px-2 py-1 text-[11px] text-slate-500 transition-colors hover:bg-white/5 hover:text-slate-400"
            @click="showTechnical = !showTechnical"
          >
            <component :is="showTechnical ? ChevronUp : ChevronDown" class="h-3 w-3" />
            Teknik Detay
          </button>
        </div>

        <!-- Timestamp -->
        <span class="text-[10px] text-slate-600">
          {{ notification.created_at.slice(0, 19).replace('T', ' ') }}
        </span>
      </div>

      <!-- Technical details (expandable) -->
      <Transition name="slide">
        <div
          v-if="showTechnical"
          class="mt-3 rounded-lg bg-black/20 p-3"
        >
          <div class="flex items-center gap-2 text-[10px] uppercase tracking-wider text-slate-500">
            <component :is="config.icon" class="h-3 w-3" />
            Orijinal Teknik Mesaj
          </div>
          <p class="mt-1.5 font-mono text-xs leading-relaxed text-slate-400">
            {{ notification.original_message }}
          </p>
          <div class="mt-2 flex items-center gap-3 text-[10px] text-slate-600">
            <span>Tur: {{ notification.original_alert_type }}</span>
            <span>Motor: {{ notification.generated_by }}</span>
          </div>
        </div>
      </Transition>
    </div>
  </div>
</template>

<style scoped>
.slide-enter-active,
.slide-leave-active {
  transition: all 0.2s ease;
}
.slide-enter-from,
.slide-leave-to {
  opacity: 0;
  max-height: 0;
  margin-top: 0;
  padding: 0;
}
.slide-enter-to,
.slide-leave-from {
  opacity: 1;
  max-height: 200px;
}
</style>
